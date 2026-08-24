package workbench

// 认知工作台（架构支柱二：会干活）——LLM 大脑的跨轮认知状态：
//   - 作战图（Problems）：进行中问题（根因假设/证据链/阻塞点/下一步）；
//   - 假设表（Hypotheses）：进行中假设（claim + 支持/反对证据 + next_check），
//     新证据到来时由假设引擎激活待验证项，追查从"每轮重来"变为"延续假设"；
//   - 待验证（PendingChecks）：等待证据的低置信裁决；
//   - 行动记录（Actions）：本轮认知动作（防重复劳动）。
//
// 持久化 workbench.json（崩溃恢复）；引擎主循环与 worker 池并发读写，
// 全部操作加锁。

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-gocel/gocode-ops/internal/common/fsutil"
	"github.com/go-gocel/gocode-ops/internal/common/model"
)

// WorkbenchProblem is an in-progress problem on the operation map.
// WorkbenchProblem 作战图中的进行中问题。
type WorkbenchProblem struct {
	ID         string   `json:"id"` // finding ID
	Host       string   `json:"host"`
	Signal     string   `json:"signal"`
	Hypothesis string   `json:"hypothesis,omitempty"` // 根因假设
	Evidence   []string `json:"evidence,omitempty"`   // 证据链
	Status     string   `json:"status"`               // tracing/remediating/verifying/blocked
	NextStep   string   `json:"next_step,omitempty"`  // 下一步动作
	UpdatedAt  string   `json:"updated_at"`
}

// WorkbenchHypothesis is an in-progress hypothesis.
// WorkbenchHypothesis 进行中假设。
type WorkbenchHypothesis struct {
	ID        string   `json:"id"`
	Claim     string   `json:"claim"`
	Support   []string `json:"support,omitempty"`
	Against   []string `json:"against,omitempty"`
	NextCheck string   `json:"next_check,omitempty"` // 待验证项（证据变化时激活）
	Active    bool     `json:"active"`
	UpdatedAt string   `json:"updated_at"`
}

// PendingCheck is a low-confidence verdict awaiting evidence.
// PendingCheck 等待证据的裁决。
type PendingCheck struct {
	FindingID string `json:"finding_id"`
	Need      string `json:"need"`  // 缺什么证据
	Probe     string `json:"probe"` // 建议的定向采集探针（collect_probe）
	CreatedAt string `json:"created_at"`
}

// Workbench is the cognitive workbench holding the LLM's cross-round cognition state.
// Workbench 认知工作台。
type Workbench struct {
	Problems   []WorkbenchProblem    `json:"problems,omitempty"`
	Hypotheses []WorkbenchHypothesis `json:"hypotheses,omitempty"`
	Pending    []PendingCheck        `json:"pending_checks,omitempty"`
	Actions    []string              `json:"actions,omitempty"` // 最近认知动作（防重复）
	UpdatedAt  string                `json:"updated_at"`
	// Writes 认知活动计数（每次落盘 +1）——运行摘要的诊断信号：一轮评测
	// 中大脑有没有真正使用工作台（0=四表从未写入，认知层空转）。
	Writes int `json:"writes,omitempty"`

	mu   sync.Mutex
	path string
}

// WorkbenchPath returns the path of the workbench state file.
// WorkbenchPath 工作台文件路径。
func WorkbenchPath(workDir string) string {
	return filepath.Join(model.ConfigDir(workDir), "workbench.json")
}

// NewWorkbench loads or initializes the workbench for the given working directory.
// NewWorkbench 加载/初始化工作台。
func NewWorkbench(workDir string) (*Workbench, error) {
	w := &Workbench{path: WorkbenchPath(workDir)}
	if err := os.MkdirAll(filepath.Dir(w.path), 0o755); err != nil {
		return nil, fmt.Errorf("workbench: 创建配置目录失败: %w", err)
	}
	data, err := os.ReadFile(w.path)
	if err == nil {
		if err := json.Unmarshal(data, w); err != nil {
			return nil, fmt.Errorf("workbench: 解析失败: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return w, nil
}

// saveLocked 落盘（调用方持锁）。
func (w *Workbench) saveLocked() {
	w.Writes++
	w.UpdatedAt = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	if data, err := json.MarshalIndent(w, "", "  "); err == nil {
		_ = fsutil.WriteFileAtomic(w.path, append(data, '\n'), 0o644)
	}
}

// WriteCount returns the cognitive activity write count (concurrency-safe).
// WriteCount 返回认知活动计数（运行摘要用；并发安全）。
func (w *Workbench) WriteCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.Writes
}

// UpsertProblem updates or inserts an operation-map problem and persists the workbench.
// UpsertProblem 更新/新建作战图问题（大脑写入）。
func (w *Workbench) UpsertProblem(p WorkbenchProblem) {
	w.mu.Lock()
	defer w.mu.Unlock()
	p.UpdatedAt = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	for i := range w.Problems {
		if w.Problems[i].ID == p.ID {
			w.Problems[i] = p
			w.saveLocked()
			return
		}
	}
	w.Problems = append(w.Problems, p)
	w.saveLocked()
}

// RemoveProblem removes the problem with the given ID.
// RemoveProblem 移除已关闭问题（finding closed 时调用）。
func (w *Workbench) RemoveProblem(id string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := range w.Problems {
		if w.Problems[i].ID == id {
			w.Problems = append(w.Problems[:i], w.Problems[i+1:]...)
			w.saveLocked()
			return
		}
	}
}

// AddHypothesis creates a hypothesis and returns its ID, reusing the existing ID when the claim already exists.
// AddHypothesis 新建假设；同 claim 已存在时返回现有 ID（幂等）。
func (w *Workbench) AddHypothesis(claim, nextCheck string) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	claim = strings.TrimSpace(claim)
	for _, h := range w.Hypotheses {
		if strings.EqualFold(h.Claim, claim) {
			return h.ID
		}
	}
	id := fmt.Sprintf("h%d", len(w.Hypotheses)+1)
	w.Hypotheses = append(w.Hypotheses, WorkbenchHypothesis{
		ID: id, Claim: claim, NextCheck: nextCheck, Active: nextCheck != "",
		UpdatedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	})
	w.saveLocked()
	return id
}

// UpdateHypothesis updates a hypothesis with new evidence, next check, and activation state.
// UpdateHypothesis 更新假设（支持/反对证据追加、next_check、激活状态）。
func (w *Workbench) UpdateHypothesis(id, evidence string, support bool, nextCheck string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := range w.Hypotheses {
		h := &w.Hypotheses[i]
		if h.ID != id {
			continue
		}
		if evidence != "" {
			if support {
				h.Support = appendUnique(h.Support, evidence)
			} else {
				h.Against = appendUnique(h.Against, evidence)
			}
		}
		if nextCheck != "" {
			h.NextCheck = nextCheck
			h.Active = true
		}
		h.UpdatedAt = time.Now().UTC().Format("2006-01-02T15:04:05Z")
		w.saveLocked()
		return true
	}
	return false
}

// ActivateHypotheses activates hypotheses awaiting evidence and returns summaries of the activated ones.
// ActivateHypotheses 证据变化时激活待验证假设（引擎在 L0 新线索后调用）：
// 返回被激活的假设摘要（提示词注入：大脑知道哪些假设需要续查）。
func (w *Workbench) ActivateHypotheses() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	for i := range w.Hypotheses {
		h := &w.Hypotheses[i]
		if h.NextCheck != "" && !h.Active {
			h.Active = true
			out = append(out, fmt.Sprintf("%s: %s（待验证: %s）", h.ID, h.Claim, h.NextCheck))
		}
	}
	if len(out) > 0 {
		w.saveLocked()
	}
	return out
}

// AddPendingCheck registers a pending check for a finding awaiting evidence.
// AddPendingCheck 登记待验证裁决（低置信裁决自动补证据）。
func (w *Workbench) AddPendingCheck(findingID, need, probe string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, p := range w.Pending {
		if p.FindingID == findingID {
			return // 已登记
		}
	}
	w.Pending = append(w.Pending, PendingCheck{
		FindingID: findingID, Need: need, Probe: probe,
		CreatedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	})
	w.saveLocked()
}

// ResolvePendingChecks resolves all pending checks and returns them for re-adjudication.
// ResolvePendingChecks 解析全部待验证（证据已到位时返回摘要供重裁）。
func (w *Workbench) ResolvePendingChecks() []PendingCheck {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := append([]PendingCheck{}, w.Pending...)
	w.Pending = nil
	w.saveLocked()
	return out
}

// RecordAction records a cognitive action and reports whether it is new.
// RecordAction 记录认知动作（防重复劳动：同 finding 同动作不重复执行）。
// 返回是否新动作（重复返回 false）。
func (w *Workbench) RecordAction(key string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, a := range w.Actions {
		if a == key {
			return false
		}
	}
	w.Actions = append(w.Actions, key)
	if len(w.Actions) > 200 {
		w.Actions = w.Actions[len(w.Actions)-200:]
	}
	w.saveLocked()
	return true
}

// Brief renders a compact workbench summary bounded by the given budget.
// Brief 紧凑摘要（提示词注入：作战图注入而非全量事实转储）。
// 每项限长，总量受 budget 约束。
func (w *Workbench) Brief(budget int) string {
	if w == nil {
		return ""
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	var b strings.Builder
	if len(w.Problems) > 0 {
		b.WriteString("## 进行中问题（作战图）\n")
		for _, p := range w.Problems {
			fmt.Fprintf(&b, "- [%s] %s/%s（%s）：%s\n", p.ID, p.Host, p.Signal, p.Status, fsutil.TruncateStr(p.Hypothesis, 80))
			if p.NextStep != "" {
				fmt.Fprintf(&b, "  下一步: %s\n", fsutil.TruncateStr(p.NextStep, 100))
			}
		}
	}
	if len(w.Hypotheses) > 0 {
		b.WriteString("## 进行中假设\n")
		for _, h := range w.Hypotheses {
			if !h.Active {
				continue
			}
			fmt.Fprintf(&b, "- %s: %s（支持 %d 条/反对 %d 条%s）\n", h.ID,
				fsutil.TruncateStr(h.Claim, 80), len(h.Support), len(h.Against),
				ternary(h.NextCheck != "", "，待验证: "+fsutil.TruncateStr(h.NextCheck, 60), ""))
		}
	}
	if len(w.Pending) > 0 {
		b.WriteString("## 待验证\n")
		for _, p := range w.Pending {
			fmt.Fprintf(&b, "- %s: %s（建议采集: %s）\n", p.FindingID, fsutil.TruncateStr(p.Need, 80), p.Probe)
		}
	}
	out := b.String()
	if budget > 0 && len(out) > budget {
		// 截断点回退到完整 rune 边界（裸字节切片会把中文切半，
		// 非法 UTF-8 进模型上下文）。
		n := budget
		for n > 0 && !utf8.RuneStart(out[n]) {
			n--
		}
		out = out[:n] + "…"
	}
	return out
}

func appendUnique(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

// SortedProblems returns the sorted problem ID list for the scheduler.
// SortedProblems 按更新时间排序的问题 ID 列表（调度器用）。
func (w *Workbench) SortedProblems() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	ids := make([]string, 0, len(w.Problems))
	for _, p := range w.Problems {
		ids = append(ids, p.ID)
	}
	sort.Strings(ids)
	return ids
}
