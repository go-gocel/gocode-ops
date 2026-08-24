package workspace

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/go-gocel/gocode-ops/internal/common/fsutil"
	"github.com/go-gocel/gocode-ops/internal/common/model"
)

// Workspace 跨阶段共享状态（协议机的事实源）：
//
//	env.json      — 环境画像（Explore 产出）
//	findings.json — 全部发现（三态：pending/confirmed/dismissed）
//	baseline.json — L0 多轮基线历史（痕迹机制：变化趋势）
//
// 报告与阶段推进都从这里读；崩溃后可恢复。
type Workspace struct {
	dir      string // 工作目录（报告等可见产出）
	stateDir string // 状态落盘目录（dir/.gocode，与配置同目录）
	mu       sync.Mutex
	// lastFindingsSave 本进程上次 findings 落盘时间（并行合并判定：
	// 磁盘 mtime 严格晚于它 = 另一进程写的最新状态，落盘前需并入；
	// 等于/早于 = 自己写的，跳过——避免旧状态覆盖新状态）。
	lastFindingsSave time.Time
	Env              *EnvInfo        `json:"env"`
	FindingList      []*Finding      `json:"findings"`
	BaselinePoints   []BaselinePoint `json:"baseline"`
	PhaseLogs        []PhaseLog      `json:"phases"`             // 阶段执行记录（耗时/结果）
	L0Facts          l0Facts         `json:"l0_facts,omitempty"` // 最近一轮安全事实（上下文管道）
	// L0Coverage 最近一轮事实覆盖语义（host → probeID → full/partial/
	// skipped；报告审计面展示 partial/skipped——覆盖度是事实的一部分）。
	L0Coverage map[string]map[string]string `json:"l0_coverage,omitempty"`
	// Inventory S2 上板基线（host → probeID → 基线；全盘枚举探针的
	// 例行替代，见 inventory.go）。
	Inventory map[string]map[string]*FactInventory `json:"fact_inventory,omitempty"`
}

// BaselinePoint 一轮 L0 基线的聚合值。
type BaselinePoint struct {
	At    time.Time                     `json:"at"`
	Hosts map[string]map[string]float64 `json:"hosts"` // host → 指标ID → 值
	// State 状态快照（配置漂移检测：host → probeID → 摘要）；与数值基线
	// 同轮采集，跨轮对比"变化即痕"。
	State map[string]map[string]string `json:"state,omitempty"`
}

// PhaseLog 一次阶段执行记录。
type PhaseLog struct {
	Phase    Phase         `json:"phase"`
	At       time.Time     `json:"at"`
	Duration time.Duration `json:"duration"`
	OK       bool          `json:"ok"`
	Err      string        `json:"err,omitempty"`
	Covered  []string      `json:"covered,omitempty"`
	Skipped  []string      `json:"skipped,omitempty"` // 无法检查的项及原因（如实交代）
}

// NewWorkspace 创建/加载工作区。状态 json 统一落盘在 dir/.gocode/（与
// 配置清单同目录），工作目录根只留报告等可见产出。
func NewWorkspace(dir string) (*Workspace, error) {
	stateDir := model.ConfigDir(dir)
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, fmt.Errorf("workspace: 创建状态目录失败: %w", err)
	}
	w := &Workspace{dir: dir, stateDir: stateDir, FindingList: []*Finding{}, BaselinePoints: []BaselinePoint{}, PhaseLogs: []PhaseLog{}}
	if err := w.load(); err != nil {
		return nil, err
	}
	return w, nil
}

// Dir 工作区目录。
func (w *Workspace) Dir() string { return w.dir }

func (w *Workspace) load() error {
	for name, dst := range map[string]any{
		"env.json":            &w.Env,
		"findings.json":       &w.FindingList,
		"baseline.json":       &w.BaselinePoints,
		"phases.json":         &w.PhaseLogs,
		"fact_inventory.json": &w.Inventory,
	} {
		data, err := os.ReadFile(filepath.Join(w.stateDir, name))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("workspace: 读 %s 失败: %w", name, err)
		}
		if err := json.Unmarshal(data, dst); err != nil {
			return fmt.Errorf("workspace: 解析 %s 失败: %w", name, err)
		}
	}
	return nil
}

func (w *Workspace) save(name string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(w.stateDir, name), data, 0o644)
}

func (w *Workspace) SetEnv(env *EnvInfo) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.Env = env
	return w.save("env.json", env)
}

// SaveFindings 落盘当前发现列表。状态不经 AddFindings 变更时使用
// （如重裁决直接改写状态——merge 规则会拒绝非 confirmed 降级已确认项，
// 不能走 AddFindings 落盘）。跨进程合并落盘（与引擎/助手并行安全）。
func (w *Workspace) SaveFindings() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.saveFindingsMerged()
}

// AddFindings 合并阶段小结中的发现：按归一化 (host, signal, key) 去重
// 升级，已有 confirmed 不被降级，已有 dismissed 不复活。
func (w *Workspace) AddFindings(list []*Finding) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	byKey := map[string]*Finding{}
	for _, f := range w.FindingList {
		byKey[dedupKeyF(f)] = f
	}
	for _, f := range list {
		if f.Host == "" || f.Signal == "" {
			continue
		}
		// ID 补全：模型上报的 finding 不带 id（输出契约无 id 字段），
		// 入库即分配——后续 respond 阶段靠 ID/signal 定位处置目标，
		// 空 ID 会让模型无从复述而自创 ID（错配根源）。
		// ID 为 (host, signal, key) 的确定性短哈希：同一去重键恒同 ID
		// （跨轮稳定、模型可复述、报告可追溯），不同对象必不同 ID——
		// 历史实现 UnixNano()%100000 同一批入库的连续 finding 取模冲突
		// （实测 3 条 exposed_listen 同 ID=44600），导致 byID 覆盖丢失、
		// 模型复述歧义、respond 处置目标错配（db 方案挂到 ssh_root_login）。
		if f.ID == "" {
			f.ID = findingID(f)
		}
		// 创建时间补全：模型输出的 finding 无 at 字段（零值），
		// 入库即补——创建时间不依赖模型（数据完整性）。
		if f.At.IsZero() {
			f.At = time.Now().UTC()
		}
		// 证据去重瘦身：证据首条与 desc 完全重复时省略（裁决链常见
		// evidence[0]==desc，findings.json 体积主要来自重复正文）。
		if len(f.Evidence) == 1 && f.Evidence[0] == f.Desc {
			f.Evidence = nil
		}
		key := dedupKeyF(f)
		old, ok := byKey[key]
		if !ok {
			w.FindingList = append(w.FindingList, f)
			byKey[key] = f
			continue
		}
		w.merge(old, f)
	}
	// 跨进程合并落盘：同一工作目录多形态并行（引擎+助手同时运行）
	// 时，先并入磁盘上另一进程的最新条目再写——不丢对方的处置状态
	// （锁内读-改-写，防竞态覆盖）。
	return w.saveFindingsMerged()
}

// saveFindingsMerged 持跨进程锁保存 findings：磁盘 mtime 严格晚于
// 本进程上次落盘（另一进程写的最新状态）时，先并入磁盘条目再写回；
// 等于/早于（自己写的）跳过合并，避免旧状态覆盖新状态。锁获取
// 失败降级为直接写（原子写兜底防半截）。
func (w *Workspace) saveFindingsMerged() error {
	return withStateLock(w.stateDir, func() error {
		path := filepath.Join(w.stateDir, "findings.json")
		if fi, err := os.Stat(path); err == nil && fi.ModTime().After(w.lastFindingsSave) {
			w.mergeDiskFindings()
		}
		if err := w.save("findings.json", w.FindingList); err != nil {
			return err
		}
		w.lastFindingsSave = time.Now()
		return nil
	})
}

// mergeDiskFindings 把磁盘 findings.json 的条目并入内存列表（按去重
// 键）：磁盘条目代表另一进程（引擎/助手）的落盘状态——同键条目用
// "只增不减"规则合入（任何一方的新进展都不得被对方旧视图回退：
// confirmed 终态保护/处置状态只增不减/计数取大/去向有者胜），磁盘
// 独有条目追加。合并后列表只增不减（本进程内存是增量源，磁盘是并存源）。
func (w *Workspace) mergeDiskFindings() {
	data, err := os.ReadFile(filepath.Join(w.stateDir, "findings.json"))
	if err != nil {
		return // 无磁盘状态（首次写入）或读失败：跳过
	}
	var disk []*Finding
	if err := json.Unmarshal(data, &disk); err != nil {
		return // 磁盘损坏：不合并（原子写保证不会读到半截）
	}
	byKey := map[string]*Finding{}
	for _, f := range w.FindingList {
		byKey[dedupKeyF(f)] = f
	}
	for _, f := range disk {
		if f == nil || f.Host == "" || f.Signal == "" {
			continue
		}
		key := dedupKeyF(f)
		old, ok := byKey[key]
		if !ok {
			w.FindingList = append(w.FindingList, f)
			byKey[key] = f
			continue
		}
		// 磁盘条目作为"并存状态"合入内存条目：只增不减——本进程内存的
		// 处置状态不回退（引擎已处置不被助手旧视图回退，反之亦然），
		// 任何一方的新证据/去向/计数都保留。
		mergeDiskInto(old, f)
	}
}

// mergeDiskInto 跨进程合并（只增不减）：磁盘条目与内存条目的字段级
// 并集——状态取更强（dismissed→pending→confirmed 可升级、confirmed
// 不降级）、处置状态（Remediated）只增不减、计数取较大值、去向
// （Actions/Disposition）有者胜、发现层非空合并。与 merge 的区别：
// 跨进程无"新旧"可比（双方都可能更新过同一字段），只增不减是最
// 小后悔方向——丢失任何一方进展的代价高于保留旧值。
func mergeDiskInto(old, disk *Finding) {
	if old.Status == FindingConfirmed && disk.Status != FindingConfirmed {
		return // confirmed 终态不降级（保留内存方向）
	}
	if old.Status == FindingDismissed && disk.Source == SourceL0 {
		return // L0 痕迹不复活已排除项
	}
	// 状态升级方向：只允许取更强（dismissed→pending→confirmed）；
	// 反向（confirmed→pending/dismissed、pending→dismissed）保留内存值
	// ——重裁决由引擎进程自身落盘传播，不靠并存合并降级。
	if rank(disk.Status) > rank(old.Status) {
		old.Status = disk.Status
	}
	// 处置状态只增不减：任何一方已处置即已处置。
	if disk.Remediated && !old.Remediated {
		old.Remediated = true
	}
	if old.RemediatedAt.IsZero() && !disk.RemediatedAt.IsZero() {
		old.RemediatedAt = disk.RemediatedAt
	}
	// 计数取较大（追查/处置/重检出进展不因对方旧视图回退）。
	if disk.Tried > old.Tried {
		old.Tried = disk.Tried
	}
	if disk.RespondTried > old.RespondTried {
		old.RespondTried = disk.RespondTried
	}
	if disk.Redetect > old.Redetect {
		old.Redetect = disk.Redetect
	}
	if disk.Rechased > old.Rechased {
		old.Rechased = disk.Rechased
	}
	// 去向有者胜：动作链/工单/验证去向非 nil 即保留（双方各自写回）。
	if len(disk.Actions) > len(old.Actions) {
		old.Actions = disk.Actions
	}
	if disk.Disposition != nil && old.Disposition == nil {
		old.Disposition = disk.Disposition
	}
	if disk.RemediationNote != "" && old.RemediationNote == "" {
		old.RemediationNote = disk.RemediationNote
	}
	if len(disk.SuggestedFix) > len(old.SuggestedFix) {
		old.SuggestedFix = disk.SuggestedFix
	}
	// 发现层：字段级非空合并（稀疏对象不得洗掉证据链，同 merge）。
	if disk.RootCause != "" {
		old.RootCause = disk.RootCause
	}
	if disk.Confidence != 0 {
		old.Confidence = disk.Confidence
	}
	if len(disk.Evidence) > 0 {
		old.Evidence = disk.Evidence
	}
	if disk.Desc != "" {
		old.Desc = disk.Desc
	}
	if disk.Domain != "" {
		old.Domain = disk.Domain
	}
}

// findingID 确定性 finding ID：host/signal/<dedupKey 的 fnv32 哈希尾部>。
// 输入与 dedupKeyF 同一归一化（小写/折叠空白），保证同去重键跨轮恒同
// ID——host/signal 前缀同样归一化（模型上报大小写不稳定，ID 是"对象
// 身份"，身份不随大小写漂移）；哈希空间 1e6（碰撞率 ~1e-6/条），同轮
// 多对象（同 signal 不同 key）必不同 ID。语义：ID 用于处置定位/报告
// 追溯/模型复述，以对象身份为准。
func findingID(f *Finding) string {
	h := fnv.New32a()
	h.Write([]byte(dedupKeyF(f)))
	return fmt.Sprintf("%s/%s/%d", normKey(f.Host), normKey(f.Signal), h.Sum32()%1000000)
}

// dedupKeyF 归一化去重键：host/signal/key——小写并折叠空白。模型输出
// 自由文本时同根因的 signal 大小写/空格不稳定，精确匹配会把同一根因
// 分裂成多条重复确认；Key 非空时参与去重（同 signal 不同子键不互吞，
// 见 stateDrift 漂移源）。
func (w *Workspace) Findings() []*Finding {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]*Finding, len(w.FindingList))
	copy(out, w.FindingList)
	sort.SliceStable(out, func(i, j int) bool {
		return rank(out[i].Status) > rank(out[j].Status)
	})
	return out
}

// Confirmed 已确认的发现。
func (w *Workspace) Confirmed() []*Finding {
	var out []*Finding
	for _, f := range w.Findings() {
		if f.Status == FindingConfirmed {
			out = append(out, f)
		}
	}
	return out
}

// Pending 未验证的线索（DeepDive 待追查）。
func (w *Workspace) Pending() []*Finding {
	var out []*Finding
	for _, f := range w.Findings() {
		if f.Status == FindingPending {
			out = append(out, f)
		}
	}
	return out
}

// Dismissed 已排除的发现（报告"已排查"区）。
func (w *Workspace) Dismissed() []*Finding {
	var out []*Finding
	for _, f := range w.Findings() {
		if f.Status == FindingDismissed {
			out = append(out, f)
		}
	}
	return out
}

// 基线保留策略：时间窗口优先（24h，覆盖完整昼夜周期——负载有昼夜节律，
// 固定轮数在巡检频率变化时窗口漂移，是监控领域惯例）；窗口内样本不足
// baselineMinPts 时放宽到最近 N 轮，保证低频巡检时趋势仍可用；硬上限
// 兜底防文件失控。
const (
	stateSummaryFactsPerHost = 12 << 10 // 单主机事实文本字节上限（≈12KB）
	stateSummaryMaxPending   = 40       // 待查线索条数上限
	stateSummaryMaxDismissed = 30       // 已排除条数上限
	stateSummaryMaxConfirmed = 40       // 确认故障条数上限
)

// StateSummary 生成工作区状态摘要（供阶段任务提示）。
func (w *Workspace) StateSummary() string {
	// 并发读：Env/L0Facts 与 SetEnv/SetL0Facts 的写路径对锁——助手形态
	// Warmup goroutine 与任务轮并发访问，不加锁读会数据竞态。
	w.mu.Lock()
	env := w.Env
	facts := w.L0Facts
	w.mu.Unlock()
	// 摘要只读副本：截断不得污染共享 L0Facts。截断点回退到完整 rune
	// 边界（fsutil.TruncateStr——裸字节切片会把中文切半）。
	trimmedFacts := make(map[string]string, len(facts))
	for host, txt := range facts {
		if len(txt) > stateSummaryFactsPerHost {
			txt = fsutil.TruncateStr(txt, stateSummaryFactsPerHost) + fmt.Sprintf("\n…（事实文本已截断，%d 字节未注入，详见 report.md）", len(txt)-stateSummaryFactsPerHost)
		}
		trimmedFacts[host] = txt
	}
	// 条数截断：超限时保留前 N 条并追加标记行——模型必须知道摘要
	// 不完整（静默截断会误导"已见全部状态"的裁决）。
	capList := func(list []*Finding, max int, label string) []*Finding {
		if len(list) <= max {
			return list
		}
		out := append([]*Finding{}, list[:max]...)
		out = append(out, &Finding{
			Host: "(省略)", Signal: "(省略)",
			Desc: fmt.Sprintf("…其余 %d 条%s未注入上下文（完整清单见工作区 findings 与 report.md）", len(list)-max, label),
		})
		return out
	}
	// 只摘要：环境画像 + 三态发现 + L0 安全事实，控制上下文。
	sum := struct {
		Env       *EnvInfo          `json:"env,omitempty"`
		Confirmed []*Finding        `json:"confirmed,omitempty"`
		Pending   []*Finding        `json:"pending,omitempty"`
		Dismissed []*Finding        `json:"dismissed,omitempty"`
		L0Facts   map[string]string `json:"l0_facts,omitempty"` // 确定性采集的环境事实
	}{
		Env:     env,
		L0Facts: trimmedFacts,
	}
	for _, f := range w.Findings() {
		switch f.Status {
		case FindingConfirmed:
			sum.Confirmed = append(sum.Confirmed, f)
		case FindingPending:
			sum.Pending = append(sum.Pending, f)
		case FindingDismissed:
			sum.Dismissed = append(sum.Dismissed, f)
		}
	}
	// 已关闭项简报化（上下文预算的结构性约束）：dismissed 与已处置的
	// confirmed 不再参与后续裁决（排除是验证回路终局、处置已完成），
	// 全量详情每批注入是上下文大头（20 条 dismissed × 全字段 JSON
	// ≈ 数 KB/批）——简报只保留身份与一行现象，模型仍能感知其存在与
	// 结论，需要细节时见工作区 findings/report.md。pending 与未处置
	// confirmed 保持全量（模型要裁决/处置它们）。
	brief := func(f *Finding) *Finding {
		cp := *f
		cp.Evidence = nil
		cp.Actions = nil
		cp.SuggestedFix = nil
		cp.Disposition = nil
		cp.RootCause = ""
		cp.Confidence = 0
		cp.Tried, cp.RespondTried, cp.Redetect, cp.Rechased = 0, 0, 0, 0
		cp.ConfirmedAt, cp.RemediatedAt = time.Time{}, time.Time{}
		if len(cp.Desc) > 120 {
			cp.Desc = cp.Desc[:120] + "…"
		}
		return &cp
	}
	for i, f := range sum.Confirmed {
		if f.Remediated {
			sum.Confirmed[i] = brief(f)
		}
	}
	for i, f := range sum.Dismissed {
		sum.Dismissed[i] = brief(f)
	}
	sum.Confirmed = capList(sum.Confirmed, stateSummaryMaxConfirmed, "确认故障")
	sum.Pending = capList(sum.Pending, stateSummaryMaxPending, "待查线索")
	sum.Dismissed = capList(sum.Dismissed, stateSummaryMaxDismissed, "已排除项")
	b, err := json.MarshalIndent(sum, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}
