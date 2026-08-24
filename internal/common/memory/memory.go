package memory

// memory.go — 记忆仓库：经验库 + 主机档案（跨轮次沉淀，线程安全）。
//
// 记忆资产（架构支柱四：能成长）——产品随运行时间增值的机制：
//   - 经验库（experience.json）：signal → 处置模板/结果统计/误报率，
//     学习闭环在发现关闭时沉淀，recall 供大脑检索；
//   - 主机档案（dossiers/<host>.json）：每台主机的历史发现/恢复模式/
//     易错点，跨轮次画像。
//
// 线程安全：worker 池并发沉淀/检索，全部操作加锁。

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-gocel/gocode-ops/internal/common/fsutil"
	"github.com/go-gocel/gocode-ops/internal/common/model"
)

// ExperienceEntry 一条经验的统计沉淀。
type ExperienceEntry struct {
	Signal     string  `json:"signal"`
	Host       string  `json:"host,omitempty"` // 空=全局
	Pattern    string  `json:"pattern"`        // 现象特征（对象/描述摘要）
	Action     string  `json:"action"`         // 有效处置动作（模板）
	Outcome    string  `json:"outcome"`        // remediated / dismissed
	Count      int     `json:"count"`          // 命中次数
	Misreports int     `json:"misreports"`     // 误报次数（dismissed 沉淀）
	LastSeen   string  `json:"last_seen"`      // 最近一次（RFC3339）
	Confidence float64 `json:"confidence"`     // 1 - misreport 比例
}

// Experience 经验库（全局 + per-host 混合，Signal 相同时 host 维度优先）。
type Experience struct {
	Entries []ExperienceEntry `json:"entries"`
}

// HostDossier 单台主机档案。
type HostDossier struct {
	Host      string   `json:"host"`
	History   []string `json:"history,omitempty"`  // 历史发现摘要（最近 20 条）
	Recovery  []string `json:"recovery,omitempty"` // 恢复模式（成功处置动作）
	Quirks    []string `json:"quirks,omitempty"`   // 易错点/误报点
	UpdatedAt string   `json:"updated_at"`
}

// Memory 记忆仓库（经验库 + 档案目录）。
type Memory struct {
	dir string // <workDir>/.gocode/memory
	mu  sync.Mutex
	exp *Experience
}

// memoryDir 记忆目录。
func memoryDir(workDir string) string { return filepath.Join(model.ConfigDir(workDir), "memory") }

// NewMemory 加载/初始化记忆仓库（目录不存在时自动创建）。
func NewMemory(workDir string) (*Memory, error) {
	dir := memoryDir(workDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("memory: 创建记忆目录失败: %w", err)
	}
	m := &Memory{dir: dir, exp: &Experience{}}
	data, err := os.ReadFile(filepath.Join(dir, "experience.json"))
	if err == nil {
		_ = json.Unmarshal(data, m.exp) // 损坏时从空库开始（不阻塞）
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return m, nil
}

// saveLocked 落盘经验库（调用方持进程内锁）。跨进程持文件锁 + 写前
// 重读磁盘并入——引擎 learnClosed 与助手 OnApproved 并行写同一经验库
// 时，后写者不得全量覆盖抹掉先写者（原子写只防半截，不防丢更新）。
func (m *Memory) saveLocked() error {
	path := filepath.Join(m.dir, "experience.json")
	return fsutil.WithFileLock(fsutil.LockPathFor(path), func() error {
		// 写前重读：磁盘上另一进程更新的条目并入内存（按键取更完整者）。
		if data, rerr := os.ReadFile(path); rerr == nil {
			var disk Experience
			if json.Unmarshal(data, &disk) == nil {
				mergeExperience(m.exp, &disk)
			}
		}
		data, merr := json.MarshalIndent(m.exp, "", "  ")
		if merr != nil {
			return merr
		}
		return fsutil.WriteFileAtomic(path, append(data, '\n'), 0o644)
	})
}

// expKey 经验条目的跨进程合并键（signal+host+pattern）。
func expKey(e ExperienceEntry) string {
	return e.Signal + "\x00" + e.Host + "\x00" + e.Pattern
}

// mergeExperience 跨进程并入（只增不减）：磁盘条目与内存条目按
// (signal, host, pattern) 键合并——内存缺键追加；双方都有时保留计数
// 更完整者（Count 大的一方），累计相同但对方 LastSeen 更新时并入
// 对方字段。任何一方的新进展都不得被对方旧视图抹掉。
func mergeExperience(mem, disk *Experience) {
	byKey := map[string]int{}
	for i, e := range mem.Entries {
		byKey[expKey(e)] = i
	}
	for _, d := range disk.Entries {
		k := expKey(d)
		i, ok := byKey[k]
		if !ok {
			mem.Entries = append(mem.Entries, d)
			byKey[k] = len(mem.Entries) - 1
			continue
		}
		cur := &mem.Entries[i]
		if d.Count > cur.Count {
			*cur = d
			continue
		}
		if d.Count == cur.Count && d.LastSeen > cur.LastSeen {
			// 相同累计但对方更新：并入对方字段（Action/Outcome/LastSeen），
			// Misreports 取更保守者（两进程各自统计的误报都要保留）。
			if d.Action != "" {
				cur.Action = d.Action
			}
			cur.Outcome = d.Outcome
			cur.LastSeen = d.LastSeen
			if d.Misreports > cur.Misreports {
				cur.Misreports = d.Misreports
			}
			if d.Confidence > cur.Confidence {
				cur.Confidence = d.Confidence
			}
		}
	}
}

// Learn 学习沉淀：发现关闭（处置成功/排除）时记录经验三元组。
// f 为已关闭的 finding（Remediated 或 Dismissed）。返回是否有更新。
func (m *Memory) Learn(f *model.Finding) bool {
	if f == nil || f.Signal == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	pattern := summarizePattern(f)
	action := summarizeAction(f)
	outcome := "remediated"
	if f.Status == model.FindingDismissed {
		outcome = "dismissed"
	}
	for i := range m.exp.Entries {
		e := &m.exp.Entries[i]
		if e.Signal == f.Signal && e.Host == f.Host && e.Pattern == pattern {
			e.Count++
			if outcome == "dismissed" {
				e.Misreports++
			}
			if action != "" {
				e.Action = action // 最近一次有效动作
			}
			e.Outcome = outcome
			e.LastSeen = nowRFC3339()
			e.Confidence = 1 - float64(e.Misreports)/float64(e.Count)
			m.syncGlobalLocked(f.Signal, pattern)
			m.saveLocked()
			return true
		}
	}
	// 全局条目（无主机维度）同 pattern 也合并——跨主机同类问题共享经验。
	for i := range m.exp.Entries {
		e := &m.exp.Entries[i]
		if e.Signal == f.Signal && e.Host == "" && e.Pattern == pattern {
			e.Count++
			if outcome == "dismissed" {
				e.Misreports++
			}
			if action != "" {
				e.Action = action
			}
			e.LastSeen = nowRFC3339()
			e.Confidence = 1 - float64(e.Misreports)/float64(e.Count)
			m.saveLocked()
			return true
		}
	}
	m.exp.Entries = append(m.exp.Entries, ExperienceEntry{
		Signal: f.Signal, Host: f.Host, Pattern: pattern, Action: action,
		Outcome: outcome, Count: 1, LastSeen: nowRFC3339(), Confidence: 1,
	})
	// 全局聚合条目（同类信号跨主机）由主机条目推出。
	m.exp.Entries = append(m.exp.Entries, ExperienceEntry{
		Signal: f.Signal, Pattern: pattern, Action: action,
		Outcome: outcome, Count: 1, LastSeen: nowRFC3339(), Confidence: 1,
	})
	m.saveLocked()
	return true
}

// syncGlobalLocked 同步全局聚合条目（同 signal+pattern 的所有主机条目
// 统计之和）——全局条目是跨主机经验的单一事实源，随主机条目更新。
func (m *Memory) syncGlobalLocked(signal, pattern string) {
	var totalCount, totalMis int
	var action, last string
	for i := range m.exp.Entries {
		e := &m.exp.Entries[i]
		if e.Signal != signal || e.Pattern != pattern || e.Host == "" {
			continue
		}
		totalCount += e.Count
		totalMis += e.Misreports
		if e.Action != "" {
			action = e.Action
		}
		if e.LastSeen > last {
			last = e.LastSeen
		}
	}
	for i := range m.exp.Entries {
		e := &m.exp.Entries[i]
		if e.Signal == signal && e.Pattern == pattern && e.Host == "" {
			e.Count = totalCount
			e.Misreports = totalMis
			if action != "" {
				e.Action = action
			}
			if last != "" {
				e.LastSeen = last
			}
			e.Confidence = 1 - float64(totalMis)/float64(totalCount)
			return
		}
	}
}

// RecordHostEvent 记录主机档案（历史/恢复/易错点）。跨进程持文件锁 +
// 锁内重读并集追加——引擎与助手并行写同一主机档案时，后写者不得抹掉
// 先写者的事件（原子写只防半截，不防丢更新）。
func (m *Memory) RecordHostEvent(host, kind, text string) {
	if host == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	p := filepath.Join(m.dir, "dossiers", host+".json")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return
	}
	_ = fsutil.WithFileLock(fsutil.LockPathFor(p), func() error {
		var d HostDossier
		if data, err := os.ReadFile(p); err == nil {
			_ = json.Unmarshal(data, &d)
		}
		d.Host = host
		d.UpdatedAt = nowRFC3339()
		switch kind {
		case "history":
			d.History = append(d.History, text)
			if len(d.History) > 20 {
				d.History = d.History[len(d.History)-20:]
			}
		case "recovery":
			d.Recovery = append(d.Recovery, text)
			if len(d.Recovery) > 10 {
				d.Recovery = d.Recovery[len(d.Recovery)-10:]
			}
		case "quirk":
			d.Quirks = append(d.Quirks, text)
			if len(d.Quirks) > 10 {
				d.Quirks = d.Quirks[len(d.Quirks)-10:]
			}
		}
		if data, err := json.MarshalIndent(d, "", "  "); err == nil {
			_ = fsutil.WriteFileAtomic(p, append(data, '\n'), 0o644)
		}
		return nil
	})
}

// Recall 经验检索：signal（+可选 host）命中经验，返回按置信度降序的
// 摘要列表（供大脑 recall 工具与提示词注入）。
func (m *Memory) Recall(signal, host string, limit int) []string {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var hits []ExperienceEntry
	for _, e := range m.exp.Entries {
		if e.Signal != signal {
			continue
		}
		if host != "" && e.Host != "" && e.Host != host {
			continue
		}
		hits = append(hits, e)
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].Confidence > hits[j].Confidence })
	if limit <= 0 || limit > len(hits) {
		limit = len(hits)
	}
	var out []string
	for _, e := range hits[:limit] {
		scope := "全局"
		if e.Host != "" {
			scope = e.Host
		}
		s := fmt.Sprintf("[%s] %s：命中 %d 次（误报 %d，置信 %.0f%%），最近 %s，处置模板: %s",
			scope, e.Pattern, e.Count, e.Misreports, e.Confidence*100, e.LastSeen, e.Action)
		out = append(out, s)
	}
	return out
}

// DossierBrief 主机档案摘要（提示词注入用）。
func (m *Memory) DossierBrief(host string) string {
	if m == nil || host == "" {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	p := filepath.Join(m.dir, "dossiers", host+".json")
	data, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	var d HostDossier
	if err := json.Unmarshal(data, &d); err != nil {
		return ""
	}
	var b strings.Builder
	if len(d.History) > 0 {
		hist := d.History
		if n := len(hist); n > 3 {
			hist = hist[n-3:]
		}
		b.WriteString("历史发现: " + strings.Join(hist, " | ") + "\n")
	}
	if len(d.Recovery) > 0 {
		b.WriteString("恢复模式: " + strings.Join(d.Recovery, " | ") + "\n")
	}
	if len(d.Quirks) > 0 {
		b.WriteString("易错点: " + strings.Join(d.Quirks, " | ") + "\n")
	}
	return strings.TrimSpace(b.String())
}

// ExperienceBrief 全库摘要（提示词注入：大脑知道"经验里有啥"）。
func (m *Memory) ExperienceBrief(limit int) string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit <= 0 {
		limit = 10
	}
	var out []string
	for _, e := range m.exp.Entries {
		if e.Host != "" {
			continue // 只列全局聚合条目
		}
		out = append(out, fmt.Sprintf("%s(%d次,置信%.0f%%)", e.Signal, e.Count, e.Confidence*100))
		if len(out) >= limit {
			break
		}
	}
	return strings.Join(out, ", ")
}

// summarizePattern 现象特征摘要（信号+对象键）。
func summarizePattern(f *model.Finding) string {
	if f.Key != "" {
		return f.Key
	}
	return fsutil.TruncateStr(f.Desc, 80)
}

// summarizeAction 有效处置动作摘要（首个 Auto 命令）。
func summarizeAction(f *model.Finding) string {
	for _, a := range f.Actions {
		if a.Auto && a.Error == "" && a.Command != "" {
			return fsutil.TruncateStr(a.Command, 120)
		}
	}
	return ""
}

func nowRFC3339() string { return time.Now().UTC().Format("2006-01-02T15:04:05Z") }
