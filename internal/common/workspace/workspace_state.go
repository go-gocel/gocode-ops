package workspace

// workspace_state.go — 基线/阶段日志/L0 事实与覆盖（工作区状态面）。

import (
	"sort"
	"time"
)

const (
	baselineWindow = 24 * time.Hour
	baselineMinPts = 120  // 趋势可用最小样本（窗口内轮次不足时放宽到最近 N 轮）
	baselineMaxPts = 5000 // 文件大小护栏（每点几百字节，上限约 1-2MB）
)

// AddBaseline records one L0 baseline round, trimming to the retention window.
// AddBaseline 记录一轮 L0 基线（时间窗口裁剪，痕迹机制的历史源）。
func (w *Workspace) AddBaseline(pt BaselinePoint) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.BaselinePoints = append(w.BaselinePoints, pt)
	w.BaselinePoints = trimBaseline(w.BaselinePoints, time.Now())
	return w.save("baseline.json", w.BaselinePoints)
}

// trimBaseline 按时间窗口裁剪基线：丢弃窗口外数据；窗口内不足最小样本
// 时保留最近 baselineMinPts 轮；超出硬上限时丢弃最旧数据。
// 调用方保证 pts 按 At 升序（追加即有序）。
func trimBaseline(pts []BaselinePoint, now time.Time) []BaselinePoint {
	cutoff := now.Add(-baselineWindow)
	i := sort.Search(len(pts), func(i int) bool { return pts[i].At.After(cutoff) })
	if len(pts)-i < baselineMinPts && len(pts) > baselineMinPts {
		i = len(pts) - baselineMinPts
	}
	out := pts[i:]
	if len(out) > baselineMaxPts {
		out = out[len(out)-baselineMaxPts:]
	}
	return out
}

// Baseline returns the baseline history.
// Baseline 返回基线历史。
func (w *Workspace) Baseline() []BaselinePoint {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]BaselinePoint, len(w.BaselinePoints))
	copy(out, w.BaselinePoints)
	return out
}

// maxPhaseLogs 阶段记录上限（防 phases.json 失控）：rescan 周期执行
// 每 30min 一条，200 条约覆盖 4 天，诊断足够。
const maxPhaseLogs = 200

// AddPhaseLog records a phase execution.
// AddPhaseLog 记录阶段执行。
func (w *Workspace) AddPhaseLog(log PhaseLog) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.PhaseLogs = append(w.PhaseLogs, log)
	if len(w.PhaseLogs) > maxPhaseLogs {
		w.PhaseLogs = w.PhaseLogs[len(w.PhaseLogs)-maxPhaseLogs:]
	}
	return w.save("phases.json", w.PhaseLogs)
}

// Phases returns the phase execution records.
// Phases 返回阶段执行记录。
func (w *Workspace) Phases() []PhaseLog {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]PhaseLog, len(w.PhaseLogs))
	copy(out, w.PhaseLogs)
	return out
}

// l0Facts 最近一轮 L0 安全事实（机制 1：大脑必须看见——
// 监听端口/用户/大文件等枚举事实每轮确定性采集并进模型上下文）。
// host → 事实文本（按探针分段，已截断）。
type l0Facts map[string]string

// SetL0Facts stores the latest L0 security facts with a deep copy.
// SetL0Facts 保存最近一轮 L0 安全事实（供阶段提示引用）。深拷贝：
// 调用方后续修改 map 不污染工作区状态（P3 修复）。
func (w *Workspace) SetL0Facts(facts map[string]string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	cp := make(map[string]string, len(facts))
	for k, v := range facts {
		cp[k] = v
	}
	w.L0Facts = l0Facts(cp)
}

// L0FactsSnapshot returns a copy of the latest L0 security facts.
// L0FactsSnapshot 返回最近一轮 L0 安全事实（加锁复制；报告覆盖声明用）。
func (w *Workspace) L0FactsSnapshot() map[string]string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make(map[string]string, len(w.L0Facts))
	for k, v := range w.L0Facts {
		out[k] = v
	}
	return out
}

// SetL0Coverage stores the latest fact coverage semantics for the current round.
// SetL0Coverage 保存最近一轮事实覆盖语义（host → probeID → full/partial/
// skipped；与 L0Facts 同轮写入）。
func (w *Workspace) SetL0Coverage(cov map[string]map[string]string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.L0Coverage = cov
}

// L0CoverageSnapshot returns a copy of the latest fact coverage semantics.
// L0CoverageSnapshot 返回最近一轮事实覆盖语义（加锁复制；报告审计面）。
func (w *Workspace) L0CoverageSnapshot() map[string]map[string]string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make(map[string]map[string]string, len(w.L0Coverage))
	for host, probes := range w.L0Coverage {
		cp := make(map[string]string, len(probes))
		for id, cov := range probes {
			cp[id] = cov
		}
		out[host] = cp
	}
	return out
}

// StateSummary 上下文预算（阶段提示注入规模护栏）：facts 按主机字节
// 截断、findings 按状态条数截断——多主机/长跑场景下阶段 prompt 不得
// 随工作区无界膨胀（19 个事实探针 × N 台主机 × 全量 findings 会吃掉
// 大半个上下文窗口）。截断仅作用于摘要注入，落盘工作区不裁剪。
