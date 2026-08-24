package workspace

// workspace_merge.go — 发现合并与去重：稳定信号/对象键/引擎字段保护（复发重置与证据链分层）。

import (
	"strings"
	"time"
)

func dedupKeyF(f *Finding) string {
	k := normKey(f.Host) + "\x00" + normKey(f.Signal)
	if f.Key != "" {
		k += "\x00" + normKey(f.Key)
	}
	return k
}

// normKey 小写、去首尾空白、折叠连续空白为单个空格。
func normKey(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(s))), " ")
}

// merge 裁决合并规则（分层：发现层非空合并，行为层引擎独占）：
//   - confirmed 是最终态：新 confirmed 可更新发现层描述，其余状态不覆盖；
//   - pending/dismissed 可被任何新裁决覆盖（模型验证后排除是合法裁决）；
//   - 行为层（Tried/RespondTried/Remediated/Actions/Note/SuggestedFix）
//     是引擎行为记录，模型上报（无行为字段）不得覆盖——防止重复上报
//     清零已处置/达限状态；引擎对象（DeepDive 链/respond 写回）全量采用。
//   - 发现层字段级非空合并：模型阶段输出（DeepDive/复扫/终裁）常为
//     稀疏对象（只回 host/signal/status，省略 desc/evidence），空字段
//     不得覆盖已有追查成果——否则验证回路的累积证据被洗掉、模型重复
//     调查、报告证据链消失（P1 级数据丢失）。
//   - L0 重检出计数：同信号线索每轮重检出 +1——待查项被持续重检出是
//     "异常持续存在"的确定性证据，驱动重追查回路（见 engine.deepDive）；
//     已处置关闭项（confirmed+remediated）被同 key 重检出同样计数——
//     watch 模式据此感知同 key 复发（不改状态不降级，任务模式不受影响）。
//
// 注意：L0 探针残留信号（journald 窗口内历史错误、状态漂移对比）在处置
// 成功后仍会持续检出同 key pending 线索——若据此自动重置处置状态，会
// 造成"处置成功 → 重置 → 重处置"的循环（run8 实测 log_errors 重复处置
// 7 次）。因此 confirmed 终态不被 L0 pending 触碰（状态不降级、发现层
// 不被 L0 稀疏对象覆盖）；真复发由不同 key 的新线索正常走 DeepDive 重新
// 处置，同 key 复发由 watch 模式的 Redetect 感知（resetRelapsed）。
func (w *Workspace) merge(old, f *Finding) {
	// L0 重检出计数先行：待查项每轮重检出 +1；已处置关闭项同 key 重检出
	// 同样计数（watch 复发感知，见 resetRelapsed；状态与发现层不受影响）——
	// 必须在 confirmed 提前返回之前执行（confirmed 终态不降级但计数照记）。
	if f.Source == SourceL0 && (old.Status == FindingPending || (old.Status == FindingConfirmed && old.Remediated)) {
		old.Redetect++
	}
	if old.Status == FindingConfirmed && f.Status != FindingConfirmed {
		return
	}
	// L0 线索（痕迹）不复活已排除项：排除是验证回路的裁决，重复出现的
	// 同信号痕迹不推翻裁决（真复发以新信号/新证据走模型裁决）。
	if old.Status == FindingDismissed && f.Source == SourceL0 {
		return
	}
	// 确认时间线：首次升为 confirmed 时记录（处置节奏指标）。
	if old.Status != FindingConfirmed && f.Status == FindingConfirmed && old.ConfirmedAt.IsZero() {
		old.ConfirmedAt = time.Now().UTC()
	}
	old.Status = f.Status
	// 发现层：字段级非空合并——空字段永不覆盖已有数据（稀疏输出/最小
	// 对象不得洗掉追查成果与证据链）。
	if f.RootCause != "" {
		old.RootCause = f.RootCause
	}
	if f.Confidence != 0 {
		old.Confidence = f.Confidence
	}
	if len(f.Evidence) > 0 {
		old.Evidence = f.Evidence
	}
	if f.Desc != "" {
		old.Desc = f.Desc
	}
	if f.Domain != "" {
		old.Domain = f.Domain
	}
	// 行为层：仅引擎对象可写（DeepDive 追查链/respond 写回）。
	if engineOwned(f) {
		old.Tried = f.Tried
		old.RespondTried = f.RespondTried
		old.Remediated = f.Remediated
		old.Actions = f.Actions
		old.RemediationNote = f.RemediationNote
		old.SuggestedFix = f.SuggestedFix
		old.Disposition = f.Disposition
	}
}

// engineOwned 判断 finding 是否携带引擎行为数据（DeepDive 追查链
// Tried>0、respond 写回的行为字段）。模型阶段上报的 finding 恒为
// false——模型推不动引擎的处置状态（单一来源：引擎）。
func engineOwned(f *Finding) bool {
	return f.Tried > 0 || f.RespondTried > 0 || f.Remediated || f.Redetect > 0 || f.Rechased > 0 ||
		len(f.Actions) > 0 || f.RemediationNote != "" || len(f.SuggestedFix) > 0 || f.Disposition != nil
}

// rank 三态强度：dismissed=0, pending=1, confirmed=2。
func rank(s string) int {
	switch s {
	case FindingConfirmed:
		return 2
	case FindingPending:
		return 1
	}
	return 0
}

// Findings 返回全部发现（按确认强度降序）。
