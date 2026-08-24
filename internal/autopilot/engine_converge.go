package autopilot

// engine_converge.go — 收敛机制：复扫/重裁决/干净轮判定/停滞与阻塞分析。

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-gocel/gocode-ops/internal/common/collect"
	"github.com/go-gocel/gocode-ops/internal/common/model"
	"github.com/go-gocel/gocode-ops/internal/common/remediate"
)

// workOrdered 该项是否为已转人工工单的闭环态（P0 修复）：工单是
// 处置机制的合法终态——模型判定无法自动处置（环境性不可修复/证据
// 不足/被守卫结构性必拒）时生成 manual_workorder（附证据包与建议
// 命令），交人工执行或改判。工单项不再阻塞收敛（报告如实标注），
// 也不参与重裁决/重复处置——否则"确认了却关不掉"死锁（chaos-r1
// 实测：auditd/TMOUT/app_error.log 等 5 项转工单后仍按未处置每轮
// 回灌，14 轮停滞退出）。
func workOrdered(f *Finding) bool {
	return f.Disposition != nil && f.Disposition.Outcome == model.DispositionManualWorkOrder
}

// reruleStuck 重裁决回路（收敛语义闭环）：处置达限仍未处置的确认项
// 若永久悬置，收敛条件"全部 confirmed 已处置"永不满足，只能靠停滞
// 检测非零退出——悬置项回灌 DeepDive 重新定态后：
//   - dismissed：此前的确认被推翻/问题已恢复 → 不再阻塞收敛；
//   - pending：证据不足 → 降回待查（如实进报告，不再阻塞收敛）；
//   - confirmed：维持确认 → 生成人工工单（P0 补全：无法自动处置即
//     闭环终态，不阻塞收敛——applyRerule 内同步工单化）；
//   - 无有效裁决/裁决失败：保持原状态（fail-closed，不假装修好）。
//
// 每个悬置项只重裁决一次（Reruled 标记），避免每轮烧模型调用。
// 已转人工工单的项是闭环终态，不参与重裁决（P0 修复）。
// 已重裁决过但仍悬置的项（历史状态/上轮裁决失败）：不再烧模型调用，
// 直接按处置机制工单化（P0 补全——续跑/恢复场景的停滞项自动闭环）。
func (e *Engine) reruleStuck(ctx context.Context) {
	if e.app == nil {
		return
	}
	var stuck []*Finding
	for _, f := range e.ws().Confirmed() {
		if f.Remediated || workOrdered(f) || f.RespondTried < maxRespondTries {
			continue
		}
		if f.Reruled {
			// 已重裁决仍悬置：无法自动处置是已确认事实，工单化闭环。
			remediate.EnsureWorkOrderAtLimit(f, "重裁决后仍无法自动处置（历史悬置项，续跑自动闭环）")
			if f.Disposition != nil {
				e.logf("重裁决遗留悬置项 %s 自动工单化（闭环终态，不再阻塞收敛）", f.ID)
			}
			continue
		}
		stuck = append(stuck, f)
	}
	if len(stuck) == 0 {
		return
	}
	e.logf("重裁决开始：%d 项处置达限悬置，回灌 DeepDive 重新定态", len(stuck))
	for _, f := range stuck {
		f.Reruled = true
	}
	var g strings.Builder
	g.WriteString("以下确认故障在处置阶段达到尝试上限仍未处置（模型曾判\"无需处置/无法处置\"或方案反复失败）。请对每一项重新裁决，不要输出处置方案：\n")
	for _, f := range stuck {
		fmt.Fprintf(&g, "\n### %s\n%s", f.ID, findingDetail(f))
		if f.RemediationNote != "" {
			fmt.Fprintf(&g, "\n- 处置记录: %s", f.RemediationNote)
		}
	}
	g.WriteString("\n\n裁决规则：\n1. 问题已恢复/此前的确认是误判 → status=dismissed，evidence 给出排除证据；\n2. 证据不足无法定论 → status=pending，说明还缺什么证据；\n3. 仍是需处置的故障 → status=confirmed（维持），说明为何无法自动处置。\n每条裁决的 host/signal 必须与上面一致。")
	e.setPhase(PhaseDeepDive)
	task := taskPromptWithHints(PhaseDeepDive, g.String(), e.cogState(), 0, e.toolErrFeedback())
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		t := task
		if attempt > 0 && lastErr != nil {
			t += fmt.Sprintf("\n\n## 上次输出被拒绝\n%v\n请修正后重新输出完整 JSON 小结。", lastErr)
		}
		start := time.Now()
		sum, content, err := runPhase(ctx, e.app, PhaseDeepDive, t, e.cfg.DiagnoseTimeout, 0)
		log := PhaseLog{Phase: PhaseDeepDive, At: time.Now(), Duration: time.Since(start)}
		if err != nil {
			log.Err = err.Error()
			e.ws().AddPhaseLog(log)
			e.logf("重裁决第 %d 次失败: %v", attempt+1, err)
			if content != "" {
				e.logf("重裁决模型原始输出: %s", collect.TruncateStr(content, 2000))
			}
			lastErr = err
			if attempt+1 < 2 {
				time.Sleep(e.retryBackoff(attempt))
			}
			continue
		}
		if len(sum.Findings) == 0 {
			log.Err = "重裁决输出无 findings"
			e.ws().AddPhaseLog(log)
			e.logf("重裁决第 %d 次失败: 输出无 findings", attempt+1)
			lastErr = fmt.Errorf("重裁决输出无 findings")
			continue
		}
		applied := e.applyRerule(stuck, sum.Findings)
		log.OK = true
		log.Covered = sum.Covered
		e.ws().AddPhaseLog(log)
		if err := e.ws().SaveFindings(); err != nil {
			e.logf("重裁决状态落盘失败: %v", err)
		}
		e.logf("重裁决：%d 项悬置，%d 项获得有效裁决", len(stuck), applied)
		return
	}
	e.logf("重裁决重试后仍失败（%v），悬置项保持原状态如实报告", lastErr)
	if err := e.ws().SaveFindings(); err != nil {
		e.logf("重裁决状态落盘失败: %v", err)
	}
}

// applyRerule 应用重裁决：按 (host, signal) 匹配悬置项，直接写状态——
// 引擎行为层，不走 AddFindings（merge 规则拒绝非 confirmed 降级已确认
// 项）。发现层字段（描述/证据）随裁决更新。返回有效裁决数。
// P0 补全：维持确认（无法自动处置）的分支同步生成人工工单——重裁决
// 后仍无法自动处置的项是闭环终态（工单不阻塞收敛），否则 rerule 与
// 停滞检测形成死锁（chaos-r2 实测：remember 项 rerule 维持确认后无
// 出口，状态冻结 3 轮停滞）。
func (e *Engine) applyRerule(stuck, rulings []*Finding) int {
	applied := 0
	for _, rf := range rulings {
		if rf.Host == "" || rf.Signal == "" {
			continue
		}
		for _, f := range stuck {
			if !strings.EqualFold(f.Host, rf.Host) || !strings.EqualFold(f.Signal, rf.Signal) {
				continue
			}
			if rf.Desc != "" {
				f.Desc = rf.Desc
			}
			if len(rf.Evidence) > 0 {
				f.Evidence = rf.Evidence
			}
			switch strings.ToLower(strings.TrimSpace(rf.Status)) {
			case FindingDismissed:
				f.Status = FindingDismissed
				f.RemediationNote += "；重裁决排除"
			case FindingPending:
				f.Status = FindingPending
				f.RemediationNote += "；重裁决证据不足，降回待查"
			case FindingConfirmed:
				f.RemediationNote += "；重裁决维持确认（无法自动处置）"
				// 无法自动处置即转人工工单（闭环终态，不阻塞收敛）。
				remediate.EnsureWorkOrderAtLimit(f, "重裁决维持确认（无法自动处置）")
			default:
				continue
			}
			applied++
			break
		}
	}
	return applied
}

// rescan 模型复扫：对已覆盖域换方法复查（process/network/log/cron/config
// 是第一遍最容易漏的域），产出新线索直接入库。返回 (新线索数, 是否完成)；
// 失败时 done=false——复扫是增强确认，失败不阻塞收敛但如实标注。
//
// 独立实现而非复用 runPhaseOnce：复扫失败不触发确定性兜底（兜底是探针
// 层的保障，复扫的目的是模型换视角——失败只记日志，下个周期再试）。
func (e *Engine) rescan(ctx context.Context) (int, bool) {
	if e.app == nil {
		return 0, true
	}
	e.rescanOK = false
	e.setPhase(PhaseRescan)
	e.logf("复扫开始：收敛前换视角复查已覆盖域（重点 process/network/log/cron/config）")
	before := len(e.ws().Findings())
	const goal = "对上一轮已覆盖的域换方法复查，重点是第一遍容易漏掉的域（process/network/log/cron/config）：用与第一遍不同的手段交叉确认（进程看启动时间与状态变化、网络看防火墙与连接状态、日志看新的时间窗口、配置与默认值/基线对比）。产出 findings（status=pending 的线索）与 covered 清单；确认无异常时 findings 为空，但 covered 必须完整声明。"
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		task := taskPromptWithHints(PhaseRescan, goal, e.cogState(), 0, e.toolErrFeedback())
		if attempt > 0 && lastErr != nil {
			task += fmt.Sprintf("\n\n## 上次输出被拒绝\n%v\n请修正后重新输出完整 JSON 小结。", lastErr)
		}
		start := time.Now()
		sum, content, err := runPhase(ctx, e.app, PhaseRescan, task, e.cfg.DiagnoseTimeout, 0)
		log := PhaseLog{Phase: PhaseRescan, At: time.Now(), Duration: time.Since(start)}
		if err != nil {
			log.Err = err.Error()
			e.ws().AddPhaseLog(log)
			e.logf("复扫第 %d 次失败: %v", attempt+1, err)
			if content != "" {
				e.logf("复扫模型原始输出: %s", collect.TruncateStr(content, 2000))
			}
			lastErr = err
			if attempt+1 < 2 {
				time.Sleep(e.retryBackoff(attempt))
			}
			continue
		}
		if verr := sum.validate(PhaseRescan, fullCoverageDomains); verr != nil {
			log.Err = verr.Error()
			e.ws().AddPhaseLog(log)
			e.logf("复扫契约校验失败: %v", verr)
			lastErr = verr
			continue
		}
		log.OK = true
		log.Covered = sum.Covered
		log.Skipped = sum.Skipped
		e.ws().AddPhaseLog(log)
		e.ws().AddFindings(sum.Findings)
		leads := len(e.ws().Findings()) - before
		if leads > 0 {
			e.logf("复扫发现 %d 条新线索", leads)
		} else {
			e.logf("复扫完成：无新发现（covered=%v）", sum.Covered)
		}
		e.rescanOK = true
		return leads, true
	}
	e.logf("复扫重试后仍失败（%v），下个周期再试", lastErr)
	return 0, false
}

// isCleanRound 本轮是否满足收敛条件（见 runUntilClean）。
// 通道健康是收敛前提：目标主机整机采集失败（SSH 失联/口令过期/账户
// 锁定）时不得判"环境干净"——失联状态被模型 dismissed 后仍收敛退出码 0
// 是评分失真点（R22 教训同族），由停滞/时限如实非零退出兜底。
func (e *Engine) isCleanRound() bool {
	if e.core.CollectFail() {
		return false
	}
	for _, f := range e.ws().Pending() {
		if f.Tried == 0 {
			return false
		}
	}
	for _, f := range e.ws().Confirmed() {
		if !f.Remediated && !workOrdered(f) {
			return false
		}
	}
	return e.core.LastLeads() == 0
}

// hasUntriedLeads 是否存在未被 DeepDive 追查过的线索（周期复扫的
// 静默期判据：有未追查线索时模型正在追查，复扫与追查重复劳动）。
func (e *Engine) hasUntriedLeads() bool {
	for _, f := range e.ws().Pending() {
		if f.Tried == 0 {
			return true
		}
	}
	return false
}

// maybePeriodicRescan 脏环境下周期复扫（见 runUntilClean 的 else 分支
// 与 rescanEveryRounds）：满足触发条件（追查静默 + 连续 N 轮未复扫）
// 时执行一次模型复扫，新线索经 rescan 入库。返回是否发现新线索；
// 不满足条件时返回 false（不消耗模型调用）。
func (e *Engine) maybePeriodicRescan(ctx context.Context) bool {
	if e.roundsSinceRescan < rescanEveryRounds || e.core.LastLeads() != 0 || e.hasUntriedLeads() {
		return false
	}
	e.roundsSinceRescan = 0
	e.logf("周期复扫触发：脏环境连续 %d 轮未复扫（%s），换视角复查已覆盖域", rescanEveryRounds, e.cleanBlockers())
	leads, _ := e.rescan(ctx)
	if leads > 0 {
		e.logf("周期复扫发现 %d 条新线索，进入追查队列", leads)
	}
	return leads > 0
}

// cleanBlockers 本轮未满足收敛条件的具体原因（排查"为什么不收敛"直接看
// 这行，而不是猜是哪条线索/哪个故障挡着）。
func (e *Engine) cleanBlockers() string {
	var parts []string
	for _, f := range e.ws().Pending() {
		if f.Tried == 0 {
			parts = append(parts, fmt.Sprintf("未追查线索 %s（%s）", f.ID, f.Signal))
		}
	}
	for _, f := range e.ws().Confirmed() {
		if !f.Remediated && !workOrdered(f) {
			parts = append(parts, fmt.Sprintf("未处置确认项 %s（%s）", f.ID, f.Signal))
		}
	}
	if n := e.core.LastLeads(); n > 0 {
		parts = append(parts, fmt.Sprintf("L0 本轮新线索 %d 条", n))
	}
	if len(parts) == 0 {
		return "收敛条件满足但状态判定未就绪（复扫/终裁路径）"
	}
	return strings.Join(parts, "；")
}

// convergenceState 停滞检测用的状态摘要（含行为进度量：处置尝试/
// 重检出/未终裁计数/dismissed 数——"计数在涨但收不拢"的慢燃场景
// 不算停滞，停滞只代表"完全无进展"）。
func (e *Engine) convergenceState() string {
	pending, confirmed, remediated, dismissed := 0, 0, 0, 0
	var respTried, redetect, finalOpen int
	for _, f := range e.ws().Findings() {
		switch f.Status {
		case FindingPending:
			pending++
			if !f.FinalRuled {
				finalOpen++
			}
		case FindingConfirmed:
			confirmed++
			if f.Remediated {
				remediated++
			}
		case FindingDismissed:
			dismissed++
		}
		respTried += f.RespondTried
		redetect += f.Redetect
	}
	return fmt.Sprintf("pending=%d confirmed=%d remediated=%d dismissed=%d lastLeads=%d respTried=%d redetect=%d finalOpen=%d",
		pending, confirmed, remediated, dismissed, e.core.LastLeads(), respTried, redetect, finalOpen)
}

// unremediatedCount 未处置且未转工单的确认故障数（时限退出结论用；
// 工单项为闭环终态不计入——P0 修复）。
func (e *Engine) unremediatedCount() int {
	n := 0
	for _, f := range e.ws().Confirmed() {
		if !f.Remediated && !workOrdered(f) {
			n++
		}
	}
	return n
}
