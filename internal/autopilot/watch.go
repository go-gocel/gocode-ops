package autopilot

// 持续运营模式（auto --watch）：收敛后引擎不退出，按周期重扫 + 复发
// 检测——"持续在岗的运维主体"的运行形态。任务模式（Run）是"处理完
// 当前问题退出"；watch 模式是"守护环境"：
//   - 周期感知（快探针走 L0 缓存/增量，成本受控）；
//   - 复发检测：已处置关闭的 finding 被 L0 重检出（Redetect>0）→ 自动
//     重置处置状态重新处置（带经验沉淀复用）；
//   - 周期报告刷新；ctx 取消（SIGTERM/Ctrl+C）优雅退出。

import (
	"context"
	"time"
)

// RunWatch runs persistent watch mode: it converges once, then rescans
// periodically.
// RunWatch 常驻运营：先尽力收敛一次（runUntilClean），然后按
// cfg.WatchInterval 周期重扫。返回 nil=正常退出（ctx 取消）；收敛阶段
// 的非取消错误如实返回。watchConverged 记录收敛阶段是否成功——评分
// 场景 result.json 的 converged 必须如实（未收敛进入守护不等于收敛）。
func (e *Engine) RunWatch(ctx context.Context) error {
	e.core.MarkStarted()
	e.logf("watch 模式：先收敛当前问题，再按 %v 周期守护（复发自动再处置）", e.cfg.WatchInterval)
	if err := e.runUntilClean(ctx); err != nil {
		select {
		case <-ctx.Done():
			return nil // 取消：watch 阶段正常退出
		default:
			// 收敛阶段未收敛（超时/停滞）：watch 模式不放弃，继续守护；
			// 但评分结论必须如实（watchConverged=false）。
			e.watchConverged = false
			e.logf("收敛阶段未收敛（%v），进入 watch 守护循环（评分如实未收敛）", err)
		}
	} else {
		e.watchConverged = true
	}
	interval := e.cfg.WatchInterval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	e.logf("watch 守护开始：周期 %v，Ctrl+C 退出", interval)
	for {
		select {
		case <-ctx.Done():
			e.logf("watch 退出（%v）", ctx.Err())
			return nil
		case <-ticker.C:
			e.watchRound(ctx)
		}
	}
}

// watchRound 一个守护周期：L0 重扫 → 复发检测 → 追查/处置新问题 →
// 学习沉淀 → 报告。
func (e *Engine) watchRound(ctx context.Context) {
	start := time.Now()
	leads := e.core.L0Round(ctx)
	relapsed := e.resetRelapsed()
	if relapsed > 0 {
		e.ws().SaveFindings()
		e.logf("复发 %d 项进入重新处置", relapsed)
	}
	e.activateHypotheses()
	e.syncWorkbench()
	if len(leads) > 0 || relapsed > 0 {
		e.deepDive(ctx)
	}
	e.respond(ctx)
	e.learnClosed()
	e.syncWorkbench()
	e.core.RenderReport()
	e.logf("watch 周期完成（%v）：新线索 %d，复发 %d，%s",
		time.Since(start).Round(time.Millisecond), len(leads), relapsed, e.workflowBrief())
}

// resetRelapsed 复发检测：已处置关闭的 confirmed 被 L0 同 key 重检出
// （Redetect 由 merge 在 confirmed+remediated 上照常递增）→ 重置处置
// 状态，重新进入处置循环。返回复发数。
// Redetect 重置后清零：复发已进入处置循环，若下一周期 L0 不再检出
// （问题已修复），残留计数不得再触发——否则"遗留 Redetect>0"的项
// 每周期误判复发、无限重处置。
func (e *Engine) resetRelapsed() int {
	relapsed := 0
	for _, f := range e.ws().Findings() {
		if f.Status == FindingConfirmed && f.Remediated && f.Redetect > 0 {
			e.logf("⚠ 复发检测：%s（%s/%s）重新出现，重置处置状态", f.ID, f.Host, f.Signal)
			f.Remediated = false
			f.RespondTried = 0
			f.Redetect = 0 // 复发计数本次消费：处置循环内不再重复触发
			f.Learned = false
			f.RemediationNote = "；复发（watch 周期重检出），重新处置"
			relapsed++
		}
	}
	return relapsed
}
