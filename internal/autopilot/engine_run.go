package autopilot

// engine_run.go — 运行主循环：Run/runUntilClean/收敛日志/loopOnce（阶段调度中枢）。

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func (e *Engine) Run(ctx context.Context) error {
	e.core.MarkStarted()
	e.logf("启动：目标 %s，环境探测完成%s",
		strings.Join(e.core.Targets(), ","), modelSuffix(e.model))
	// 全局时限（可选）：比赛/评审环境按 --timeout 设定，超时如实退出。
	if e.cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.cfg.Timeout)
		defer cancel()
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	// 关闭远程复用连接（SSH 连接缓存，见 ops remote_ssh.go getClient）。
	defer func() {
		if c, ok := e.remote.(interface{ CloseAll() }); ok {
			c.CloseAll()
		}
	}()

	// L0 预热：初始化阶段前先跑一轮确定性快检——重探针缓存预热 + 线索/
	// 基线/事实就绪，survey 阶段即可见 l0_facts 与既有线索（盲扫变有据）。
	e.core.L0Round(ctx)

	return e.runUntilClean(ctx)
}

// ── 收敛循环节奏 ─────────────────────────────────────────────────────
const (
	cleanConfirmRounds = 2
	stallLimit         = 5
	// rescanEveryRounds 脏环境下周期复扫间隔：连续该轮数未复扫且追查
	// 处于静默期（无未追查线索、本轮无新线索）时触发一次换视角复查。
	// 对齐停滞检测上限（5）：完全停滞的环境在第 6 轮复扫前已如实退出，
	// 复扫只发生在"仍有动作但长期不收敛"的环境，成本受控。
	rescanEveryRounds = 6
)

// runUntilClean 收敛主循环：检出 → 追查 → 处置，直到连续
// cleanConfirmRounds 轮满足收敛条件才退出。收敛条件（每轮
// loopOnce 结束后判定）：
//
//  1. 没有 Tried==0 的 pending 线索（每个线索都被 DeepDive 追查过）；
//  2. 所有 confirmed 均已处置（无漏修）；
//  3. 本轮 L0 快检无新增线索（环境当前干净）。
//
// 证据不足的 pending（Tried>0）不阻塞收敛，如实进报告"待查"区；
// 处置达限未修的 confirmed 不满足条件 2，由停滞检测强制退出非零。
func (e *Engine) runUntilClean(ctx context.Context) error {
	e.logf("收敛模式：检出→追查→处置，连续 %d 轮无新线索且全部处置完成才退出", cleanConfirmRounds)
	e.runInitPhases(ctx)
	cleanRounds := 0
	stall := 0
	lastState := ""
	for round := 1; ; round++ {
		// 每轮状态基线可见：暂停/重跑都清楚当前卡在哪（四元组对齐停滞检测）。
		e.logf("第 %d 轮开始：%s", round, e.convergenceState())
		if err := e.loopOnce(ctx); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			if e.cfg.Timeout > 0 && ctx.Err() == context.DeadlineExceeded {
				// 全局时限已到：如实非零退出（比赛/评审环境按退出码评分）。
				e.core.SetConclusion(fmt.Sprintf("⏱ 全局时限已到（%v），未收敛：剩余待查 %d，未处置 %d，详见报告分区。", e.cfg.Timeout, len(e.ws().Pending()), e.unremediatedCount()))
				e.core.RenderReport()
				e.logSummary(round, "全局时限已到", stall)
				return fmt.Errorf("全局时限已到（%v），未收敛", e.cfg.Timeout)
			}
			// 外部取消（SIGTERM/中断）：被中断的运行不是正常收敛，不得标记
			// 收敛——评分（result.json converged）必须如实记录（R22 实测：
			// 评测超时 SIGTERM 截断仍标 converged=true 导致两率失真）。
			e.core.SetConclusion(fmt.Sprintf("⏹ 运行被取消（%v）：剩余待查 %d，未处置 %d，详见报告分区。", ctx.Err(), len(e.ws().Pending()), e.unremediatedCount()))
			e.core.RenderReport()
			e.logf("停止（%s），未收敛", ctx.Err())
			e.logSummary(round, "运行被取消", stall)
			return fmt.Errorf("运行被取消（%v），未收敛", ctx.Err())
		default:
		}
		// 重裁决回路：处置达限仍悬置的确认项回灌 DeepDive 重新定态——
		// 排除/降级的项不再阻塞收敛，维持确认的项由停滞检测如实退出。
		e.reruleStuck(ctx)
		if e.isCleanRound() {
			e.roundsSinceRescan = 0
			if !e.rescanDone {
				// 快收敛了：先做一次模型复扫（换视角复查第一遍覆盖的域），
				// 复扫无新发现才算真的干净——模型第一遍漏检的窗口由此收敛。
				e.rescanDone = true
				if leads, _ := e.rescan(ctx); leads > 0 {
					cleanRounds = 0
					continue
				}
			}
			// 收敛前终裁：剩余待查线索在退出前回灌一次终裁（每条一次）——
			// pending 不阻塞收敛，但引擎不带着"从未终裁"的线索退出；
			// 新确认的进入处置循环（重置干净计数）。终裁全部批次失败时
			// 不得当作完成：标记后收敛结论如实标注（与复扫失败同构，
			// 不静默收敛）。
			if changed, failed := e.finalAdjudicate(ctx); changed {
				cleanRounds = 0
				continue
			} else if failed {
				e.finalAdjudicateFailed = true
			}
			cleanRounds++
			if cleanRounds >= cleanConfirmRounds {
				rescanNote := "复扫无新发现"
				if !e.rescanOK {
					rescanNote = "复扫未完成（模型失败，不阻塞收敛，如实标注）"
				}
				if e.finalAdjudicateFailed {
					rescanNote += "；存在未终裁待查项（终裁连续失败，如实标注）"
				}
				e.core.SetConclusion(fmt.Sprintf("✅ 收敛完成：%s，连续 %d 轮无新增线索，全部线索已追查、确认故障均已处置（检出 %d，确认 %d，排除 %d）。",
					rescanNote, cleanConfirmRounds, len(e.ws().Findings()), len(e.ws().Confirmed()), len(e.ws().Dismissed())))
				e.core.RenderReport()
				e.logf("收敛：%s且连续 %d 轮干净，退出", rescanNote, cleanConfirmRounds)
				e.logSummary(round, "收敛", stall)
				return nil
			}
		} else {
			cleanRounds = 0
			e.rescanDone = false // 环境变脏：下次收敛前需重新复扫确认
			e.roundsSinceRescan++
			// 周期复扫：脏环境下追查静默（无未追查线索、本轮无新线索）
			// 且连续 rescanEveryRounds 轮未复扫时，换视角复查第一遍已
			// 覆盖的域——处置长期悬置/追查长期无果时，首轮漏检的窗口
			// 仍会闭合。复扫结果走 L0 线索入库路径（新线索下轮被追查）；
			// 不影响 rescanDone（收敛前的确认复扫照常）。
			e.maybePeriodicRescan(ctx)
			e.logf("第 %d 轮未收敛：%s", round, e.cleanBlockers())
		}
		// 停滞检测：状态四元组（pending/confirmed/未修/lastLeads）连续不变
		// 意味着无任何进展——处置达限未修、追查无进展时停止空转。
		st := e.convergenceState()
		if st == lastState {
			stall++
			e.logf("停滞 %d/%d：状态无变化（%s）", stall, stallLimit, st)
			if stall >= stallLimit {
				e.core.SetConclusion(fmt.Sprintf("❌ 未收敛：连续 %d 轮状态无变化（%s）。存在未处置或无法自动收敛的项，详见上文分区。", stallLimit, st))
				e.core.RenderReport()
				e.logSummary(round, "停滞退出", stall)
				return fmt.Errorf("未收敛：连续 %d 轮状态无变化（%s）", stallLimit, st)
			}
		} else {
			stall = 0
			lastState = st
		}
	}
}

// logSummary 运行结束摘要（收敛/超时/取消/停滞统一出口）：轮次、总耗时、
// 阶段耗时、工具调用统计、批失败/回滚、findings 分布——复盘直接读摘要块，
// 无需 grep 逐条计数。机器可读（固定行首标签）。
func (e *Engine) logSummary(round int, reason string, stall int) {
	st := &e.stats
	var sb strings.Builder
	sb.WriteString("── 运行摘要")
	if reason != "" {
		sb.WriteString("（" + reason + "）")
	}
	sb.WriteString(" ──")
	e.logf("%s", sb.String())
	started := e.core.Started()
	if !started.IsZero() {
		e.logf("摘要 总耗时: %s", time.Since(started).Round(time.Second))
	}
	e.logf("摘要 轮次: %d", round)
	var phs []string
	for _, p := range e.ws().Phases() {
		mark := "✓"
		if !p.OK {
			mark = "✗"
		}
		phs = append(phs, fmt.Sprintf("%s %s%s", p.Phase, p.Duration.Round(time.Second), mark))
	}
	if len(phs) > 0 {
		e.logf("摘要 阶段: %s", strings.Join(phs, " ｜ "))
	}
	e.logf("摘要 工具调用: %d（成功 %d ｜ 失败 %d ｜ 守卫拦截 %d）",
		st.toolCalls.Load(), st.toolCalls.Load()-st.toolErrors.Load(), st.toolErrors.Load(), st.toolBlocked.Load())
	wbWrites := 0
	if e.wb != nil {
		wbWrites = e.wb.WriteCount()
	}
	e.logf("摘要 认知活动: workbench 写入 %d 次（0=认知层空转，四表从未使用）", wbWrites)
	e.logf("摘要 批失败: %d ｜ 回滚: %d ｜ 停滞: %d", st.batchFails.Load(), st.rollbacks.Load(), stall)
	f := e.ws().Findings()
	var conf, rem, pend, dis int
	for _, x := range f {
		switch x.Status {
		case FindingConfirmed:
			conf++
			if x.Remediated {
				rem++
			}
		case FindingPending:
			pend++
		case FindingDismissed:
			dis++
		}
	}
	e.logf("摘要 findings: %d（confirmed %d ｜ remediated %d ｜ pending %d ｜ dismissed %d）", len(f), conf, rem, pend, dis)
	e.logf("── 摘要结束 ──")
}

// loopOnce 一轮 L0 循环：快检（含期望偏差）→ 线索入库 → S2 上板基线
// 同步 → DeepDive → Respond → 认知同步 → 渲染。
func (e *Engine) loopOnce(ctx context.Context) error {
	start := time.Now()
	e.core.L0Round(ctx)
	// S2 上板基线周期刷新（确定性，产漂移线索）：全盘枚举探针上板一次、
	// 周期比对，例行轮绝不重扫全盘（2.3T/7000 万 inode 事故根因）。
	e.syncInventory(ctx)
	// 认知同步：新证据激活待验证假设；作战图反映引擎侧状态。
	e.activateHypotheses()
	e.syncWorkbench()
	e.deepDive(ctx)
	e.respond(ctx)
	// 学习闭环：已关闭发现沉淀进记忆（经验库+主机档案）。
	e.learnClosed()
	e.syncWorkbench()
	e.logf("%s", e.workflowBrief())
	if err := e.core.RenderReport(); err != nil {
		e.logf("报告渲染失败: %v", err)
	}
	e.logf("本轮完成（%v）：线索 %d，确认 %d，待查 %d，排除 %d",
		time.Since(start).Round(time.Millisecond),
		len(e.ws().Findings()), len(e.ws().Confirmed()), len(e.ws().Pending()), len(e.ws().Dismissed()))
	return nil
}

// l0Round 确定性一轮：快检 → 线索入库 → 基线/事实落盘。返回本轮新
// 检出的线索（供上下文注入），去重后的新增数记入 lastLeads。交互式运维助手
// （SnapshotL0）与引擎主循环共用——L0 是两种形态共用的确定性底座。
const (
	reChaseRedetect = 2
	maxRechase      = 2
)

// deepDiveBatchSize 单批追查的线索条数上限——**并行子代理粒度**：
// 1 = 每条线索一个独立 agent 会话并行追查（worker 池并行派发）。
// 单线索会话：上下文只含该线索详情 + 全局状态摘要，聚焦无批内干扰，
// 模型调用次数 = 线索数（token 开销 ~2-3 倍，换取波内全并行）；
// 预算 1 条 × 60s = 1m << 6m 阶段超时，余量充裕。
//
// 历史（多线索/批）对比：11 条线索 3 条/批 × 5 worker → 1 波 × 3m
// （批内 3 条串行）；1 条/批 × 8 worker → 2 波 × 1m ≈ 2m（省 ~33%）。
// 30 条线索：2 波 × 3m = 6m → 4 波 × 1m ≈ 4m（省 ~33%）。
// 线索 ≤ worker 时 1 波完成（单条会话 ~1m，总耗时 ≈ 单条追查时间）。
//
// 终裁（finalAdjudicate）复用本常量：单线索终裁同样更聚焦。
const deepDiveBatchSize = 1
