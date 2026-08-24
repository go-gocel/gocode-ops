package autopilot

// 并行调度层（架构中枢）：问题工作流状态机 + worker 池 + 认知护栏预算。
//
// 工作流状态（per-finding，由 finding 行为字段映射）：
//
//	pending(Tried==0)      → tracing（待追查）
//	pending(Tried>0)       → tracing 中（证据不足，可重追查）
//	confirmed(!Remediated) → remediating（处置中）
//	confirmed(Remediated)  → verifying→closed（引擎复检通过后闭合）
//	dismissed              → closed
//
// 收敛判定 = 无 tracing 未追查 + 无 remediating 未处置（isCleanRound），
// 与"工作流空"等价。调度器把阶段批次（DeepDive/Respond/终裁）投入
// worker 池并行执行——批次间零依赖（不同 finding），工作项级失败隔离
// （单批失败只影响该批，下轮重试）。

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gocel/gocode-ops/internal/common/workbench"
)

// maxParallelWorkers 模型 worker 并发硬上限：--parallel 是用户可调参数，
// 不设上限会因误配/极端值造成"线程风暴"（N 个 agent 会话 × N 路 API
// 并发）。池化语义：活跃并发恒等于 worker 数（≤ 本上限），批数再多
// 仅排队等待，不产生额外 goroutine 或 API 并发。
const maxParallelWorkers = 16

// parallelWorkers 返回模型 worker 并发数（0/负 → 默认 6；1 → 串行；
// 超上限 → 截断到 maxParallelWorkers）。并发活跃的 worker 数 == 返回值，
// 由 runBatches 的 worker 池保证（有界池，无风暴）。
func (e *Engine) parallelWorkers() int {
	n := e.cfg.Parallel.Workers
	if n <= 0 {
		n = 6
	}
	if n > maxParallelWorkers {
		return maxParallelWorkers
	}
	return n
}

// parallelEnabled 是否启用批次并行。
func (e *Engine) parallelEnabled() bool { return e.parallelWorkers() > 1 }

// workerApps 返回 worker 池的独立阶段 agent（每 worker 一个 App/Session——
// Session.RunFresh 写 history，不可共享；装配无 LLM 调用，成本可忽略）。
// 懒装配：首次需要时创建；model 为 nil 时返回空。
func (e *Engine) workerApps() []*phaseAgent {
	if e.model == nil {
		return nil
	}
	n := e.parallelWorkers()
	if n <= 1 {
		return nil
	}
	e.workerOnce.Do(func() {
		hooks := &cognitionHooks{
			collectProbe: e.collectProbe,
			recall:       e.recall,
			updateBench:  e.updateBench,
		}
		apps := make([]*phaseAgent, 0, n)
		for i := 0; i < n; i++ {
			app, err := newPhaseAgent(e.model, e.guard, e.remote, e.agentsmd, e.cfg.WorkDir, e.tplVars, e.onPhaseEvent, hooks, e.audit)
			if err != nil {
				e.logf("worker %d 装配失败: %v（该 worker 降级为共享 app）", i, err)
				continue
			}
			apps = append(apps, app)
		}
		e.workers = apps
	})
	return e.workers
}

// runBatches 并行执行一批任务（worker 池）；workers<=1 时串行。
// fn 收 (i, app)：i 为批下标，app 为该 worker 独占的 *phaseAgent
// （= 一个 Session——Session.RunFresh 写 history，不可共享）。
// fn 返回是否成功；返回成功批数。ctx 取消时未开始的批不再启动。
//
// 关键不变式：并发活跃的 worker 数 == len(workerApps())，且每个 worker
// 在其生命周期内独占同一 app。批次经带缓冲的 jobs channel 派发，因此
// 同一个 *phaseAgent 永远只被一个 goroutine 调用——彻底消除 Session 数据
// 竞争（旧实现按批下标取模选 app，批数>worker 时不同批会撞同一 app）。
func (e *Engine) runBatches(ctx context.Context, label string, batches int, fn func(i int, app *phaseAgent) bool) int {
	workers := e.parallelWorkers()
	if batches <= 0 {
		return 0
	}
	// 串行路径：单 worker 或仅一批，直接用主 app（无并发，无需 worker 池）。
	if workers <= 1 || batches == 1 {
		ok := 0
		for i := 0; i < batches; i++ {
			if fn(i, e.app) {
				ok++
			}
		}
		return ok
	}
	// 并行路径：每 worker 一个独占 *phaseAgent；批次经 jobs channel 派发，
	// 保证同一 app 永不被两个 goroutine 同时调用（消除 Session 竞争）。
	apps := e.workerApps()
	effective := len(apps)
	// 无 worker（model==nil 或全装配失败）→ 退回主 app 串行，绝不共享 Session。
	if effective == 0 {
		ok := 0
		for i := 0; i < batches; i++ {
			if fn(i, e.app) {
				ok++
			}
		}
		return ok
	}
	if effective < workers {
		e.logf("并行 %s：%d 个 worker 装配成功（请求 %d），并发降为 %d（绝不共享 Session）",
			label, effective, workers, effective)
	}
	// 缓冲容量 = batches：派发 goroutine 永不阻塞在发送上，避免 ctx 取消
	// 时 worker 提前退出导致 sender 永久阻塞（死锁 + goroutine 泄露）。
	jobs := make(chan int, batches)
	var wg sync.WaitGroup
	var done atomic.Int32
	for w := 0; w < effective; w++ {
		wg.Add(1)
		go func(app *phaseAgent) {
			defer wg.Done()
			for i := range jobs {
				if ctx.Err() != nil {
					return
				}
				if fn(i, app) {
					done.Add(1)
				}
			}
		}(apps[w])
	}
	go func() {
		defer close(jobs)
		for i := 0; i < batches; i++ {
			if ctx.Err() != nil {
				return
			}
			jobs <- i
		}
	}()
	wg.Wait()
	e.logf("并行 %s：%d/%d 批成功（并发 %d）", label, done.Load(), batches, effective)
	return int(done.Load())
}

// ── 问题工作流状态机（可视化 + 收敛辅助） ─────────────────────────────

// workflowStage 计算 finding 的工作流阶段。
func workflowStage(f *Finding) string {
	switch f.Status {
	case FindingDismissed:
		return "closed"
	case FindingConfirmed:
		if f.Remediated {
			return "closed"
		}
		if f.RespondTried >= maxRespondTries {
			return "blocked"
		}
		return "remediating"
	default: // pending
		if f.Tried == 0 {
			return "tracing"
		}
		return "tracing(evidence-insufficient)"
	}
}

// workflowBrief 工作流状态摘要（日志 + 报告："还差什么才收敛"）。
func (e *Engine) workflowBrief() string {
	var tracing, remediating, blocked, closed int
	for _, f := range e.ws().Findings() {
		switch workflowStage(f) {
		case "tracing", "tracing(evidence-insufficient)":
			tracing++
		case "remediating":
			remediating++
		case "blocked":
			blocked++
		case "closed":
			closed++
		}
	}
	return fmt.Sprintf("工作流: tracing=%d remediating=%d blocked=%d closed=%d",
		tracing, remediating, blocked, closed)
}

// syncWorkbench 同步作战图（引擎侧状态 → 工作台；大脑经 update_workbench
// 工具回写假设/下一步）。每次 L0 轮与 respond 后调用。
func (e *Engine) syncWorkbench() {
	if e.wb == nil {
		return
	}
	for _, f := range e.ws().Findings() {
		stage := workflowStage(f)
		switch stage {
		case "closed":
			e.wb.RemoveProblem(f.ID)
		default:
			next := ""
			if f.Tried == 0 {
				next = "待追查（deepdive）"
			} else if f.Status == FindingConfirmed && !f.Remediated {
				next = "待处置（respond）"
			}
			e.wb.UpsertProblem(opsWorkbenchProblem(f, stage, next))
		}
	}
}

// opsWorkbenchProblem 由 finding 构造作战图问题项（保持大脑已有假设/证据
// 不被引擎覆盖：仅当大脑未写假设时用 finding 现象兜底）。
func opsWorkbenchProblem(f *Finding, stage, next string) workbench.WorkbenchProblem {
	p := workbench.WorkbenchProblem{
		ID: f.ID, Host: f.Host, Signal: f.Signal,
		Status: stage, NextStep: next,
		UpdatedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}
	if len(f.Evidence) > 0 {
		p.Evidence = append([]string{}, f.Evidence...)
	}
	p.Hypothesis = f.RootCause
	if p.Hypothesis == "" {
		p.Hypothesis = f.Desc
	}
	return p
}

// ── 认知护栏：per-finding 预算 ────────────────────────────────────────

// findingToolBudget 返回单 finding 每轮的认知工具调用预算（0=不限）。
func (e *Engine) findingToolBudget() int { return e.cfg.Parallel.PerFindingToolBudget }

// findingModelBudget 返回单 finding 每轮的模型调用预算（0=不限）。
func (e *Engine) findingModelBudget() int { return e.cfg.Parallel.PerFindingModelBudget }

// workbenchSummary 提示词注入用的认知状态（作战图 + 待验证 + 经验）。
func (e *Engine) workbenchSummary() string {
	var b strings.Builder
	if e.wb != nil {
		if s := e.wb.Brief(6000); s != "" {
			b.WriteString(s)
			b.WriteString("\n")
		}
	}
	if e.mem != nil {
		if s := e.mem.ExperienceBrief(8); s != "" {
			b.WriteString("## 经验库（历史同类问题）\n" + s + "\n")
		}
	}
	return strings.TrimSpace(b.String())
}
