package autopilot

// engine_deepdive.go — 追查阶段：deepDive 分批并行（线索→确认/排除）。

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-gocel/gocode-ops/internal/common/collect"
	"github.com/go-gocel/gocode-ops/internal/common/l0"
	"github.com/go-gocel/gocode-ops/internal/common/workspace"
)

// deepDive 对未追查的 pending 线索做模型深挖（确认/排除）；对被 L0
// 连续重检出的待查项做重追查（累计证据后重新裁决）。
// 线索量大时逐批调用模型：每批 ≤ deepDiveBatchSize 独立裁决，
// 全部批次处理完才算本轮追查完成；批失败只影响该批（下轮重试）。
func (e *Engine) deepDive(ctx context.Context) {
	if e.app == nil {
		return
	}
	e.setPhase(PhaseDeepDive)
	started := time.Now()
	var targets, rechase []*Finding
	for _, f := range e.ws().Pending() {
		switch {
		case f.Tried == 0:
			targets = append(targets, f)
		case f.Redetect >= reChaseRedetect && f.Rechased < maxRechase:
			rechase = append(rechase, f)
		}
	}
	if len(targets) == 0 && len(rechase) == 0 {
		return
	}
	// 批次组合：重追查线索在前（时间敏感，先处理），未追查线索在后。
	items := make([]struct {
		f       *Finding
		rechase bool
	}, 0, len(targets)+len(rechase))
	for _, f := range rechase {
		items = append(items, struct {
			f       *Finding
			rechase bool
		}{f, true})
	}
	for _, f := range targets {
		items = append(items, struct {
			f       *Finding
			rechase bool
		}{f, false})
	}
	batches := (len(items) + deepDiveBatchSize - 1) / deepDiveBatchSize
	e.logf("DeepDive 开始：追查 %d 条未追查线索（重追查 %d 条，分 %d 批，并发 %d）",
		len(targets), len(rechase), batches, e.parallelWorkers())
	// 批次并行（worker 池）：批次间零依赖（不同 finding），单批失败只
	// 影响该批（下轮重试）——工作项级失败隔离。
	batchList := make([][]struct {
		f       *Finding
		rechase bool
	}, 0, batches)
	for start := 0; start < len(items); start += deepDiveBatchSize {
		end := start + deepDiveBatchSize
		if end > len(items) {
			end = len(items)
		}
		batchList = append(batchList, items[start:end])
	}
	// 认知状态预构建：并行批内不再调用 cogState（StateSummary 全量
	// 序列化会读其他批正在修改的 finding 字段——数据竞争）。
	state := e.cogState()
	var merged []*Finding
	var mergedMu sync.Mutex
	done := e.runBatches(ctx, "DeepDive", len(batchList), func(i int, app *phaseAgent) bool {
		findings, ok := e.deepDiveBatchApp(ctx, app, batchList[i], state)
		if ok && len(findings) > 0 {
			mergedMu.Lock()
			merged = append(merged, findings...)
			mergedMu.Unlock()
		}
		return ok
	})
	// 统一入库（批次完成后一次序列化——并行批内 save 会读其他批正在
	// 修改的字段）。
	if len(merged) > 0 {
		e.ws().AddFindings(merged)
	}
	// DeepDive 阶段耗时留痕（phases.json 此前缺追查阶段——复盘阶段
	// 耗时分布只能靠日志反推）。
	e.ws().AddPhaseLog(workspace.PhaseLog{Phase: PhaseDeepDive, At: started, Duration: time.Since(started), OK: done == batches})
	e.logf("DeepDive 完成：%d/%d 批成功", done, batches)
}

// recallHits 记忆预检（P0 修复）：按追查目标的 signal/host 汇总记忆库
// 命中的经验（每条 finding 至多 2 条，总量有界），引擎注入追查上下文
// 而非模型显式调 recall。无命中返回空串。
func (e *Engine) recallHits(targets, rechase []*Finding) string {
	if e.mem == nil {
		return ""
	}
	seen := map[string]bool{}
	var parts []string
	add := func(f *Finding) {
		key := f.Signal + "\x00" + f.Host
		if seen[key] {
			return
		}
		seen[key] = true
		for _, hit := range e.mem.Recall(f.Signal, f.Host, 2) {
			parts = append(parts, fmt.Sprintf("- [%s/%s] %s", f.Host, f.Signal, collect.TruncateStr(hit, 240)))
		}
	}
	for _, f := range targets {
		add(f)
	}
	for _, f := range rechase {
		add(f)
	}
	if len(parts) == 0 {
		return ""
	}
	if len(parts) > 12 {
		parts = parts[:12]
	}
	return strings.Join(parts, "\n")
}

// deepDiveBatchApp 追查一批线索（app 为执行该批的独立阶段 agent；
// state 为调度器预构建的认知状态，批内不可再调 cogState）：
// 构造任务 → 运行阶段 → 标记该批已追查。失败返回 (nil, false)（该批
// 不标记，下轮重试）；成功返回模型产出（调度器统一入库）。
func (e *Engine) deepDiveBatchApp(ctx context.Context, app *phaseAgent, items []struct {
	f       *Finding
	rechase bool
}, state string) ([]*Finding, bool) {
	var targets, rechase []*Finding
	for _, it := range items {
		if it.rechase {
			rechase = append(rechase, it.f)
		} else {
			targets = append(targets, it.f)
		}
	}
	var goal string
	if len(targets) > 0 {
		goal = fmt.Sprintf("对以下线索逐条追查：痕迹追踪（时间线/系统自省/对比）→ 假设 → 只读验证。\n每条线索必须裁决为 confirmed（有证据）或 dismissed（说明排除理由）；证据不足保持 pending 并说明还需要什么。\n线索：\n%s", findingsBrief(targets))
	}
	if len(rechase) > 0 {
		if goal != "" {
			goal += "\n\n"
		}
		goal += fmt.Sprintf("以下线索已被 L0 连续多轮重检出（异常持续存在的确定性证据），此前裁决为证据不足待查——请基于累计证据重新裁决（不要沿用旧结论）：\n%s", findingsBrief(rechase))
	}
	// 经验预检注入（P0 修复）：引擎把记忆库命中的经验直接注入追查
	// 上下文（auto-recall，零工具调用）——模型无需再显式调 recall
	// 查"有没有旧经验"（chaos-r1 实测 recall 空转 ~90 次，绝大多数
	// 返回"无相关经验"）；记忆库为空时注入空说明，提示跳过 recall。
	var hint strings.Builder
	if hits := e.recallHits(targets, rechase); hits != "" {
		fmt.Fprintf(&hint, "## 历史经验（引擎已预检，无需再调 recall）\n%s\n", hits)
	} else {
		hint.WriteString("## 历史经验（引擎已预检）：本环境无相关历史经验/档案——无需调用 recall，直接基于现场证据追查。\n")
	}
	if fb := e.toolErrFeedback(); fb != "" {
		hint.WriteString(fb)
	}
	// 认知护栏（P0 修复）：单线索追查的模型调用预算（ReAct 步数上限），
	// 默认开启（PerFindingModelBudget）——深挖有界，防单线索无界烧钱
	// （chaos-r1 的 PAM 域深挖 5+ 轮同类命令）。
	maxSteps := 0
	if e.cfg.Parallel.PerFindingModelBudget > 0 {
		maxSteps = e.cfg.Parallel.PerFindingModelBudget
	}
	sum, content, err := runPhase(ctx, app, PhaseDeepDive, taskPromptWithHints(PhaseDeepDive, goal, state, maxSteps, hint.String()), e.cfg.DiagnoseTimeout, maxSteps)
	if err != nil {
		e.stats.batchFails.Add(1)
		e.logf("DeepDive 批失败（追查 %d 条/重追查 %d 条）: %v", len(targets), len(rechase), err)
		if content != "" {
			e.logf("DeepDive 模型原始输出: %s", collect.TruncateStr(content, 2000))
		}
		return nil, false
	}
	for _, f := range targets {
		f.Tried++      // 参与过一次追查
		f.Redetect = 0 // 重检出计数从本次裁决后重新累计
	}
	// 重追查计数：重检出计数清零重新累计；达上限后不再重查（如实留在待查区）。
	for _, f := range rechase {
		f.Tried++
		f.Rechased++
		f.Redetect = 0
	}
	if len(rechase) > 0 {
		e.logf("DeepDive 重追查 %d 条持续重检出的待查线索", len(rechase))
	}
	e.logf("DeepDive：裁决 %d 条线索，明细：", len(sum.Findings))
	for _, f := range sum.Findings {
		e.logf("  - [%s] %s%s → %s: %s", f.Host, f.Signal, l0.KeyNote(f.Key), f.Status, collect.TruncateStr(f.Desc, 120))
	}
	// 模型产出由调度器统一入库（批次完成后一次 AddFindings）——
	// 并行批内直接 AddFindings 会在批 A 全量序列化时读批 B 正在
	// 修改的 finding 字段（数据竞争）。
	return sum.Findings, true
}
