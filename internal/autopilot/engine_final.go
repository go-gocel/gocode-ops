package autopilot

// engine_final.go — 终裁：收敛前每条线索的三态终裁（含大清单分批）。

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/go-gocel/gocode-ops/internal/common/collect"
)

// finalAdjudicate 收敛前终裁：剩余 pending 线索在退出前回灌一次终裁
// （每条线索一次，FinalRuled 标记）——pending 不阻塞收敛，但引擎不
// 带着"从未终裁"的线索退出。模型基于全部已知状态做最后裁决：新确认
// 的进入处置循环（返回 true 重置干净计数），维持待查/排除的如实进
// 报告。R20 实测：cachex 挂载/横幅/4 条 hint 线索 pending 未终裁即
// 收敛，多项 ground truth 漏在收敛线外。
// 线索量大时与 DeepDive 同样分批（每批 ≤ deepDiveBatchSize）：批失败
// 只影响该批（未标记 FinalRuled，下个干净轮重试），已处理批不重复。
// 返回 (新增确认数>0, 全部批次失败)：全部失败时调用方不得把终裁当作
// 完成——收敛结论必须如实标注"存在未终裁待查项"，不静默收敛。
func (e *Engine) finalAdjudicate(ctx context.Context) (bool, bool) {
	if e.app == nil {
		return false, false
	}
	var targets []*Finding
	for _, f := range e.ws().Pending() {
		if !f.FinalRuled {
			targets = append(targets, f)
		}
	}
	if len(targets) == 0 {
		return false, false
	}
	e.setPhase(PhaseDeepDive)
	batches := (len(targets) + deepDiveBatchSize - 1) / deepDiveBatchSize
	e.logf("收敛前终裁开始：%d 条待查线索（分 %d 批，并发 %d）", len(targets), batches, e.parallelWorkers())
	// 批次并行（worker 池）：批失败只影响该批（未标记 FinalRuled，
	// 下个干净轮重试）；已处理批不重复。
	chunks := make([][]*Finding, 0, batches)
	for start := 0; start < len(targets); start += deepDiveBatchSize {
		end := start + deepDiveBatchSize
		if end > len(targets) {
			end = len(targets)
		}
		chunks = append(chunks, targets[start:end])
	}
	var newlyAll atomic.Int32
	var merged []*Finding
	var mergedMu sync.Mutex
	state := e.cogState() // 预构建：并行批内不可再调 cogState（竞争）
	done := e.runBatches(ctx, "终裁", len(chunks), func(i int, app *phaseAgent) bool {
		chunk := chunks[i]
		goal := fmt.Sprintf("收敛前终裁：引擎即将退出，以下待查线索做最后一次裁决（每条都必须处理）：\n%s\n\n要求：证据足以确认的 → confirmed（给足证据）；确属误报/已恢复的 → dismissed（说明排除依据）；证据仍不足的 → 保持 pending 并说明缺什么。基于已有调查裁决，不要展开新的大规模排查。", findingsBrief(chunk))
		sum, content, err := runPhase(ctx, app, PhaseDeepDive, taskPromptWithHints(PhaseDeepDive, goal, state, 0, e.toolErrFeedback()), e.cfg.DiagnoseTimeout, 0)
		if err != nil {
			e.stats.batchFails.Add(1)
			e.logf("收敛前终裁批失败: %v", err)
			if content != "" {
				e.logf("终裁模型原始输出: %s", collect.TruncateStr(content, 2000))
			}
			return false
		}
		for _, f := range chunk {
			f.FinalRuled = true
			f.Tried++
		}
		for _, ff := range sum.Findings {
			if ff.Status == FindingConfirmed {
				newlyAll.Add(1)
			}
		}
		if len(sum.Findings) > 0 {
			mergedMu.Lock()
			merged = append(merged, sum.Findings...)
			mergedMu.Unlock()
		}
		return true
	})
	// 统一入库（批次完成后一次序列化）。
	if len(merged) > 0 {
		e.ws().AddFindings(merged)
	} else {
		e.ws().SaveFindings()
	}
	newly := int(newlyAll.Load())
	e.logf("收敛前终裁：%d 条线索终裁（成功 %d 批），新增确认 %d", len(targets), done, newly)
	return newly > 0, done == 0
}

// maxRespondTries 单故障处置尝试上限（对齐 LLM SDK 重试实践：3 次尝试）。
// 达限停止自动重试：无限重试每轮烧一次 LLM 调用且故障永不处置，
// 不如如实进报告"未处置原因"。
