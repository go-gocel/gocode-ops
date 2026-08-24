package l0

// engine_report.go — L0 报告渲染与日志出口（report.md 实时刷新）。

import (
	"fmt"
	"github.com/go-gocel/gocode-ops/internal/common/fsutil"
	"io"
	"time"
)

func (e *Engine) renderReport() error {
	started := e.MarkStarted()
	// 收敛模式退出结论：实时报告不含结论，退出前按终态断言渲染最终版
	// （处置机制：终态报告断言 confirmed 去向闭合——未完成运行必然
	// 触发头部"不变量违规/中途快照"横幅，结构上不能伪装成完成报告）。
	if c := e.Conclusion(); c != "" {
		report := RenderReportFinal(e.ws, started, c)
		return fsutil.WriteFileAtomic(e.ReportPath(), []byte(report), 0o644)
	}
	report := RenderReport(e.ws, started)
	return fsutil.WriteFileAtomic(e.ReportPath(), []byte(report), 0o644)
}

func (e *Engine) logf(format string, args ...any) {
	// 时间戳带月-日：auto 评测跨天运行（23:57→00:10）时无日期无法对齐时间线。
	fmt.Fprintf(e.logOut, "[engine] %s "+format+"\n", append([]any{time.Now().Format("01-02 15:04:05")}, args...)...)
}

// onPhaseEvent 阶段 agent 事件回调：工具调用/结果实时打进引擎日志，
// 失败结果带 ✗ 标记——能逐条看到模型在做什么。
func (e *Engine) SetLogOut(w io.Writer) {
	if w != nil {
		e.logOut = w
	}
}

// findingsBrief 线索摘要（限制长度，控制上下文）。
