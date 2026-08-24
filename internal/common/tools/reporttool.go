package tools

// reporttool.go — generate_report 工具：交互式运维助手报告**按需生成**
// （人在环：交互过程在操作员手里，除非操作员明确要求，否则不主动生成
// 报告）。全自动运维引擎不注册本工具——引擎的报告由主循环每轮自动
// 渲染（无人值守，报告是给人看的结果）。

import (
	"context"
	"fmt"

	"github.com/go-gocel/gocel-core/core/kernel"
	"github.com/go-gocel/gocel-core/core/tool"
)

// ReportRenderer 报告渲染接口（*l0.Engine 实现；接口化便于测试注入）。
type ReportRenderer interface {
	// RenderReport 渲染实时报告到工作目录 report.md。
	RenderReport() error
	// ReportPath 返回报告路径。
	ReportPath() string
}

// ReportTool 返回 generate_report 工具：渲染工作目录 report.md 并返回
// 路径。仅当操作员明确要求生成报告时由模型调用（"出个报告"/"生成巡检
// 报告"等）；日常问答与处置任务不调用本工具。
func ReportTool(e ReportRenderer) kernel.Tool {
	return tool.MustToolFromFunc(
		func(ctx context.Context, _ struct{}) (string, error) {
			if e == nil {
				return "", fmt.Errorf("generate_report: 报告底座未就绪")
			}
			if err := e.RenderReport(); err != nil {
				return "", fmt.Errorf("generate_report: 报告渲染失败: %w", err)
			}
			return fmt.Sprintf("报告已生成：%s（含巡检概览/确认故障/根因分析/修复记录/待查项/覆盖声明，操作员可在工作目录查看；对话区可继续追问细节）", e.ReportPath()), nil
		},
		tool.WithToolName("generate_report"),
		tool.WithToolDescription("按需生成运维巡检报告（渲染工作目录 report.md：巡检概览/故障清单/根因分析/修复记录/修复建议）。仅在操作员明确要求生成报告时调用；日常问答与处置任务不调用本工具。"),
		tool.WithToolSource("gocode"),
	)
}
