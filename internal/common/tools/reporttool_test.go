package tools

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// generate_report 工具测试：按需渲染报告并返回路径（人在环：仅在操作员
// 明确要求时由模型调用；全自动引擎不注册本工具）。

type fakeReportRenderer struct {
	rendered bool
	path     string
	err      error
}

func (f *fakeReportRenderer) RenderReport() error {
	f.rendered = true
	return f.err
}
func (f *fakeReportRenderer) ReportPath() string { return f.path }

func TestReportTool_RendersOnDemand(t *testing.T) {
	fake := &fakeReportRenderer{path: "/work/report.md"}
	tool := ReportTool(fake)
	if tool == nil || tool.Name() != "generate_report" {
		t.Fatalf("generate_report 工具应存在: %v", tool)
	}
	out, err := tool.Run(context.Background(), `{}`)
	if err != nil {
		t.Fatalf("generate_report: %v", err)
	}
	if !fake.rendered {
		t.Error("generate_report 应触发报告渲染")
	}
	if !strings.Contains(out, "/work/report.md") {
		t.Errorf("返回应含报告路径: %q", out)
	}
}

func TestReportTool_RenderFailure(t *testing.T) {
	fake := &fakeReportRenderer{err: errors.New("渲染失败")}
	_, err := ReportTool(fake).Run(context.Background(), `{}`)
	if err == nil || !strings.Contains(err.Error(), "渲染失败") {
		t.Errorf("渲染失败应如实报错: %v", err)
	}
}

func TestReportTool_NilRendererFails(t *testing.T) {
	if _, err := ReportTool(nil).Run(context.Background(), `{}`); err == nil {
		t.Error("无报告底座时 generate_report 应报错（fail-closed）")
	}
}
