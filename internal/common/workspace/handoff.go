package workspace

// handoff.go — 接力协同：全自动引擎 → 交互式运维助手。
//
// 两种形态共享同一工作区（.gocode/findings.json 等）。引擎跑完后
// 遗留的未处置项与人工工单（manual_workorder）由交互助手接管：
// 助手启动时读取遗留摘要注入上下文并提示横幅，用户下达"接续处理"
// 类指令后直接处置；处置完成后再跑一次引擎复检确认收敛（引擎的
// 确定性复检闭环收口）。并行运行同样安全（findings 跨进程锁+合并）。

import (
	"fmt"
	"strings"

	"github.com/go-gocel/gocode-ops/internal/common/model"
)

// Handoff 引擎遗留状态摘要（接力协同输入面）。
type Handoff struct {
	// Open 未处置项摘要（pending 待裁决 / confirmed 未修复）。
	Open []string `json:"open,omitempty"`
	// WorkOrders 人工工单摘要（manual_workorder，含建议命令）。
	WorkOrders []string `json:"work_orders,omitempty"`
}

// HasWork 是否存在可接管的遗留项。
func (h *Handoff) HasWork() bool {
	return len(h.Open) > 0 || len(h.WorkOrders) > 0
}

// String 紧凑摘要（注入助手上下文用，控制长度）。
func (h *Handoff) String() string {
	var b strings.Builder
	if len(h.Open) > 0 {
		fmt.Fprintf(&b, "未处置项 %d 个：\n", len(h.Open))
		for _, s := range h.Open {
			b.WriteString("  - " + s + "\n")
		}
	}
	if len(h.WorkOrders) > 0 {
		fmt.Fprintf(&b, "人工工单 %d 个（需人工处置）：\n", len(h.WorkOrders))
		for _, s := range h.WorkOrders {
			b.WriteString("  - " + s + "\n")
		}
	}
	return b.String()
}

// LoadHandoff 读取工作区引擎遗留状态。容错：findings.json 不存在/
// 损坏/无遗留 → 空 Handoff（不阻塞助手启动）。工作目录与引擎同
// 目录时才是接力场景；助手独立使用（无引擎遗留）时为空。
func LoadHandoff(workDir string) *Handoff {
	ws, err := NewWorkspace(workDir)
	if err != nil {
		return &Handoff{}
	}
	h := &Handoff{}
	for _, f := range ws.FindingList {
		// 工单项（manual_workorder）只进工单清单（已有处置去向，不重复
		// 计入待处置）。
		if f.Disposition != nil && f.Disposition.Outcome == model.DispositionManualWorkOrder && !f.Remediated {
			h.WorkOrders = append(h.WorkOrders, summarizeFinding(f, "工单"))
			continue
		}
		switch {
		case f.Status == FindingPending:
			h.Open = append(h.Open, summarizeFinding(f, "待裁决"))
		case f.Status == FindingConfirmed && !f.Remediated:
			h.Open = append(h.Open, summarizeFinding(f, "已确认未处置"))
		}
	}
	return h
}

// summarizeFinding 单条遗留项摘要（signal/key/状态/一句根因/建议）。
// 建议命令截断（工单区全文在 report.md，此处只给提示）。
func summarizeFinding(f *Finding, tag string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] %s", tag, f.Signal)
	if f.Key != "" {
		fmt.Fprintf(&b, " (%s)", f.Key)
	}
	if f.RootCause != "" {
		b.WriteString("：")
		b.WriteString(truncateRune(f.RootCause, 60))
	}
	if f.Disposition != nil && f.Disposition.WorkOrder != nil && len(f.Disposition.WorkOrder.SuggestedCommands) > 0 {
		b.WriteString("；建议: ")
		b.WriteString(truncateRune(strings.Join(f.Disposition.WorkOrder.SuggestedCommands, " "), 80))
	}
	return b.String()
}

// truncateRune 按 rune 截断（中文安全）。
func truncateRune(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
