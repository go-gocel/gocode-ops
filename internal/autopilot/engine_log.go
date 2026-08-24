package autopilot

// engine_log.go — 日志与摘要：阶段事件行/发现简报/反馈上下文/汇总。

import (
	"fmt"
	"strings"

	"github.com/go-gocel/gocel-core/core/kernel"
	"github.com/go-gocel/gocel-core/types"

	"github.com/go-gocel/gocode-ops/internal/common/audit"
	"github.com/go-gocel/gocode-ops/internal/common/collect"
)

// setPhase 原子记录当前阶段（并行批次并发写 currentPhase）。
func (e *Engine) setPhase(p Phase) { e.currentPhase.Store(p) }

// getPhase 读取当前阶段（事件日志前缀）。
func (e *Engine) getPhase() Phase {
	if v := e.currentPhase.Load(); v != nil {
		return v.(Phase)
	}
	return ""
}

// renderReport 渲染实时报告并原子落盘。
func (e *Engine) onPhaseEvent(ev *types.Event) {
	switch ev.Type {
	case types.EventToolCall:
		e.stats.toolCalls.Add(1)
	case types.EventToolResult:
		if audit.IsToolError(ev.Content) {
			e.stats.toolErrors.Add(1)
			if strings.Contains(ev.Content, "blocked") || strings.Contains(ev.Content, "安全守卫") {
				e.stats.toolBlocked.Add(1)
			}
			// 工具错误反馈缓冲（P0 修复：跨轮错误记忆，见 recordToolError）。
			e.recordToolError(ev.ToolName, ev.Content)
		}
	}
	if line, ok := phaseEventLine(e.getPhase(), ev); ok {
		e.logf("%s", line)
	}
}

// recordToolError 记录工具失败到反馈缓冲。同类错误去重（保留最新），
// 保留最近 toolErrCap 条——错误缓冲不是流水账，是"下一轮别再犯"的
// 修正提示（ReAct 无跨轮记忆，chaos-r1 实测 remote_terminal 缺 host
// 参数连续报错 29 次）。
func (e *Engine) recordToolError(toolName, content string) {
	summary := strings.TrimSpace(collect.TruncateStr(oneLine(content), 160))
	if summary == "" {
		return
	}
	e.toolErrMu.Lock()
	defer e.toolErrMu.Unlock()
	entry := fmt.Sprintf("%s: %s", toolName, summary)
	kept := e.toolErrs[:0]
	for _, old := range e.toolErrs {
		if old == entry {
			continue
		}
		kept = append(kept, old)
	}
	kept = append(kept, entry)
	if len(kept) > toolErrCap {
		kept = kept[len(kept)-toolErrCap:]
	}
	e.toolErrs = kept
}

// toolErrFeedback 返回注入下一阶段任务提示的工具错误修正块；无错误
// 返回空串。含通用修正要点（高频错误形态），模型在下一阶段直接规避。
func (e *Engine) toolErrFeedback() string {
	e.toolErrMu.Lock()
	defer e.toolErrMu.Unlock()
	if len(e.toolErrs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("## 上一阶段工具错误（修正提示，本阶段不要再犯）\n")
	for _, s := range e.toolErrs {
		fmt.Fprintf(&b, "- %s\n", s)
	}
	b.WriteString("修正要点：remote_terminal/remote_batch 必须带 host/hosts 参数（清单别名）；update_workbench 的 payload 是 JSON 字符串字段；参数类型不符的命令不会被执行。\n")
	return b.String()
}

// toolErrCap 工具错误反馈缓冲条数。
const toolErrCap = 8

// phaseEventLine 把阶段 agent 事件格式化为日志行；不需记录的事件返回
// ("", false)（模型正文与推理不进日志，防刷屏）。工具参数/结果截断到
// 可完整定位问题的长度，超长时标注原始长度（排查"模型传了什么"不猜）。
// 内容中的换行转义为字面 \n——日志必须一行一条事件，多行块会破坏
// grep/按行分析（此前整段输出原样落盘，日志行内嵌换行）。
func phaseEventLine(phase Phase, ev *types.Event) (string, bool) {
	switch ev.Type {
	case types.EventToolCall:
		args := oneLine(ev.ToolArgs)
		return fmt.Sprintf("[%s] 调用 %s(%s)%s", phase, ev.ToolName, collect.TruncateStr(args, 400), truncNote(ev.ToolArgs, 400)), true
	case types.EventToolResult:
		mark := "✔"
		if audit.IsToolError(ev.Content) {
			mark = "✗"
		}
		content := oneLine(ev.Content)
		return fmt.Sprintf("[%s] %s %s%s: %s", phase, mark, ev.ToolName, truncNote(ev.Content, 1500), collect.TruncateStr(content, 1500)), true
	}
	return "", false
}

// oneLine 把多行文本压成单行（换行/回车转义为字面 \n、\r）——日志行
// 单行化，避免整段输出破坏按行解析。
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\\n")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return strings.ReplaceAll(s, "\r", "\\r")
}

// truncNote 超长内容截断并标注原始长度（日志行：原始长度 + 截断标记）。
func truncNote(s string, n int) string {
	if len(s) <= n {
		return ""
	}
	return fmt.Sprintf("（%d 字符，已截断）", len(s))
}

func modelSuffix(m kernel.Model) string {
	if m == nil {
		return "（无模型）"
	}
	return ""
}

// SetLogOut 替换引擎日志输出（默认 os.Stderr；TUI 注入界面通道）。
func findingsBrief(list []*Finding) string {
	var parts []string
	for i, f := range list {
		if i >= 20 {
			parts = append(parts, fmt.Sprintf("…其余 %d 条", len(list)-20))
			break
		}
		parts = append(parts, fmt.Sprintf("- [%s] %s: %s", f.Host, f.Signal, f.Desc))
	}
	return strings.Join(parts, "\n")
}

func findingDetail(f *Finding) string {
	return fmt.Sprintf("- ID: %s\n- 主机: %s\n- 信号: %s\n- 子键: %s\n- 现象: %s\n- 根因: %s\n- 证据: %s",
		f.ID, f.Host, f.Signal, f.Key, f.Desc, f.RootCause, strings.Join(f.Evidence, " | "))
}

// respondFeedback 生成上次处置执行摘要（反馈闭环用）：动作名 + 状态
// （成功/失败原因/验证结果/回滚结果/建议未执行原因）。
// 无历史执行记录时，生成/校验类失败（Actions 为空但 note 有原因）
// 同样回灌——模型据此修正而非盲目重试同样的失败。
func respondFeedback(f *Finding) string {
	if len(f.Actions) == 0 {
		if f.RemediationNote != "" &&
			(strings.Contains(f.RemediationNote, "三件套") ||
				strings.Contains(f.RemediationNote, "方案为空") ||
				strings.Contains(f.RemediationNote, "未生成") ||
				strings.Contains(f.RemediationNote, "解析失败") ||
				strings.Contains(f.RemediationNote, "生成失败") ||
				strings.Contains(f.RemediationNote, "证据对应") ||
				strings.Contains(f.RemediationNote, "验证对象")) {
			return "- 上轮方案被拒绝：" + f.RemediationNote
		}
		return ""
	}
	// 执行成功但确定性复检未通过：线索仍存在（处置未生效/对象错位）。
	if !f.Remediated && strings.Contains(f.RemediationNote, "复检未通过") {
		return "- 上轮处置执行成功但引擎确定性复检未通过（线索仍存在）：处置未生效或对象错位，请修正处置对象/方式后重试。"
	}
	var parts []string
	for _, a := range f.Actions {
		switch {
		case a.Advised:
			parts = append(parts, fmt.Sprintf("- %s：未执行（自影响风险转人工建议）%s", a.Name, suffix(a.AdvisedReason)))
		case a.Error != "":
			parts = append(parts, fmt.Sprintf("- %s：执行失败 %s", a.Name, suffix(a.Error)))
		case a.RolledBac:
			parts = append(parts, fmt.Sprintf("- %s：验证失败已回滚（命令: %s）%s", a.Name, a.Command, suffix(a.VerifyNote)))
		case a.Verified:
			parts = append(parts, fmt.Sprintf("- %s：成功且验证通过（命令: %s）", a.Name, a.Command))
		default:
			parts = append(parts, fmt.Sprintf("- %s：验证未通过 %s", a.Name, suffix(a.VerifyNote)))
		}
	}
	return strings.Join(parts, "\n")
}

// suffix 摘要后缀（去空白，限长）。
func suffix(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 160 {
		return s[:160] + "…"
	}
	return s
}
