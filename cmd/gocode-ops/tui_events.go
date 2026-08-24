package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/go-gocel/gocel-core/types"
	"github.com/go-gocel/termagent/pkg/components/display"
	"github.com/go-gocel/termagent/pkg/theme"

	"github.com/go-gocel/gocode-ops/internal/common/audit"
	"github.com/go-gocel/gocode-ops/internal/common/remote"
)

// ── TUI 周期消息 ─────────────────────────────────────────────────────

// liveFlushMsg 实时输出合并批次到点：把缓冲块一次性灌入对话区
// （高频输出合并渲染，避免逐块全量 View）。
type liveFlushMsg struct{}

// elapsedTickMsg 任务耗时刷新 tick（每秒）。
type elapsedTickMsg time.Time

// ── 事件处理 ─────────────────────────────────────────────────────────

// handleEvent 消费 agent 事件：思考段落缓冲、工具过程入对话与表格、
// 模型输出直入对话区。
func (m *rootModel) handleEvent(msg agentEventMsg) {
	ev := msg.ev
	switch ev.Type {
	case types.EventReasoning:
		m.reasonBuf += ev.Content
	case types.EventToken:
		m.flushReason()
		m.chat.Update(display.AppendMsg{Text: ev.Content})
	case types.EventToolCall:
		m.flushReason()
		m.chat.Update(display.AppendMsg{Text: toolCallLine(ev.ToolName, ev.ToolArgs) + "\n"})
		m.addToolRow(ev.ToolName, truncate(ev.ToolArgs, 60), parseToolTarget(ev.ToolName, ev.ToolArgs))
	case types.EventToolResult:
		m.flushReason()
		m.chat.Update(display.AppendMsg{Text: toolResultLine(ev.ToolName, ev.Content, audit.IsToolError(ev.Content)) + "\n"})
		m.finishToolRow(ev.ToolName, ev.Content, audit.IsToolError(ev.Content))
	}
}

// ── 底座日志节流 ─────────────────────────────────────────────────────

// baseLogMax 每任务在对话区展示的底座（L0）日志条数上限；超限折叠为
// 一行提示，防止确定性底座日志淹没对话。
const baseLogMax = 30

// handleBaseLog 公用内核（L0 快检底座）日志行显示在对话区（节流折叠）。
// 注意：这是 l0.Engine（确定性底座）的日志，与全自动运维引擎（auto）无关——
// TUI 不展示引擎日志，引擎日志直接输出到终端（stderr）。
func (m *rootModel) handleBaseLog(msg baseLogMsg) {
	if msg.line == "" {
		return
	}
	if m.baseLogN >= baseLogMax {
		if !m.baseLogFold {
			m.baseLogFold = true
			m.chat.Update(display.AppendMsg{Text: "🔧 …其余底座日志已省略\n"})
		}
		return
	}
	m.baseLogN++
	m.chat.Update(display.AppendMsg{Text: "🔧 " + msg.line + "\n"})
}

// ── 实时输出：合并缓冲 ───────────────────────────────────────────────

// bufferLive 实时输出块入合并缓冲（高频输出合并渲染）。归属在缓冲时
// 解析：无归属工具行立即提示一次（不静默吞），避免延迟误报。
func (m *rootModel) bufferLive(prefix, text string) {
	if text == "" {
		return
	}
	idx := -1
	for i := len(m.toolRows) - 1; i >= 0; i-- {
		if m.toolRows[i].status != toolStatusDone && m.toolRows[i].status != toolStatusFailed {
			idx = i
			break
		}
	}
	if idx == -1 {
		// 无归属工具行（进度块晚于工具结果到达等）：丢弃并提示一次，
		// 不静默吞掉——操作员知道有输出没被展示。
		if !m.liveDropNotified {
			m.liveDropNotified = true
			m.toast.Update(display.ToastMsg{Text: toastLiveDropped, Semantic: theme.Warning})
		}
		return
	}
	m.liveBuf = append(m.liveBuf, liveChunk{prefix: prefix, text: text, rowIdx: idx})
}

// flushLive 把合并缓冲一次性灌入对话区（同一次 Update 周期完成全部
// 追加，N 个输出块只触发一次全量渲染）。
func (m *rootModel) flushLive() tea.Cmd {
	m.liveTicking = false
	if len(m.liveBuf) == 0 {
		return nil
	}
	buf := m.liveBuf
	m.liveBuf = nil
	for _, c := range buf {
		m.appendLiveTo(c.rowIdx, c.prefix, c.text)
	}
	return nil
}

// appendLiveTo 把一条实时输出块追加进其归属工具行（行级总量保护）。
func (m *rootModel) appendLiveTo(rowIdx int, prefix, text string) {
	if rowIdx < 0 || rowIdx >= len(m.toolRows) {
		return // 行已被清空（/new 等）：缓冲期已提示，此处静默
	}
	row := &m.toolRows[rowIdx]
	if row.status == toolStatusDone || row.status == toolStatusFailed {
		return // 行已收尾：迟到的输出块不再追认
	}
	budget := liveMaxChar - row.liveChar
	if budget <= 0 {
		if !row.liveOver {
			row.liveOver = true
			m.chat.Update(display.AppendMsg{Text: prefix + "…" + toastLiveOver + "\n"})
		}
		return
	}
	if len(text) > budget {
		// 本块超出剩余额度：截断并提示（防止单块刷屏）。
		row.liveChar = liveMaxChar
		chunk := truncate(text, budget)
		if chunk != "" {
			m.chat.Update(display.AppendMsg{Text: prefix + strings.TrimRight(chunk, "\n") + "\n"})
		}
		if !row.liveOver {
			row.liveOver = true
			m.chat.Update(display.AppendMsg{Text: prefix + "…" + toastLiveOver + "\n"})
		}
		return
	}
	row.liveChar += len(text)
	m.chat.Update(display.AppendMsg{Text: prefix + strings.TrimRight(text, "\n") + "\n"})
}

// ── 远程进度 ─────────────────────────────────────────────────────────

// handleRemoteProgress 远程实时进度：输出块进对话区（合并缓冲），
// 传输进度更新表格（百分比节流 + 短进度条）。
func (m *rootModel) handleRemoteProgress(p remote.RemoteProgress) {
	switch p.Phase {
	case "output":
		if p.Text != "" {
			m.bufferLive("📡 ["+p.Host+"] ", p.Text)
		}
	case "upload":
		m.updateTransferRow("⬆", p)
	case "download":
		m.updateTransferRow("⬇", p)
	}
}

// transferThrottleDelta 传输进度表格更新的最小百分比变化（<1% 不重建表格）。
const transferThrottleDelta = 0.01

// updateTransferRow 上传/下载进度：更新当前运行工具的表格状态列
// （百分比变化 ≥1% 才更新——大文件高频进度消息不再逐条全表重建）。
func (m *rootModel) updateTransferRow(arrow string, p remote.RemoteProgress) {
	row := m.lastRunningRow()
	if row == nil {
		return
	}
	if p.Total <= 0 {
		row.status = "…"
		m.pushTools()
		return
	}
	pct := float64(p.Done) / float64(p.Total)
	// 节流：变化 <1% 且未完成时不刷新表格（初始值 -1 强制展示一次）。
	if m.lastPct >= 0 && pct-m.lastPct < transferThrottleDelta && p.Done < p.Total {
		return
	}
	m.lastPct = pct
	row.status = transferStatus(pct)
	m.pushTools()
	if p.Done >= p.Total {
		m.toast.Update(display.ToastMsg{
			Text:     fmt.Sprintf(toastTransferDone, arrow, p.Host, p.Path, humanSize(p.Total)),
			Semantic: theme.Success,
		})
	}
}

// transferStatus 传输状态列文本：短进度条 + 百分比。
// 列宽 8 内恰好放下（"███ 100%" = 3+1+4；"███ 50%" = 3+1+3）。
func transferStatus(pct float64) string {
	return progressBar(pct, 3) + " " + fmt.Sprintf("%.0f%%", pct*100)
}

// ── 思考段落 ─────────────────────────────────────────────────────────

// flushReason 把缓冲的思考段落作为引用块刷入对话区。
func (m *rootModel) flushReason() {
	if m.reasonBuf == "" {
		return
	}
	m.chat.Update(display.AppendMsg{Text: blockquote("💭 "+strings.TrimSpace(m.reasonBuf)) + "\n"})
	m.reasonBuf = ""
}

// ── 一轮结束 ─────────────────────────────────────────────────────────

// handleFinish 一轮结束：恢复状态栏、收尾悬挂的工具行、展示结果/错误/
// 中断标记（含耗时），继续排队任务。
func (m *rootModel) handleFinish(msg agentFinishMsg) {
	m.flushReason()
	m.running = false
	m.ticking = false
	m.spinner.SetLabel("")
	m.chat.SetRich(true) // 回答稳定后全量渲染（代码高亮/表格对齐；失败/中断同样恢复）
	m.lastErr = msg.err
	m.taskCount++
	if msg.err != nil {
		// 中断/失败时把仍处于运行中的工具行收尾，避免悬挂"运行中"状态；
		// 操作员中断标"已中断"（不等于工具失败），其余标"失败"。
		endStatus := toolStatusFailed
		if errors.Is(msg.err, context.Canceled) {
			endStatus = toolStatusInterrupt
		}
		for i := range m.toolRows {
			if m.toolRows[i].status != toolStatusDone && m.toolRows[i].status != toolStatusFailed {
				m.toolRows[i].status = endStatus
				m.toolRows[i].dur = humanDuration(time.Since(m.toolRows[i].started))
			}
		}
		m.pushTools()
		switch {
		case errors.Is(msg.err, context.Canceled):
			m.chat.Update(display.AppendMsg{Text: "\n" + blockquote("✗ 任务已中断") + "\n"})
			m.status.Set(statusStateReady, statusInterrupted, theme.Info)
			m.toast.Update(display.ToastMsg{Text: "任务已中断", Semantic: theme.Warning})
		default:
			m.chat.Update(display.AppendMsg{Text: "\n" + blockquote("✗ "+msg.err.Error()) + "\n"})
			m.status.Set(statusStateReady, statusFailed, theme.Error)
			// 通知里保留关键信息（状态码/原因），完整错误在对话区。
			m.toast.Update(display.ToastMsg{Text: "✗ " + truncate(msg.err.Error(), 140), Semantic: theme.Error})
		}
		m.maybeStartNext()
		return
	}
	m.chat.Update(display.AppendMsg{Text: finishSeparator(m.taskStart) + "\n"})
	m.status.Set(statusStateReady, statusDone, theme.Success)
	// 成功不发通知（状态行已反馈），避免多条"任务完成"堆叠刷屏。
	m.maybeStartNext()
}

// finishSeparator 轮间分隔线；任务真实执行超过 1s 时附带耗时。
func finishSeparator(start time.Time) string {
	sep := "\n---"
	if !start.IsZero() {
		if d := time.Since(start); d > time.Second && d < 24*time.Hour {
			sep = fmt.Sprintf("\n--- (%s)", humanDuration(d))
		}
	}
	return sep
}

func (m *rootModel) usageString() string {
	if m.app == nil {
		return ""
	}
	return m.app.usageString()
}

// 工具结果打印上限：超过 maxLines 行或单行超过 maxWidth 字符时截断，
// 防止日志、大目录列举等超长输出刷屏。
const (
	toolResultMaxLines = 100 // 非终端模式完整展示上限
	toolResultMaxWidth = 200
	toolChatLines      = 6 // 对话区工具结果摘要上限
	toolChatWidth      = 180
)

// ── 工具行展示 ───────────────────────────────────────────────────────

// toolCallLine 对话区的工具调用行：⚡ 工具名 → 目标（参数细节在工具表格页，
// 不把长 JSON 挤进对话区）。
func toolCallLine(name, args string) string {
	line := "⚡ " + toolDisplayName(name)
	if isRemoteTool(name) {
		if target := parseToolTarget(name, args); target != "" && target != "远程" {
			line += " → " + target
		}
	}
	return line
}

// toolResultLine 对话区的工具结果行：✔/✗ 工具名 + 摘要（目标已在调用行标识）。
func toolResultLine(name, content string, failed bool) string {
	mark := "✔"
	if failed {
		mark = "✗"
	}
	return mark + " " + toolDisplayName(name) + ": " + clipResult(content, toolChatLines, toolChatWidth)
}

// toolDisplayName 界面展示的工具名：远程工具加 🌐 前缀（本地/远程逻辑
// 一致，显示区分——需求：远程与本地操作逻辑相同、显示效果不同）。
func toolDisplayName(name string) string {
	if isRemoteTool(name) {
		return "🌐 " + name
	}
	return name
}

// isRemoteTool 判断工具是否面向远端。
func isRemoteTool(name string) bool {
	switch name {
	case "remote_terminal", "remote_batch", "remote_upload", "remote_download", "remote_file", "remote_list", "remote_copy":
		return true
	}
	return false
}

// parseToolTarget 从工具参数解析目标（远程工具取主机别名，其余为本机）。
func parseToolTarget(name, args string) string {
	if !isRemoteTool(name) {
		return "本机"
	}
	var parsed struct {
		Hosts []string `json:"hosts"`
		Host  string   `json:"host"`
		// remote_copy 的目标主机字段。
		TargetHosts []string `json:"target_hosts"`
	}
	_ = json.Unmarshal([]byte(args), &parsed)
	if len(parsed.Hosts) > 0 {
		if len(parsed.Hosts) == 1 {
			return parsed.Hosts[0]
		}
		return strings.Join(parsed.Hosts, ",")
	}
	if len(parsed.TargetHosts) > 0 {
		if len(parsed.TargetHosts) == 1 {
			return parsed.TargetHosts[0]
		}
		return strings.Join(parsed.TargetHosts, ",")
	}
	if parsed.Host != "" {
		return parsed.Host
	}
	return "远程"
}
