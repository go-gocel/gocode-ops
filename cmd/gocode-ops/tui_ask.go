package main

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/go-gocel/termagent/pkg/theme"
)

// ── 操作员提问 ───────────────────────────────────────────────────────

// maxCustomAnswer 自定义回答的最大长度（防粘贴长文本刷屏）。
const maxCustomAnswer = 200

// openAsk 打开提问：缺省选项补 y/n；界面统一渲染为可导航选项列表，
// y/n 选项支持直接按键回答。列表末尾固定追加"其他"入口——选项不
// 满足时输入补充说明，回答以用户原话返回给模型（模型不应再追问）。
func (m *rootModel) openAsk(msg askMsg) {
	opts := msg.options
	if len(opts) == 0 {
		opts = []string{"y", "n"}
	}
	m.ask = &askState{
		question: msg.prompt,
		options:  opts,
		resp:     msg.resp,
	}
}

func (m *rootModel) handleAskKey(msg tea.KeyMsg) tea.Cmd {
	// 自定义输入模式：全部按键交给输入处理。
	if m.ask.custom {
		return m.handleCustomAnswerKey(msg)
	}
	switch msg.String() {
	case "up":
		m.ask.move(-1)
	case "down":
		m.ask.move(1)
	case "enter":
		if m.ask.current == len(m.ask.options) {
			// 选中"其他"：进入自定义输入模式，由用户输入补充说明。
			m.ask.custom = true
			m.ask.input = ""
		} else {
			m.resolveAsk(m.ask.options[m.ask.current])
		}
	case "y":
		if isYNOptions(m.ask.options) {
			m.resolveAsk("y")
		}
	case "n":
		if isYNOptions(m.ask.options) {
			m.resolveAsk("n")
		}
	case "esc", "ctrl+c":
		m.resolveAsk("") // 取消：非肯定回答按拒绝处理
	}
	return nil
}

// handleCustomAnswerKey 自定义输入模式：可打印字符追加、退格删除、
// Enter 提交（空输入视为放弃，返回选项列表）、Esc 返回选项列表。
func (m *rootModel) handleCustomAnswerKey(msg tea.KeyMsg) tea.Cmd {
	switch {
	case msg.Type == tea.KeyEsc || msg.Type == tea.KeyCtrlC:
		m.ask.custom = false // 返回选项列表（不取消提问）
	case msg.Type == tea.KeyEnter:
		ans := strings.TrimSpace(m.ask.input)
		if ans == "" {
			m.ask.custom = false
		} else {
			m.resolveAsk(ans)
		}
	case msg.Type == tea.KeyBackspace:
		if runes := []rune(m.ask.input); len(runes) > 0 {
			m.ask.input = string(runes[:len(runes)-1])
		}
	case msg.Type == tea.KeyRunes:
		if len([]rune(m.ask.input)) < maxCustomAnswer {
			m.ask.input += string(msg.Runes)
		}
	}
	return nil
}

// resolveAsk 把回答送回等待中的 agent goroutine 并关闭提问。
func (m *rootModel) resolveAsk(ans string) {
	if m.ask != nil {
		m.ask.resp <- ans
		m.ask = nil
	}
}

// isYNOptions 判断选项是否以 y/n 开头（支持直接按键回答；守卫确认
// 可能带第三个选项 a=本会话全部放行，y/n 快捷键仍可用）。
func isYNOptions(opts []string) bool {
	return len(opts) >= 2 && strings.EqualFold(opts[0], "y") && strings.EqualFold(opts[1], "n")
}

// askView 提问弹窗渲染：问题行数上限折叠 + 选项列表 + 快捷键提示。
// 外层 View 负责居中（layout.Center）。
func (m *rootModel) askView() string {
	width := m.w - 8
	if width < 24 {
		width = 24
	}
	var sb strings.Builder
	sb.WriteString(m.th.Style(theme.Warning).Bold(true).Render(askTitle) + "\n\n")
	// 问题按行渲染；超过 askMaxLines 行折叠（完整内容见对话区/模型侧）。
	lines := strings.Split(m.ask.question, "\n")
	if len(lines) > askMaxLines {
		lines = append(lines[:askMaxLines], strings.TrimPrefix(askTruncatedSuffix, "\n"))
	}
	for _, line := range lines {
		sb.WriteString(m.th.Style(theme.Muted).Render("  "+ansi.Truncate(line, width-4, "…")) + "\n")
	}
	sb.WriteString("\n")
	if m.ask.custom {
		sb.WriteString(m.th.Style(theme.Info).Render(askCustomLabel) + "\n\n")
		sb.WriteString("  " + m.th.Style(theme.Info).Render(m.ask.input) + "▌\n\n")
		sb.WriteString(m.th.Style(theme.Muted).Render(askCustomHint))
	} else {
		for i, opt := range m.ask.options {
			if i == m.ask.current {
				sb.WriteString(m.th.Style(theme.Info).Bold(true).Render("  ▸ "+opt) + "\n")
			} else {
				sb.WriteString(m.th.Style(theme.Muted).Render("    "+opt) + "\n")
			}
		}
		if m.ask.current == len(m.ask.options) {
			sb.WriteString(m.th.Style(theme.Info).Bold(true).Render("  ▸ "+askOtherEntry) + "\n")
		} else {
			sb.WriteString(m.th.Style(theme.Muted).Render("    "+askOtherEntry) + "\n")
		}
		hint := askHintSelect
		if isYNOptions(m.ask.options) {
			hint = askHintSelectYN
		}
		sb.WriteString("\n" + m.th.Style(theme.Muted).Render(hint))
	}
	return box(sb.String(), width)
}
