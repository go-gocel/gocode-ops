package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/go-gocel/termagent/pkg/keymap"
	"github.com/go-gocel/termagent/pkg/layout"
	"github.com/go-gocel/termagent/pkg/theme"
)

// ── 布局渲染 ──────────────────────────────────────────────────────────

// headerView 顶部两行信息条（左右分布，不留大片空白）：
//
//	行1：logo + 运行状态（● READY/RUNNING + 当前任务/耗时）……模型（右对齐）
//	行2：环境元信息（主机 · 高危 · 远程[· 在线] · 排队）……token 用量（右对齐）
func (m *rootModel) headerView() string {
	var left1 []string
	left1 = append(left1, m.th.Style(theme.Primary).Render(" gocode-ops "))
	if m.running {
		left1 = append(left1, m.spinner.View())
	}
	left1 = append(left1, m.status.View())
	line1 := leftRight(strings.Join(left1, "  "), truncate(m.meta.model, 28), m.w)

	var left2 []string
	left2 = append(left2, "主机 "+truncate(m.meta.host, 24))
	left2 = append(left2, "高危 "+m.meta.risky)
	if m.remoteOK {
		left2 = append(left2, fmt.Sprintf("远程 %d 台", len(m.hostRows)))
		if m.probeDone {
			left2 = append(left2, fmt.Sprintf("在线 %d/%d", m.onlineCount(), len(m.hostRows)))
		}
	} else if m.meta.invPath != "" {
		left2 = append(left2, "远程未配置")
	}
	if len(m.pending) > 0 {
		left2 = append(left2, fmt.Sprintf("排队 %d", len(m.pending)))
	}
	line2 := leftRight(strings.Join(left2, " · "), m.usageString(), m.w)
	return line1 + "\n" + line2
}

// sepLine 全宽分隔线（区块边界：信息条/主区/输入区）。
func (m *rootModel) sepLine() string {
	w := m.w
	if w < 1 {
		w = 1
	}
	return m.th.Style(theme.Muted).Render(strings.Repeat("─", w))
}

// hintView 输入框下方的快捷键提示行（按当前界面状态切换）。
func (m *rootModel) hintView() string {
	switch {
	case m.help:
		return m.th.Style(theme.Muted).Render(hintHelp)
	case m.onHostsTab():
		return m.th.Style(theme.Muted).Render(hintHosts)
	default:
		return m.th.Style(theme.Muted).Render(hintDefault)
	}
}

// onHostsTab 当前是否在「远程主机」标签页。
func (m *rootModel) onHostsTab() bool {
	return m.tabs != nil && m.tabs.Active() == hostsTabIndex
}

// toastLines 当前通知占用的行数（布局预留）。
func (m *rootModel) toastLines() int {
	n := len(m.toast.Items())
	if n > 3 {
		n = 3
	}
	return n
}

// fixedRows 固定占用行数：2(header) + 1(分隔) + 1(分隔) + 1(hint) + 4(两行输入框)。
const fixedRows = 9

func (m *rootModel) View() string {
	if m.w == 0 {
		return "loading…"
	}
	// 模态/提问/详情为全屏覆盖：内容居中于屏幕（lipgloss.Place 语义）。
	if m.modal.IsOpen() {
		return layout.Center(m.modal.View(), m.w, m.h)
	}
	if m.ask != nil {
		return layout.Center(m.askView(), m.w, m.h)
	}
	if m.hostDetail != nil {
		return layout.Center(m.hostDetailView(), m.w, m.h)
	}
	if m.palette.Open() {
		return m.palette.View()
	}

	// 布局：顶部信息条（2 行）→ 通知（短提示）→ 分隔线 → 主区（对话/
	// 帮助/标签页）→ 分隔线 → 快捷键提示行 → 两行输入框（2 内容行）。
	// 提示行放在输入框上方：输入前先看到可用操作（回车发送/切页/帮助）。
	// 区块以分隔线为界，互不挤占。
	// 注意：textarea 的 SetHeight(h) 实际渲染 h+2 行（上下边框 + h 内容行），
	// 输入框不能 padTo 强制高度——会把下边框/内容截掉（历史 bug：输入框
	// 下半部分显示不完整）。宽度由 WindowSizeMsg 广播保证全宽。
	// 行数精确控制：各部分 splitLines 后 join，避免"段尾 \n"多出空行。
	toastN := m.toastLines()
	mainH := m.h - fixedRows - toastN
	if mainH < 1 {
		mainH = 1
	}
	var lines []string
	lines = append(lines, splitLines(m.headerView())...)
	if toastN > 0 {
		// 通知区域只占自身行数：若用全屏尺寸，Place 会返回满屏填充行，
		// 把整个 View 撑出屏幕高度，输入框被终端滚动挤出。
		m.toast.SetSize(m.w, toastN)
		if t := m.toast.View(); t != "" {
			lines = append(lines, splitLines(t)...)
		}
	}
	lines = append(lines, m.sepLine()) // 信息条与主区分界
	if m.help {
		// 帮助页：独立面板内容（viewport 滚动，不污染对话区）。
		m.helpPane.SetSize(m.w, mainH)
		lines = append(lines, splitLines(padTo(m.helpPane.View(), mainH, m.w))...)
	} else {
		// 对话区 viewport 尺寸（滚动窗口高度 = 主区高度）。
		m.chat.SetSize(m.w, mainH)
		lines = append(lines, splitLines(padTo(m.tabs.View(), mainH, m.w))...)
	}
	lines = append(lines, m.sepLine()) // 主区与输入区分界
	lines = append(lines, splitLines(m.hintView())...)
	lines = append(lines, splitLines(strings.TrimRight(m.input.View(), "\n"))...)
	return strings.Join(lines, "\n")
}

// box 圆角边框容器（居中遮罩用）。
func box(content string, width int) string {
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("3")).
		Padding(1, 2).
		Width(width).
		Render(content)
}

// ── 键位 ─────────────────────────────────────────────────────────────

func buildKeymap() *keymap.Keymap {
	km := keymap.New()
	must(km.Register("global", keymap.Binding{Key: "ctrl+c", Action: "interrupt", Help: "中断任务；空闲时退出"}))
	must(km.Register("global", keymap.Binding{Key: "ctrl+p", Action: "palette", Help: "打开命令面板"}))
	must(km.Register("global", keymap.Binding{Key: "tab", Action: "focus-next", Help: "切到下一焦点（输入框/标签页）"}))
	must(km.Register("global", keymap.Binding{Key: "shift+tab", Action: "focus-prev", Help: "切到上一焦点"}))
	must(km.Register("global", keymap.Binding{Key: "?", Action: "help", Help: "打开/关闭帮助"}))
	must(km.Register("tabs", keymap.Binding{Key: "left", Action: "tab-prev", Help: "上一个标签页"}))
	must(km.Register("tabs", keymap.Binding{Key: "right", Action: "tab-next", Help: "下一个标签页"}))
	must(km.Register("input", keymap.Binding{Key: "enter", Action: "submit", Help: "发送任务"}))
	must(km.Register("input", keymap.Binding{Key: "ctrl+up", Action: "history-prev", Help: "上一条输入历史"}))
	must(km.Register("input", keymap.Binding{Key: "ctrl+down", Action: "history-next", Help: "下一条输入历史"}))
	return km
}

// 实时输出与进度显示的上限。
const (
	liveMaxChar = 4000 // 单个工具调用的实时输出累计上限（字符）

	// liveBatchInterval 实时输出合并批次的间隔：高频输出（tail -f、编译
	// 日志）按批合并渲染，避免每个输出块触发一次全量 View。
	liveBatchInterval = 50 * time.Millisecond
)
