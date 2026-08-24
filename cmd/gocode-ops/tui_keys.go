package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/go-gocel/termagent/pkg/components/display"
	"github.com/go-gocel/termagent/pkg/theme"
)

// ── 键盘 ─────────────────────────────────────────────────────────────

func (m *rootModel) handleKey(msg tea.KeyMsg) {
	// 命令面板优先（Ctrl+P 开关 + 面板内交互）
	m.palette.Update(msg)
	if m.palette.Open() {
		return
	}
	// 模态打开：焦点锁定（退出/中断确认覆盖提问）
	if m.modal.IsOpen() {
		m.modal.Update(msg)
		return
	}
	if m.ask != nil {
		m.handleAskKey(msg)
		return
	}
	// 主机详情弹窗：Enter/Esc 关闭，其余键吞掉（焦点锁定）。
	if m.hostDetail != nil {
		switch msg.String() {
		case "enter", "esc":
			m.hostDetail = nil
		}
		return
	}
	// Ctrl+C 永远是全局键：运行中中断任务，空闲时退出（输入框聚焦也
	// 生效——退出不应依赖 tab 切焦点）。帮助页打开时同样生效（先于
	// help 分支处理，否则帮助页吞掉 Ctrl+C 无法退出）。
	if msg.String() == "ctrl+c" {
		if m.running {
			m.modal.ShowConfirm("中断任务", "确定中断当前任务吗？", func(ok bool) {
				if ok {
					if m.cancel != nil {
						m.cancel()
					}
					m.pending = nil
					// 中断已取消任务：挂起的操作员提问一并拒绝——残留
					// ask 在确认框打开期间可能已投递（modal 覆盖显示），
					// 用户随后按 y 会放行已取消任务的命令。
					m.resolveAsk("")
				}
			})
		} else {
			m.quitting = true
		}
		return
	}
	// 帮助页打开：?/Esc 关闭；滚动键进帮助面板（viewport），其余忽略。
	if m.help {
		switch msg.String() {
		case "?", "esc":
			m.help = false
		default:
			m.helpPane.Update(msg)
		}
		return
	}
	// tab / shift+tab 永远是焦点切换键（即使输入框聚焦），否则焦点切不出去。
	switch msg.String() {
	case "tab":
		m.fm.Next()
		return
	case "shift+tab":
		m.fm.Prev()
		return
	}
	// Alt+1/2/3 直接切标签页（任意焦点生效，保持输入焦点——切页后
	// 可直接继续输入下一条任务）。不用 Ctrl+数字：bubbletea 不产生
	// ctrl+digit 序列，Alt+数字（ESC+digit）所有终端可捕获。
	if idx, ok := tabJumpIndex(msg.String()); ok {
		m.tabs.Select(idx)
		return
	}
	// 输入框聚焦：滚动键（PgUp/PgDn/Ctrl+u/Ctrl+d）转发给激活面板
	// （Markdown viewport 原生处理），其余按键全部交给输入框
	// （q/r/p/c/s/? 等全局键不拦截——打字优先）。
	if m.fm.Focused() == "input" {
		switch msg.String() {
		case "pgup", "pgdown", "ctrl+u", "ctrl+d":
			m.tabs.Update(msg)
			return
		}
		m.input.Update(msg)
		return
	}
	switch msg.String() {
	case "?":
		m.help = !m.help
	case "r":
		if m.onHostsTab() {
			m.loadHosts()
			m.toast.Update(display.ToastMsg{Text: toastHostsRefreshed, Semantic: theme.Info})
		}
	case "p":
		if m.onHostsTab() {
			m.probeHosts()
		}
	case "s":
		if m.onHostsTab() {
			m.cycleHostSort()
		}
	case "c":
		m.copyLastToolResult()
	default:
		m.tabs.Update(msg)
	}
}

// tabJumpIndex Alt+1/2/3 → 标签页下标。
func tabJumpIndex(key string) (int, bool) {
	switch key {
	case "alt+1":
		return 0, true
	case "alt+2":
		return 1, true
	case "alt+3":
		return 2, true
	}
	return 0, false
}

// confirmQuit 任务运行中退出需确认；确认后取消任务并退出。
func (m *rootModel) confirmQuit() {
	m.modal.ShowConfirm("退出", "任务正在执行，确定退出吗？", func(ok bool) {
		if ok {
			m.quit()
		}
	})
}

// quit 退出：取消运行中任务、解除阻塞的提问。
func (m *rootModel) quit() {
	if m.cancel != nil {
		m.cancel()
	}
	m.resolveAsk("")
	m.pending = nil
	m.quitting = true
}

// ── 内置命令 ─────────────────────────────────────────────────────────

type slashCmd int

const (
	cmdUnknown slashCmd = iota
	cmdHelp
	cmdNew
	cmdHosts
	cmdTokens
	cmdExport
	cmdExit
)

// parseSlash 解析输入行：/help /new /hosts /tokens /export /exit 等内置命令。
// 非 / 开头返回 ok=false；未知 / 命令返回 cmdUnknown。
func parseSlash(line string) (slashCmd, bool) {
	switch strings.ToLower(strings.TrimSpace(line)) {
	case cmdLineHelp, "/?":
		return cmdHelp, true
	case cmdLineNew:
		return cmdNew, true
	case cmdLineHosts:
		return cmdHosts, true
	case cmdLineTokens:
		return cmdTokens, true
	case cmdLineExport:
		return cmdExport, true
	case cmdLineExit, "/quit":
		return cmdExit, true
	}
	if strings.HasPrefix(strings.TrimSpace(line), "/") {
		return cmdUnknown, true
	}
	return cmdUnknown, false
}

func (m *rootModel) execCommand(cmd slashCmd) {
	switch cmd {
	case cmdHelp:
		m.help = true
	case cmdHosts:
		if m.tabs != nil {
			m.tabs.Select(hostsTabIndex)
			m.fm.Focus("tabs")
		}
	case cmdNew:
		if m.running {
			m.toast.Update(display.ToastMsg{Text: toastQueueBusy, Semantic: theme.Warning})
			return
		}
		if m.app != nil {
			m.app.reset()
		}
		m.chat.SetValue("")
		m.toolRows = nil
		m.taskCount = 0
		m.lastErr = nil
		m.pushTools()
		m.status.Set(statusStateReady, statusReadyNew, theme.Success)
	case cmdTokens:
		m.toast.Update(display.ToastMsg{Text: m.usageString(), Semantic: theme.Info})
	case cmdExport:
		m.execExport()
	case cmdExit:
		if m.running {
			m.confirmQuit()
			return
		}
		m.quitting = true
	case cmdUnknown:
		m.toast.Update(display.ToastMsg{Text: toastUnknownCmd, Semantic: theme.Warning})
	}
}

// execExport 导出会话记录（toast 反馈结果路径）。
func (m *rootModel) execExport() {
	path, err := m.exportTranscript()
	if err != nil {
		m.toast.Update(display.ToastMsg{Text: fmt.Sprintf(toastExportFailed, truncate(err.Error(), 60)), Semantic: theme.Error})
		return
	}
	m.toast.Update(display.ToastMsg{Text: fmt.Sprintf(toastExported, path), Semantic: theme.Success})
}
