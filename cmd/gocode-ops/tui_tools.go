package main

import (
	"fmt"
	"time"

	"github.com/atotto/clipboard"
	"github.com/go-gocel/termagent/pkg/components/display"
	"github.com/go-gocel/termagent/pkg/theme"
)

// ── 工具调用表格 ─────────────────────────────────────────────────────

var toolColumns = []display.Column{
	{Key: "tool", Title: colTitleTool, Width: 20},
	{Key: "target", Title: colTitleTarget, Width: 14},
	{Key: "args", Title: colTitleArgs, Width: 0},
	{Key: "status", Title: colTitleStatus, Width: 8},
	{Key: "dur", Title: colTitleDur, Width: 8},
}

// toolResultMaxCopy 工具结果保留给复制/导出的上限（字符）。
const toolResultMaxCopy = 8000

func (m *rootModel) addToolRow(name, args, target string) {
	m.toolRows = append(m.toolRows, toolRow{
		name: name, args: args, target: target,
		status: toolStatusRunning, dur: "…",
		started: time.Now(),
	})
	m.pushTools()
}

// finishToolRow 把最近一条同名「运行中」记录标记为完成/失败，记录耗时
// 与结果内容（复制/导出用）。
func (m *rootModel) finishToolRow(name, content string, failed bool) {
	status := toolStatusDone
	if failed {
		status = toolStatusFailed
	}
	for i := len(m.toolRows) - 1; i >= 0; i-- {
		if m.toolRows[i].name == name && m.toolRows[i].status != toolStatusDone && m.toolRows[i].status != toolStatusFailed {
			m.toolRows[i].status = status
			m.toolRows[i].dur = humanDuration(time.Since(m.toolRows[i].started))
			m.toolRows[i].result = clipResult(content, 100, toolResultMaxCopy)
			break
		}
	}
	m.pushTools()
}

// lastRunningRow 当前正在运行的工具行（实时输出/进度的归属）。
func (m *rootModel) lastRunningRow() *toolRow {
	for i := len(m.toolRows) - 1; i >= 0; i-- {
		if m.toolRows[i].status != toolStatusDone && m.toolRows[i].status != toolStatusFailed {
			return &m.toolRows[i]
		}
	}
	return nil
}

func (m *rootModel) pushTools() {
	rows := make([]map[string]string, 0, len(m.toolRows))
	styles := make([]map[string]theme.Semantic, 0, len(m.toolRows))
	for _, r := range m.toolRows {
		rows = append(rows, map[string]string{
			"tool": toolDisplayName(r.name), "target": r.target, "args": r.args,
			"status": r.status, "dur": r.dur,
		})
		if sem := statusSemantic(r.status); sem != "" {
			styles = append(styles, map[string]theme.Semantic{"status": sem})
		} else {
			styles = append(styles, nil)
		}
	}
	m.tools.Update(display.TableMsg{Columns: toolColumns, Rows: rows, Styles: styles})
	m.updateTabTitles()
}

// statusSemantic 工具/主机行状态 → 语义色（运行中黄/完成绿/失败红/中断蓝）。
func statusSemantic(status string) theme.Semantic {
	switch status {
	case toolStatusRunning, "探测中…":
		return theme.Warning
	case toolStatusDone, "在线":
		return theme.Success
	case toolStatusFailed, "离线":
		return theme.Error
	case toolStatusInterrupt:
		return theme.Info
	}
	return ""
}

// ── 复制 ─────────────────────────────────────────────────────────────

// clipboardWriteAll 剪贴板写入（包变量：测试可替换）。
var clipboardWriteAll = clipboard.WriteAll

// copyLastToolResult 把最近一条已收尾工具的结果复制到剪贴板（c 键）。
func (m *rootModel) copyLastToolResult() {
	for i := len(m.toolRows) - 1; i >= 0; i-- {
		r := m.toolRows[i]
		if (r.status == toolStatusDone || r.status == toolStatusFailed) && r.result != "" {
			if err := clipboardWriteAll(r.result); err != nil {
				m.toast.Update(display.ToastMsg{Text: fmt.Sprintf(toastCopyFailed, truncate(err.Error(), 40)), Semantic: theme.Warning})
				return
			}
			m.toast.Update(display.ToastMsg{Text: fmt.Sprintf(toastCopied, toolDisplayName(r.name)), Semantic: theme.Info})
			return
		}
	}
	m.toast.Update(display.ToastMsg{Text: toastCopyNothing, Semantic: theme.Info})
}

// updateTabTitles 刷新标签页标题（工具计数/主机在线统计）。
func (m *rootModel) updateTabTitles() {
	if m.tabs == nil {
		return
	}
	_ = m.tabs.SetTitle(toolsTabIndex, tabTitleToolsWithCount(len(m.toolRows)))
	_ = m.tabs.SetTitle(hostsTabIndex, tabTitleHostsWithOnline(m.onlineCount(), len(m.hostRows), m.probeDone))
}
