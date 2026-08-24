package main

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/go-gocel/termagent/pkg/components/display"
	"github.com/go-gocel/termagent/pkg/theme"

	"github.com/go-gocel/gocode-ops/internal/common/remote"
)

// ── 远程主机页 ────────────────────────────────────────────────────────

// hostColumns 「远程主机」表格列定义。
var hostColumns = []display.Column{
	{Key: "name", Title: colTitleHost, Width: 14, Sortable: true},
	{Key: "address", Title: colTitleAddress, Width: 22, Sortable: true},
	{Key: "user", Title: colTitleUser, Width: 10},
	{Key: "auth", Title: colTitleAuth, Width: 6},
	{Key: "status", Title: colTitleStatus, Width: 0},
}

// hostStatusProbing/Online/Offline/Unknown 主机状态文本。
const (
	hostStatusUnknown = "未探测"
	hostStatusProbing = "探测中…"
	hostStatusOnline  = "在线"
	hostStatusOffline = "离线"
)

// loadHosts 从清单文件加载主机（失败时界面提示，不阻断）。
func (m *rootModel) loadHosts() {
	m.hostRows = nil
	views, err := remote.ListInventory(m.meta.invPath)
	if err != nil {
		m.remoteOK = false
		m.hosts.Update(display.TableMsg{Columns: hostColumns, Rows: nil})
		if m.rt != nil {
			m.toast.Update(display.ToastMsg{Text: "主机清单加载失败：" + truncate(err.Error(), 60), Semantic: theme.Warning})
		}
		return
	}
	m.remoteOK = true
	for _, v := range views {
		m.hostRows = append(m.hostRows, hostRow{
			name: v.Name, address: v.Address, user: v.User, auth: v.Auth, status: hostStatusUnknown,
		})
	}
	m.pushHosts()
}

// pushHosts 把主机清单推入表格（含状态着色与排序键应用）。
func (m *rootModel) pushHosts() {
	rows := make([]map[string]string, 0, len(m.hostRows))
	styles := make([]map[string]theme.Semantic, 0, len(m.hostRows))
	for _, r := range m.hostRows {
		rows = append(rows, map[string]string{
			"name": r.name, "address": r.address, "user": r.user, "auth": r.auth, "status": r.status,
		})
		if sem := statusSemantic(r.status); sem != "" {
			styles = append(styles, map[string]theme.Semantic{"status": sem})
		} else {
			styles = append(styles, nil)
		}
	}
	// 排序键持久化：push 后按当前键排序（Table.SortBy 同时驱动表头 ▲ 标记）。
	if m.hostSortKey != "" {
		key := m.hostSortKey
		sort.SliceStable(rows, func(i, j int) bool { return rows[i][key] < rows[j][key] })
	}
	m.hosts.Update(display.TableMsg{Columns: hostColumns, Rows: rows, Styles: styles})
	if m.hostSortKey != "" {
		m.hosts.SortBy(m.hostSortKey, true)
	}
	m.updateTabTitles()
}

// cycleHostSort 循环切换主机页排序键：未排序 → 按名称 → 按地址 → 取消（s 键）。
func (m *rootModel) cycleHostSort() {
	switch m.hostSortKey {
	case "":
		m.hostSortKey = "name"
		m.toast.Update(display.ToastMsg{Text: toastSortByName, Semantic: theme.Info})
	case "name":
		m.hostSortKey = "address"
		m.toast.Update(display.ToastMsg{Text: toastSortByAddress, Semantic: theme.Info})
	default:
		m.hostSortKey = ""
		m.toast.Update(display.ToastMsg{Text: toastSortOff, Semantic: theme.Info})
	}
	m.pushHosts()
}

// onlineCount 当前在线主机数（header 在线统计/表格标题用）。
func (m *rootModel) onlineCount() int {
	n := 0
	for _, r := range m.hostRows {
		if r.status == hostStatusOnline {
			n++
		}
	}
	return n
}

// probeHosts 并发探测全部主机连通性（异步，结果经 hostsProbeMsg 回投）。
// 探测使用独立上下文（probeCtx）：不随任务中断取消，也不与主循环
// 重建任务 ctx 产生数据竞争。
func (m *rootModel) probeHosts() {
	if m.remote == nil || m.probeBusy {
		return
	}
	m.probeBusy = true
	for i := range m.hostRows {
		m.hostRows[i].status = hostStatusProbing
	}
	m.pushHosts()
	aliases := make([]string, 0, len(m.hostRows))
	for _, r := range m.hostRows {
		aliases = append(aliases, r.name)
	}
	go func() {
		ctx := m.probeCtx
		if ctx == nil {
			ctx = context.Background()
		}
		status := m.remote.Probe(ctx, aliases, 0)
		if m.rt != nil {
			m.rt.Send(hostsProbeMsg{status: status})
		}
	}()
}

// applyProbe 应用连通性探测结果。
func (m *rootModel) applyProbe(status map[string]string) {
	m.probeBusy = false
	m.probeDone = true
	for i := range m.hostRows {
		if s, ok := status[m.hostRows[i].name]; ok {
			m.hostRows[i].status = s
		}
	}
	m.pushHosts()
	online := m.onlineCount()
	m.toast.Update(display.ToastMsg{Text: fmt.Sprintf(toastProbeDone, online, len(m.hostRows)), Semantic: theme.Info})
}

// ── 主机详情弹窗 ─────────────────────────────────────────────────────

// showHostDetail 主机表格行选中（Enter）→ 详情弹窗。
func (m *rootModel) showHostDetail(rowIndex int) {
	if rowIndex < 0 || rowIndex >= len(m.hostRows) {
		return
	}
	r := m.hostRows[rowIndex]
	m.hostDetail = &hostDetailState{
		title: "🌐 主机详情 " + r.name,
		lines: []string{
			"地址: " + r.address,
			"用户: " + r.user,
			"认证: " + r.auth,
			"状态: " + r.status,
		},
	}
}

// hostDetailView 详情弹窗渲染（居中覆盖层）。
func (m *rootModel) hostDetailView() string {
	d := m.hostDetail
	if d == nil {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(m.th.Style(theme.Primary).Bold(true).Render(" "+d.title+" ") + "\n\n")
	for _, line := range d.lines {
		sb.WriteString(m.th.Style(theme.Muted).Render("  "+line) + "\n")
	}
	sb.WriteString("\n" + m.th.Style(theme.Muted).Render("  [Enter/Esc] 关闭"))
	return box(sb.String(), m.w-8)
}
