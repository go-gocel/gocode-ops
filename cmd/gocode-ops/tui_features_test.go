package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/go-gocel/gocel-core/types"
	"github.com/go-gocel/gocel/tools/shell"
	"github.com/go-gocel/termagent/pkg/theme"

	"github.com/go-gocel/gocode-ops/internal/common/remote"
	"github.com/go-gocel/gocode-ops/internal/common/session"
)

// displayWidth 显示宽度（ANSI 感知；测试断言布局用）。
func displayWidth(s string) int { return ansi.StringWidth(s) }

func isValidUTF8(s string) bool { return strings.ToValidUTF8(s, "\uFFFD") == s }

// ── 文本工具（UTF-8/宽度安全） ───────────────────────────────────────

func TestTruncate_CJKSafe(t *testing.T) {
	// 中文按 2 列宽计算且不切坏多字节字符（历史缺陷：按字节切片乱码）。
	got := truncate("巡检系统健康", 5)
	if !strings.ContainsRune(got, '…') {
		t.Fatalf("CJK truncate should add ellipsis: %q", got)
	}
	if !isValidUTF8(got) {
		t.Fatalf("truncate produced invalid UTF-8: %q", got)
	}
	if w := displayWidth(got); w > 6 {
		t.Fatalf("truncate width = %d, want <= 6 (5 cols + ellipsis)", w)
	}
	// 短文本不截断
	if got := truncate("短", 10); got != "短" {
		t.Fatalf("short CJK should pass through: %q", got)
	}
	// ANSI 安全的宽度感知（复用 termagent util）
	if got := truncate("abc", 2); got != "a…" {
		t.Fatalf("ascii truncate = %q, want a…", got)
	}
}

// ── 进度条/传输状态 ──────────────────────────────────────────────────

func TestProgressBar(t *testing.T) {
	if got := progressBar(0.5, 4); got != "██░░" {
		t.Fatalf("progressBar(0.5, 4) = %q, want ██░░", got)
	}
	if got := progressBar(0.0, 4); got != "░░░░" {
		t.Fatalf("progressBar(0, 4) = %q", got)
	}
	if got := progressBar(1.0, 4); got != "████" {
		t.Fatalf("progressBar(1, 4) = %q", got)
	}
	if got := progressBar(1.5, 4); got != "████" {
		t.Fatalf("progressBar should clamp over-range: %q", got)
	}
	if got := progressBar(-0.5, 4); got != "░░░░" {
		t.Fatalf("progressBar should clamp under-range: %q", got)
	}
}

func TestTransferStatus(t *testing.T) {
	got := transferStatus(0.5)
	if !strings.Contains(got, "50%") || !strings.Contains(got, "█") {
		t.Fatalf("transferStatus(0.5) = %q, want bar + 50%%", got)
	}
	// 列宽 8 内恰好放下（"████ 100%"）
	if w := displayWidth(transferStatus(1.0)); w > 8 {
		t.Fatalf("transferStatus width = %d, want <= 8", w)
	}
}

func TestHumanDuration(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{500 * time.Millisecond, "<1s"},
		{5 * time.Second, "5s"},
		{65 * time.Second, "1m05s"},
		{2*time.Hour + 3*time.Minute, "2h03m"},
	}
	for _, c := range cases {
		if got := humanDuration(c.d); got != c.want {
			t.Errorf("humanDuration(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

// ── 底座日志节流 ─────────────────────────────────────────────────────

func TestBaseLog_Throttled(t *testing.T) {
	m := newTestRoot()
	for i := 0; i < baseLogMax+10; i++ {
		m.Update(baseLogMsg{line: "l0 log " + strconv.Itoa(i)})
	}
	v := m.chat.Value()
	if strings.Count(v, "🔧 l0 log") != baseLogMax {
		t.Fatalf("base logs shown = %d, want %d", strings.Count(v, "🔧 l0 log"), baseLogMax)
	}
	if !strings.Contains(v, "其余底座日志已省略") {
		t.Fatalf("throttle should fold with hint: %q", v)
	}
	// 新一轮任务重置计数，可再次展示（maybeStartNext 重置）
	m.baseLogN = 0
	m.baseLogFold = false
	m.Update(baseLogMsg{line: "fresh"})
	if !strings.Contains(m.chat.Value(), "🔧 fresh") {
		t.Fatalf("new task should reset base log budget: %q", m.chat.Value())
	}
}

// ── 头部：排队/在线统计 ──────────────────────────────────────────────

func TestHeaderView_QueueAndOnline(t *testing.T) {
	m := newTestRoot()
	m.app = &taskRunner{sess: session.NewSession(nil, nil, false), totalUsage: &types.TokenUsage{}}
	m.remoteOK = true
	m.hostRows = []hostRow{{name: "web-01", status: "在线"}, {name: "db-01", status: "离线"}}
	m.pending = []string{"任务一", "任务二"}
	m.probeDone = true
	m.pushHosts()

	header := m.headerView()
	for _, want := range []string{"远程 2 台", "在线 1/2", "排队 2"} {
		if !strings.Contains(header, want) {
			t.Errorf("headerView 缺少 %q:\n%s", want, header)
		}
	}
	// 未探测时无在线统计（保持既有 "远程 N 台" 契约）
	m.probeDone = false
	if strings.Contains(m.headerView(), "在线 1/2") {
		t.Fatal("未探测不应显示在线统计")
	}
}

// ── ask 弹窗：长问题折叠 + y/n 提示 ─────────────────────────────────

func TestAskView_LongQuestionFolded(t *testing.T) {
	m := newTestRoot()
	m.w = 100
	long := strings.Repeat("line\n", askMaxLines+5)
	resp := make(chan string, 1)
	m.Update(askMsg{prompt: long, options: []string{"y", "n"}, resp: resp})
	view := m.askView()
	if !strings.Contains(view, "问题过长") {
		t.Fatalf("long question should fold with hint:\n%s", view)
	}
	// y/n 选项显示直接按键提示
	if !strings.Contains(view, "[y] 是") {
		t.Fatalf("y/n options should show direct-key hint:\n%s", view)
	}
	// 非 y/n 选项无直接按键提示
	resp2 := make(chan string, 1)
	m2 := newTestRoot()
	m2.w = 100
	m2.Update(askMsg{prompt: "选择方案", options: []string{"重启", "取消"}, resp: resp2})
	if strings.Contains(m2.askView(), "[y] 是") {
		t.Fatal("non-y/n options must not show direct-key hint")
	}
}

// ── 主机页：排序/详情 ────────────────────────────────────────────────

func TestHostSortCycle(t *testing.T) {
	m := newTestRoot()
	m.hostRows = []hostRow{
		{name: "web-02", address: "10.0.0.2", user: "root", auth: "key", status: "未探测"},
		{name: "web-01", address: "10.0.0.1", user: "root", auth: "key", status: "未探测"},
	}
	m.pushHosts()

	m.cycleHostSort() // → 按名称
	if m.hostSortKey != "name" {
		t.Fatalf("sort key = %q, want name", m.hostSortKey)
	}
	rows := m.hosts.Rows()
	if rows[0]["name"] != "web-01" {
		t.Fatalf("sorted by name: %+v", rows)
	}
	m.cycleHostSort() // → 按地址
	if m.hostSortKey != "address" {
		t.Fatalf("sort key = %q, want address", m.hostSortKey)
	}
	rows = m.hosts.Rows()
	if rows[0]["address"] != "10.0.0.1" {
		t.Fatalf("sorted by address: %+v", rows)
	}
	m.cycleHostSort() // → 取消
	if m.hostSortKey != "" {
		t.Fatalf("sort key = %q, want off", m.hostSortKey)
	}
}

func TestHostDetail_OpenAndClose(t *testing.T) {
	m := newTestRoot()
	m.hostRows = []hostRow{{name: "web-01", address: "10.0.0.11", user: "root", auth: "key", status: "在线"}}
	m.pushHosts()
	// 主机页聚焦后 Enter 打开详情（表格 onSelect）
	m.execCommand(cmdHosts)
	m.Update(Key("enter"))
	if m.hostDetail == nil {
		t.Fatal("enter on hosts tab should open detail")
	}
	view := m.hostDetailView()
	for _, want := range []string{"web-01", "10.0.0.11", "root", "在线"} {
		if !strings.Contains(view, want) {
			t.Errorf("host detail 缺少 %q:\n%s", want, view)
		}
	}
	m.Update(Key("esc"))
	if m.hostDetail != nil {
		t.Fatal("esc should close host detail")
	}
}

// ── 标签页快捷切换 ───────────────────────────────────────────────────

func TestTabJump_AltKeys(t *testing.T) {
	m := newTestRoot()
	// 输入框聚焦（默认）时 Alt+2 直接切到工具页，焦点仍留在输入框
	m.Update(Key("alt+2"))
	if m.tabs.Active() != toolsTabIndex {
		t.Fatalf("alt+2 should jump to tools tab, active = %d", m.tabs.Active())
	}
	if m.fm.Focused() != "input" {
		t.Fatalf("tab jump must keep input focus, focused = %q", m.fm.Focused())
	}
	m.Update(Key("alt+3"))
	if m.tabs.Active() != hostsTabIndex {
		t.Fatalf("alt+3 should jump to hosts tab")
	}
	m.Update(Key("alt+1"))
	if m.tabs.Active() != chatTabIndex {
		t.Fatalf("alt+1 should jump to chat tab")
	}
	// 未知组合忽略
	m.Update(Key("alt+9"))
	if m.tabs.Active() != chatTabIndex {
		t.Fatal("alt+9 should be ignored")
	}
}

// ── 复制最近工具结果 ─────────────────────────────────────────────────

func TestCopyLastToolResult(t *testing.T) {
	orig := clipboardWriteAll
	defer func() { clipboardWriteAll = orig }()
	var copied string
	clipboardWriteAll = func(s string) error { copied = s; return nil }

	m := newTestRoot()
	m.Update(agentEventMsg{ev: types.ToolResultEvent("terminal", "df -h 输出内容", "c1")})
	// 无工具调用记录：提示无内容
	m.copyLastToolResult()
	if copied != "" {
		t.Fatalf("no rows should not copy, got %q", copied)
	}
	// 有完成行：复制其结果
	m.Update(agentEventMsg{ev: types.ToolCallEvent("terminal", `{"command":"df -h"}`, "c1")})
	m.Update(agentEventMsg{ev: types.ToolResultEvent("terminal", "df -h 输出内容", "c1")})
	m.copyLastToolResult()
	if copied != "df -h 输出内容" {
		t.Fatalf("copied = %q, want tool result", copied)
	}
}

// ── 会话导出 ─────────────────────────────────────────────────────────

func TestExportTranscript(t *testing.T) {
	m := newTestRoot()
	dir := t.TempDir()
	m.meta.workDir = dir
	m.app = &taskRunner{sess: session.NewSession(nil, nil, false), totalUsage: &types.TokenUsage{TotalTokens: 42}}
	m.taskCount = 2
	m.chat.SetValue("### 👤 巡检磁盘\n\n磁盘正常。")
	m.toolRows = []toolRow{{name: "terminal", args: `{"command":"df -h"}`, target: "本机", status: "完成", dur: "3s"}}

	path, err := m.exportTranscript()
	if err != nil {
		t.Fatalf("exportTranscript: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, want := range []string{"会话记录", "工具调用摘要", "terminal", "巡检磁盘", "磁盘正常。", "tokens: 输入 0 + 输出 0 = 42"} {
		if !strings.Contains(content, want) {
			t.Errorf("导出内容缺少 %q:\n%s", want, content)
		}
	}
	// 导出目录位于 .gocode/sessions 下
	if !strings.Contains(path, filepath.Join(".gocode", "sessions")) {
		t.Fatalf("导出路径不在 sessions 目录: %s", path)
	}
}

// ── 帮助面板 ─────────────────────────────────────────────────────────

func TestHelpPane_ContentAndToggle(t *testing.T) {
	m := newTestRoot()
	// 帮助内容进入独立面板（键位/命令/示例齐全）
	for _, want := range []string{"gocode-ops 帮助", "Alt+1/2/3", "/export", "远程运维示例"} {
		if !strings.Contains(m.helpPane.Value(), want) {
			t.Errorf("help pane 缺少 %q", want)
		}
	}
	// 对话区不被帮助内容污染
	if strings.Contains(m.chat.Value(), "gocode-ops 帮助") {
		t.Fatal("help content must not leak into chat")
	}
	// 键盘切换：tabs 聚焦时 ? 开/关；帮助打开时滚动键不崩溃
	m.execCommand(cmdHelp)
	if !m.help {
		t.Fatal("/help should open help pane")
	}
	m.Update(Key("pgdown"))
	m.Update(Key("up"))
	m.Update(Key("?"))
	if m.help {
		t.Fatal("? should close help pane")
	}
}

// ── 轮间分隔线（耗时） ───────────────────────────────────────────────

func TestFinishSeparator(t *testing.T) {
	if got := finishSeparator(time.Time{}); got != "\n---" {
		t.Fatalf("zero start should give plain separator: %q", got)
	}
	got := finishSeparator(time.Now().Add(-2 * time.Minute))
	if !strings.Contains(got, "2m") {
		t.Fatalf("separator should carry duration: %q", got)
	}
}

// ── 实时输出合并 ─────────────────────────────────────────────────────

func TestLiveBuffer_MergesChunks(t *testing.T) {
	m := newTestRoot()
	m.Update(agentEventMsg{ev: types.ToolCallEvent("terminal", `{"command":"tail -f x"}`, "c1")})
	m.Update(localProgressMsg{p: shell.Progress{Text: "chunk1"}})
	m.Update(localProgressMsg{p: shell.Progress{Text: "chunk2"}})
	m.Update(localProgressMsg{p: shell.Progress{Text: "chunk3"}})
	if len(m.liveBuf) != 3 {
		t.Fatalf("liveBuf = %d, want 3 buffered", len(m.liveBuf))
	}
	m.Update(liveFlushMsg{})
	if len(m.liveBuf) != 0 {
		t.Fatal("flush should drain buffer")
	}
	for _, c := range []string{"chunk1", "chunk2", "chunk3"} {
		if !strings.Contains(m.chat.Value(), c) {
			t.Fatalf("flushed chunk %q missing: %q", c, m.chat.Value())
		}
	}
	// 行已收尾后迟到的缓冲块不追认（不崩溃）
	m.Update(localProgressMsg{p: shell.Progress{Text: "late"}})
	m.Update(agentEventMsg{ev: types.ToolResultEvent("terminal", "done", "c1")})
	m.Update(liveFlushMsg{})
}

// ── 传输进度节流 ─────────────────────────────────────────────────────

func TestTransferThrottle(t *testing.T) {
	m := newTestRoot()
	m.Update(agentEventMsg{ev: types.ToolCallEvent("remote_upload", `{"hosts":["web-01"]}`, "c1")})
	// 0.5%：首次强制展示
	m.Update(remoteProgressMsg{p: remote.RemoteProgress{Host: "web-01", Phase: "upload", Done: 500, Total: 100000}})
	rows := m.tools.Rows()
	if len(rows) != 1 || !strings.Contains(rows[0]["status"], "%") {
		t.Fatalf("first progress should show: %+v", rows)
	}
	// +0.3%：变化 <1%，表格不重建（status 引用不变即未更新）
	m.Update(remoteProgressMsg{p: remote.RemoteProgress{Host: "web-01", Phase: "upload", Done: 800, Total: 100000}})
	rows2 := m.tools.Rows()
	if rows2[0]["status"] != rows[0]["status"] {
		t.Fatalf("sub-1%% progress must not refresh table: %q -> %q", rows[0]["status"], rows2[0]["status"])
	}
	// +1.5%：达到阈值，刷新
	m.Update(remoteProgressMsg{p: remote.RemoteProgress{Host: "web-01", Phase: "upload", Done: 2300, Total: 100000}})
	rows3 := m.tools.Rows()
	if rows3[0]["status"] == rows2[0]["status"] {
		t.Fatal(">=1% progress should refresh table")
	}
}

// ── 状态栏耗时刷新 ───────────────────────────────────────────────────

func TestElapsedTick_RunningStatus(t *testing.T) {
	m := newTestRoot()
	m.running = true
	m.currentTask = "巡检系统健康"
	m.taskStart = time.Now().Add(-90 * time.Second)
	m.status.Set(statusStateRunning, runningStatusText(m.currentTask, humanDuration(0)), theme.Warning)
	// 直接调用刷新路径（tick 由 Update 尾部的 startTickers 驱动，单测手动触发）
	m.onElapsedTick(elapsedTickMsg(time.Now()))
	if got := m.status.Text(); !strings.Contains(got, "1m30s") || !strings.Contains(got, "巡检系统健康") {
		t.Fatalf("elapsed status = %q, want task + 1m30s", got)
	}
}
