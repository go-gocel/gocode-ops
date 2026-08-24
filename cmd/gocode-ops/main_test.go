package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/go-gocel/gocel-core/types"
	"github.com/go-gocel/gocel/tools/shell"

	"github.com/go-gocel/termagent/pkg/components/display"
	"github.com/go-gocel/termagent/pkg/theme"
	"github.com/go-gocel/termagent/testutil"

	"github.com/go-gocel/gocode-ops/internal/common/model"
	"github.com/go-gocel/gocode-ops/internal/common/remote"
	"github.com/go-gocel/gocode-ops/internal/common/session"
	"github.com/go-gocel/gocode-ops/internal/common/tools"
)

// newTestRoot 构造带默认主题/键位的根模型（无运行时、无远程执行器，
// 供单元测试）。
func newTestRoot() *rootModel {
	return newRoot(theme.Agent(theme.ProfileAuto), buildKeymap(), tuiMeta{host: "test", model: "test-model", risky: "ask"}, nil)
}

// ── 内置命令解析 ──────────────────────────────────────────────────────

func TestParseSlash(t *testing.T) {
	cases := []struct {
		in   string
		want slashCmd
		ok   bool
	}{
		{"/help", cmdHelp, true},
		{"/?", cmdHelp, true},
		{"/new", cmdNew, true},
		{"/hosts", cmdHosts, true},
		{"/tokens", cmdTokens, true},
		{"/export", cmdExport, true},
		{"/exit", cmdExit, true},
		{"/quit", cmdExit, true},
		{"/unknown", cmdUnknown, true},
		{"  /help  ", cmdHelp, true},
		{"巡检磁盘", cmdUnknown, false},
		{"", cmdUnknown, false},
	}
	for _, c := range cases {
		got, ok := parseSlash(c.in)
		if ok != c.ok || got != c.want {
			t.Fatalf("parseSlash(%q) = (%v, %v), want (%v, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestCommand_NewResetsSession(t *testing.T) {
	m := newTestRoot()
	m.app = &taskRunner{sess: session.NewSession(nil, nil, false), totalUsage: &types.TokenUsage{TotalTokens: 1}}
	m.chat.SetValue("旧内容")
	m.toolRows = []toolRow{{name: "terminal", status: "完成"}}

	m.execCommand(cmdNew)

	if m.chat.Value() != "" {
		t.Fatalf("chat = %q, want empty after /new", m.chat.Value())
	}
	if len(m.toolRows) != 0 {
		t.Fatalf("toolRows = %d, want 0 after /new", len(m.toolRows))
	}
	if got := m.app.usageString(); got != "tokens: 输入 0 + 输出 0 = 0" {
		t.Fatalf("usage after /new = %q, want reset", got)
	}
}

// ── 文本裁剪 ─────────────────────────────────────────────────────────

func TestClipResult(t *testing.T) {
	if got := clipResult("", 10, 200); got != "" {
		t.Fatalf("clipResult(\"\") = %q, want empty", got)
	}
	if got := clipResult("a\nb\n", 10, 200); got != "a\nb" {
		t.Fatalf("clipResult with trailing newline = %q, want no trailing blank line", got)
	}
	if got := clipResult(strings.Repeat("x", 250), 10, 200); got != strings.Repeat("x", 200)+"…" {
		t.Fatalf("clipResult wide line = %q, want 200 chars + ellipsis", got)
	}
	var lines []string
	for i := 0; i < 12; i++ {
		lines = append(lines, fmt.Sprintf("line%d", i))
	}
	got := clipResult(strings.Join(lines, "\n"), 10, 200)
	if !strings.Contains(got, "…（省略 2 行）") {
		t.Fatalf("clipResult = %q, want omitted-line hint", got)
	}
	if strings.Contains(got, "line10") {
		t.Fatalf("clipResult contains omitted tail: %q", got)
	}
}

func TestBlockquote(t *testing.T) {
	if got := blockquote("a\nb"); got != "> a\n> b" {
		t.Fatalf("blockquote = %q, want per-line prefix", got)
	}
	if got := blockquote("a\n"); got != "> a" {
		t.Fatalf("blockquote with trailing newline = %q", got)
	}
	if got := blockquote(""); got != "" {
		t.Fatalf("blockquote(\"\") = %q, want empty", got)
	}
}

// ── 操作员提问覆盖层 ─────────────────────────────────────────────────

func TestAskOverlay_OptionsSelect(t *testing.T) {
	m := newTestRoot()
	resp := make(chan string, 1)
	m.Update(askMsg{prompt: "选择处置方案", options: []string{"重启", "仅重载配置", "取消"}, resp: resp})
	if m.ask == nil {
		t.Fatal("ask overlay should open")
	}
	m.Update(testutil.Key("down"))
	m.Update(testutil.Key("down"))
	m.Update(testutil.Key("enter"))
	if got := <-resp; got != "取消" {
		t.Fatalf("answer = %q, want 取消", got)
	}
	if m.ask != nil {
		t.Fatal("ask overlay should close after answer")
	}
}

func TestAskOverlay_EscCancels(t *testing.T) {
	m := newTestRoot()
	resp := make(chan string, 1)
	m.Update(askMsg{prompt: "允许执行吗?", options: []string{"y", "n"}, resp: resp})
	m.Update(testutil.Key("esc"))
	if got := <-resp; got != "" {
		t.Fatalf("answer = %q, want empty on cancel", got)
	}
	if m.ask != nil {
		t.Fatal("ask overlay should close on cancel")
	}
}

func TestAskOverlay_YNDirectKeys(t *testing.T) {
	for _, key := range []string{"y", "n"} {
		m := newTestRoot()
		resp := make(chan string, 1)
		m.Update(askMsg{prompt: "允许执行吗?", options: []string{"y", "n"}, resp: resp})
		m.Update(testutil.Key(key))
		if got := <-resp; got != key {
			t.Fatalf("answer = %q, want %q", got, key)
		}
	}
}

// TestAskOverlay_YNDirectKeysWithThirdOption 守卫确认带第三个选项
// （a=本会话全部放行）时，y/n 直接按键仍可用（选项列表按 y/n 开头判定）。
func TestAskOverlay_YNDirectKeysWithThirdOption(t *testing.T) {
	for _, key := range []string{"y", "n"} {
		m := newTestRoot()
		resp := make(chan string, 1)
		m.Update(askMsg{prompt: "允许执行吗? [y/N/a=本会话全部放行]", options: []string{"y", "n", "a"}, resp: resp})
		m.Update(testutil.Key(key))
		if got := <-resp; got != key {
			t.Fatalf("answer = %q, want %q", got, key)
		}
	}
	// 第三个选项经导航选中后按原值返回（守卫按精确匹配识别 a）。
	m := newTestRoot()
	resp := make(chan string, 1)
	m.Update(askMsg{prompt: "允许执行吗? [y/N/a=本会话全部放行]", options: []string{"y", "n", "a"}, resp: resp})
	m.Update(testutil.Key("down"))
	m.Update(testutil.Key("down"))
	m.Update(testutil.Key("enter"))
	if got := <-resp; got != "a" {
		t.Fatalf("answer = %q, want a", got)
	}
}

func TestAskOverlay_OtherCustomInput(t *testing.T) {
	// 选项不满足时选"其他"：进入自定义输入模式，输入补充说明后提交——
	// 回答以用户原话返回给模型（模型不应再追问）。
	m := newTestRoot()
	resp := make(chan string, 1)
	m.Update(askMsg{prompt: "选择处置方案", options: []string{"重启", "仅重载配置"}, resp: resp})
	// 导航到末尾的"其他"入口（options 2 个 + 其他 = 3 项，down×2）
	m.Update(testutil.Key("down"))
	m.Update(testutil.Key("down"))
	m.Update(testutil.Key("enter"))
	if m.ask == nil || !m.ask.custom {
		t.Fatal("选中其他应进入自定义输入模式")
	}
	// 输入补充说明（可打印字符 + 退格修正）
	for _, r := range "改成重启并保留数据" {
		m.Update(testutil.Key(string(r)))
	}
	m.Update(testutil.Key("backspace")) // 删掉最后一个字
	m.Update(testutil.Key("据"))
	m.Update(testutil.Key("enter"))
	if got := <-resp; got != "改成重启并保留数据" {
		t.Fatalf("answer = %q, want 用户原话", got)
	}
	if m.ask != nil {
		t.Fatal("ask overlay should close after custom answer")
	}
}

func TestAskOverlay_CustomEscReturnsToOptions(t *testing.T) {
	// 自定义输入模式 Esc 返回选项列表（不取消提问），再 Esc 才取消。
	m := newTestRoot()
	resp := make(chan string, 1)
	m.Update(askMsg{prompt: "选择处置方案", options: []string{"重启", "取消"}, resp: resp})
	m.Update(testutil.Key("down"))
	m.Update(testutil.Key("down")) // 到"其他"
	m.Update(testutil.Key("enter"))
	m.Update(testutil.Key("输入中"))
	m.Update(testutil.Key("esc")) // 返回选项列表
	if m.ask == nil || m.ask.custom {
		t.Fatal("esc 应返回选项列表")
	}
	// 选项列表仍可正常选择
	m.Update(testutil.Key("up"))
	m.Update(testutil.Key("enter"))
	if got := <-resp; got != "取消" {
		t.Fatalf("answer = %q, want 取消", got)
	}
}

func TestAskOverlay_EmptyOptionsDefaultYN(t *testing.T) {
	m := newTestRoot()
	resp := make(chan string, 1)
	m.Update(askMsg{prompt: "允许执行吗?", resp: resp})
	m.Update(testutil.Key("y"))
	if got := <-resp; got != "y" {
		t.Fatalf("answer = %q, want y (default y/n)", got)
	}
}

// ── 事件路由 ─────────────────────────────────────────────────────────

func TestEventRouting_ReasoningBufferedThenFlushed(t *testing.T) {
	m := newTestRoot()
	m.Update(agentEventMsg{ev: types.ReasoningEvent("先检查磁盘")})
	m.Update(agentEventMsg{ev: types.ReasoningEvent("，再看挂载点")})
	if strings.Contains(m.chat.Value(), "> 💭") {
		t.Fatalf("reasoning flushed before non-reasoning event: %q", m.chat.Value())
	}
	m.Update(agentEventMsg{ev: types.TokenEvent("磁盘使用率 92%。")})
	if !strings.Contains(m.chat.Value(), "> 💭 先检查磁盘，再看挂载点") {
		t.Fatalf("reasoning not flushed as one paragraph: %q", m.chat.Value())
	}
	if !strings.Contains(m.chat.Value(), "磁盘使用率 92%。") {
		t.Fatalf("token not appended: %q", m.chat.Value())
	}
}

func TestEventRouting_ToolCallAndResult(t *testing.T) {
	m := newTestRoot()
	m.Update(agentEventMsg{ev: types.ToolCallEvent("terminal", `{"command":"df -h"}`, "call-1")})
	if !strings.Contains(m.chat.Value(), "⚡ terminal\n") {
		t.Fatalf("tool call not in chat: %q", m.chat.Value())
	}
	rows := m.tools.Rows()
	if len(rows) != 1 || rows[0]["tool"] != "terminal" || rows[0]["status"] != "运行中" {
		t.Fatalf("tool rows after call = %+v, want one running row", rows)
	}

	m.Update(agentEventMsg{ev: types.ToolResultEvent("terminal", "/dev/sda1 92% /\n", "call-1")})
	if !strings.Contains(m.chat.Value(), "✔ terminal: /dev/sda1 92% /") {
		t.Fatalf("tool result not in chat: %q", m.chat.Value())
	}
	rows = m.tools.Rows()
	if len(rows) != 1 || rows[0]["status"] != "完成" {
		t.Fatalf("tool rows after result = %+v, want finished", rows)
	}
}

// ── 工具目标解析与显示 ────────────────────────────────────────────────

func TestParseToolTarget(t *testing.T) {
	cases := []struct {
		name string
		args string
		want string
	}{
		{"terminal", `{"command":"uptime"}`, "本机"},
		{"read", `{"path":"/etc/hosts"}`, "本机"},
		{"remote_terminal", `{"host":"web-01","command":"uptime"}`, "web-01"},
		{"remote_batch", `{"hosts":["web-01","db-01"],"command":"uptime"}`, "web-01,db-01"},
		{"remote_upload", `{"hosts":["web-01"],"local_path":"a.tar","remote_path":"/opt/a.tar"}`, "web-01"},
		{"remote_list", `{}`, "远程"},
	}
	for _, c := range cases {
		if got := parseToolTarget(c.name, c.args); got != c.want {
			t.Errorf("parseToolTarget(%s, %s) = %q, want %q", c.name, c.args, got, c.want)
		}
	}
}

func TestToolDisplayName_RemotePrefix(t *testing.T) {
	if got := toolDisplayName("remote_terminal"); got != "🌐 remote_terminal" {
		t.Errorf("remote tool should carry globe prefix, got %q", got)
	}
	if got := toolDisplayName("terminal"); got != "terminal" {
		t.Errorf("local tool must keep plain name, got %q", got)
	}
}

// ── 实时输出路由 ──────────────────────────────────────────────────────

func TestLocalProgress_AppendsToChat(t *testing.T) {
	m := newTestRoot()
	m.Update(agentEventMsg{ev: types.ToolCallEvent("terminal", `{"command":"ping -c 2 x"}`, "c1")})

	// 实时输出进合并缓冲，tick 到点（测试手动驱动 liveFlushMsg）后入对话区。
	m.Update(localProgressMsg{p: shell.Progress{Phase: "stdout", Text: "64 bytes from 10.0.0.1"}})
	if strings.Contains(m.chat.Value(), "64 bytes from 10.0.0.1") {
		t.Fatal("buffered live output should not appear before flush")
	}
	m.Update(liveFlushMsg{})

	if !strings.Contains(m.chat.Value(), "▸ 64 bytes from 10.0.0.1") {
		t.Fatalf("local live output not in chat: %q", m.chat.Value())
	}
}

func TestRemoteProgress_OutputAndTransfer(t *testing.T) {
	m := newTestRoot()
	m.Update(agentEventMsg{ev: types.ToolCallEvent("remote_batch", `{"hosts":["web-01"],"command":"tail -f /var/log/x"}`, "c1")})

	// 命令输出块 → 对话区带主机标记（合并缓冲，flush 后可见）
	m.Update(remoteProgressMsg{p: remote.RemoteProgress{Host: "web-01", Phase: "output", Text: "line1\nline2"}})
	m.Update(liveFlushMsg{})
	if !strings.Contains(m.chat.Value(), "📡 [web-01] line1") {
		t.Fatalf("remote live output not in chat: %q", m.chat.Value())
	}

	// 上传进度 → 表格状态列实时百分比（短进度条 + 百分比）
	m.Update(agentEventMsg{ev: types.ToolCallEvent("remote_upload", `{"hosts":["web-01"],"local_path":"a.tar","remote_path":"/opt/a.tar"}`, "c2")})
	m.Update(remoteProgressMsg{p: remote.RemoteProgress{Host: "web-01", Phase: "upload", Path: "/opt/a.tar", Done: 512, Total: 1024}})
	rows := m.tools.Rows()
	if len(rows) < 2 || !strings.Contains(rows[1]["status"], "50%") {
		t.Fatalf("upload progress should show 50%% in tool table: %+v", rows)
	}

	// 工具结果 → 状态恢复完成
	m.Update(agentEventMsg{ev: types.ToolResultEvent("remote_upload", "上传完成", "c2")})
	rows = m.tools.Rows()
	if rows[1]["status"] != "完成" {
		t.Fatalf("upload row should finish: %+v", rows)
	}
}

func TestLiveOutput_TotalBudget(t *testing.T) {
	m := newTestRoot()
	m.Update(agentEventMsg{ev: types.ToolCallEvent("terminal", `{"command":"dd"}`, "c1")})
	big := strings.Repeat("x", liveMaxChar+100)
	m.Update(localProgressMsg{p: shell.Progress{Text: big}})
	m.Update(liveFlushMsg{})
	if !strings.Contains(m.chat.Value(), "输出过长") {
		t.Fatalf("live output over budget should hint truncation: %q", m.chat.Value())
	}
}

// ── 远程主机页 ────────────────────────────────────────────────────────

func TestHostsTab_LoadAndProbe(t *testing.T) {
	// 无清单：加载失败但不崩溃，界面提示
	m := newTestRoot()
	if m.remoteOK {
		t.Fatal("empty inventory should not be marked ok")
	}

	// 有清单：加载展示 + 探测结果应用
	m2 := newTestRoot()
	dir := t.TempDir()
	invPath := dir + "/hosts.yaml"
	if err := os.WriteFile(invPath, []byte("hosts:\n  - name: web-01\n    address: 10.0.0.11\n    user: root\n    key_file: ~/.ssh/id_ed25519\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m2.meta.invPath = invPath
	m2.loadHosts()
	if !m2.remoteOK || len(m2.hostRows) != 1 {
		t.Fatalf("hosts should load: ok=%v rows=%d", m2.remoteOK, len(m2.hostRows))
	}
	m2.applyProbe(map[string]string{"web-01": "在线"})
	if m2.hostRows[0].status != "在线" {
		t.Fatalf("probe status not applied: %+v", m2.hostRows[0])
	}
}

// ── 布局渲染 ─────────────────────────────────────────────────────────

func TestHeaderView_IntegratesAllInfo(t *testing.T) {
	m := newTestRoot()
	m.app = &taskRunner{sess: session.NewSession(nil, nil, false), totalUsage: &types.TokenUsage{TotalTokens: 42}}
	m.remoteOK = true
	m.hostRows = []hostRow{{name: "web-01"}}

	header := m.headerView()
	// 顶部信息条整合：状态、主机、模型、高危策略、远程主机数、token 用量
	for _, want := range []string{
		"gocode-ops", "READY", "主机 test", "高危 ask", "远程 1 台", "tokens: 输入 0 + 输出 0 = 42",
	} {
		if !strings.Contains(header, want) {
			t.Errorf("headerView 缺少 %q:\n%s", want, header)
		}
	}
}

func TestHeaderView_NarrowScreenTruncates(t *testing.T) {
	m := newTestRoot()
	m.app = &taskRunner{sess: session.NewSession(nil, nil, false), totalUsage: &types.TokenUsage{TotalTokens: 1}}
	m.w = 40
	header := m.headerView()
	for _, line := range splitLines(header) {
		if ansi.StringWidth(line) > 40 {
			t.Fatalf("headerView 行超出窗口宽度: %d > 40\n%s", ansi.StringWidth(line), header)
		}
	}
}

func TestView_HeightStaysWithinScreen(t *testing.T) {
	// 回归：toast 通知区域曾用全屏尺寸，把 View 撑出屏幕导致输入框被
	// 终端滚动挤出。View 总行数必须始终 ≤ 屏幕高度，输入框完整可见。
	m := newTestRoot()
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})

	if n := len(splitLines(m.View())); n > 30 {
		t.Fatalf("view without toast exceeds screen: %d lines", n)
	}

	m.toast.Update(display.ToastMsg{Text: "任务完成", Semantic: theme.Success})
	m.toast.Update(display.ToastMsg{Text: "✗ 错误信息", Semantic: theme.Error})
	view := m.View()
	lines := splitLines(view)
	if len(lines) > 30 {
		t.Fatalf("view with toast exceeds screen: %d lines", len(lines))
	}
	// 输入框完整可见：以 placeholder（"输入运维/实施任务"）定位输入框，
	// 内容行与下边框都在屏幕内（提示行在其下方，通知区在顶部）
	inputIdx := -1
	for i, l := range lines {
		if strings.Contains(l, "输入运维/实施任务") {
			inputIdx = i
		}
	}
	if inputIdx < 0 {
		t.Fatalf("input placeholder not visible:\n%s", view)
	}
	if inputIdx+1 >= len(lines) {
		t.Fatalf("input content line out of screen:\n%s", view)
	}
	// 通知区必须在输入框上方（回归：曾显示在输入框下方，遮挡操作区）
	toastIdx := -1
	for i, l := range lines {
		if strings.Contains(l, "任务完成") {
			toastIdx = i
			break
		}
	}
	if toastIdx < 0 {
		t.Fatalf("toast not visible:\n%s", view)
	}
	if toastIdx > inputIdx {
		t.Fatalf("toast 应在输入框上方: toast@%d input@%d\n%s", toastIdx, inputIdx, view)
	}
	// 输入框下边框（╰）必须可见：被截断说明输入框显示不完整
	bottomSeen := false
	for _, l := range lines {
		if strings.Contains(l, "╰") {
			bottomSeen = true
			break
		}
	}
	if !bottomSeen {
		t.Fatalf("input bottom border not visible:\n%s", view)
	}
}

// ── 一轮结束 ─────────────────────────────────────────────────────────

func TestFinishFlow_Success(t *testing.T) {
	m := newTestRoot()
	m.app = &taskRunner{sess: session.NewSession(nil, nil, false), totalUsage: &types.TokenUsage{TotalTokens: 42}}
	m.running = true

	m.Update(agentFinishMsg{err: nil})

	if m.running {
		t.Fatal("running should clear after finish")
	}
	if !strings.Contains(m.chat.Value(), "---") {
		t.Fatalf("chat missing separator after success: %q", m.chat.Value())
	}
	if got := m.status.Text(); got != "任务完成" {
		t.Fatalf("status = %q, want 任务完成 (tokens 在顶部元信息行展示)", got)
	}
	if m.toastLines() != 0 {
		t.Fatalf("success must not enqueue a toast, got %d", m.toastLines())
	}
	if !m.chat.Rich() {
		t.Fatal("chat should be rich after turn finishes")
	}
}

func TestFinishFlow_Error(t *testing.T) {
	m := newTestRoot()
	m.Update(agentFinishMsg{err: errors.New("guard: 拒绝")})
	if !strings.Contains(m.chat.Value(), "✗ guard: 拒绝") {
		t.Fatalf("chat missing error marker: %q", m.chat.Value())
	}
	if got := m.status.Text(); got != "本轮失败" {
		t.Fatalf("status = %q, want 本轮失败", got)
	}
	if !m.chat.Rich() {
		t.Fatal("chat should restore rich rendering after failed turn")
	}
}

func TestFinishFlow_Interrupt(t *testing.T) {
	m := newTestRoot()
	m.Update(agentFinishMsg{err: context.Canceled})
	if !strings.Contains(m.chat.Value(), "任务已中断") {
		t.Fatalf("chat missing interrupt marker: %q", m.chat.Value())
	}
	if got := m.status.Text(); got != "已中断" {
		t.Fatalf("status = %q, want 已中断", got)
	}
}

func TestFinishFlow_ErrorSweepsRunningRows(t *testing.T) {
	// 失败收尾：仍悬挂“运行中”的工具行标为“失败”，不再悬挂。
	m := newTestRoot()
	m.Update(agentEventMsg{ev: types.ToolCallEvent("terminal", `{"command":"ls"}`, "c1")})
	m.Update(agentFinishMsg{err: errors.New("boom")})
	if m.toolRows[0].status != "失败" {
		t.Fatalf("hanging row after failure = %q, want 失败", m.toolRows[0].status)
	}
}

func TestFinishFlow_InterruptMarksRowsInterrupted(t *testing.T) {
	// 操作员中断：悬挂的工具行标“已中断”（中断 ≠ 工具失败）。
	m := newTestRoot()
	m.Update(agentEventMsg{ev: types.ToolCallEvent("terminal", `{"command":"ls"}`, "c1")})
	m.Update(agentFinishMsg{err: context.Canceled})
	if m.toolRows[0].status != "已中断" {
		t.Fatalf("hanging row after interrupt = %q, want 已中断", m.toolRows[0].status)
	}
}

// ── 任务队列 ─────────────────────────────────────────────────────────

func TestOnSubmit_QueuesWhileRunning(t *testing.T) {
	m := newTestRoot()
	m.running = true

	m.onSubmit("任务一")
	m.onSubmit("任务二")

	if len(m.pending) != 2 {
		t.Fatalf("pending = %d, want 2 queued", len(m.pending))
	}
	if !strings.Contains(m.chat.Value(), "### 👤 任务一") {
		t.Fatalf("user message not in chat: %q", m.chat.Value())
	}
}

func TestOnSubmit_SlashCommand(t *testing.T) {
	m := newTestRoot()
	m.app = &taskRunner{sess: session.NewSession(nil, nil, false), totalUsage: &types.TokenUsage{}}
	m.chat.SetValue("旧内容")

	m.onSubmit("/new")

	if len(m.pending) != 0 {
		t.Fatalf("pending = %d, slash command should not queue", len(m.pending))
	}
	if m.chat.Value() != "" {
		t.Fatalf("chat = %q, want cleared by /new", m.chat.Value())
	}
}

// ── 退出流程 ─────────────────────────────────────────────────────────

func TestNewTaskCtx_RebuildsAfterCancel(t *testing.T) {
	// Ctrl+C 中断后 ctx 已取消：再次提交任务必须重建上下文，否则新任务
	// 立即以"任务已中断"结束。
	m := newTestRoot()
	m.ctx, m.cancel = context.WithCancel(context.Background())
	m.cancel() // 模拟中断
	if m.ctx.Err() == nil {
		t.Fatal("前置：ctx 应已取消")
	}

	m.newTaskCtx()

	if m.ctx.Err() != nil {
		t.Fatal("newTaskCtx 应重建未取消的上下文")
	}
	// 未取消时不重建（复用同一实例，不产生多余 cancel）
	keep := m.ctx
	m.newTaskCtx()
	if m.ctx != keep {
		t.Fatal("ctx 未取消时不应重建")
	}
	// 新 ctx 可正常取消（再次中断/退出仍有效）
	m.cancel()
	if m.ctx.Err() == nil {
		t.Fatal("新 ctx 应可被 cancel")
	}
}

func TestInterruptConfirm_WhileRunning(t *testing.T) {
	m := newTestRoot()
	m.running = true
	cancelled := false
	m.cancel = func() { cancelled = true }

	// Ctrl+C 是全局中断键：输入框聚焦时也生效（退出不依赖切焦点）
	m.Update(testutil.Key("ctrl+c"))
	if !m.modal.IsOpen() {
		t.Fatal("interrupt confirm modal should open while running")
	}
	m.Update(testutil.Key("y"))
	if m.modal.IsOpen() {
		t.Fatal("modal should close after confirming")
	}
	if !cancelled {
		t.Fatal("confirming interrupt should cancel the task")
	}
}

func TestQuit_InputFocusedCtrlCQuits(t *testing.T) {
	m := newTestRoot()
	// 空闲时输入框聚焦按 Ctrl+C 直接退出
	_, cmd := m.Update(testutil.Key("ctrl+c"))
	if cmd == nil {
		t.Fatal("ctrl+c should quit while idle, even with input focused")
	}
}

func TestQuit_NoQKey(t *testing.T) {
	// q 不再绑定退出：输入框聚焦时 q 是普通字符，非输入焦点时也不退出
	m := newTestRoot()
	m.running = true
	m.Update(testutil.Key("q"))
	if m.quitting || m.modal.IsOpen() {
		t.Fatal("q must never trigger quit")
	}
	if got := m.input.Value(); got != "q" {
		t.Fatalf("q should be typed into input, value = %q", got)
	}
	// 非输入焦点（标签页）时按 q 也不退出
	m2 := newTestRoot()
	m2.Update(testutil.Key("tab"))
	m2.Update(testutil.Key("q"))
	if m2.quitting || m2.modal.IsOpen() {
		t.Fatal("q must not quit even with tabs focused")
	}
}

func TestHelpOpen_CtrlCStillWorks(t *testing.T) {
	// 帮助页打开时 Ctrl+C 不再被吞：空闲退出、运行中弹中断确认。
	m := newTestRoot()
	m.help = true
	_, cmd := m.Update(testutil.Key("ctrl+c"))
	if cmd == nil {
		t.Fatal("帮助页空闲时 ctrl+c 应返回退出命令")
	}

	m2 := newTestRoot()
	m2.help = true
	m2.running = true
	m2.Update(testutil.Key("ctrl+c"))
	if !m2.modal.IsOpen() {
		t.Fatal("帮助页运行中 ctrl+c 应弹中断确认")
	}
}

func TestAppendLive_NoRowToastsOnce(t *testing.T) {
	// 实时输出无归属工具行：丢弃并提示一次（不静默吞、不刷屏）。
	m := newTestRoot()
	m.Update(localProgressMsg{p: shell.Progress{Text: "orphan chunk"}})
	m.Update(localProgressMsg{p: shell.Progress{Text: "orphan chunk 2"}})
	if n := m.toastLines(); n != 1 {
		t.Fatalf("无归属输出应只提示一次: %d", n)
	}
	// 新任务重置提示状态。
	m.running = false
	m.liveDropNotified = false
	m.Update(localProgressMsg{p: shell.Progress{Text: "again"}})
	if n := m.toastLines(); n != 2 {
		t.Fatalf("新一轮应可再次提示: %d", n)
	}
}

func TestSubmit_EnterSends(t *testing.T) {
	m := newTestRoot()
	m.running = true // 防 maybeStartNext 启动任务（单测无 app）
	m.input.SetValue("巡检磁盘")
	m.Update(testutil.Key("enter"))
	if len(m.pending) != 1 || m.pending[0] != "巡检磁盘" {
		t.Fatalf("enter should submit task, pending = %v", m.pending)
	}
	if m.input.Value() != "" {
		t.Fatalf("input should clear after submit, value = %q", m.input.Value())
	}
	if !strings.Contains(m.chat.Value(), "👤 巡检磁盘") {
		t.Fatalf("submitted task should appear in chat: %q", m.chat.Value())
	}
}

func TestQuit_WhileAskOpenResolvesAsk(t *testing.T) {
	m := newTestRoot()
	resp := make(chan string, 1)
	m.Update(askMsg{prompt: "允许执行吗?", options: []string{"y", "n"}, resp: resp})

	m.Update(testutil.Key("esc")) // 取消提问

	if got := <-resp; got != "" {
		t.Fatalf("ask answer = %q, want empty on cancel", got)
	}
	if m.ask != nil {
		t.Fatal("ask overlay should close on cancel")
	}
	// 取消后空闲，Ctrl+C 退出
	_, cmd := m.Update(testutil.Key("ctrl+c"))
	if cmd == nil {
		t.Fatal("ctrl+c should quit after ask closed")
	}
}

// ── 非终端模式输出 ───────────────────────────────────────────────────

func TestPlainPrinter_Routing(t *testing.T) {
	var out, errOut bytes.Buffer
	p := &plainPrinter{verbose: true, out: &out, errOut: &errOut}

	p.Sink(&types.Event{Type: types.EventReasoning, Content: "先检查磁盘"})
	p.Sink(&types.Event{Type: types.EventToken, Content: "磁盘使用率 92%。"})

	if got := out.String(); got != "磁盘使用率 92%。" {
		t.Fatalf("stdout = %q, want only model tokens", got)
	}
	if got := errOut.String(); got != "\n💭 先检查磁盘\n" {
		t.Fatalf("stderr = %q, want reasoning paragraph", got)
	}
}

func TestPlainPrinter_Quiet(t *testing.T) {
	var out, errOut bytes.Buffer
	p := &plainPrinter{verbose: false, out: &out, errOut: &errOut}

	p.Sink(&types.Event{Type: types.EventReasoning, Content: "内部思考"})
	p.Sink(&types.Event{Type: types.EventToolCall, ToolName: "terminal", ToolArgs: "{}"})
	p.Sink(&types.Event{Type: types.EventToken, Content: "结论"})

	if errOut.Len() != 0 {
		t.Fatalf("stderr = %q, want empty in quiet mode", errOut.String())
	}
	if got := out.String(); got != "结论" {
		t.Fatalf("stdout = %q, want model tokens", got)
	}
}

// ── init 子命令 ──────────────────────────────────────────────────────

func TestInitCmd_CreatesGocodeDir(t *testing.T) {
	dir := t.TempDir()
	cmd := newInitConfigCmd(&rootFlags{workDir: dir})
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("init: %v", err)
	}
	for _, p := range []string{
		model.InventoryPath(dir), model.AgentsMDPath(dir),
		model.AssistantPromptPath(dir), model.EnginePromptPath(dir), model.HelperPath(dir),
	} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("init 应生成 %s: %v", p, err)
		}
	}
	// hosts.yaml 是凭证文件：0600（Windows 不强制 POSIX 权限，跳过校验）
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(model.InventoryPath(dir)); err == nil {
			if perm := info.Mode().Perm(); perm != 0o600 {
				t.Errorf("hosts.yaml 权限 = %o, want 600", perm)
			}
		}
	}
	// AGENTS.md 创建空文件（无需模板）：空文件视为未配置，填写正文后即注入。
	md, err := os.ReadFile(model.AgentsMDPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if len(md) != 0 {
		t.Errorf("AGENTS.md 应为空文件（不需要模板），got %q", md)
	}
	// prompt.assistant.md 与内置交互提示的产品专属面一致（覆盖后仍可用）；
	// 共享构建块（安全规则/方法论）不在模板内——加载时强制追加。
	ip, err := os.ReadFile(model.AssistantPromptPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"交互式运维助手", "命令优先", "任务处置 SOP"} {
		if !strings.Contains(string(ip), want) {
			t.Errorf("prompt.assistant.md 模板应包含交互提示内容 %q", want)
		}
	}
	if strings.Contains(string(ip), "## 追查方法论") {
		t.Error("prompt.assistant.md 模板不应内嵌共享构建块（加载时统一追加）")
	}
	// prompt.engine.md 与引擎内置系统提示的引擎专属面一致（覆盖后仍可用）；
	// 共享构建块不在模板内——加载时强制追加。
	ap, err := os.ReadFile(model.EnginePromptPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"资深 Linux 运维排障专家", "系统协作 SOP", "协议骨架"} {
		if !strings.Contains(string(ap), want) {
			t.Errorf("prompt.engine.md 模板应包含引擎专属面内容 %q", want)
		}
	}
	if strings.Contains(string(ap), "## 追查方法论") {
		t.Error("prompt.engine.md 模板不应内嵌共享构建块（加载时统一追加）")
	}
	// helper.md 为内置手册
	helper, err := os.ReadFile(model.HelperPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(helper), "gocode-ops 使用手册") {
		t.Error("helper.md 应为内置使用手册")
	}
	if !model.IsInitialized(dir) {
		t.Error("init 后 IsInitialized 应为 true")
	}
}

func TestInitCmd_NoOverwriteExceptHelper(t *testing.T) {
	dir := t.TempDir()
	cmd := newInitConfigCmd(&rootFlags{workDir: dir})
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("init: %v", err)
	}
	// 用户改写的文件不被二次 init 覆盖；helper.md 总是刷新为内置版本。
	customAgentsMD := "- 环境为 3 节点 web 服务\n"
	customAssistant := "# 我公司的交互规范\n"
	customEngine := "# 我公司的排障方法论\n"
	if err := os.WriteFile(model.AgentsMDPath(dir), []byte(customAgentsMD), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(model.AssistantPromptPath(dir), []byte(customAssistant), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(model.EnginePromptPath(dir), []byte(customEngine), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(model.HelperPath(dir), []byte("旧手册"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("二次 init: %v", err)
	}
	md, err := os.ReadFile(model.AgentsMDPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if string(md) != customAgentsMD {
		t.Errorf("AGENTS.md 被二次 init 覆盖: %q", md)
	}
	ip, err := os.ReadFile(model.AssistantPromptPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if string(ip) != customAssistant {
		t.Errorf("prompt.assistant.md 被二次 init 覆盖: %q", ip)
	}
	ap, err := os.ReadFile(model.EnginePromptPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if string(ap) != customEngine {
		t.Errorf("prompt.engine.md 被二次 init 覆盖: %q", ap)
	}
	helper, err := os.ReadFile(model.HelperPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(helper), "gocode-ops 使用手册") {
		t.Error("helper.md 应随二次 init 刷新为内置版本")
	}
}

func TestNotInitHint(t *testing.T) {
	if got := notInitHint("/tmp/work"); !strings.Contains(got, "gocode-ops init") {
		t.Errorf("未 init 提示应引导执行 init: %q", got)
	}
}

// ── 公用内核：L0 快检按需触发（l0_snapshot 工具）───────────────────

type fakeL0Engine struct {
	snap string
	err  error
}

func (f *fakeL0Engine) SnapshotL0(ctx context.Context) (string, error) { return f.snap, f.err }

func TestL0SnapshotTool_OnDemand(t *testing.T) {
	// L0 快检是模型按需调用的工具：无引擎/失败不阻断任务，返回摘要文本。
	eng := &fakeL0Engine{snap: "## L0 确定性快检（引擎自动采集，无需重复执行）\n本轮无新检出线索。\n"}
	tool := tools.L0SnapshotTool(eng)
	if tool == nil || tool.Name() != "l0_snapshot" {
		t.Fatalf("l0_snapshot 工具应存在: %v", tool)
	}
	out, err := tool.Run(context.Background(), `{}`)
	if err != nil || !strings.Contains(out, "L0 确定性快检") {
		t.Fatalf("l0_snapshot 应返回快检摘要: %q, %v", out, err)
	}
}

func TestL0SnapshotTool_NilEngineFails(t *testing.T) {
	if _, err := tools.L0SnapshotTool(nil).Run(context.Background(), `{}`); err == nil {
		t.Error("无底座时 l0_snapshot 应报错（fail-closed，不静默放行）")
	}
}
