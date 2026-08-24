package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/go-gocel/gocel-core/types"
	"github.com/go-gocel/gocel/tools/shell"
	"github.com/go-gocel/termagent/pkg/behavior"
	"github.com/go-gocel/termagent/pkg/components"
	"github.com/go-gocel/termagent/pkg/components/display"
	"github.com/go-gocel/termagent/pkg/components/interactive"
	"github.com/go-gocel/termagent/pkg/i18n"
	"github.com/go-gocel/termagent/pkg/keymap"
	"github.com/go-gocel/termagent/pkg/runtime"
	"github.com/go-gocel/termagent/pkg/theme"

	"github.com/go-gocel/gocode-ops/internal/common/model"
	"github.com/go-gocel/gocode-ops/internal/common/remote"
)

// ── 根模型 ───────────────────────────────────────────────────────────

type rootModel struct {
	th   *theme.Theme
	km   *keymap.Keymap
	fm   *behavior.FocusManager
	meta tuiMeta

	app    *taskRunner
	rt     *runtime.Runtime
	remote remote.RemoteExecutor // 远程执行器（主机页探测/刷新复用）

	chat     *display.Markdown
	helpPane *display.Markdown // 帮助面板（独立内容，滚动不污染对话区）
	tools    *display.Table
	hosts    *display.Table // 远程主机清单表
	tabs     *interactive.Tabs
	input    *interactive.Input
	modal    *interactive.Modal
	palette  *interactive.CommandPalette
	toast    *display.Toast
	spinner  *display.Spinner
	status   *display.StatusBar

	ctx    context.Context
	cancel context.CancelFunc
	// probeCtx 主机连通性探测专用上下文（独立于任务 ctx：探测不随任务
	// 中断取消，也不与主循环重建任务 ctx 产生数据竞争）。由 runTUI
	// 注入并在退出时 cancel。
	probeCtx context.Context

	running   bool      // 当前是否有任务在执行
	pending   []string  // 排队任务（执行期间提交）
	toolRows  []toolRow // 工具调用记录（界面单一来源）
	hostRows  []hostRow // 远程主机清单（界面单一来源）
	remoteOK  bool      // 清单是否加载成功
	probeBusy bool      // 连通性探测进行中
	probeDone bool      // 是否完成过探测（header 在线统计）
	// liveDropNotified 实时输出无归属工具行时的丢弃提示（每轮只提示一次）。
	liveDropNotified bool
	reasonBuf        string // 思考段落缓冲（下一类事件时整段刷出）
	ask              *askState
	hostDetail       *hostDetailState // 主机详情弹窗（Enter 打开）
	help             bool
	quitting         bool
	w, h             int

	// ── 任务/队列状态 ──
	currentTask string    // 当前执行中的任务文本（状态栏展示）
	taskStart   time.Time // 当前任务开始时间（耗时刷新）
	taskCount   int       // 已执行轮数（导出/进度提示用）
	ticking     bool      // 耗时 ticker 是否运行中
	lastErr     error     // 最后一轮结果（退出码语义）
	baseLogN    int       // 本轮已展示的底座日志条数
	baseLogFold bool      // 底座日志是否已折叠提示

	// ── 实时输出合并缓冲（高频输出合并渲染） ──
	liveBuf     []liveChunk
	liveTicking bool

	// ── 传输进度节流（百分比变化 ≥1% 才更新表格） ──
	lastPct float64 // -1 表示未展示过（首次强制展示）

	// ── 主机页排序 ──
	hostSortKey string // "" | "name" | "address"
}

// liveChunk 一条待合并的实时输出块（缓冲时归属到当时的工具行下标）。
type liveChunk struct {
	prefix string
	text   string
	rowIdx int // 归属工具行（-1 = 无归属，缓冲时已提示）
}

// hostDetailState 主机详情弹窗内容。
type hostDetailState struct {
	title string
	lines []string
}

// newRoot 组装组件树。remote 为远程执行器（可为空实现——测试场景）；
// 运行时与 app 在 runTUI 中注入。
func newRoot(th *theme.Theme, km *keymap.Keymap, meta tuiMeta, remote remote.RemoteExecutor) *rootModel {
	m := &rootModel{
		th:       th,
		km:       km,
		meta:     meta,
		remote:   remote,
		chat:     display.NewMarkdown(display.WithMarkdownTheme(th)),
		helpPane: display.NewMarkdown(display.WithMarkdownTheme(th)),
		tools:    display.NewTable(display.WithTableTheme(th), display.WithTableEmptyState(toolTableEmptyText)),
		hosts:    display.NewTable(display.WithTableTheme(th), display.WithTableEmptyState(hostTableEmptyText)),
		toast:    display.NewToast(display.WithToastTheme(th), display.WithMax(3)),
		spinner:  display.NewSpinner(display.WithSpinnerTheme(th)),
		status:   display.NewStatusBar(display.WithStatusBarTheme(th)),
		modal:    interactive.NewModal(interactive.WithModalTheme(th)),
		lastPct:  -1,
		palette: interactive.NewCommandPalette(
			interactive.WithPaletteTheme(th),
			interactive.WithPaletteMessages(i18n.Default(i18n.Zh)),
		),
		input: interactive.NewInput(
			interactive.WithTheme(th),
			interactive.WithHistory(50),
			// 两行输入框：长任务/粘贴内容有足够展示空间（单行时内容过多显示不全）。
			// 多行语义下 ↑/↓ 是光标移动，历史改用 Ctrl+↑/↓（组件内置）。
			interactive.WithSize(0, 2),
			// Enter 直接发送（最符合终端直觉）；Shift+Enter 兼容保留（部分
			// 终端无 Shift+Enter 转义序列，不能作为唯一提交键）。
			interactive.WithSubmitKeys("enter", "shift+enter"),
			interactive.WithPlaceholder(inputPlaceholder),
		),
	}
	m.input.SetOnSubmit(m.onSubmit)
	m.chat.SetValue(welcomeText(meta))
	// 帮助面板：独立 Markdown 实例，内容固定、滚动独立（不污染对话区）。
	// GotoTop：静态面板打开时定位到顶部（避免自动跟随逻辑首屏滚到末尾）。
	m.helpPane.SetValue(helpMarkdown(km))
	m.helpPane.GotoTop()
	m.pushTools()
	m.pushHosts()
	m.status.Set(statusStateReady, statusReadyWait, theme.Success)

	// 主机表格需行选中回调（Enter → 详情），字面量内无法引用方法值，
	// 这里重建一次并以其装配标签页。
	m.hosts = display.NewTable(
		display.WithTableTheme(th),
		display.WithTableEmptyState(hostTableEmptyText),
		display.WithTableOnSelect(m.showHostDetail),
	)
	var err error
	m.tabs, err = interactive.NewTabs(
		[]string{tabTitleChat, tabTitleTools, tabTitleHosts},
		[]components.Component{m.chat, m.tools, m.hosts},
		interactive.WithTabsTheme(th),
	)
	must(err)

	m.fm = behavior.NewFocusManager()
	must(m.fm.Add("input", &m.input.Focusable))
	must(m.fm.Add("tabs", &m.tabs.Focusable))

	// tabs 就绪后同步一次标题计数（newRoot 早期的 pushTools/pushHosts
	// 发生在 tabs 创建前，标题更新被跳过——初始计数从此一致）。
	m.updateTabTitles()

	m.loadHosts()

	m.palette.Register(interactive.Command{ID: "new", Title: "新会话（清空上下文）", Keywords: "new 清空 上下文", Run: func() { m.execCommand(cmdNew) }})
	m.palette.Register(interactive.Command{ID: "hosts", Title: "远程主机（清单/连通性）", Keywords: "hosts 远程 主机 清单", Run: func() { m.execCommand(cmdHosts) }})
	m.palette.Register(interactive.Command{ID: "tokens", Title: "Token 用量", Keywords: "tokens 用量", Run: func() { m.execCommand(cmdTokens) }})
	m.palette.Register(interactive.Command{ID: "export", Title: "导出会话记录", Keywords: "export 导出 会话 记录", Run: func() { m.execCommand(cmdExport) }})
	m.palette.Register(interactive.Command{ID: "help", Title: "帮助", Keywords: "help 帮助", Run: func() { m.execCommand(cmdHelp) }})
	m.palette.Register(interactive.Command{ID: "exit", Title: "退出", Keywords: "exit 退出", Run: func() { m.execCommand(cmdExit) }})
	return m
}

func (m *rootModel) attach(rt *runtime.Runtime) { m.rt = rt }

// setApp 注入 app 并挂接实时输出回调（本地命令/远程进度的界面通道）。
func (m *rootModel) setApp(app *taskRunner) {
	m.app = app
	app.onLocal = func(p shell.Progress) {
		if m.rt != nil {
			m.rt.Send(localProgressMsg{p: p})
		}
	}
	app.onRemote = func(p remote.RemoteProgress) {
		if m.rt != nil {
			m.rt.Send(remoteProgressMsg{p: p})
		}
	}
}

func (m *rootModel) submitTask(text string) { m.onSubmit(text) }

// Sink 是 agent 事件回调（经 input.StreamSender 注入）：把 agent 事件转发进 TUI 事件循环。
func (m *rootModel) Sink(ev *types.Event) bool {
	if m.rt != nil {
		m.rt.Send(agentEventMsg{ev: ev})
	}
	return true
}

// Init 合并子组件启动命令。
func (m *rootModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Init(), m.toast.Init())
}

func (m *rootModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		m.tabs.Update(msg)     // 广播到面板（Markdown 宽度 / Table 视口）
		m.input.Update(msg)    // 输入框跟随窗口宽度（否则停留初始小尺寸）
		m.helpPane.Update(msg) // 帮助面板跟随窗口
		m.toast.Update(msg)
		m.spinner.Update(msg)
	case agentEventMsg:
		m.handleEvent(msg)
	case baseLogMsg:
		m.handleBaseLog(msg)
	case agentFinishMsg:
		m.handleFinish(msg)
	case askMsg:
		m.openAsk(msg)
	case localProgressMsg:
		m.bufferLive("▸ ", msg.p.Text)
	case remoteProgressMsg:
		m.handleRemoteProgress(msg.p)
	case hostsProbeMsg:
		m.applyProbe(msg.status)
	case liveFlushMsg:
		return m, m.flushLive()
	case elapsedTickMsg:
		return m, m.onElapsedTick(msg)
	case runtime.DroppedMsg:
		m.toast.Update(display.ToastMsg{Text: toastBufferOverflow, Semantic: theme.Warning})
	case tea.KeyMsg:
		m.handleKey(msg)
	default:
		if m.help {
			// 帮助页打开：非按键消息（鼠标滚轮等）进帮助面板。
			m.helpPane.Update(msg)
		} else {
			m.tabs.Update(msg)
		}
		m.spinner.Update(msg)
	}
	if m.quitting {
		m.quitting = false
		return m, tea.Quit
	}
	return m, m.startTickers()
}

// startTickers 按需启动耗时/实时输出合并 ticker（同一 Update 至多启动
// 一个；其余在后续 Update/下一次 tick 中启动）。
func (m *rootModel) startTickers() tea.Cmd {
	if m.running && !m.ticking && m.rt != nil {
		m.ticking = true
		return tea.Tick(time.Second, func(t time.Time) tea.Msg { return elapsedTickMsg(t) })
	}
	if len(m.liveBuf) > 0 && !m.liveTicking && m.rt != nil {
		m.liveTicking = true
		return tea.Tick(liveBatchInterval, func(t time.Time) tea.Msg { return liveFlushMsg{} })
	}
	return nil
}

// ── 任务队列 ─────────────────────────────────────────────────────────

// onSubmit 输入框提交回调：内置命令直接执行，任务入队串行执行。
func (m *rootModel) onSubmit(value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if cmd, ok := parseSlash(value); ok {
		m.execCommand(cmd)
		return
	}
	m.pending = append(m.pending, value)
	m.chat.Update(display.AppendMsg{Text: "\n### 👤 " + value + "\n"})
	m.maybeStartNext()
}

// maybeStartNext 启动下一条排队任务（无任务或已有任务在执行时不动作）。
func (m *rootModel) maybeStartNext() {
	if m.running || len(m.pending) == 0 {
		return
	}
	text := m.pending[0]
	m.pending = m.pending[1:]
	m.running = true
	m.liveDropNotified = false
	m.currentTask = text
	m.taskStart = time.Now()
	m.lastPct = -1
	m.baseLogN = 0
	m.baseLogFold = false
	// 上一轮可能被 Ctrl+C 中断（ctx 已取消）：启动新任务前重建上下文，
	// 否则新任务会立即以"任务已中断"结束。
	m.newTaskCtx()
	m.spinner.SetLabel("任务执行中…")
	m.status.Set(statusStateRunning, runningStatusText(text, humanDuration(0)), theme.Warning)
	m.chat.SetRich(false) // 流式阶段保持 Raw 渲染
	go m.runTurn(text)
}

// newTaskCtx 若任务上下文已被取消（如 Ctrl+C 中断、quit），重建新上下文。
// 在主循环线程（onSubmit/maybeStartNext 调用链）执行，避免与 agent
// goroutine 并发读写。
func (m *rootModel) newTaskCtx() {
	if m.ctx != nil && m.ctx.Err() != nil {
		m.ctx, m.cancel = context.WithCancel(context.Background())
	}
}

// finishSendTimeout 终态消息可靠投递超时（SendCritical）：事件循环
// 持续 drain 缓冲，正常负载毫秒级送达；超时仅发生在事件循环严重卡死。
const finishSendTimeout = 5 * time.Second

func (m *rootModel) runTurn(text string) {
	ctx := m.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	// agent goroutine 不在 Error Boundary（bubbletea model）覆盖范围内：
	// 工具层 panic 直接崩掉整个会话——defer 恢复并作为任务失败收尾。
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "[gocode-ops] panic: %v\n%s", r, debug.Stack())
			if m.rt != nil {
				m.rt.SendCritical(agentFinishMsg{err: fmt.Errorf("任务执行 panic: %v", r)}, finishSendTimeout)
			}
		}
	}()
	_, err := m.app.turn(ctx, text)
	if m.rt != nil {
		// 终态消息可靠投递：agentFinishMsg 被背压丢弃会让 m.running 恒
		// true、队列永不前进（永久卡死）——SendCritical 阻塞重试直到
		// 送达（超时回退 best-effort，防事件循环卡死时无限自旋）。
		m.rt.SendCritical(agentFinishMsg{err: err}, finishSendTimeout)
	}
}

// onElapsedTick 每秒刷新运行状态（耗时）并自续期。
func (m *rootModel) onElapsedTick(msg elapsedTickMsg) tea.Cmd {
	m.ticking = false
	if m.running {
		m.status.Set(statusStateRunning, runningStatusText(m.currentTask, humanDuration(time.Since(m.taskStart))), theme.Warning)
	}
	cmds := []tea.Cmd{}
	if m.running && m.rt != nil {
		m.ticking = true
		cmds = append(cmds, tea.Tick(time.Second, func(t time.Time) tea.Msg { return elapsedTickMsg(t) }))
	}
	if len(m.liveBuf) > 0 && !m.liveTicking && m.rt != nil {
		m.liveTicking = true
		cmds = append(cmds, tea.Tick(liveBatchInterval, func(t time.Time) tea.Msg { return liveFlushMsg{} }))
	}
	return tea.Batch(cmds...)
}

// ── 会话导出 ─────────────────────────────────────────────────────────

// exportTranscript 把当前会话（对话 + 工具摘要 + 用量）导出为 markdown。
// 返回导出文件路径。会话含命令原文（凭证已脱敏但仍是敏感操作记录）：
// 目录 0700、文件 0600，仅属主可读（P3 修复）。
func (m *rootModel) exportTranscript() (string, error) {
	dir := model.SessionsDir(m.meta.workDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, time.Now().Format("20060102-150405")+".md")
	content := m.buildTranscriptMD()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// buildTranscriptMD 组装导出内容：头部元信息 + 工具摘要 + 对话全文。
func (m *rootModel) buildTranscriptMD() string {
	var sb strings.Builder
	sb.WriteString("# gocode-ops 会话记录\n\n")
	sb.WriteString(fmt.Sprintf("- 时间: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("- 主机: %s\n", m.meta.host))
	sb.WriteString(fmt.Sprintf("- 模型: %s\n", m.meta.model))
	sb.WriteString(fmt.Sprintf("- 工作目录: %s\n", m.meta.workDir))
	sb.WriteString(fmt.Sprintf("- 高危策略: %s\n", m.meta.risky))
	sb.WriteString(fmt.Sprintf("- 任务轮数: %d\n", m.taskCount))
	if m.app != nil {
		sb.WriteString("- 用量: " + m.app.usageString() + "\n")
	}
	sb.WriteString("\n## 工具调用摘要\n\n")
	if len(m.toolRows) == 0 {
		sb.WriteString("（无）\n")
	} else {
		sb.WriteString("| 工具 | 目标 | 状态 | 耗时 | 参数 |\n")
		sb.WriteString("|---|---|---|---|---|\n")
		for _, r := range m.toolRows {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
				r.name, r.target, r.status, r.dur, truncate(r.args, 80)))
		}
	}
	sb.WriteString("\n## 对话全文\n\n")
	if v := m.chat.Value(); v != "" {
		sb.WriteString(v)
	} else {
		sb.WriteString("（空）\n")
	}
	if !strings.HasSuffix(sb.String(), "\n") {
		sb.WriteString("\n")
	}
	return sb.String()
}
