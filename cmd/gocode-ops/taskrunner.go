package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-gocel/gocel-core/types"
	"github.com/go-gocel/gocel/tools/shell"
	"github.com/go-gocel/termagent/pkg/runtime"

	"github.com/go-gocel/gocode-ops/internal/common/env"
	"github.com/go-gocel/gocode-ops/internal/common/memory"
	"github.com/go-gocel/gocode-ops/internal/common/remote"
	"github.com/go-gocel/gocode-ops/internal/common/session"
)

// taskRunner 封装一轮任务的执行：维护累计 token 用量，并在执行期间把本地/
// 远程命令的实时输出回调给界面。多轮历史与 agent 事件由 session.Session 统一
// 管理（「初始指令 → 工作」执行模型，TUI 共用）。
//
// 报告策略（人在环）：交互形态不主动生成报告——过程在操作员手里，报告
// 只在操作员明确要求时由模型调用 generate_report 工具渲染（见 tools.ReportTool）；
// 全自动运维引擎（auto）不经过本结构，报告由引擎主循环每轮自动渲染。
type taskRunner struct {
	sess       *session.Session
	totalUsage *types.TokenUsage
	// workDir 工作目录（terminal 工具 cwd 注入——与文件工具/底座产物
	// 保持同一路径语义，避免相对路径分裂）。
	workDir string
	// host 本机显示名（主机档案上下文注入：任务开始附带"这台机器的
	// 历史操作/恢复模式/易错点"——越用越懂）。
	host string
	// onLocal 本地 terminal 实时输出回调（shell.Progress），界面注入。
	onLocal func(p shell.Progress)
	// onRemote 远程 remote_* 工具实时进度回调（输出块/传输进度），界面注入。
	onRemote func(p remote.RemoteProgress)
}

// turn 执行一轮：追加用户消息 → agent 运行 → 更新用量。
// L0 快检与报告均不自动触发：快检由模型按需调用 l0_snapshot 工具
// （帮助/闲聊/知识类问题零开销）；报告由模型在操作员明确要求时调用
// generate_report 工具（不主动生成）。
func (a *taskRunner) turn(ctx context.Context, text string) (string, error) {
	// 实时输出通道：本地命令输出、远程输出块/传输进度在执行期间直接回传界面。
	if a.onLocal != nil {
		ctx = shell.WithProgress(ctx, a.onLocal)
	}
	if a.onRemote != nil {
		ctx = remote.WithRemoteProgress(ctx, a.onRemote)
	}
	if a.workDir != "" {
		// terminal 的相对路径以工作目录为基准（与文件工具同语义）。
		ctx = shell.WithWorkDir(ctx, a.workDir)
	}
	// 本地执行 shell 探测注入：bash-only 容器/无 Git Bash 的 Windows
	// 上 terminal/task_run 不再因硬编码 sh 整片失败（见 internal/common/shell.go）。
	ls := env.LocalShell()
	ctx = shell.WithShellInContext(ctx, ls.Name, ls.Args...)
	// 主机档案上下文注入：任务开始即携带"这台机器的历史"——操作员
	// 每次批准的操作都沉淀进档案，助手越用越懂（人在环背书）。
	if a.workDir != "" && a.host != "" {
		if d := memory.LoadDossier(a.workDir, a.host); d != "" {
			text = "（本机档案：" + d + "）\n" + text
		}
	}
	result, err := a.sess.Run(ctx, text)
	if err != nil {
		return "", err
	}
	if result.TokenUsage != nil {
		a.totalUsage.PromptTokens += result.TokenUsage.PromptTokens
		a.totalUsage.CompletionTokens += result.TokenUsage.CompletionTokens
		a.totalUsage.TotalTokens += result.TokenUsage.TotalTokens
	}
	return result.Content, nil
}

// reset 清空对话上下文与用量（/new 命令）。
func (a *taskRunner) reset() {
	a.sess.Reset()
	a.totalUsage = &types.TokenUsage{}
}

// usageString 累计 token 用量描述。
func (a *taskRunner) usageString() string {
	u := a.totalUsage
	return fmt.Sprintf("tokens: 输入 %d + 输出 %d = %d", u.PromptTokens, u.CompletionTokens, u.TotalTokens)
}

// baseLogWriter 把公用内核（l0.Engine，L0 快检）日志行转发进 TUI 事件循环。
// 注意：仅交互式运维助手使用；全自动运维引擎（auto）的日志直接输出到终端，不经 TUI。
// Write 由底座 goroutine 调用，rt.Send 并发安全。
type baseLogWriter struct {
	rt *runtime.Runtime
}

func (w *baseLogWriter) Write(p []byte) (int, error) {
	if w.rt != nil {
		w.rt.Send(baseLogMsg{line: strings.TrimRight(string(p), "\n")})
	}
	return len(p), nil
}

// ── 操作员终端（TUI） ────────────────────────────────────────────────

// tuiOperator 通过 TUI 完成操作员交互：向事件循环投递 askMsg 并阻塞等待回答。
// 高危命令守卫与 ask_operator 工具在 agent goroutine 中同步调用 Ask，
// 界面侧渲染确认框后把回答送回 channel。
type tuiOperator struct {
	rt   *runtime.Runtime
	once sync.Once
	done chan struct{}
}

func newTUIOperator() *tuiOperator {
	return &tuiOperator{done: make(chan struct{})}
}

func (o *tuiOperator) attach(rt *runtime.Runtime) { o.rt = rt }

// close 解除阻塞中的 Ask（程序退出时调用，防 goroutine 泄漏）。
func (o *tuiOperator) close() { o.once.Do(func() { close(o.done) }) }

// askSendTimeout askMsg 可靠投递超时（SendCritical）：事件循环持续
// drain 缓冲，正常负载毫秒级送达；超时仅发生在事件循环严重卡死。
const askSendTimeout = 3 * time.Second

func (o *tuiOperator) Ask(prompt string, options []string) (string, error) {
	if o.rt == nil {
		return "", errors.New("ask_operator: TUI 未就绪")
	}
	resp := make(chan string, 1)
	// askMsg 可靠投递：被背压丢弃会让 agent goroutine 永久阻塞（Ask
	// 无超时）——SendCritical 阻塞重试直到送达（超时回退 best-effort）。
	o.rt.SendCritical(askMsg{prompt: prompt, options: options, resp: resp}, askSendTimeout)
	select {
	case ans := <-resp:
		return ans, nil
	case <-o.done:
		return "", errors.New("ask_operator: TUI 已退出")
	}
}

// ── TUI 消息 ─────────────────────────────────────────────────────────

// agentEventMsg 把 agent 事件转发进 TUI 事件循环（Sink → rt.Send）。
type agentEventMsg struct {
	ev *types.Event
}

// baseLogMsg 公用内核日志行（底座 goroutine 产生，显示在对话区）。
// 仅交互式运维助手使用；全自动运维引擎（auto）日志不经 TUI。
type baseLogMsg struct {
	line string
}

// agentFinishMsg 一轮任务结束（含中断与失败）。
type agentFinishMsg struct {
	err error
}

// localProgressMsg 本地 terminal 命令的实时输出块（agent goroutine 产生）。
type localProgressMsg struct {
	p shell.Progress
}

// remoteProgressMsg 远程 remote_* 工具的实时进度（输出块/传输进度）。
type remoteProgressMsg struct {
	p remote.RemoteProgress
}

// hostsProbeMsg 远程主机连通性探测结果（探测 goroutine 产生）。
type hostsProbeMsg struct {
	status map[string]string
}

// askMsg 操作员提问（高危确认 / ask_operator），由 agent goroutine 投递，
// resp 接收界面侧的回答（取消时收到空串）。
type askMsg struct {
	prompt  string
	options []string
	resp    chan string
}

// askState 非缺省选项的提问（界面内渲染为可导航选项列表；末尾固定
// 追加"其他"入口，选中后进入自定义输入模式——选项不满足时输入补充
// 说明，回答以用户原话返回给模型）。
type askState struct {
	question string
	options  []string
	current  int
	resp     chan string
	custom   bool   // 自定义输入模式（选中"其他"后）
	input    string // 自定义输入缓冲
}

// move 在选项间移动；末尾的"其他"入口参与导航（total = 选项数 + 1）。
func (a *askState) move(step int) {
	total := len(a.options) + 1
	if total <= 1 {
		return
	}
	a.current = (a.current + step + total) % total
}

// toolRow 「工具调用」标签页的一行记录。
type toolRow struct {
	name     string
	args     string
	target   string // 目标："本机" 或主机别名列表（远程工具）
	status   string // 运行中 | 完成 | 失败 | 百分比（传输中）
	dur      string // 耗时（运行中 "…"，收尾后 humanDuration）
	result   string // 工具结果内容（复制/导出用，截断存储）
	started  time.Time
	liveChar int  // 实时输出累计字符（总量保护）
	liveOver bool // 实时输出是否已超限提示
}

// hostRow 「远程主机」标签页的一行记录。
type hostRow struct {
	name    string
	address string
	user    string
	auth    string
	status  string
}
