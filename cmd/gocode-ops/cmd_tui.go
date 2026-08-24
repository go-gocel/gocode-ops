package main

// cmd_tui.go — TUI 会话启动：tuiMeta 元信息与 runTUI 入口。

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-gocel/gocel-core/core/kernel"
	"github.com/go-gocel/gocel-core/types"
	"github.com/go-gocel/termagent/pkg/components/display"
	"github.com/go-gocel/termagent/pkg/runtime"
	"github.com/go-gocel/termagent/pkg/theme"

	"github.com/go-gocel/gocode-ops/internal/assistant"
	"github.com/go-gocel/gocode-ops/internal/common/guard"
	"github.com/go-gocel/gocode-ops/internal/common/l0"
	"github.com/go-gocel/gocode-ops/internal/common/model"
	"github.com/go-gocel/gocode-ops/internal/common/remote"
	"github.com/go-gocel/gocode-ops/internal/common/session"
	"github.com/go-gocel/gocode-ops/internal/common/workspace"
)

// handoffBanner 接力协同启动横幅（引擎遗留项提示）。
const handoffBanner = "⚙ 检测到引擎遗留：%d 个未处置项、%d 个人工工单——输入「接续处理」接管（处置后可再跑 gocode-ops auto 复检收敛）"

// engineRunningBanner 并行协同提示（引擎正在同一工作目录运行）。
const engineRunningBanner = "⚙ 全自动引擎正在运行中（共享状态已并行安全；远端命令注意与引擎错峰，守卫通道保护兜底）"

// tuiMeta 展示用元信息（TUI 头部/状态栏）。
type tuiMeta struct {
	host        string
	workDir     string
	model       string
	risky       string
	invPath     string
	initialized bool   // 工作目录是否已 init（false 时启动提示）
	themeFile   string // 显式主题文件（--theme；空则探测 .gocode/theme.json）
}

// loadTheme 加载主题：显式 --theme 优先，其次 .gocode/theme.json，兜底
// 内置 Agent 主题。加载失败不阻断启动（stderr 提示 + 内置主题）。
func loadTheme(meta tuiMeta) *theme.Theme {
	file := meta.themeFile
	if file == "" {
		file = model.ThemePath(meta.workDir)
	}
	if file != "" {
		if _, err := os.Stat(file); err == nil {
			if th, err := theme.LoadFromFile(file, theme.ProfileAuto); err == nil {
				return th
			} else {
				fmt.Fprintln(os.Stderr, "gocode-ops: 主题加载失败（使用内置主题）:", err)
			}
		} else if meta.themeFile != "" {
			fmt.Fprintln(os.Stderr, "gocode-ops: 主题文件不存在（使用内置主题）:", file)
		}
	}
	return theme.Agent(theme.ProfileAuto)
}

// runTUI 以 TermAgent TUI 运行交互会话（阻塞直到退出）。
// 返回进程退出码：最后一轮任务失败/中断时返回 1（脚本链式调用可感知）。
func runTUI(baseCtx context.Context, llm kernel.Model, meta tuiMeta, policy guard.Policy, initial string) int {
	th := loadTheme(meta)
	km := buildKeymap()
	op := newTUIOperator()
	rmt := remote.NewSSHExecutor(remote.RemoteConfig{InventoryPath: meta.invPath})
	// 退出时回收复用连接：长驻 TUI 的空闲连接此前永不清除（CloseAll 只在
	// 引擎路径调用），服务端重启后成半开连接、资源泄漏至进程退出。
	defer func() {
		if c, ok := rmt.(interface{ CloseAll() }); ok {
			c.CloseAll()
		}
	}()
	root := newRoot(th, km, meta, rmt)

	ctx, cancel := context.WithCancel(baseCtx)
	defer cancel()
	root.ctx = ctx
	root.cancel = cancel
	// 探测上下文独立于任务上下文：探测不随任务中断取消。
	probeCtx, probeCancel := context.WithCancel(baseCtx)
	defer probeCancel()
	root.probeCtx = probeCtx

	rt, err := runtime.New(root,
		runtime.WithAltScreen(true),
		runtime.WithFallback(true),
		runtime.WithMouse(true), // 对话区鼠标滚轮滚动
		// 缓冲放大：流式 token 启用后事件更密集，256 偏紧（终态消息
		// 已有 SendCritical 可靠投递兜底，进度类消息丢弃无害）。
		runtime.WithSendBuffer(1024),
		runtime.WithOnError(func(err error) {
			fmt.Fprintln(os.Stderr, "[gocode-ops] Error Boundary:", err)
		}),
		runtime.WithOnExit(op.close), // 退出时解除阻塞中的操作员提问
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gocode-ops:", err)
		return 1
	}
	op.attach(rt)
	root.attach(rt)
	// 启动时清单加载失败无提示（newRoot 时 rt 未注入，toast 发不出去）：
	// rt 就绪后补一次加载，失败原因经 toast 可见（r 键刷新同路径）。
	if !root.remoteOK && meta.invPath != "" {
		root.loadHosts()
	}

	// 公用内核：交互式运维助手复用 L0 快检/findings/基线（人在环驱动），
	// 与全自动运维引擎 同一份工作区状态（findings.json/baseline.json）。
	// 底座只跑确定性层，日志转发进对话区（🔧 行）；L0 快检由模型按需
	// 调用 l0_snapshot 工具触发（不再每轮无条件前置）；报告按需生成——
	// 操作员明确要求时模型调用 generate_report 工具渲染 report.md
	// （交互形态不主动生成报告；全自动运维引擎的报告由引擎主循环自动渲染）。
	var l0s model.L0Snapshooter
	if ecfg := discoverEngineConfig(meta.workDir, meta.invPath); ecfg.Local || len(ecfg.Hosts) > 0 {
		if e, err := l0.NewEngine(ecfg, rmt); err == nil {
			e.SetLogOut(&baseLogWriter{rt: rt})
			l0s = e
		} else {
			fmt.Fprintln(os.Stderr, "gocode-ops: L0 快检底座构建失败（继续运行，无确定性底座）:", err)
		}
	}

	app, err := assistant.NewAgentWithL0(llm, meta.workDir, meta.host, op, policy, rmt, meta.invPath, l0s)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gocode-ops: 装配 agent 失败:", err)
		return 1
	}
	// 流式会话：思考段/回答 token 逐字回传界面（README 宣称的流式
	// 渲染此前 stream=false 实际未启用——长思考期间对话区无进展）。
	sess := session.NewSession(app, root.Sink, true)
	oa := &taskRunner{sess: sess, totalUsage: &types.TokenUsage{}, workDir: meta.workDir, host: meta.host}
	root.setApp(oa)

	// 接力协同横幅：全自动引擎遗留的未处置项/工单提示（引擎 → 助手
	// 接力场景；助手上下文已注入遗留摘要，操作员输入"接续处理"即接管）。
	if h := workspace.LoadHandoff(meta.workDir); h.HasWork() {
		root.toast.Update(display.ToastMsg{
			Text:     fmt.Sprintf(handoffBanner, len(h.Open), len(h.WorkOrders)),
			Semantic: theme.Warning,
		})
	}
	// 并行协同提示：引擎正在同一工作目录运行（engine.running 标记）——
	// 共享状态已做跨进程锁+合并（并行安全），远端命令为常规双管理员
	// 交错风险（守卫通道保护兜底）。
	if _, err := os.Stat(filepath.Join(model.ConfigDir(meta.workDir), "engine.running")); err == nil {
		root.toast.Update(display.ToastMsg{
			Text:     engineRunningBanner,
			Semantic: theme.Info,
		})
	}

	if initial != "" {
		root.submitTask(initial)
	}
	if err := rt.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "gocode-ops:", err)
		return 1
	}
	// ── 退出收尾 ──
	if u := root.usageString(); u != "" {
		fmt.Fprintln(os.Stderr, u)
	}
	// 会话导出：有任务执行过就落盘（审计价值；导出失败不阻断退出）。
	if root.taskCount > 0 {
		if p, err := root.exportTranscript(); err == nil {
			fmt.Fprintln(os.Stderr, "会话已导出:", p)
		} else {
			fmt.Fprintln(os.Stderr, "会话导出失败:", err)
		}
	}
	if root.lastErr != nil {
		// 最后任务失败/中断：stderr 摘要 + 非零退出码（脚本可感知）。
		fmt.Fprintln(os.Stderr, "最后任务未成功:", root.lastErr)
		return 1
	}
	return 0
}
