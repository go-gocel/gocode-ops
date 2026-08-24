package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/go-gocel/gocel-core/core/kernel"
	"github.com/go-gocel/gocel-core/types"
	"github.com/go-gocel/gocel/tools/shell"
	"github.com/go-gocel/gocode-ops/internal/assistant"
	"github.com/go-gocel/gocode-ops/internal/common/audit"
	"github.com/go-gocel/gocode-ops/internal/common/guard"
	"github.com/go-gocel/gocode-ops/internal/common/l0"
	"github.com/go-gocel/gocode-ops/internal/common/model"
	"github.com/go-gocel/gocode-ops/internal/common/remote"
	"github.com/go-gocel/gocode-ops/internal/common/session"
)

// ── 非终端模式输出 ───────────────────────────────────────────────────

// plainPrinter 非终端模式的进度输出：思考与工具过程走 stderr，
// 模型回答走 stdout（可重定向保存）。
type plainPrinter struct {
	verbose  bool
	out      io.Writer
	errOut   io.Writer
	inReason bool // 是否正在打印思考段落
	// lastNewline 最后一段输出是否以换行结尾（回答收尾补换行用——
	// 终端提示符不粘连，P2 修复）。
	lastNewline bool
}

func (p *plainPrinter) Sink(ev *types.Event) bool {
	switch ev.Type {
	case types.EventReasoning:
		if !p.verbose {
			return true
		}
		if !p.inReason {
			fmt.Fprint(p.errOut, "\n💭 ")
			p.inReason = true
		}
		fmt.Fprint(p.errOut, ev.Content)
	case types.EventToken:
		p.endReasoning()
		fmt.Fprint(p.out, ev.Content)
		p.lastNewline = strings.HasSuffix(ev.Content, "\n")
	case types.EventToolCall:
		p.endReasoning()
		if p.verbose {
			fmt.Fprintf(p.errOut, "\n⚡ %s(%s)\n", ev.ToolName, truncate(ev.ToolArgs, 160))
		}
	case types.EventToolResult:
		p.endReasoning()
		if p.verbose {
			mark := "✔"
			if audit.IsToolError(ev.Content) {
				mark = "✗"
			}
			fmt.Fprintf(p.errOut, "%s %s: %s\n", mark, ev.ToolName, clipResult(ev.Content, toolResultMaxLines, toolResultMaxWidth))
		}
	}
	return true
}

func (p *plainPrinter) endReasoning() {
	if p.inReason {
		fmt.Fprintln(p.errOut)
		p.inReason = false
	}
}

// ── 文本工具 ─────────────────────────────────────────────────────────

// clipResult 裁剪工具结果：超过 maxLines 行省略、超宽单行截断，附省略提示。
func clipResult(s string, maxLines, maxWidth int) string {
	s = strings.TrimRight(s, "\n")
	lines := strings.Split(s, "\n")
	omitted := 0
	if len(lines) > maxLines {
		omitted = len(lines) - maxLines
		lines = lines[:maxLines]
	}
	for i, line := range lines {
		if len(line) > maxWidth {
			lines[i] = line[:maxWidth] + "…"
		}
	}
	if omitted > 0 {
		lines = append(lines, fmt.Sprintf("…（省略 %d 行）", omitted))
	}
	return strings.Join(lines, "\n")
}

// blockquote 把多行文本转成 markdown 引用块（每行 "> " 前缀）。
func blockquote(s string) string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return ""
	}
	return "> " + strings.ReplaceAll(s, "\n", "\n> ")
}

// runPlain 非终端环境：非交互式执行一次任务后退出（供脚本/管道调用）。
// 无操作员终端：ask 策略下高危命令一律拒绝，ask_operator 不可用。
func runPlain(baseCtx context.Context, llm kernel.Model, meta tuiMeta, policy guard.Policy, task string) int {
	if task == "" {
		fmt.Fprintln(os.Stderr, "gocode-ops: 交互式运维助手需要终端；非终端环境请附带任务参数，如: gocode-ops \"巡检磁盘\"")
		return 2
	}
	ctx, stop := signal.NotifyContext(baseCtx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	printer := &plainPrinter{verbose: true, out: os.Stdout, errOut: os.Stderr}
	// 公用内核：非终端交互同样复用 L0 快检（日志走 stderr）；报告按需
	// 生成（操作员明确要求时经 generate_report 工具，不主动渲染）。
	var l0s model.L0Snapshooter
	rmt := remote.NewSSHExecutor(remote.RemoteConfig{InventoryPath: meta.invPath})
	// 任务结束后回收复用连接（与 runTUI 同语义）。
	defer func() {
		if c, ok := rmt.(interface{ CloseAll() }); ok {
			c.CloseAll()
		}
	}()
	if ecfg := discoverEngineConfig(meta.workDir, meta.invPath); ecfg.Local || len(ecfg.Hosts) > 0 {
		if e, err := l0.NewEngine(ecfg, rmt); err == nil {
			l0s = e
		} else {
			fmt.Fprintln(os.Stderr, "gocode-ops: L0 快检底座构建失败（继续运行，无确定性底座）:", err)
		}
	}
	app, err := assistant.NewAgentWithL0(llm, meta.workDir, meta.host, nil, policy, rmt, meta.invPath, l0s)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gocode-ops: 装配 agent 失败:", err)
		return 1
	}
	sess := session.NewSession(app, printer.Sink, false)
	oa := &taskRunner{
		sess:       sess,
		totalUsage: &types.TokenUsage{},
		workDir:    meta.workDir,
		host:       meta.host,
		onLocal: func(p shell.Progress) {
			if p.Text != "" {
				fmt.Fprint(os.Stderr, p.Text)
			}
		},
		onRemote: func(p remote.RemoteProgress) {
			if p.Phase == "output" && p.Text != "" {
				fmt.Fprintf(os.Stderr, "[%s] %s", p.Host, p.Text)
			}
		},
	}
	ctx = shell.WithProgress(ctx, oa.onLocal)
	ctx = remote.WithRemoteProgress(ctx, oa.onRemote)
	// 回答经 EventToken 流式打印到 stdout（plainPrinter.Sink），此处不再
	// 重复输出——此前双份打印违背“回答走 stdout 可重定向”契约。
	_, err = oa.turn(ctx, task)
	if err != nil {
		fmt.Fprintln(os.Stderr, "\n✗ 任务失败:", err)
		return 1
	}
	// 回答收尾补换行：stdout 可重定向保存/管道消费，末行不粘连。
	if !printer.lastNewline {
		fmt.Fprintln(os.Stdout)
	}
	fmt.Fprintln(os.Stderr, oa.usageString())
	return 0
}
