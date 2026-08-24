package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/go-gocel/gocel/tools/shell"
	"github.com/spf13/cobra"

	"github.com/go-gocel/gocode-ops/internal/autopilot"
	"github.com/go-gocel/gocode-ops/internal/common/env"
	"github.com/go-gocel/gocode-ops/internal/common/fsutil"
	"github.com/go-gocel/gocode-ops/internal/common/model"
	"github.com/go-gocel/gocode-ops/internal/common/probe"
	"github.com/go-gocel/gocode-ops/internal/common/remote"
)

// ── auto 子命令：全自动运维引擎启动入口 ────────────────────────────────
//
// 核心在 internal/engine（纯库：NewEngine + SetLogOut + OnEvent +
// Run，可被任意宿主 import 嵌入），这里只做启动入口：装配 → 运行 →
// result.json + 退出码。终端/非终端同一路径：引擎直接运行，日志实时
// 输出到终端（引擎默认 stderr 出口），报告实时落盘。
//
// 本文件与交互 TUI（tui_*.go）完全隔离：TUI 不 import internal/engine，
// 也不承担引擎日志展示；两者只共用 internal/common 底座与模型构建。
//
// 公用内核在 internal/common（L0/工作区/报告/守卫/审计/远程）。
// 配置自动发现（.gocode/hosts.yaml / .gocode/AGENTS.md /
// .gocode/prompt.engine.md）。

// autoFlags auto 子命令的专属参数（定义在 auto 命令上，非全局）。
type autoFlags struct {
	timeout     time.Duration // 全局时限；0=不设
	jsonPath    string        // result.json 路径；空=缺省 <工作目录>/.gocode/result.json
	watch       time.Duration // watch 模式感知周期；0=任务模式（收敛退出）
	parallel    int           // 并行 worker 数；0=默认 6，1=串行
	initDesired bool          // 初始化期望状态文件（desired.json 模板）
}

// result 机器评分的结构化结果。
type result struct {
	Converged bool   `json:"converged"`
	Error     string `json:"error,omitempty"`
	Elapsed   string `json:"elapsed"`
	Report    string `json:"report"`
	Findings  struct {
		Total      int `json:"total"`
		Confirmed  int `json:"confirmed"`
		Remediated int `json:"remediated"`
		Pending    int `json:"pending"`
		Dismissed  int `json:"dismissed"`
	} `json:"findings"`
}

// buildEngine 构建全自动运维引擎（固定默认模型）。模型名固定
// defaultModelName，API Key 从环境变量读取（与交互式运维助手一致）。
func buildAutopilot(rf *rootFlags, af *autoFlags) (*autopilot.Engine, error) {
	cfg := autopilot.DefaultConfig()
	cfg.EngineConfig = discoverEngineConfig(rf.workDir, model.InventoryPath(rf.workDir))
	cfg.Timeout = af.timeout
	cfg.Parallel.Workers = af.parallel
	cfg.WatchInterval = af.watch

	var rmt remote.RemoteExecutor
	if !cfg.Local {
		rmt = remote.NewSSHExecutor(remote.RemoteConfig{InventoryPath: cfg.InventoryPath})
	}
	llm, err := buildModel(rf.provider, defaultModelName, "")
	if err != nil {
		return nil, err
	}
	ap, err := autopilot.NewEngine(cfg, llm, rmt)
	if err != nil {
		return nil, fmt.Errorf("启动失败: %w", err)
	}
	return ap, nil
}

// writeResult 把机器评分结果落盘（缺省 <工作目录>/.gocode/result.json）。
// converged 如实：watch 模式下收敛阶段未收敛（watchConverged=false）
// 不得虚报（评分场景结论失真）。
func writeResult(workDir string, jsonPath string, ap *autopilot.Engine, runErr error, elapsed time.Duration, watchMode bool) {
	res := result{
		Converged: runErr == nil && (!watchMode || ap.WatchConverged()),
		Elapsed:   elapsed.Round(time.Millisecond).String(),
		Report:    ap.ReportPath(),
	}
	if runErr != nil {
		res.Error = runErr.Error()
	} else if watchMode && !ap.WatchConverged() {
		res.Error = "watch 收敛阶段未收敛（守护循环继续运行，评分如实未收敛）"
	}
	if ws := ap.Core().Workspace(); ws != nil {
		res.Findings.Total = len(ws.Findings())
		res.Findings.Confirmed = len(ws.Confirmed())
		res.Findings.Pending = len(ws.Pending())
		res.Findings.Dismissed = len(ws.Dismissed())
		for _, f := range ws.Confirmed() {
			if f.Remediated {
				res.Findings.Remediated++
			}
		}
	}
	out := jsonPath
	if out == "" {
		out = filepath.Join(model.ConfigDir(workDir), "result.json")
	}
	data, err := json.MarshalIndent(res, "", "  ")
	if err == nil {
		// 原子写：崩溃不留下半截 result.json（评分读取方不会读到损坏内容）。
		err = fsutil.WriteFileAtomic(out, append(data, '\n'), 0o644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "gocode-ops: result.json 写入失败:", err)
		return
	}
	fmt.Fprintf(os.Stderr, "[gocode-ops] 评分结果: %s\n", out)
}

// engineMarkTTL 引擎运行标记的陈旧阈值：超过视为崩溃/强杀残留
// （正常退出会清理；SIGKILL/断电不会）。
const engineMarkTTL = 30 * time.Minute

// runAutopilot 运行全自动运维引擎（终端/非终端同一路径）：日志实时输出到
// stderr（引擎默认日志出口），报告实时落盘，退出码 0=收敛 / 1=未收敛。
func runAutopilot(rf *rootFlags, af *autoFlags) int {
	if err := os.MkdirAll(rf.workDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "gocode-ops: 创建工作目录失败:", err)
		return 1
	}
	ap, err := buildAutopilot(rf, af)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gocode-ops:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "[gocode-ops] 实时报告: %s\n", ap.ReportPath())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// 本地执行 shell 探测注入：阶段 agent 的 terminal/task_run 工具
	// 用探测到的 shell（bash-only 容器/无 Git Bash 的 Windows 不趴窝）。
	ls := env.LocalShell()
	ctx = shell.WithShellInContext(ctx, ls.Name, ls.Args...)

	start := time.Now()
	// 引擎运行标记：同一工作目录并行运行的交互运维助手据此感知
	// （.gocode/engine.running，退出/中断即清理）。陈旧标记（崩溃/
	// 强杀残留，mtime 超 30 分钟）启动时清理——否则 TUI 会永久显示
	// "引擎运行中"提示（P2 修复）。
	engineMark := filepath.Join(model.ConfigDir(rf.workDir), "engine.running")
	if fi, err := os.Stat(engineMark); err == nil && time.Since(fi.ModTime()) > engineMarkTTL {
		os.Remove(engineMark)
	}
	if err := os.WriteFile(engineMark, []byte(fmt.Sprintf("pid=%d started=%s\n", os.Getpid(), start.UTC().Format(time.RFC3339))), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "gocode-ops: 引擎运行标记写入失败:", err)
	}
	var runErr error
	if af.watch > 0 {
		runErr = ap.RunWatch(ctx)
	} else {
		runErr = ap.Run(ctx)
	}
	os.Remove(engineMark)
	writeResult(rf.workDir, af.jsonPath, ap, runErr, time.Since(start), af.watch > 0)
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "[gocode-ops] 未收敛: %v\n", runErr)
		return 1
	}
	if af.watch > 0 {
		fmt.Fprintf(os.Stderr, "[gocode-ops] watch 结束（%s）\n", time.Since(start).Round(time.Millisecond))
		return 0
	}
	fmt.Fprintf(os.Stderr, "[gocode-ops] 收敛完成（%s）\n", time.Since(start).Round(time.Millisecond))
	return 0
}

// newEngineCmd 全自动运维引擎子命令：`gocode-ops auto`。协议驱动引擎，
// 全程零人工干预，面向未知故障环境的自动巡检排障（比赛/评审用途）。
// 核心在 internal/engine 纯库（可被嵌入托管），这里只做启动入口。
// 退出码 0=收敛，1=未收敛/失败/时限到；result.json 记录机器评分结果。
// 终端/非终端同一路径：直接运行引擎，日志实时输出到终端（引擎默认
// stderr 出口）。与交互 TUI 完全隔离：TUI 不 import internal/engine，
// 也不承担引擎日志展示。全局参数 -d/-p 继承自根命令；--risky 不生效
// （引擎使用独立的 PolicyAuto 策略）。
func newEngineCmd(rf *rootFlags) *cobra.Command {
	af := &autoFlags{}
	cmd := &cobra.Command{
		Use:   "auto",
		Short: "全自动运维引擎（协议驱动，零人工干预）",
		Long: `协议驱动引擎：L0 确定性快检 → 线索追查（DeepDive）→ 动态处置（三件套
契约）→ 实时报告，全程零人工干预。收敛模式：连续 2 轮无新增线索且
全部确认故障已处置才退出（退出码 0=收敛，1=未收敛；证据不足的线索
如实进报告待查区，处置达限未修由停滞检测强制非零退出），运行中
Ctrl+C 提前结束。不预装任何故障知识，靠三个通用机制应对未知环境
（未知故障、异常隐患、安全隐患）：协议骨架、痕迹追踪、验证回路。
配置自动发现（.gocode/hosts.yaml / .gocode/AGENTS.md /
.gocode/prompt.engine.md），报告实时生成在 <工作目录>/report.md，
评分结果写入 result.json（converged/error/elapsed/findings）。`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(c *cobra.Command, args []string) error {
			if !model.IsInitialized(rf.workDir) {
				fmt.Fprintln(os.Stderr, "gocode-ops:", notInitHint(rf.workDir))
			}
			if af.initDesired {
				created, err := probe.InitDesired(rf.workDir)
				if err != nil {
					return err
				}
				if created {
					fmt.Fprintln(os.Stderr, "[gocode-ops] 期望状态模板已创建: .gocode/desired.json（按需编辑角色/期望/策略后运行 auto）")
				} else {
					fmt.Fprintln(os.Stderr, "[gocode-ops] 期望状态已存在: .gocode/desired.json")
				}
				return nil
			}
			// 终端/非终端同一路径：引擎直接运行，日志实时输出到 stderr。
			os.Exit(runAutopilot(rf, af))
			return nil
		},
	}
	cmd.Flags().DurationVar(&af.timeout, "timeout", 0, "全局时限（如 30m/2h）；0=不设时限，收敛或停滞才退出")
	cmd.Flags().StringVar(&af.jsonPath, "json", "", "result.json 输出路径（缺省 <工作目录>/result.json）")
	cmd.Flags().DurationVar(&af.watch, "watch", 0, "watch 模式（常驻守护）：先收敛当前问题，再按该周期持续感知并自动处置复发（如 5m）；0=任务模式（收敛即退出）")
	cmd.Flags().IntVar(&af.parallel, "parallel", 6, "并行 worker 数（子代理池）：DeepDive 单线索/Respond 双故障批次并行上限（1=串行；API 限流环境建议调低）")
	cmd.Flags().BoolVar(&af.initDesired, "init-desired", false, "初始化期望状态文件（.gocode/desired.json 模板）后退出")
	return cmd
}
