// gocode-ops 是 Linux 运维/实施/部署领域的 AI 助手 CLI（Cobra + TermAgent
// TUI），单一入口、一个产品的两种形态：
//
//   - 交互式运维助手（默认，人在环形态）：底部输入框下达任务，对话区流式
//     展示思考与回答，本地/远程命令输出实时可见；高危命令执行前确认，
//     ask_operator 提问在界面内应答；远程能力按粒度拆分为工具族（单机/
//     批量/上传/下载/文件信息/清单）。操作员输入按队列串行执行，Ctrl+C
//     可中断当前任务。非终端环境（管道/脚本）退化为非交互模式：执行
//     一次任务后退出。
//   - 全自动运维引擎（auto 子命令，自主形态）：无人值守的协议引擎
//     （快检→判定→追查→处置→实时报告），退出码 + result.json 可机器
//     评分（比赛/评审）。auto 子命令只是自主形态的启动入口：装配后
//     直接运行（终端/非终端同一路径），引擎日志实时输出到终端（stderr），
//     与交互 TUI 完全隔离——TUI 不 import internal/autopilot，也不展示
//     引擎日志。自主形态核心在 internal/autopilot（纯库，可直接被
//     import 嵌入托管）。
//
// 包结构（公用内核 + 两种形态）：
//
//	internal/common       公用内核（两种形态的单一来源，每模块一个目录）：
//	                      model 领域模型/env 环境探测/probe 探针判定/
//	                      collect 采集编排/l0 L0 确定性引擎/workspace 工作区/
//	                      guard 守卫/audit 审计/remote 远程执行/memory 记忆/
//	                      workbench 认知工作台/agent 统一装配/session 执行模型/
//	                      tools 工具集/prompt 提示词构建块/fsutil 文件工具/
//	                      remediate 处置执行器
//	internal/assistant  交互形态独有：人在环装配（NewAgent）+ 交互提示词
//	internal/autopilot  自主形态独有：协议骨架 + 收敛循环（依赖 common）
//
// 配置约定：init 在工作目录生成 .gocode/ 隐藏目录（hosts.yaml 清单、
// AGENTS.md 环境约定、prompt.assistant.md / prompt.engine.md 提示词覆盖、
// helper.md 使用手册），运行时自动发现，无需任何参数；未 init 时给出提示。
// 模型：当前版本仅支持 DeepSeek（模型固定 deepseek-v4-flash，API Key 从
// 环境变量 DEEPSEEK_API_KEY 读取；多供应商支持后续经配置文件提供）。
//
// 文件组织（main 包，按职责拆分）：
//
//	main.go        入口与命令树（root/init/auto 子命令）
//	engine.go      auto 装配与运行（启动入口，终端/非终端同一路径）
//	taskrunner.go   会话封装（taskRunner）+ 操作员终端（tuiOperator）+ TUI 消息
//	tui_model.go   根模型：组件树组装/消息分发/任务队列
//	tui_view.go    布局渲染（View/headerView/hintView）+ 键位表
//	tui_keys.go    键盘处理 + 内置命令（/help /new ...）
//	tui_tools.go   工具调用表格
//	tui_hosts.go   远程主机页（清单/连通性探测）
//	tui_events.go  agent 事件流处理（工具过程/实时输出/结束收尾）
//	tui_ask.go     操作员提问弹窗（高危确认/ask_operator）
//	tui_strings.go 界面文案集中（状态/提示/帮助/命令，i18n 铺路）
//	plain.go       非终端模式输出
//	model.go       模型构建 + 工作目录模板
//	helper.md      完整使用手册（go:embed 打包进二进制，init 释放）
//	format.go      文本/尺寸工具
//
// 用法：
//
//	gocode-ops                                      # 交互 TUI
//	DEEPSEEK_API_KEY=... gocode-ops "巡检系统健康"   # 交互 TUI 带初始任务
//	gocode-ops init                                 # 初始化 .gocode/ 配置目录与模板
//	gocode-ops auto --timeout 2h                     # 全自动运维引擎（直接运行，日志实时输出）
//
// 全局参数 -d/--dir、-p/--provider、--risky、--theme 对交互式运维助手/
// init/auto 子命令通用；auto 忽略 --risky（引擎使用独立的自动策略），
// 另有 --timeout/--json。
//
// 交互式运维助手不设全局时限；L0 快检由模型按需触发（l0_snapshot 工具），
// 报告按需生成（操作员明确要求时经 generate_report 工具，不主动生成；
// 全自动引擎的报告由引擎主循环自动渲染）。
//
// 内置命令（输入框键入或 Ctrl+P 命令面板）：/help /new /hosts /tokens /export /exit
package main

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-gocel/termagent/pkg/runtime"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"github.com/go-gocel/gocode-ops/internal/common/model"
)

// helperManual 内置的完整使用手册（helper.md）：init 阶段释放到
// .gocode/helper.md，内容随二进制版本更新。
//
//go:embed helper.md
var helperManual string

// rootFlags 全局参数（交互式运维助手/init 子命令共享，定义在根命令上）。
//
// CLI 刻意精简：模型名固定 defaultModelName，API Key 只从环境变量读取，
// 主机清单固定 .gocode/hosts.yaml——模型/凭证/目标等连接配置不通过
// 命令行暴露，避免脚本场景参数失控。多供应商支持后续经 .gocode
// 配置文件提供，不在 CLI 扩张。
type rootFlags struct {
	workDir  string
	provider string
	risky    string
	theme    string
}

func main() {
	root := newRootCmd()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "gocode-ops:", err)
		os.Exit(1)
	}
}

// newRootCmd 构建命令树：根命令（交互式运维助手）+ init 子命令。
// -d/--dir、-p/--provider、--risky 全部是根命令的持久参数（全局），
// 子命令不再各自定义。
func newRootCmd() *cobra.Command {
	rf := &rootFlags{}

	cmd := &cobra.Command{
		Use:   "gocode-ops [任务...]",
		Short: "Linux 运维/实施/部署 Agent（交互式 TUI + 全自动运维引擎）",
		Long: `面向 Linux 运维与实施场景的 AI 助手（DeepSeek）。

交互式运维助手（默认）：巡检、诊断、日志分析、服务处置、环境部署、应用发布，
支持远程主机（批量）运维与文件传输；高危命令执行前确认，凭证对模型
不可见，操作全程审计。

全自动运维引擎（auto 子命令）：协议驱动引擎，零人工干预，面向未知故障
环境的自动巡检排障，报告实时生成，退出码 + result.json 可机器评分；
auto 子命令只是引擎的启动入口，终端/非终端都直接运行，日志实时输出到终端，
与交互 TUI 完全隔离。

首次使用建议先执行 gocode-ops init：在工作目录生成 .gocode/ 配置目录
（hosts.yaml 主机清单 / AGENTS.md 环境约定 / prompt.assistant.md 与
prompt.engine.md 提示词覆盖 / helper.md 使用手册），运行时自动发现。`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ArbitraryArgs,
		RunE: func(c *cobra.Command, args []string) error {
			return runAssistant(c, args, rf)
		},
	}

	pf := cmd.PersistentFlags()
	pf.StringVarP(&rf.workDir, "dir", "d", ".", "工作目录（巡检报告、脚本、审计日志与 .gocode/ 配置的落盘处）")
	pf.StringVarP(&rf.provider, "provider", "p", defaultProvider, "模型提供商（当前仅支持: deepseek；多供应商支持后续经配置文件提供）")
	pf.StringVar(&rf.risky, "risky", "ask", "高危命令策略: ask（逐条确认）| allow（自动放行）| deny（一律拒绝）")
	pf.StringVar(&rf.theme, "theme", "", "TUI 主题 JSON 文件（默认探测 .gocode/theme.json，缺失用内置主题）")

	cmd.AddCommand(newInitConfigCmd(rf), newEngineCmd(rf))
	return cmd
}

// isTerminalStdin 检测 stdin 是否为终端（与 runtime.IsTerminal 的 stdout
// 检测互补——两个都必须是终端才进 TUI）。
func isTerminalStdin() bool {
	return isatty.IsTerminal(os.Stdin.Fd())
}

// runAssistant 交互式运维助手入口：终端下进入 TUI，非终端退化为一次性执行。
func runAssistant(c *cobra.Command, args []string, rf *rootFlags) error {
	policy, err := parsePolicy(rf.risky)
	if err != nil {
		return err
	}
	dir := rf.workDir
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("创建工作目录失败: %w", err)
	}
	host := "localhost"
	if h, err := os.Hostname(); err == nil && h != "" {
		host = h
	}
	llm, err := buildModel(rf.provider, defaultModelName, "")
	if err != nil {
		return err
	}
	meta := tuiMeta{
		host:        host,
		workDir:     dir,
		model:       defaultModelName,
		risky:       rf.risky,
		invPath:     model.InventoryPath(rf.workDir),
		initialized: model.IsInitialized(rf.workDir),
		themeFile:   rf.theme,
	}
	initial := strings.TrimSpace(strings.Join(args, " "))

	// 终端检测：stdout 与 stdin 都必须是终端——stdin 为管道时（echo "任务" |
	// gocode-ops / gocode-ops < script.txt）进 TUI 会读到垃圾输入/raw 模式
	// 异常（P2 修复）。
	if runtime.IsTerminal() && isTerminalStdin() {
		os.Exit(runTUI(context.Background(), llm, meta, policy, initial))
	}
	if !meta.initialized {
		fmt.Fprintln(os.Stderr, "gocode-ops:", notInitHint(rf.workDir))
	}
	os.Exit(runPlain(context.Background(), llm, meta, policy, initial))
	return nil
}
