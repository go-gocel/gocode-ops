package autopilot

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-gocel/gocel-core/core/kernel"
	"github.com/go-gocel/gocel-core/types"
	"github.com/go-gocel/gocel/tools/shell"

	"github.com/go-gocel/gocode-ops/internal/common/agent"
	"github.com/go-gocel/gocode-ops/internal/common/audit"
	"github.com/go-gocel/gocode-ops/internal/common/env"
	"github.com/go-gocel/gocode-ops/internal/common/guard"
	"github.com/go-gocel/gocode-ops/internal/common/model"
	"github.com/go-gocel/gocode-ops/internal/common/probe"
	"github.com/go-gocel/gocode-ops/internal/common/remote"
	"github.com/go-gocel/gocode-ops/internal/common/session"
	"github.com/go-gocel/gocode-ops/internal/common/tools"
	"github.com/go-gocel/gocode-ops/internal/common/workspace"
)

// ── 共享域类型的包内别名（单一来源在 common 公用内核）───────────────────
//
// engine 只做自动协议骨架（阶段推进/收敛/处置执行），发现/工作区/守卫/
// 远程执行等域类型由 ops 定义。别名让引擎代码直接用短名引用共享类型，
// 不复制定义。

type (
	// Phase is a package-level alias for model.Phase.
	// Phase 是 model.Phase 的适配层别名。
	Phase       = model.Phase
	// Finding is a package-level alias for model.Finding.
	// Finding 是 model.Finding 的适配层别名。
	Finding     = model.Finding
	// PhaseLog is a package-level alias for workspace.PhaseLog.
	// PhaseLog 是 workspace.PhaseLog 的适配层别名。
	PhaseLog    = workspace.PhaseLog
	// EnvInfo is a package-level alias for model.EnvInfo.
	// EnvInfo 是 model.EnvInfo 的适配层别名。
	EnvInfo     = model.EnvInfo
	// Env is a package-level alias for env.Env.
	// Env 是 env.Env 的适配层别名。
	Env         = env.Env
	// Action is a package-level alias for model.Action.
	// Action 是 model.Action 的适配层别名。
	Action      = model.Action
	// Session is a package-level alias for session.Session.
	// Session 是 session.Session 的适配层别名。
	Session     = session.Session
	// LenientBool is a package-level alias for model.LenientBool.
	// LenientBool 是 model.LenientBool 的适配层别名。
	LenientBool = model.LenientBool
)

// PhaseSurvey is the survey phase of the engine's protocol skeleton.
// 模型阶段常量：ops 只保留 PhaseRescan（报告层合并依赖），其余阶段是
// 引擎协议骨架（survey/deepdive/respond）专属。
const (
	PhaseSurvey   Phase = "survey"
	PhaseDeepDive Phase = "deepdive"
	PhaseRespond  Phase = "respond"
	PhaseRescan         = model.PhaseRescan

	SourceL0         = model.SourceL0
	SourceDeepDive   = model.SourceDeepDive
	FindingPending   = model.FindingPending
	FindingConfirmed = model.FindingConfirmed
	FindingDismissed = model.FindingDismissed
)

// PhaseSummary is the structured summary (JSON contract) produced at the end
// of each phase.
// PhaseSummary 每个阶段结束时的结构化小结（JSON 契约）。
//
// 引擎解析小结并校验契约（如 survey 必须声明 covered 非空），
// 校验失败 → 重试一次或确定性兜底——自动化推进不依赖模型自觉。
type PhaseSummary struct {
	Phase    string      `json:"phase"`
	Done     LenientBool `json:"done"`               // 本阶段是否完成（模型可能输出字符串布尔）
	Findings []*Finding  `json:"findings,omitempty"` // 发现（线索/确认/排除）
	Covered  []string    `json:"covered,omitempty"`  // 检查覆盖声明（域）
	Skipped  []string    `json:"skipped,omitempty"`  // 无法检查的项（含原因）
	Env      *EnvInfo    `json:"env,omitempty"`      // survey 产出：环境画像
	Notes    string      `json:"notes,omitempty"`
	Next     string      `json:"next,omitempty"` // 建议的下一步（引擎参考，不强制）
}

// phaseAgent 阶段 ReAct 子任务执行器。
//
// 工具集：terminal（本地）+ remote_terminal（远程）+ 认知工具族
// （collect_probe/recall/update_workbench，hooks 非 nil 时装配）——
// 模型用 shell 追查一切 + 大脑用定向采集/经验/作战图做认知。守卫由
// 引擎共享（PolicyAuto，经 agent.AgentConfig.Guard 注入），AGENTS.md 模块
// 挂 OnMessagesBuilt 注入环境信息。事件经 Session 注入（「初始指令 →
// 工作」统一执行模型）。
type phaseAgent struct {
	sess *Session
}

// newPhaseAgent 创建阶段 agent（model 为 nil 时返回 nil）。
//
// 系统提示：工作目录 .gocode/prompt.engine.md 存在且含有效内容时覆盖
// 内置系统提示（提示词可配），模板变量 {{workdir}}/{{hosts}}/{{host}}
// 在加载时渲染；AGENTS.md 模块挂 OnMessagesBuilt 注入环境信息。
// onEvent 非 nil 时把模型调用/工具调用/结果事件实时上抛（引擎日志），
// nil 则不产生事件。hooks 非 nil 时装配认知工具族（大脑的"手"）。
// auditLog 非 nil 时挂工具调用审计（引擎形态同样全量留痕——survey/
// deepdive 主体的只读工具调用此前无 tool 审计，守卫决策记录只覆盖
// 命中规则/风险审查的命令）。
func newPhaseAgent(llm kernel.Model, risky *guard.RiskyCommandGuard, remote remote.RemoteExecutor, agentsmd *agent.AgentsMDModule, workDir string, vars map[string]string, onEvent func(*types.Event), hooks *cognitionHooks, auditLog *audit.AuditLog) (*phaseAgent, error) {
	if llm == nil {
		return nil, nil
	}

	modules := make([]kernel.Module, 0, 2)
	if agentsmd != nil {
		modules = append(modules, agentsmd)
	}
	if auditLog != nil {
		modules = append(modules, &audit.AuditModule{Log: auditLog})
	}

	app, err := agent.NewAgent(agent.AgentConfig{
		Model:        llm,
		Name:         "ops-engine-phase",
		SystemPrompt: loadPrompt(workDir, vars),
		MaxSteps:     40,
		WorkDir:      workDir,
		Policy:       guard.PolicyAuto,
		Guard:        risky,
		// 阶段小结是结构化 JSON 契约：强制 JSON 输出模式，由服务端保证
		// 语法合法（不支持 response_format 的提供商自动忽略该参数）。
		JSONOutput: true,
		ToolBuilder: func(g *guard.RiskyCommandGuard) []kernel.Tool {
			toolSet := shell.AllTools(shell.WithDefaultTimeout(tools.TerminalDefaultTimeout), shell.WithMaxTimeout(tools.TerminalMaxTimeout))
			if remote != nil {
				toolSet = append(toolSet, tools.RemoteTerminalTool(remote, g))
			}
			if hooks != nil {
				toolSet = append(toolSet, collectProbeTool(hooks), recallTool(hooks), updateBenchTool(hooks))
			}
			return toolSet
		},
		Modules: modules,
	})
	if err != nil {
		return nil, fmt.Errorf("engine: assemble phase agent: %w", err)
	}

	var sink func(*types.Event) bool
	if onEvent != nil {
		sink = func(ev *types.Event) bool {
			onEvent(ev)
			return true
		}
	}
	return &phaseAgent{sess: session.NewSession(app, sink, false)}, nil
}

// runPhase 执行一个阶段：构造任务提示词 → agent 运行 → 解析小结。
// 返回 (小结, 原始输出)。解析失败时小结为 nil（由调用方决定重试/兜底）。
// maxSteps>0 时限制本次会话 ReAct 步数（阶段职责机械约束，见
// Session.RunFreshSteps；0=不限制）。
func runPhase(ctx context.Context, app *phaseAgent, phase Phase, task string, timeout time.Duration, maxSteps int) (*PhaseSummary, string, error) {
	if app == nil {
		return nil, "", fmt.Errorf("phase %s: 未配置模型", phase)
	}
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	res, err := app.sess.RunFreshSteps(pctx, task, maxSteps)
	if err != nil {
		return nil, "", fmt.Errorf("phase %s: %w", phase, err)
	}
	content := strings.TrimSpace(res.Content)
	sum, err := parsePhaseSummary(content)
	if err != nil {
		return nil, content, fmt.Errorf("phase %s: 小结解析失败: %w", phase, err)
	}
	return sum, content, nil
}

// parsePhaseSummary 从 agent 输出解析阶段小结（容忍代码块包裹与前后缀文本，
// 并经 parseModelJSON 做语法容错）。
func parsePhaseSummary(content string) (*PhaseSummary, error) {
	var sum PhaseSummary
	if err := parseModelJSON(content, &sum); err != nil {
		return nil, fmt.Errorf("非法 JSON: %w", err)
	}
	return &sum, nil
}

// fullCoverageDomains Survey 全域覆盖契约：模型必须逐域声明检查覆盖。
// 覆盖契约是"覆盖说谎"的闸门——模型说查过但实际没查的域会被引擎
// 追问补查（validate 失败 → 反馈重试）；查不了的必须如实声明 skipped
// 并说明原因（进报告，不假装覆盖）。
var fullCoverageDomains = []string{
	"cpu", "mem", "disk", "inode", "zombie", // 资源
	"svc", "process", "network", "log", // 运行时
	"cron", "security", // 配置与安全
}

// validate 阶段契约校验：要求 mustCover 全部被 covered 或 skipped 声明
// （skipped=尝试过但查不了，如实交代即可）；校验失败返回 error，调用方
// 按协议重试（反馈追问）或兜底。
func (s *PhaseSummary) validate(phase Phase, mustCover []string) error {
	if s == nil {
		return fmt.Errorf("phase %s: 小结为空", phase)
	}
	if !s.Done {
		return fmt.Errorf("phase %s: 未声明完成", phase)
	}
	if len(s.Covered) == 0 {
		return fmt.Errorf("phase %s: 未声明检查覆盖（covered 为空）", phase)
	}
	declared := append(append([]string{}, s.Covered...), s.Skipped...)
	for _, need := range mustCover {
		if !containsFold(declared, need) {
			return fmt.Errorf("phase %s: 未声明检查覆盖 %q（covered=%v skipped=%v）", phase, need, s.Covered, s.Skipped)
		}
	}
	return nil
}

func containsFold(list []string, want string) bool {
	for _, s := range list {
		if strings.EqualFold(strings.TrimSpace(s), want) {
			return true
		}
	}
	return false
}

// taskPrompt 构造阶段任务提示：阶段目标 + 工作区状态 + 引擎专属规则
// （阶段分工/安全）+ 输出契约。引擎专属规则附在任务层而非系统提示层——
// 系统提示（autopilot.SystemPrompt）与 交互式运维助手（assistant.SystemPrompt）
// 各自独立成文，共享规则与方法论构建块单一来源在 ops。
func taskPrompt(phase Phase, goal string, state string, maxSteps int) string {
	return taskPromptWithHints(phase, goal, state, maxSteps, "")
}

// taskPromptWithHints 同 taskPrompt，追加 hints 块（工具错误反馈/经验
// 预检等引擎注入的上下文，P0 修复——见 Engine.toolErrFeedback）。
func taskPromptWithHints(phase Phase, goal string, state string, maxSteps int, hints string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## 当前阶段：%s\n\n%s\n\n", phase, goal)
	if hints != "" {
		fmt.Fprintf(&b, "%s\n\n", hints)
	}
	if state != "" {
		fmt.Fprintf(&b, "## 已知状态（工作区）\n%s\n\n", state)
	}
	b.WriteString("说明：已知状态中的 l0_facts 是引擎确定性采集的环境事实（监听端口/用户/大文件/连接等），可直接作为检查依据，无需重复采集。\n\n")
	b.WriteString(`## 阶段分工（控制节奏）
- survey：快速全扫三合一（环境画像/全域基线/安全隐患）——每域用 1-2 条
  命令覆盖，疑点进 findings（pending），不做深挖；不要重复采集 l0_facts
  已提供的事实。
- deepdive：只对线索深挖（时间线/系统自省/对比 → 假设 → 只读验证）。
- respond：生成处置方案。

## 安全
- 只读命令直接执行；变更类命令（重启/安装/删除/修改）会被安全守卫审查——
  不要尝试绕过（换写法/加 sudo/拼接均不允许），需要处置时在 findings 中
  标记为 confirmed 并在后续 respond 阶段生成处置方案。
- 任何疑点（可疑/异常/后门/待查等）必须进 findings（status=pending），
  notes/next 只允许流程说明——引擎会从自由文本提取疑点兜底，但结构化
  输出更可靠。

`)
	b.WriteString(`## 输出契约
阶段结束时输出一个 JSON 对象（不要输出 JSON 以外的内容）：
{
  "phase": "<阶段名>",
  "done": true,
	  "findings": [可选，每条发现（线索/确认/排除）：
	    {"host":"<主机>","domain":"<域>","signal":"<稳定信号名>","desc":"<现象>",
	     "key":"<可选，线索子键——复述 L0 线索的对象（违规行/端口/挂载点）原值才能与 L0 线索合并为同一条>",
	     "status":"pending|confirmed|dismissed","evidence":["<证据命令或输出要点>"],
	     "root_cause":"<可选，根因>","confidence":0.0~1.0}],
	  "covered": ["<检查覆盖的域，必须是以下全域的子集并尽量全覆盖：cpu/mem/disk/inode/zombie/svc/process/network/log/cron/security；k8s 域在环境具备 kubectl 时声明（pod/deployment/node/配额/敏感配置）>"],
	  "skipped": ["<无法检查的项及原因（查不了必须如实声明，不得假装覆盖）>"],
  	"env": {仅 survey 阶段；布尔值必须输出 true/false（不要写成字符串）：
    "os":"Ubuntu 22.04","kernel":"5.15","hostname":"web-01","service_mgr":"systemd",
    "container": false,"docker_cmd":"docker","network":"192.168.1.0/24",
    "services":["nginx"],"log_paths":["/var/log/nginx/"],
    "toolchain":{"curl":"/usr/bin/curl"}},
  "notes": "<说明>",
  "next": "<建议下一步>"
}
规则：
1. 只做只读检查（高危命令会被守卫拒绝，不要尝试绕过）；
2. 任何 status=confirmed 的发现必须有证据（evidence 非空）；
3. status 默认 pending；未经验证不得确认；
4. 所有疑点（可疑/异常/后门/待查等）必须进 findings（status=pending）——
   notes/next 只允许流程说明，不允许承载疑点；引擎会从自由文本提取
   疑点兜底，但结构化输出更可靠；
5. 裁决证据门槛：confidence 与证据强度挂钩——单一弱证据（仅 mtime、仅
   文件名相似）不高于 0.5，不得凭此 confirm；confirm 需要可复述的
   正面证据（命令输出/前后对比/多来源一致）；排除（dismissed）同样
   需要实测依据——要列出具体对象与只读验证结果，猜测性排除（"容器
   常见"、"属正常"）必须先验证后下结论；
`)
	// 规则 5 引用 L0 稳定信号词表（单一来源：ops/judge.go）——signal 是
	// 去重键，模型不得为同一根因发明新名称，否则同根因会分裂成多条重复确认。
	fmt.Fprintf(&b, "6. signal 是去重键：同一根因必须复用同一 signal 名（L0 信号词表：%s），不得为同一根因发明新名称；大小写与空格保持一致。\n", strings.Join(probe.SignalNames(), "/"))
	return b.String()
}
