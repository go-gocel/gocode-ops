// Package assistant 是 gocode-ops 交互式运维助手的领域装配。
//
// 本包只放交互式运维助手（人在环形态）专属的装配与提示词：NewAgent
// （Operator + Policy、ask_operator、交互系统提示词）。公用内核在
// common（L0/工作区/报告/守卫/审计/远程执行/工具/方法论提示词）；
// 自主形态（全自动运维引擎）在 autopilot。
package assistant

import (
	"fmt"
	"os"

	"github.com/go-gocel/gocel-core/core/kernel"
	"github.com/go-gocel/gocel/agents"

	"github.com/go-gocel/gocode-ops/internal/common/agent"
	"github.com/go-gocel/gocode-ops/internal/common/audit"
	"github.com/go-gocel/gocode-ops/internal/common/collect"
	"github.com/go-gocel/gocode-ops/internal/common/guard"
	"github.com/go-gocel/gocode-ops/internal/common/l0"
	"github.com/go-gocel/gocode-ops/internal/common/memory"
	"github.com/go-gocel/gocode-ops/internal/common/model"
	"github.com/go-gocel/gocode-ops/internal/common/remote"
	"github.com/go-gocel/gocode-ops/internal/common/tools"
	"github.com/go-gocel/gocode-ops/internal/common/workspace"
)

// AgentName 标识 Linux 运维 agent。
const AgentName = "gocode-ops"

// maxLoopSteps 是运维任务的步数上限（1<<30 即"无实际上限"）：
// 终止由 React 策略（无工具调用即完成）与 ctx 取消决定，避免长任务
// （日志分析、批量巡检）被步数截断。
const maxLoopSteps = 1 << 30

// NewAgent 创建 Linux 运维领域的 ReAct agent（交互式运维助手默认装配）。
//
// 参数：
//   - llm：模型（kernel.Model）。
//   - workDir：工作目录。文件工具（write/multi_edit/trash）被限制在其中，
//     巡检报告、修复脚本等落地于此；系统路径的读写走 terminal（受安全守卫管控）。
//   - host：目标主机标识（仅用于提示词展示）。
//   - operator：操作员交互终端（实现 model.Operator 接口）。nil 表示
//     非交互环境，此时高危命令一律阻止（等同 PolicyDeny）。
//   - policy：高危命令策略（ask/allow/deny），见 guard.Policy。
//   - invPath：远程主机清单路径（凭证所在，模型不可见）；为空则不启用远程执行，
//     同时参与模板变量 {{hosts}} 的计算。
//
// 与全自动运维引擎同一套信息注入面、各自独立的提示词面：系统提示经
// loadAssistantPrompt 加载（.gocode/prompt.assistant.md 有效内容覆盖
// + {{变量}} 渲染，否则内置 SystemPrompt），AGENTS.md 模块注入环境信息——
// 信息注入单一来源，提示词成文相互独立（覆盖文件也不共用）。
//
// 安全模型是机械强制而非提示词约束：workspace 守卫限制文件工具范围；
// RiskyCommandGuard 在 OnToolCall 钩子中拦截高危 terminal 命令。
func NewAgent(llm kernel.Model, workDir, host string, operator model.Operator, policy guard.Policy, invPath string) (*agents.App, error) {
	return newAgent(llm, workDir, host, operator, policy, remote.NewSSHExecutor(remote.RemoteConfig{InventoryPath: invPath}), invPath, nil)
}

// NewAgentWithRemote 与 NewAgent 相同，但使用调用方提供的远程执行器
// （如 NewSSHExecutor 配 OnProgress 实现逐台流式回传，或测试注入 fake）。
func NewAgentWithRemote(llm kernel.Model, workDir, host string, operator model.Operator, policy guard.Policy, rmt remote.RemoteExecutor, invPath string) (*agents.App, error) {
	return newAgent(llm, workDir, host, operator, policy, rmt, invPath, nil)
}

// NewAgentWithL0 与 NewAgentWithRemote 相同，并注入 l0_snapshot 工具
// （公用内核快检，模型按需触发）。l0s 为 nil 时不追加该工具。
func NewAgentWithL0(llm kernel.Model, workDir, host string, operator model.Operator, policy guard.Policy, rmt remote.RemoteExecutor, invPath string, l0s model.L0Snapshooter) (*agents.App, error) {
	return newAgent(llm, workDir, host, operator, policy, rmt, invPath, l0s)
}

// newAgent 是 NewAgent 的内部实现，允许测试注入远程执行器与 L0。
func newAgent(llm kernel.Model, workDir, host string, operator model.Operator, policy guard.Policy, rmt remote.RemoteExecutor, invPath string, l0s model.L0Snapshooter) (*agents.App, error) {
	al, err := audit.NewAuditLog(workDir)
	if err != nil {
		// 审计缺失是安全降级：不能静默——操作员必须知道高危操作不会
		// 留痕（此前错误被吞掉，审计静默缺失无任何提示）。
		fmt.Fprintln(os.Stderr, "gocode-ops: 审计日志不可用（高危操作将不留痕）:", err)
		al = nil
	}
	// 记忆仓库（经验库/主机档案）：人在环的背书沉淀（守卫 OnApproved）
	// 与 recall 检索共用；失败不致命（记忆降级为不可用）。
	mem, _ := memory.NewMemory(workDir)
	vars := l0.TemplateVars(workDir, host, invPath)
	modules := make([]kernel.Module, 0, 3)
	if al != nil {
		modules = append(modules, &audit.AuditModule{Log: al})
	}
	// 环境信息注入与全自动运维引擎同一模块/同一文件（.gocode/AGENTS.md）——
	// 交互式运维助手同样吃环境约定，不因产品拆分而分裂。
	modules = append(modules, agent.NewAgentsMDModule(model.AgentsMDPath(workDir), vars))

	// 守卫注入（区别于默认内部创建）：挂操作员背书回调——高危命令经
	// 操作员确认（y/a/会话放行）即"人在环背书"，沉淀进主机档案
	// （越用越懂这台机器；PolicyAuto 不触发）。
	risky := guard.NewRiskyCommandGuard(operator, policy)
	if rmt != nil {
		risky.ResolveHosts = rmt.Resolve
		if rf, ok := rmt.(interface {
			ConnFacts([]string) map[string]model.ConnFact
		}); ok {
			risky.ConnFacts = rf.ConnFacts
		}
	}
	if al != nil {
		risky.Audit = al
	}
	if mem != nil {
		risky.OnApproved = func(cmd string, hosts []string) {
			h := "本机"
			if len(hosts) > 0 {
				h = hosts[0]
			}
			mem.RecordHostEvent(h, "history", "操作员批准: "+collect.TruncateStr(cmd, 120))
		}
	}

	// 定向采集能力：L0 底座实现 ProbeCollector（l0.Engine）时可用。
	var pc tools.ProbeCollector
	if l0s != nil {
		if v, ok := l0s.(tools.ProbeCollector); ok {
			pc = v
		}
	}
	// 报告按需生成：L0 底座实现 ReportRenderer（l0.Engine）时注册
	// generate_report 工具——操作员明确要求时才渲染 report.md（人在环
	// 不主动生成报告；全自动运维引擎不经过本装配，报告由引擎主循环
	// 自动渲染）。
	var rr tools.ReportRenderer
	if l0s != nil {
		if v, ok := l0s.(tools.ReportRenderer); ok {
			rr = v
		}
	}

	return agent.NewAgent(agent.AgentConfig{
		Model:        llm,
		Name:         AgentName,
		Description:  "Linux 运维 agent：巡检、诊断、处置、验证，高危操作需操作员确认。",
		SystemPrompt: buildAssistantSystem(workDir, host, policy, vars),
		MaxSteps:     maxLoopSteps,
		WorkDir:      workDir,
		Host:         host,
		Operator:     operator,
		Policy:       policy,
		Remote:       rmt,
		Audit:        al,
		Guard:        risky,
		Modules:      modules,
		L0:           l0s,
		// 认知工具：经验检索/定向采集/期望声明（人在环形态的接入面）。
		ToolBuilder: func(g *guard.RiskyCommandGuard) []kernel.Tool {
			toolSet := tools.AllTools(operator, rmt, g)
			toolSet = append(toolSet, tools.RecallTool(mem))
			if pc != nil {
				toolSet = append(toolSet, tools.CollectProbeTool(pc))
			}
			if rr != nil {
				toolSet = append(toolSet, tools.ReportTool(rr))
			}
			toolSet = append(toolSet, tools.UpdateDesiredTool(workDir))
			return toolSet
		},
	})
}

// buildAssistantSystem 构建交互助手系统提示：基础提示 + 引擎遗留状态
// （接力协同：引擎跑完遗留的未处置项/工单注入助手上下文，用户下达
// "接续处理"指令后助手直接接管处置；处置完再跑 auto 复检收敛）。
func buildAssistantSystem(workDir, host string, policy guard.Policy, vars map[string]string) string {
	sys := loadAssistantPrompt(workDir, host, policy, vars)
	if h := workspace.LoadHandoff(workDir); h.HasWork() {
		sys += "\n\n## 引擎遗留状态（接力协同）\n全自动引擎此前运行遗留以下未处置项与人工工单（处置完成后建议再运行一次 `gocode-ops auto` 让引擎复检确认收敛）：\n" + h.String()
	}
	return sys
}
