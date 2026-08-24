// Package autopilot — 全自动运维引擎（无人值守：协议骨架驱动巡检/排障/
// 处置，收敛或如实退出）。依赖公用内核 common（L0 确定性层/工作区/
// 报告/守卫/审计/远程执行/处置执行器）。
//
// 设计目标：纯库——gocode-ops 的 auto 子命令直接 import 驱动（CLI 薄壳
// 在 cmd/gocode-ops/engine.go）；也可被其他宿主嵌入托管：SetLogOut 接入
// 界面日志、OnEvent 上抛工具调用/结果事件、Run 阻塞直至收敛/停滞/超时。
//
// 三个通用机制应对未知环境（知识驱动 + 协议骨架）：
//  1. 协议骨架：survey（巡检三合一）→ deepdive → respond → 复扫 → 终裁，
//     引擎只管推进、超时、安全；每阶段查什么由模型基于现场与方法论决定；
//  2. 痕迹机制：L0 确定性快检（公用内核）产"线索"不产结论；
//  3. 验证回路：三态裁决 + 三件套契约（remediate）+ 处置后确定性复检——
//     误报与假 ✓ 在结构上被排除。
package autopilot

import (
	"context"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gocel/gocel-core/core/kernel"
	"github.com/go-gocel/gocel-core/types"

	"github.com/go-gocel/gocode-ops/internal/common/agent"
	"github.com/go-gocel/gocode-ops/internal/common/audit"
	"github.com/go-gocel/gocode-ops/internal/common/env"
	"github.com/go-gocel/gocode-ops/internal/common/guard"
	"github.com/go-gocel/gocode-ops/internal/common/l0"
	"github.com/go-gocel/gocode-ops/internal/common/memory"
	"github.com/go-gocel/gocode-ops/internal/common/model"
	"github.com/go-gocel/gocode-ops/internal/common/remediate"
	"github.com/go-gocel/gocode-ops/internal/common/remote"
	"github.com/go-gocel/gocode-ops/internal/common/workbench"
	"github.com/go-gocel/gocode-ops/internal/common/workspace"
)

// Engine is the fully autonomous operations engine.
// Engine 全自动运维引擎。
type Engine struct {
	// core 公用内核（L0 快检/工作区/报告/预热）。
	core   *l0.Engine
	cfg    Config
	guard  *guard.RiskyCommandGuard
	remote remote.RemoteExecutor
	audit  *audit.AuditLog
	model  kernel.Model // nil=纯 L0（无模型阶段）
	app    *phaseAgent  // 阶段 agent（model nil 时为 nil）
	// workers 并行 worker 池的独立阶段 agent（每 worker 一个 App/Session，
	// 懒装配；Session.RunFresh 写 history 不可共享）。
	workers    []*phaseAgent
	workerOnce sync.Once
	// tplVars 提示词模板变量（worker 装配复用）。
	tplVars map[string]string
	// wb 认知工作台（作战图/假设/待验证，nil=不可用降级）。
	wb *workbench.Workbench
	// mem 记忆仓库（经验库/主机档案，nil=不可用降级）。
	mem *memory.Memory
	// logMu 日志输出互斥（并行 worker 并发写日志不交错）。
	logMu sync.Mutex
	// agentsmd 环境信息约定模块（AGENTS.md 注入模型上下文）。
	agentsmd *agent.AgentsMDModule
	// retryBackoff 阶段/处置失败重试前的退避（默认指数退避+抖动；测试注入 0）。
	retryBackoff func(attempt int) time.Duration
	// rescanDone 复扫确认标记（环境变脏后重置，要求再复扫一次）；
	// rescanOK 最近一次复扫是否完成（收敛结论如实标注）。
	rescanDone bool
	rescanOK   bool
	// finalAdjudicateFailed 收敛前终裁最近一次是否全部批次失败（收敛
	// 结论如实标注"存在未终裁待查项"——终裁失败不得静默收敛）。
	finalAdjudicateFailed bool
	// watchConverged watch 模式收敛阶段是否成功（评分结论如实：未收敛
	// 进入守护不等于收敛）。
	watchConverged bool
	// roundsSinceRescan 距上次复扫的轮数（脏环境下周期复扫的触发
	// 依据：收敛前复扫只在干净轮触发，脏环境长期不收敛时首轮漏检
	// 的域需要周期换视角复查——漏检窗口由此闭合）。
	roundsSinceRescan int
	// currentPhase 当前阶段（事件日志前缀）。并行批次并发写——原子化
	// （setPhase/getPhase）。
	currentPhase atomic.Value // Phase
	// onEvent 阶段事件回调（工具调用/结果——TUI 嵌入实时展示）。
	onEvent func(*types.Event)
	// stats 运行期统计（日志摘要用；并行 worker 并发写）。
	stats runStats
	// toolErrMu 工具错误反馈缓冲互斥（并行 worker 并发写读）。
	toolErrMu sync.Mutex
	// toolErrs 最近工具失败（"tool: 错误摘要"），注入下一阶段任务提示
	// （P0 修复：ReAct 无跨轮记忆，模型会重复同样的失败调用——chaos-r1
	// 实测 remote_terminal 缺 host 参数连续报错 29 次；把上轮失败与
	// 修正提示带回上下文，同类错误不再复发）。
	toolErrs []string
}

// runStats 运行期计数器（结束摘要的机器可读依据——复盘不再靠 grep 数）。
type runStats struct {
	toolCalls   atomic.Int64 // 工具调用总数
	toolErrors  atomic.Int64 // 工具结果失败（✗）
	toolBlocked atomic.Int64 // 其中：安全守卫拦截
	batchFails  atomic.Int64 // 阶段批失败（DeepDive/终裁/Respond）
	rollbacks   atomic.Int64 // 处置回滚
}

// maxRespondTries 处置尝试上限（单一来源在 remediate.MaxTries——处置
// 机制是公用内核能力，达限升级人工工单的语义两边一致）。
const maxRespondTries = remediate.MaxTries

// ── 处置执行器装配（执行机制单一来源在 common/remediate）────────────

// remediateCfg 处置执行配置（autopilot Config → remediate.Config）。
func (e *Engine) remediateCfg() remediate.Config {
	return remediate.Config{
		ActTimeout:    e.cfg.ActTimeout,
		VerifyTimeout: e.cfg.VerifyTimeout,
		Local:         e.cfg.Local,
		LocalHost:     e.cfg.LocalHost,
		Guard:         e.guard,
	}
}

// executor 处置执行器（三件套契约执行/验证/回滚/幂等预检）。
func (e *Engine) executor() *remediate.Executor {
	return remediate.NewExecutor(e.remediateCfg(), e.guard, e.remote, e.logf, &e.stats.rollbacks)
}

// rechecker 处置后确定性复检器（模型 verify ✓ 不算数，线索消失才算）。
func (e *Engine) rechecker() *remediate.Rechecker {
	return &remediate.Rechecker{L0: e.core, Thresholds: e.cfg.Thresholds, Logf: e.logf}
}

// NewEngine creates a fully autonomous operations engine. llm may be nil to run L0 only (debugging).
// NewEngine 创建全自动运维引擎。llm 可为 nil：只跑 L0（调试）。
// remote 可为 nil：仅本机。
func NewEngine(cfg Config, llm kernel.Model, remote remote.RemoteExecutor) (*Engine, error) {
	e := env.DetectEnv(context.Background())
	mergeRemoteEnv(e, cfg, remote)
	return newEngine(cfg, llm, remote, e)
}

// mergeRemoteEnv 把远端系统面能力合并进本机环境（机制层修复，演练
// R5）：L0 快检的探针清单按环境裁剪（HasSystemd/HasDocker/HasSS），
// Windows 本机恒无 systemd——直接用本机环境会让远端 Linux 目标缺失
// 全部 systemd 探针（svc_failed/svc_inactive/log_errors/svc_units/
// enabled_units 等），站点健康门控因此静默失效（R5 实测 site_down
// 快检不产线）。远端确定性只读探测补齐：OR 语义只增强不降级，探测
// 失败静默降级（不虚报能力）。
func mergeRemoteEnv(e *env.Env, cfg Config, remote remote.RemoteExecutor) {
	if remote == nil || len(cfg.EngineConfig.Hosts) == 0 {
		return
	}
	if re := detectRemoteEnv(context.Background(), remote, cfg.EngineConfig.Hosts); re != nil {
		e.HasSystemd = e.HasSystemd || re.HasSystemd
		e.HasDocker = e.HasDocker || re.HasDocker
		e.HasSS = e.HasSS || re.HasSS
	}
}

// remoteEnvProbe 远端系统面确定性只读探测命令：systemd 运行目录/docker、
// ss 二进制存在性。命令固定、只读、带 timeout 护栏，失败静默降级
// （与 env.DetectEnv 同级确定性验证豁免——不产错误、不阻塞启动）。
const remoteEnvProbe = "test -d /run/systemd/system && echo SYSTEMD=1; command -v docker >/dev/null 2>&1 && echo DOCKER=1; command -v ss >/dev/null 2>&1 && echo SS=1; true"

// remoteEnvProbeTimeout 远端环境探测超时：连不上/挂死时快速放弃
// （快检清单裁剪不完整时由缺失降级兜底，不得拖慢启动）。
const remoteEnvProbeTimeout = 10 * time.Second

// detectRemoteEnv 在远端目标上执行确定性只读探测，返回目标侧系统面
// 能力。多目标取首个成功结果（同构组假定：探测失败的目标按缺失降级，
// 不因单台失败丢弃整体能力）。全部失败返回 nil（调用方不补齐）。
func detectRemoteEnv(ctx context.Context, remote remote.RemoteExecutor, hosts []string) *env.Env {
	rctx, cancel := context.WithTimeout(ctx, remoteEnvProbeTimeout)
	defer cancel()
	out, err := remote.Exec(rctx, hosts, remoteEnvProbe, remoteEnvProbeTimeout)
	if err != nil && strings.TrimSpace(out) == "" {
		return nil
	}
	e := &env.Env{}
	for _, line := range strings.Split(out, "\n") {
		switch strings.TrimSpace(line) {
		case "SYSTEMD=1":
			e.HasSystemd = true
		case "DOCKER=1":
			e.HasDocker = true
		case "SS=1":
			e.HasSS = true
		}
	}
	if !e.HasSystemd && !e.HasDocker && !e.HasSS {
		return nil // 无任何能力信号：视为探测失败，不补齐
	}
	return e
}

// newEngine 内部构造（测试注入确定性环境探测结果）。
func newEngine(cfg Config, llm kernel.Model, remote remote.RemoteExecutor, env *env.Env) (*Engine, error) {
	core, err := l0.NewEngineWithEnv(cfg.EngineConfig, remote, env)
	if err != nil {
		return nil, err
	}
	risky := guard.NewRiskyCommandGuard(nil, guard.PolicyAuto)
	al, err := audit.NewAuditLog(cfg.WorkDir)
	if err != nil {
		return nil, err
	}
	risky.Audit = al
	if remote != nil {
		risky.ResolveHosts = remote.Resolve
		// 自影响审查需要连接事实（用户/认证方式/管理端口）；
		// remote 未实现时按保守模式（通道面一律视为风险）。
		if rf, ok := remote.(interface {
			ConnFacts([]string) map[string]model.ConnFact
		}); ok {
			risky.ConnFacts = rf.ConnFacts
		}
	}
	vars := l0.EngineTemplateVars(cfg.EngineConfig)
	// 认知工作台与记忆仓库：失败不致命（认知/记忆降级为不可用，
	// 确定性路径不受影响——架构兼容承诺）。
	wb, wbErr := workbench.NewWorkbench(cfg.WorkDir)
	if wbErr != nil {
		wb = nil
	}
	mem, memErr := memory.NewMemory(cfg.WorkDir)
	if memErr != nil {
		mem = nil
	}
	// l0.NewEngine 在 AgentsMDPath 为空时自动解析为 <工作目录>/.gocode/AGENTS.md——
	// 以底座解析后的配置为准（单一来源）。
	resolvedCfg := core.Config()
	e := &Engine{
		core:         core,
		cfg:          cfg,
		guard:        risky,
		remote:       remote,
		audit:        al,
		tplVars:      vars,
		wb:           wb,
		mem:          mem,
		agentsmd:     agent.NewAgentsMDModule(resolvedCfg.AgentsMDPath, vars),
		retryBackoff: defaultRetryBackoff,
	}
	if llm != nil {
		e.model = llm
		// 事件回调把阶段 agent 的工具调用/结果实时打进引擎日志。
		hooks := &cognitionHooks{
			collectProbe: e.collectProbe,
			recall:       e.recall,
			updateBench:  e.updateBench,
		}
		app, err := newPhaseAgent(llm, risky, remote, e.agentsmd, cfg.WorkDir, vars, e.onPhaseEvent, hooks, al)
		if err != nil {
			return nil, err
		}
		e.app = app
	}
	return e, nil
}

// ── 嵌入接口（gocode-ops 托管模式：import engine 即可驱动）───────────

// Core returns the shared kernel (L0 quick-scan, workspace, and report).
// Core 返回公用内核（L0 快检/工作区/报告）。
func (e *Engine) Core() *l0.Engine { return e.core }

// WatchConverged reports whether the watch-mode convergence phase succeeded, so result.json's converged flag is not inflated by continued guarding.
// WatchConverged 返回 watch 模式收敛阶段是否成功（评分结论如实：
// result.json 的 converged 不因 watch 继续守护而虚报）。
func (e *Engine) WatchConverged() bool { return e.watchConverged }

// ReportPath returns the live report file path.
// ReportPath 实时报告路径。
func (e *Engine) ReportPath() string { return e.core.ReportPath() }

// RenderReport renders the live report; the engine loop calls it every round and embedding hosts may refresh it proactively.
// RenderReport 渲染实时报告（引擎每轮循环自动调用；嵌入方也可主动刷新）。
func (e *Engine) RenderReport() error { return e.core.RenderReport() }

// SetLogOut replaces the engine log output (TUI embedding: logs stream into the UI in real time).
// SetLogOut 替换引擎日志输出（TUI 嵌入：日志实时进界面）。
func (e *Engine) SetLogOut(w io.Writer) { e.core.SetLogOut(w) }

// OnEvent registers a phase-event callback (tool calls, results, and failures for real-time TUI display); nil cancels it.
// OnEvent 注册阶段事件回调（工具调用/结果/失败——TUI 实时展示）；nil 取消。
func (e *Engine) OnEvent(fn func(*types.Event)) { e.onEvent = fn }

// Logf writes an engine log line through the same output channel as the shared kernel.
// Logf 引擎日志（与公用内核同一输出通道）。
func (e *Engine) Logf(format string, args ...any) { e.core.Logf(format, args...) }

// logf 内部日志薄封装（引擎循环代码原样调用）。并行 worker 并发写日志，
// 加锁防交错。
func (e *Engine) logf(format string, args ...any) {
	e.logMu.Lock()
	defer e.logMu.Unlock()
	e.core.Logf(format, args...)
}

// ws 薄封装：引擎循环代码原样访问共享工作区。
func (e *Engine) ws() *workspace.Workspace { return e.core.Workspace() }

// Warmup runs one warm-up L0 quick-scan round so the first task's snapshot returns instantly while the full rescan finishes in the background.
// Warmup 预热一轮 L0 快检（嵌入方在启动后异步调用：重探针全盘扫描
// 在后台完成，首个任务的快检即时返回）。
func (e *Engine) Warmup(ctx context.Context) []*model.Finding { return e.core.Warmup(ctx) }
