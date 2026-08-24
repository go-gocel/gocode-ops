// Engine 是 gocode-ops 公用内核的 L0 确定性引擎：快检/线索/基线/
// 漂移/安全事实）+ 工作区（findings 三态/基线/阶段记录）+ 实时报告 +
// 预热与快检接口。
//
// 两种形态共用本底座：
//   - gocode-ops（交互式运维助手）：每轮任务按需 SnapshotL0/任务后
//     RenderReport，人在环；
//   - autopilot（全自动运维引擎）：组合本内核 + 模型阶段协议骨架
//     （survey/deepdive/respond/复扫/终裁）与收敛循环。
//
// 三个通用机制应对未知环境（知识驱动 + 协议骨架）：
//  1. 痕迹机制：L0 确定性快检产生“线索”（不产结论）、多轮基线趋势、
//     多主机横向对比——故障必留痕，追痕不猜型；
//  2. 验证回路：发现三态（pending/confirmed/dismissed），处置只对
//     confirmed；任何结论必须有验证证据——误报在结构上被排除；
//  3. 安全：守卫机械强制（credential 零泄露/硬禁/自影响审查）——
//     命令级安全不依赖模型自觉。
package l0

import (
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-gocel/gocode-ops/internal/common/collect"
	"github.com/go-gocel/gocode-ops/internal/common/fsutil"
)

// 跨主机时钟偏差阈值（clock_skew）：warn ≥90s / crit ≥300s。NTP 正常
// 的主机偏差 <1s；90s 起点排除跨机房毫秒级抖动与 SSH 往返延迟。
const (
	clockSkewWarnSecs = 90.0
	clockSkewCritSecs = 300.0
)

// Engine is the shared kernel of gocode-ops (L0 inspection + workspace + report).
// Engine 公用内核（L0 + 工作区 + 报告）。
type Engine struct {
	cfg EngineConfig
	col *collect.Collector
	ws  *Workspace
	// started 引擎启动时间（报告计时）。
	started time.Time
	// lastLeads 上一轮 L0 快检去重后新增的线索数（收敛判定用）。
	lastLeads int
	// collectFail 上一轮 L0 快检是否存在主机整机采集失败（Errors["collect"]：
	// SSH 失联/口令过期/账户锁定等通道异常）。收敛判定用——目标不可达时
	// 不得判"环境干净"（失联状态被模型 dismissed 后仍会假收敛，P1 修复）。
	collectFail bool
	// rebaseline 下一轮 L0 对状态快照静默重基线（自身处置动作执行后置位——
	// 引擎自己的变更不产漂移线索）。只对进程派生类探针
	// （state_units/state_ports）整体生效；文件内容类探针在重基线轮仍做
	// 行级 diff + 自身动作归属（见 stateDrift）。
	rebaseline bool
	// selfCommands 最近一轮处置阶段真实执行的自身动作命令（重基线轮
	// 行级归属的依据；下一轮 L0 消费后清空）。
	selfCommands []string
	// conclusion 收敛模式退出结论（渲染进最终报告；引擎经 SetConclusion 写入）。
	conclusion string
	// logOut 引擎日志输出（默认 os.Stderr；TUI 嵌入/测试注入）。
	logOut io.Writer
	// stateMu 保护跨 goroutine 共享的引擎状态字段（lastLeads/rebaseline/
	// selfCommands/started/conclusion）：助手形态 Warmup goroutine 与任务
	// 快检轮并发访问；引擎主循环单线程，锁对其是无开销的空操作。
	stateMu sync.Mutex
}

// NewEngine creates the shared kernel; remote may be nil for local-only operation.
// NewEngine 创建公用内核。remote 可为 nil：仅本机。
// cfg.AgentsMDPath 非空时注入环境信息（供引擎阶段 agent 使用）。
func NewEngine(cfg EngineConfig, remote RemoteExecutor) (*Engine, error) {
	return newEngine(cfg, remote, DetectEnv(context.Background()))
}

// NewEngineWithEnv is like NewEngine but uses the caller-provided deterministic environment probe.
// NewEngineWithEnv 与 NewEngine 相同，但使用调用方提供的确定性环境探测
// 结果（测试注入/嵌入方预探测）。
func NewEngineWithEnv(cfg EngineConfig, remote RemoteExecutor, env *Env) (*Engine, error) {
	return newEngine(cfg, remote, env)
}

// newEngine 内部构造（测试可注入确定的探测结果）。
func newEngine(cfg EngineConfig, remote RemoteExecutor, env *Env) (*Engine, error) {
	if cfg.WorkDir == "" {
		return nil, fmt.Errorf("ops: WorkDir 不能为空")
	}
	if !cfg.Local && len(cfg.Hosts) == 0 {
		return nil, fmt.Errorf("ops: Local=false 且 Hosts 为空，没有巡检目标")
	}
	if cfg.LocalHost == "" {
		cfg.LocalHost = "localhost"
	}
	// 环境信息约定自动发现：未显式指定时默认工作目录 .gocode/AGENTS.md
	// （不存在则模块空转）。
	if cfg.AgentsMDPath == "" {
		cfg.AgentsMDPath = AgentsMDPath(cfg.WorkDir)
	}
	ws, err := NewWorkspace(cfg.WorkDir)
	if err != nil {
		return nil, err
	}
	return &Engine{
		cfg:    cfg,
		col:    collect.NewCollector(cfg, env, remote),
		ws:     ws,
		logOut: os.Stderr,
	}, nil
}

// Workspace returns the engine's shared workspace.
// Workspace 返回引擎关联的共享工作区。
func (e *Engine) Workspace() *Workspace { return e.ws }
// Config returns the engine configuration.
// Config 返回引擎配置。
func (e *Engine) Config() EngineConfig  { return e.cfg }

// Env returns the deterministic environment probe result.
// Env 返回确定性环境探测结果。
func (e *Engine) Env() *Env { return e.col.Env() }

// Targets returns the inspection target list (local host name first, then remote aliases).
// Targets 返回巡检目标列表（本机显示名在前，远程别名在后）。
func (e *Engine) Targets() []string { return e.col.Targets() }

// L0Round runs one round of the L0 inspection, writes leads/baseline/facts into the shared workspace, and returns the new leads.
// L0Round 运行一轮 L0 快检并把线索/基线/事实写入共享工作区，返回本轮
// 新检出的线索。交互式运维助手（SnapshotL0）与全自动运维引擎 主循环共用。
func (e *Engine) L0Round(ctx context.Context) []*Finding { return e.l0Round(ctx) }

// LastLeads returns the number of new leads from the last L0 round after deduplication.
// LastLeads 返回上一轮 L0 去重后新增的线索数（引擎收敛判定用）。
func (e *Engine) LastLeads() int {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	return e.lastLeads
}

// CollectFail reports whether any host failed whole-machine collection in the last L0 round (channel errors: SSH loss, expired password, locked account, etc.).
// CollectFail 返回上一轮 L0 快检是否存在主机整机采集失败（通道异常：
// SSH 失联/口令过期/账户锁定等）。引擎收敛判定用——存在通道异常时
// 不得判"环境干净"，由停滞/时限如实非零退出（失联被模型裁决 dismissed
// 后仍假收敛是评分失真点）。
func (e *Engine) CollectFail() bool {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	return e.collectFail
}

// RebaselineNext schedules a silent re-baseline for the next L0 round and records the engine's own action commands.
// RebaselineNext 置位下一轮 L0 的静默重基线并记录自身动作命令（处置
// 执行后由引擎调用——引擎自身变更不产漂移线索，见 stateDrift）。
func (e *Engine) RebaselineNext(cmds []string) {
	e.stateMu.Lock()
	e.rebaseline = true
	e.selfCommands = append(e.selfCommands, cmds...)
	e.stateMu.Unlock()
}

// InvalidateFactCache invalidates the re-probe cache for the given host (called after the engine performs remediation).
// InvalidateFactCache 失效指定主机的重探针缓存（引擎处置执行后调用）：
// 处置后复检需实采验证对象确实消失，而非复用 TTL 内旧缓存。
func (e *Engine) InvalidateFactCache(host string) {
	e.col.InvalidateFactCache(host)
}

// CollectSnapshot collects a full inspection round without writing baselines or producing leads.
// CollectSnapshot 采集一轮完整快检（不写基线/不产线索——引擎处置
// 后确定性复检用）。
func (e *Engine) CollectSnapshot(ctx context.Context) (*Snapshot, error) {
	return e.col.Collect(ctx)
}

// CollectProbes collects only the specified probes (deterministic re-check after remediation): lighter than a full inspection.
// CollectProbes 定向采集指定探针（处置后确定性复检用）：只采集判定
// 给定信号所需的指标/事实，比全量快检轻量（见 collector.CollectProbes）。
func (e *Engine) CollectProbes(ctx context.Context, ms []Metric, factIDs []string) (*Snapshot, error) {
	return e.col.CollectProbes(ctx, ms, factIDs)
}

// CollectMetrics collects the given probes from all targets without writing baselines or producing leads.
// CollectMetrics 按给定探针清单采集全部目标（不写基线/不产线索）。
func (e *Engine) CollectMetrics(ctx context.Context, ms []Metric) (*Snapshot, error) {
	return e.col.CollectMetrics(ctx, ms)
}

// SetConclusion writes the convergence exit conclusion (rendered into the final report).
// SetConclusion 写入收敛退出结论（渲染进最终报告）。
func (e *Engine) SetConclusion(s string) {
	e.stateMu.Lock()
	e.conclusion = s
	e.stateMu.Unlock()
}

// Conclusion returns the convergence exit conclusion.
// Conclusion 返回收敛退出结论（测试/嵌入方读取）。
func (e *Engine) Conclusion() string {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	return e.conclusion
}

// MarkStarted records the start time (idempotent; only the first call takes effect).
// MarkStarted 记录启动时间（幂等；首次调用生效）。
func (e *Engine) MarkStarted() time.Time {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	if e.started.IsZero() {
		e.started = time.Now()
	}
	return e.started
}

// Started returns the start time (zero value when not started).
// Started 返回启动时间（未启动为零值）。
func (e *Engine) Started() time.Time {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	return e.started
}

// Logf writes engine log output (engine and assistant share the same output channel).
// Logf 引擎日志输出（engine/assistant 复用同一输出通道）。
func (e *Engine) Logf(format string, args ...any) {
	e.logf(format, args...)
}

// ReportPath returns the live report path.
// ReportPath 返回实时报告路径。
func (e *Engine) ReportPath() string { return filepath.Join(e.cfg.WorkDir, "report.md") }

// RenderReport renders the live report (refreshed after each interactive assistant task round).
// RenderReport 渲染实时报告（交互式运维助手每轮任务结束后刷新——与全自动运维引擎
// 共用同一份 report.md，工作区状态跨产品延续）。
func (e *Engine) RenderReport() error {
	e.MarkStarted()
	return e.renderReport()
}

// SnapshotL0 is the deterministic base for the interactive assistant: runs an L0 round and returns summary text for the task context.
// SnapshotL0 交互式运维助手的确定性底座：运行一轮 L0 快检并把线索/基线/事实
// 写入共享工作区，返回可注入任务上下文的摘要文本（新线索 + 环境事实）。
// 交互式运维助手与全自动运维引擎 共用同一 findings/基线/报告——这是两种形态共用的核心。
func (e *Engine) SnapshotL0(ctx context.Context) (string, error) {
	e.MarkStarted()
	leads := e.l0Round(ctx)
	var b strings.Builder
	b.WriteString("## L0 确定性快检（引擎自动采集，无需重复执行）\n")
	// 目标无数据可见性：全部/部分主机连不上时如实标注——交互式运维助手下
	// 操作员需要知道快检的覆盖范围（静默缺失会误导"全绿"）。
	targets := e.col.Targets()
	if bl := e.ws.Baseline(); len(bl) > 0 {
		have := bl[len(bl)-1].Hosts
		var missing []string
		for _, t := range targets {
			if _, ok := have[t]; !ok {
				missing = append(missing, t)
			}
		}
		if len(missing) > 0 {
			b.WriteString(fmt.Sprintf("注意：%d/%d 台目标无采集数据（连接失败/不可达）：%s\n", len(missing), len(targets), strings.Join(missing, ", ")))
		}
	}
	if len(leads) > 0 {
		b.WriteString(fmt.Sprintf("本轮新检出线索 %d 条（已入 findings 待查区）：\n", len(leads)))
		for i, f := range leads {
			if i >= 20 {
				b.WriteString(fmt.Sprintf("- …其余 %d 条\n", len(leads)-20))
				break
			}
			b.WriteString(fmt.Sprintf("- [%s] %s: %s\n", f.Host, f.Signal, f.Desc))
		}
	} else {
		b.WriteString("本轮无新检出线索。\n")
	}
	if state := e.ws.StateSummary(); state != "" {
		b.WriteString("\n## 已知状态（工作区）\n" + state + "\n")
	}
	return b.String(), nil
}

// Warmup pre-runs one L0 inspection round (called asynchronously by the interactive assistant after the base starts).
// Warmup 预热一轮 L0 快检（交互式运维助手在底座启动后异步调用：重探针全盘
// 扫描在后台完成，操作员首个任务的快检即时返回；线索/基线/事实同样
// 就绪）。与任务快检轮由采集器整轮串行化，并发安全。
func (e *Engine) Warmup(ctx context.Context) []*Finding {
	e.MarkStarted()
	return e.l0Round(ctx)
}

// l0Round 确定性一轮：快检 → 线索入库 → 基线/事实落盘。返回本轮新
// 检出的线索（供上下文注入），去重后的新增数记入 lastLeads。交互式运维助手
// （SnapshotL0）与全自动运维引擎 主循环共用——L0 是两种形态共用的确定性底座。
func (e *Engine) l0Round(ctx context.Context) []*Finding {
	leads := e.l0Scan(ctx)
	e.stateMu.Lock()
	if len(leads) > 0 {
		before := len(e.ws.Findings())
		e.ws.AddFindings(leads)
		// 去重后的新增数：重复信号（环境未变化）不计为新线索。
		e.lastLeads = len(e.ws.Findings()) - before
	} else {
		e.lastLeads = 0
	}
	e.stateMu.Unlock()
	return leads
}

// l0Scan 确定性快检：返回本轮新出现的 pending 线索（去重由工作区做）。
func (e *Engine) l0Scan(ctx context.Context) []*Finding {
	start := time.Now()
	snap, err := e.col.Collect(ctx)
	dur := time.Since(start)
	// 通道健康状态记录：整机采集失败（Errors["collect"]）即通道异常——
	// 收敛判定据此不得判"环境干净"（即使模型把 collect_anomaly dismissed）。
	cf := false
	if err == nil {
		for i := range snap.Hosts {
			if _, ok := snap.Hosts[i].Errors["collect"]; ok {
				cf = true
				break
			}
		}
	} else {
		cf = true // 整轮采集失败同样视为通道异常
	}
	e.stateMu.Lock()
	e.collectFail = cf
	e.stateMu.Unlock()
	if err != nil {
		e.logf("L0 快检失败: %v", err)
		return nil
	}
	// 采集耗时可见：非 LLM 耗时的主要来源（重探针全盘扫描/远程采集）。
	if hits, total := e.col.FactCacheStats(); hits > 0 {
		e.logf("L0 采集耗时 %v（重探针缓存命中 %d/%d，TTL %v）",
			dur.Round(time.Millisecond), hits, total, e.cfg.FactRefreshInterval)
	} else {
		e.logf("L0 采集耗时 %v", dur.Round(time.Millisecond))
	}
	// 采集概况：每台主机的数据可见性逐台标注（指标/状态/安全事实/错误数）——
	// 排查"某主机为什么没数据/少数据"直接看这行，不用翻报告。
	for i := range snap.Hosts {
		hm := &snap.Hosts[i]
		e.logf("L0 采集 %s: 指标 %d 项，状态探针 %d 项，安全事实 %d 项，错误 %d 条%s",
			hm.Host, len(hm.Metrics), len(hm.State), len(securityFactIDs()), len(hm.Errors), cacheAgeNote(hm))
	}
	// 单台主机的采集错误（SSH 失联、指标解析失败）逐条留痕——
	// 测试阶段定位"某台主机为什么没数据"必须能看到原因。
	for i := range snap.Hosts {
		hm := &snap.Hosts[i]
		for id, msg := range hm.Errors {
			e.logf("L0 %s 采集 %s 失败: %s", hm.Host, id, msg)
		}
	}
	// 基线历史入库（痕迹机制）。
	pt := BaselinePoint{At: time.Now()}
	pt.Hosts = map[string]map[string]float64{}
	pt.State = map[string]map[string]string{}
	for i := range snap.Hosts {
		hm := &snap.Hosts[i]
		m := map[string]float64{}
		if hm.CPU != nil && hm.CPU.Pct >= 0 {
			m["cpu"] = hm.CPU.Pct
		}
		for k, vals := range hm.Metrics {
			for kk, v := range vals {
				m[k+"_"+kk] = v
			}
		}
		pt.Hosts[hm.Host] = m
		if len(hm.State) > 0 {
			pt.State[hm.Host] = hm.State
		}
	}
	// 安全事实进上下文管道（机制 1：大脑必须看见——枚举数据每轮进
	// 阶段提示，模型不可跳过；判定权仍在模型）。
	e.publishL0Facts(snap)

	var out []*Finding
	// 配置漂移检测：状态快照与上一轮对比，变化产线索（变化即痕）。
	// 必须在 AddBaseline 之前对比——此前 AddBaseline 先行导致本轮
	// 快照成为"上一轮"，自比恒无变化，漂移机制从未真实触发
	// （R12 实测发现：state_sshd 摘要跨轮变化无线索，单测未覆盖
	// 引擎真实调用顺序）。
	// 重基线轮（自身处置后）：进程派生类探针（state_units/state_ports）
	// 跳过对比（杀进程/启停服务必然改变摘要且无法行级归属）；文件
	// 内容类探针照常对比，变化行能被自身动作解释的才豁免——攻击者
	// 与自身处置交错同一目标时，解释不了的新增/删除行仍是攻击痕迹
	// （R14 实测：整轮跳过的摘要级豁免把攻击者追加的 MaxAuthTries
	// 并入新基线永久吞掉）。
	// 读取+清空在锁内原子完成：助手形态 Warmup goroutine 与任务快检
	// 轮并发时不丢置位、不重复消费。
	e.stateMu.Lock()
	selfCmds := e.selfCommands
	rebaseline := e.rebaseline
	e.selfCommands = nil
	e.rebaseline = false
	e.stateMu.Unlock()
	out = append(out, e.stateDrift(&pt, selfCmds, rebaseline)...)
	for _, a := range Judge(snap, e.cfg.Thresholds) {
		out = append(out, a.ToFinding())
	}
	// 跨主机时钟偏差（P0 修复：时钟漂移故障的确定性检出面）。timedatectl
	// 的 NTPSynchronized 只是"同步标志"——hv_utils/云厂商时钟源会把错误
	// 时钟标为已同步（chaos-r1 实测：目标时钟拨慢 8 分钟仍报
	// NTPSynchronized=yes，时钟漂移完全漏检）。以引擎侧时间为参照对比
	// 目标 epoch（时区无关、客观）：|skew| ≥ warn 秒产 clock_skew 线索，
	// 处置（启用 NTP/校准）后复检走同探针自动转绿。无 clock 数据（精简
	// 环境无 date）跳过；首轮预热即生效。
	for i := range snap.Hosts {
		hm := &snap.Hosts[i]
		if hm.Metrics["clock"] == nil {
			continue
		}
		epoch, ok := hm.Metrics["clock"]["epoch"]
		if !ok || epoch <= 0 {
			continue
		}
		skew := math.Abs(float64(time.Now().Unix()) - epoch)
		if skew < clockSkewWarnSecs {
			continue
		}
		sev := "疑似"
		if skew >= clockSkewCritSecs {
			sev = "严重"
		}
		out = append(out, NewFinding(hm.Host, "clock", "clock_skew",
			fmt.Sprintf("系统时钟与引擎侧偏差 %ds（%s）——时间漂移/未同步，日志时间线与故障归因会失真（等保基线要求时间同步）", int64(skew), sev)))
	}
	// 期望状态偏差（架构：懂系统）——观测 vs 期望（.gocode/desired.json），
	// 偏差即线索。每轮重载（操作员改期望无需重启）；无声明时跳过。
	// 解析失败必须留痕——此前 derr 被静默吞掉，desired.json 手误一次
	// 全部期望守护静默失效且不可见（P2 修复）。
	if desired, derr := LoadDesired(e.cfg.WorkDir); derr == nil && desired != nil {
		for _, d := range ComputeDeviations(desired, snap) {
			out = append(out, d.ToFinding())
		}
	} else if derr != nil {
		e.logf("L0 期望状态加载失败（期望偏差守护本轮跳过）: %v", derr)
	}
	// 本轮快照在对比完成后才成为新基线。
	e.ws.AddBaseline(pt)
	// 线索明细留痕：判定层产了什么必须可见（排查"某类异常没被检出/误报"
	// 时先看这行，而不是猜）——signal 列表不够，现象描述与对象子键才是
	// 判定依据。
	if len(out) > 0 {
		e.logf("L0 线索 %d 条：", len(out))
		for _, f := range out {
			e.logf("  - [%s] %s%s: %s", f.Host, f.Signal, KeyNote(f.Key), fsutil.TruncateStr(f.Desc, 160))
		}
	}
	if len(selfCmds) > 0 {
		e.logf("L0 重基线轮：引擎自身动作 %d 条（进程派生类探针静默豁免，内容类探针行级归属）", len(selfCmds))
	}
	return out
}

// cacheAgeNote 重探针缓存命中的数据龄期标注（每探针 id=龄期，排序后拼串）；
// 实采（无缓存）返回空串——排查"模型看到的事实有多新"直接看这行。
