package autopilot

import (
	"time"

	"github.com/go-gocel/gocode-ops/internal/common/model"
)

// ParallelConfig holds the parallel scheduling configuration (parallelism is a first-class citizen by design).
// ParallelConfig 并行调度配置（架构：并行是第一公民）。
type ParallelConfig struct {
	// Workers 模型 worker 并发数：DeepDive/Respond/终裁批次并行上限——
	// 每 worker 一个独立 agent 会话（子代理池），批次（deepdive 单线索/
	// respond 双故障）并行派发。
	// 0=默认 6；1=关闭并行（串行，兼容旧行为）。
	// 默认 6：单线索子代理粒度下（线索数 ≤6 → 1 波全并行）覆盖比赛
	// 常规规模；6 路并发在 DeepSeek API 常规限流下留足余量（8 路在
	// 7-8 条线索边界快 ~2m，但限流退避风险更高——模型 API 延迟不
	// 另做调优时优先稳定）；限流环境可用 --parallel 1-4 调低。
	Workers int
	// PerFindingToolBudget 单问题每轮认知工具调用上限（认知护栏：
	// 防大脑死循环烧钱）。0=不设上限。
	PerFindingToolBudget int
	// PerFindingModelBudget 单问题每轮模型调用上限（认知护栏）。
	// 0=不设上限。
	PerFindingModelBudget int
}

// Config is the configuration of the autonomous operations engine: the shared kernel (model.EngineConfig) plus model-phase timeouts.
// Config 是全自动运维引擎的配置：公用内核（model.EngineConfig：工作目录/目标/
// 阈值/采集节奏）+ 模型阶段超时。WorkDir 必填；Local 与 Hosts 至少其一
// （由 l0.NewEngine 校验）。
type Config struct {
	// EngineConfig 公用内核配置（L0 快检/工作区/报告）。
	model.EngineConfig

	// Parallel 并行调度配置（批次级并行 + 认知护栏预算）。
	Parallel ParallelConfig
	// WatchInterval watch 模式（auto --watch）的感知周期；0=不启用 watch。
	WatchInterval time.Duration

	// ActTimeout 单条处置动作命令的执行超时（修复/清理类命令常规上限）。
	ActTimeout time.Duration // 默认 60s
	// VerifyTimeout 处置后验证命令的执行超时（验证必须快，慢验证会拖慢收敛循环）。
	VerifyTimeout time.Duration // 默认 30s
	// DiagnoseTimeout 单个模型阶段（survey/deepdive/respond/复扫/终裁）
	// 的会话超时——一次会话内含多次工具往返，LLM 生成 + 命令执行的总时限。
	// 默认 6m：覆盖最深批预算（3 条线索 × 60s/条 = 3m）两倍余量，
	// 预算不足会导致整批追查超时失败、下轮重追同一批（死循环）。
	DiagnoseTimeout time.Duration // 默认 6m
	// Settle 处置后确定性复检前的状态沉降等待（P0 修复）：动作"瞬时
	// 生效"不等于"稳定生效"——chaos-r1 实测 auditd enable --now 后
	// 瞬时 active（verify ✓），3 秒后 failed（容器无审计控制节点），
	// 假 ✓ 混过模型验证。复检前等待沉降窗口，慢发故障（服务启动失败/
	// 配置渐进生效）在确定性层被真实状态捕获。默认 4s。
	Settle time.Duration
	// Timeout 全局时限（可选）：非零时整个 Run 在该时限内必须收敛，
	// 超时如实退出（退出码非零）；零=不设全局时限（比赛/评审环境建议设）。
	Timeout time.Duration
}

// DefaultConfig returns the default configuration of the autonomous operations engine.
// DefaultConfig 返回全自动运维引擎默认配置。
func DefaultConfig() Config {
	return Config{
		EngineConfig:    model.DefaultEngineConfig(),
		Parallel:        ParallelConfig{Workers: 6, PerFindingToolBudget: 24, PerFindingModelBudget: 16},
		ActTimeout:      60 * time.Second,
		VerifyTimeout:   30 * time.Second,
		DiagnoseTimeout: 6 * time.Minute,
		Settle:          4 * time.Second,
	}
}
