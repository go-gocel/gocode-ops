package session

import (
	"context"

	"github.com/go-gocel/gocel-core/core/kernel"
	"github.com/go-gocel/gocel-core/types"
	"github.com/go-gocel/gocel/agents"
)

// Session 是「初始指令 → 工作」的统一执行会话：装配好的 Agent 在会话中
// 运行，每轮追加用户指令、注入事件回调（可选逐 token 流式）、维护多轮
// 历史。交互式运维助手（TUI 多轮对话）与全自动运维引擎（单轮阶段任务）共用
// 同一个执行模型——入口只需要一个初始指令，剩下的交给 Agent。
//
// Session is the unified "initial instruction → work" execution session:
// a run loop over an assembled agent with per-turn instruction appending,
// optional event/streaming injection, and multi-turn history. Both the
// assistant (TUI) and the auto engine share this execution model.
type Session struct {
	app     *agents.App
	history []*types.Message
	sink    func(*types.Event) bool // nil 时不产生事件
	stream  bool                    // 逐 token 流式模型调用（需 sink 非 nil）
}

// NewSession 创建统一执行会话。
// sink 非 nil 时 agent 事件（token/工具调用/结果）实时回调给调用方；
// stream 为 true 时启用逐 token 流式输出。
func NewSession(app *agents.App, sink func(*types.Event) bool, stream bool) *Session {
	return &Session{app: app, sink: sink, stream: stream}
}

// Run 执行一轮：追加用户指令 → agent 运行 → 更新历史。
// 返回最终结果；失败时历史回滚（不带着残缺上下文进入下一轮）。
func (s *Session) Run(ctx context.Context, task string) (*kernel.Result, error) {
	input := &types.AgentInput{
		Messages: append(append([]*types.Message{}, s.history...), types.NewUserMessage(task)),
	}
	// 事件回调经 input.StreamSender 注入：装配产物 Agent 每次执行自动接线
	// （AgentContext 由 Runner 注入，sender 取自 input）。
	if s.sink != nil {
		input.StreamSender = s.sink
		if s.stream {
			input.EnableStreaming = true
		}
	}

	result, err := s.app.RunWithInput(ctx, input)
	if err != nil {
		return nil, err
	}
	s.history = trimHistory(stripSystem(result.Messages))
	return result, nil
}

// historyMaxBytes 多轮历史总字节预算：超限时从最旧消息开始丢弃（保住
// 最近上下文）。长会话无界累积会撑爆模型上下文窗口——引擎用 RunFresh
// 规避，交互形态靠本预算。48K ≈ 12K token，多轮问答够用且留足工具
// 输出空间。
const historyMaxBytes = 48 << 10

// trimHistory 把历史裁剪到字节预算内：从最旧开始丢；丢弃后首条若是
// tool 消息（孤立工具结果没有对话锚点，模型无法解读）继续丢。
func trimHistory(msgs []*types.Message) []*types.Message {
	var total int
	for _, m := range msgs {
		total += msgSize(m)
	}
	if total <= historyMaxBytes {
		return msgs
	}
	out := append([]*types.Message{}, msgs...)
	for len(out) > 2 && total > historyMaxBytes {
		total -= msgSize(out[0])
		out = out[1:]
	}
	for len(out) > 1 && out[0].Role == types.RoleTool {
		total -= msgSize(out[0])
		out = out[1:]
	}
	return out
}

func msgSize(m *types.Message) int {
	if m == nil {
		return 0
	}
	return len(m.Content)
}

// RunFresh 执行一轮独立任务：清空历史后运行（阶段式任务语义）。
//
// 阶段间状态不靠对话历史累积——已由调用方通过工作区状态摘要注入任务
// 提示（如 全自动运维引擎的 StateSummary）。历史只承载「当前任务内」的追查
// 连续性；跨任务无界累积会撑爆上下文窗口（引擎收敛循环实测风险）。
func (s *Session) RunFresh(ctx context.Context, task string) (*kernel.Result, error) {
	return s.RunFreshSteps(ctx, task, 0)
}

// RunFreshSteps 执行一轮独立任务并限制 ReAct 步数（maxSteps>0 时生效，
// <=0 等同 RunFresh）。步数预算是阶段职责的机械约束：如 survey 巡检
// 阶段限步防止模型在"浅扫"阶段无界深挖（深挖属于 deepdive 职责）——
// 步数耗尽时 ReAct 策略以当前信息收尾输出，任务不会挂死。
func (s *Session) RunFreshSteps(ctx context.Context, task string, maxSteps int) (*kernel.Result, error) {
	s.history = nil
	input := &types.AgentInput{
		Messages: []*types.Message{types.NewUserMessage(task)},
		MaxSteps: maxSteps,
	}
	// 事件回调经 input.StreamSender 注入（与 Run 同语义）。
	if s.sink != nil {
		input.StreamSender = s.sink
		if s.stream {
			input.EnableStreaming = true
		}
	}
	result, err := s.app.RunWithInput(ctx, input)
	if err != nil {
		return nil, err
	}
	s.history = trimHistory(stripSystem(result.Messages))
	return result, nil
}

// Reset 清空对话上下文（新会话）。
func (s *Session) Reset() {
	s.history = nil
}

// stripSystem 去掉消息历史中的 system 消息（每轮由 agent 重新注入），
// 保留 user/assistant/tool 消息以维持对话连续性。
func stripSystem(msgs []*types.Message) []*types.Message {
	out := make([]*types.Message, 0, len(msgs))
	for _, m := range msgs {
		if m == nil || m.Role == types.RoleSystem {
			continue
		}
		out = append(out, m)
	}
	return out
}
