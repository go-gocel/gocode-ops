package agent

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/go-gocel/gocel-core/core/kernel"
	"github.com/go-gocel/gocel-core/types"
)

// AgentsMDModule 把 AGENTS.md（或任意知识/信息文件）注入 agent 的系统提示。
//
// 设计意图（工作目录约定的信息注入面）：
//   - 只注入"信息"（环境预期、部署形态、业务方提示、重点怀疑方向），
//     不注入任何"故障规则/处置方案"——未知故障由模型结合现场追查；
//   - 文件在首次注入时读取并缓存；内容作为独立 system 消息追加，
//     不污染主系统提示；
//   - 文件不存在、为空或全为注释（init 释放的空模板未填写）时静默跳过，
//     不阻断 agent——未配置的模板不会被当成环境信息灌给模型；
//   - 内容中的 {{变量}} 模板占位（workdir/hosts/host）在加载时渲染。
type AgentsMDModule struct {
	// Path 信息文件路径；空或不存在时跳过注入。
	Path string
	// Vars 模板变量（{{key}} 占位渲染）；nil 时不做渲染。
	Vars map[string]string

	once sync.Once
	data string
}

// NewAgentsMDModule 创建 AGENTS.md 注入模块。path 为空时模块空转。
func NewAgentsMDModule(path string, vars map[string]string) *AgentsMDModule {
	return &AgentsMDModule{Path: path, Vars: vars}
}

// Register 挂接 OnMessagesBuilt 钩子：在消息构建后、模型调用前注入。
func (m *AgentsMDModule) Register(rt kernel.HookRegistrar) {
	rt.OnMessagesBuilt(m.inject)
}

func (m *AgentsMDModule) inject(ctx context.Context, msgs []*types.Message) (context.Context, []*types.Message, error) {
	content := m.load()
	if content == "" {
		return ctx, msgs, nil
	}
	// 追加独立 system 消息（不修改已有消息，避免污染主提示）。
	sys := types.NewSystemMessage(fmt.Sprintf("## 环境信息约定（AGENTS.md）\n%s", content))
	return ctx, append(msgs, sys), nil
}

// load 读取、渲染并缓存文件内容（只读一次，此后复用）。
func (m *AgentsMDModule) load() string {
	m.once.Do(func() {
		if m.Path == "" {
			return
		}
		data, err := os.ReadFile(m.Path)
		if err != nil {
			return // 不存在/不可读 → 空转
		}
		content := RenderVars(string(data), m.Vars)
		// 空文件/全注释视为未配置：init 释放的模板是空文件，
		// 未填写前不应注入。
		if !HasEffectiveContent(content) {
			return
		}
		m.data = content
	})
	return m.data
}
