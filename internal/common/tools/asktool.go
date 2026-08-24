package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-gocel/gocel-core/core/kernel"
	"github.com/go-gocel/gocel-core/core/tool"
)

// askParams 是 ask_operator 的参数。
type askParams struct {
	// Question 向操作员提出的问题。
	Question string `json:"question" description:"向操作员提出的问题"`
	// Options 可选答案列表（如 ["重启", "仅重载配置", "取消"]）；缺省为 y/n 确认。
	Options []string `json:"options,omitempty" description:"可选答案列表，缺省 y/n"`
}

// AskOperatorTool returns the ask_operator tool that asks the operator a
// question and waits for an answer during task execution.
// AskOperatorTool 返回 ask_operator 工具：在任务执行中向操作员提问并
// 等待回答。用于补充信息、方案选择、执行前确认。无交互终端时返回错误。
func AskOperatorTool(operator Operator) kernel.Tool {
	return tool.MustToolFromFunc(
		func(ctx context.Context, p askParams) (string, error) {
			question := strings.TrimSpace(p.Question)
			if question == "" {
				return "", fmt.Errorf("ask_operator: question 必填")
			}
			if operator == nil {
				return "", fmt.Errorf("ask_operator: 当前无操作员交互终端，无法提问——请基于已有信息做保守处置或给出建议命令")
			}
			options := p.Options
			if len(options) == 0 {
				options = []string{"y", "n"}
			}
			// 操作员的回答可能是选项之一，也可能是选项之外的补充说明（原话）——
			// 模型应以操作员原话为准，不要用新方案反复追问。
			prompt := fmt.Sprintf("❓ 操作员，需要您确认：%s\n选项：%s（也可直接输入其他补充说明）", question, strings.Join(options, "/"))
			ans, err := operator.Ask(prompt, options)
			if err != nil {
				return "", fmt.Errorf("ask_operator: 等待操作员输入失败: %w", err)
			}
			return strings.TrimSpace(ans), nil
		},
		tool.WithToolName("ask_operator"),
		tool.WithToolDescription("向操作员提问并等待回答（补充信息、方案选择、处置确认）。只在确实需要人工决策时用；能自行判断就不要打断操作员。"),
		tool.WithToolSource("gocode"),
	)
}
