package autopilot

import (
	"github.com/go-gocel/gocel/jsonx"
)

// 模型输出的 JSON 容错解析——单一来源在 harness（gocel/jsonx），
// 消费层不自行实现本属 gocel 的能力（见 AGENTS.md「消费层只依赖 gocel」）。

// parseModelJSON 从模型输出解析 JSON 对象：截取 → 语法修复 → 严格解构。
// 截取容忍 ```json 代码块与前后缀文本；修复覆盖全角标点、尾随逗号、
// 字符串内裸换行、单引号字符串、裸键等常见瑕疵。
func parseModelJSON(content string, v any) error {
	return jsonx.Parse(content, v)
}
