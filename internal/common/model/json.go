package model

import (
	"github.com/go-gocel/gocel/jsonx"
)

// 模型输出的 JSON 容错解析——单一来源在 harness（gocel/jsonx），
// 消费层不自行实现本属 gocel 的能力（见 AGENTS.md「消费层只依赖 gocel」）。

// LenientBool 宽松布尔（jsonx 提供；本包别名保持既有契约字段类型不变）。
type LenientBool = jsonx.LenientBool
