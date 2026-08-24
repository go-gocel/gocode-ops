package model

// interfaces.go — 消费方接口与通道事实（定义在模型层，实现方不反向依赖消费方）。

import (
	"context"
)

// Operator is the interactive terminal interface for the human operator.
// Operator 是操作员交互终端接口。CLI 用 stdin/stdout 实现；桌面应用可
// 换成对话框实现。nil 表示非交互环境（高危命令一律阻止，ask_operator
// 返回错误）。
type Operator interface {
	// Ask 向操作员展示 prompt（含问题与选项说明），返回其原始回答。
	Ask(prompt string, options []string) (string, error)
}

// L0Snapshooter is the snapshot provider of the l0_snapshot tool.
// L0Snapshooter 是 l0_snapshot 工具的快检提供者。*Engine 实现本接口；
// 接口化便于消费方（TUI/非终端形态）注入 fake 与测试。
type L0Snapshooter interface {
	// SnapshotL0 运行一轮确定性快检（线索/基线/事实写入共享工作区），
	// 返回可注入任务上下文的摘要文本。
	SnapshotL0(ctx context.Context) (string, error)
}

// ConnFact is the channel fact of the engine connecting to a host (from the inventory; credentials stay out of the model context).
// ConnFact 引擎连接一台主机的通道事实（来自主机清单，凭据不入模型上下文）。
type ConnFact struct {
	// Host 主机别名。
	Host string
	// User 引擎登录用户（如 root）。
	User string
	// Auth 当前认证方式：password / key / none（无凭据，仅本机）。
	Auth string
	// Port 引擎连接的管理端口（外部视角；容器内 SSH 端口通常为 22）。
	Port string
}

// ImpactRisk is the result of the self-impact review (non-nil means a risk was hit).
// ImpactRisk 自身影响面审查结果（非 nil 表示命中风险）。
type ImpactRisk struct {
	// Category 风险类别：channel-auth/channel-service/channel-firewall/
	// channel-network/channel-user/toolchain。
	Category string
	// Reason 面向操作员/报告的解释。
	Reason string
	// Advice 安全替代建议（"只给建议，不做处置"的落点）。
	Advice string
}
