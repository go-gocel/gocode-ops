package tools

import (
	"context"
	"fmt"

	"github.com/go-gocel/gocel-core/core/kernel"
	"github.com/go-gocel/gocel-core/core/tool"
)

// L0SnapshotTool returns the l0_snapshot tool that triggers a deterministic
// quick scan on demand.
// L0SnapshotTool 返回 l0_snapshot 工具：模型按需触发一轮确定性快检。
// LLM 是核心——快检在模型需要全局状态时调用（巡检类任务开场、诊断时
// 需要系统事实），不再无条件每轮前置（帮助/闲聊/知识类问题零开销）。
func L0SnapshotTool(e L0Snapshooter) kernel.Tool {
	return tool.MustToolFromFunc(
		func(ctx context.Context, _ struct{}) (string, error) {
			if e == nil {
				return "", fmt.Errorf("l0_snapshot: L0 快检底座未就绪")
			}
			return e.SnapshotL0(ctx)
		},
		tool.WithToolName("l0_snapshot"),
		tool.WithToolDescription("运行一轮确定性快检（CPU/内存/磁盘/inode/僵尸进程/失败服务/错误日志/安全事实/配置漂移），线索写入共享工作区并返回摘要（新线索 + 环境事实 + 已知状态）。巡检/诊断类任务需要全局状态时按需调用；纯知识问答不需要。"),
		tool.WithToolSource("gocode"),
	)
}
