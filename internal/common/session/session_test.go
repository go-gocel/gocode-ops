package session

import (
	"strings"
	"testing"

	"github.com/go-gocel/gocel-core/types"
)

// TestTrimHistory_Budget 多轮历史超预算时从最旧丢弃、首条不得是孤立
// tool 消息、最近消息保留（长会话无界累积会撑爆上下文窗口）。
func TestTrimHistory_Budget(t *testing.T) {
	// 超预算序列：旧 user/assistant 被丢，最近 user + tool 保留。
	var msgs []*types.Message
	big := strings.Repeat("x", 20000)
	for i := 0; i < 4; i++ {
		msgs = append(msgs,
			types.NewUserMessage(big),
			types.NewToolMessage("r"+big[:100], "c", "terminal"),
		)
	}
	msgs = append(msgs, types.NewUserMessage("最近的问题"))
	msgs = append(msgs, types.NewToolMessage("最近的工具结果", "c", "terminal"))

	out := trimHistory(msgs)
	var total int
	for _, m := range out {
		total += msgSize(m)
	}
	if total > historyMaxBytes {
		t.Fatalf("裁剪后仍超预算: %d > %d", total, historyMaxBytes)
	}
	if out[0].Role == types.RoleTool {
		t.Fatal("裁剪后首条不应是孤立 tool 消息")
	}
	last := out[len(out)-1]
	if last.Role != types.RoleTool || last.Content != "最近的工具结果" {
		t.Fatalf("最近消息应保留: %+v", last)
	}
	if out[len(out)-2].Content != "最近的问题" {
		t.Fatalf("最近 user 消息应保留: %+v", out[len(out)-2])
	}
}

// TestTrimHistory_UnderBudget 未超预算原样返回（不复制）。
func TestTrimHistory_UnderBudget(t *testing.T) {
	msgs := []*types.Message{
		types.NewUserMessage("hi"),
		types.NewToolMessage("ok", "c", "terminal"),
	}
	if out := trimHistory(msgs); len(out) != 2 {
		t.Fatalf("未超预算不应裁剪: %d", len(out))
	}
}
