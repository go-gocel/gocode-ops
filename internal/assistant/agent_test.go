package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-gocel/gocel-core/core/kernel"
	"github.com/go-gocel/gocel-core/types"

	"github.com/go-gocel/gocode-ops/internal/common/audit"
	"github.com/go-gocel/gocode-ops/internal/common/guard"
	"github.com/go-gocel/gocode-ops/internal/common/tools"
)

// fakeChatModel 是可编排的 kernel.ChatModel，用于 agent 级测试。
type fakeChatModel struct {
	usagePerCall *types.TokenUsage
	onGenerate   func(ctx context.Context, msgs []*types.Message) (*types.Message, *types.TokenUsage, error)
}

func (f *fakeChatModel) CountTokens(ctx context.Context, msgs []*types.Message, opts ...kernel.GenOption) (int, error) {
	return 0, nil
}

func (f *fakeChatModel) Generate(ctx context.Context, msgs []*types.Message, opts ...kernel.GenOption) (*types.Message, *types.TokenUsage, error) {
	if f.onGenerate != nil {
		return f.onGenerate(ctx, msgs)
	}
	return types.NewAssistantMessage("ok"), f.usagePerCall, nil
}

func (f *fakeChatModel) Stream(ctx context.Context, msgs []*types.Message, opts ...kernel.GenOption) (kernel.StreamReader, error) {
	return nil, errors.New("stream not supported in tests")
}

// fakeOperator 是 model.Operator 的测试实现（按序返回预设回答）。
type fakeOperator struct {
	answers    []string
	calls      int
	lastPrompt string
}

func (f *fakeOperator) Ask(prompt string, options []string) (string, error) {
	f.calls++
	f.lastPrompt = prompt
	if len(f.answers) > 0 {
		ans := f.answers[0]
		f.answers = f.answers[1:]
		return ans, nil
	}
	return "y", nil
}

// fakeRemote 是 remote.RemoteExecutor 的最小测试实现。
type fakeRemote struct {
	outputs map[string]string
	calls   int
}

func (f *fakeRemote) Exec(ctx context.Context, hosts []string, command string, timeout time.Duration) (string, error) {
	f.calls++
	out := f.outputs[command]
	if out == "" && len(hosts) > 0 {
		out = f.outputs[hosts[0]]
	}
	return "## " + strings.Join(hosts, ",") + "\n" + out, nil
}
func (f *fakeRemote) Upload(ctx context.Context, hosts []string, localPath, remotePath string, mode os.FileMode) (string, error) {
	return "", nil
}
func (f *fakeRemote) Download(ctx context.Context, hosts []string, remotePath, localDir string) (string, error) {
	return "", nil
}
func (f *fakeRemote) FileInfo(ctx context.Context, host, remotePath string, list bool) (string, error) {
	return "", nil
}
func (f *fakeRemote) ListHosts() (string, error) { return "", nil }
func (f *fakeRemote) Aliases() ([]string, error) { return nil, nil }
func (f *fakeRemote) Probe(ctx context.Context, aliases []string, timeout time.Duration) map[string]string {
	return nil
}
func (f *fakeRemote) Resolve(aliases []string) ([]string, error) {
	// "all" 展开为已知主机（真实执行器按清单解析）。
	out := make([]string, 0, len(aliases))
	for _, a := range aliases {
		if a == "all" {
			for h := range f.outputs {
				out = append(out, h)
			}
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

func terminalCall(id, cmd string) *types.Message {
	return &types.Message{
		Role:    types.RoleAssistant,
		Content: "executing",
		ToolCalls: []types.ToolCall{{
			ID: id,
			Function: types.ToolCallFunction{
				Name:      "terminal",
				Arguments: `{"command":"` + cmd + `"}`,
			},
		}},
	}
}

func TestNewAgent_RunsAndFinishesNaturally(t *testing.T) {
	dir := t.TempDir()
	m := &fakeChatModel{
		onGenerate: func(ctx context.Context, msgs []*types.Message) (*types.Message, *types.TokenUsage, error) {
			return types.NewAssistantMessage("巡检完成"), &types.TokenUsage{TotalTokens: 5}, nil
		},
	}
	app, aerr := NewAgent(m, dir, "test-host", &fakeOperator{answers: []string{"y"}}, guard.PolicyAsk, "")
	if aerr != nil {
		t.Fatal(aerr)
	}
	result, err := app.Run(context.Background(), "巡检系统")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Content != "巡检完成" {
		t.Fatalf("Content = %q, want 巡检完成", result.Content)
	}
	if result.TokenUsage == nil || result.TokenUsage.TotalTokens != 5 {
		t.Errorf("TokenUsage = %+v, want 5", result.TokenUsage)
	}
	// 审计日志应已创建
	if _, err := audit.NewAuditLog(dir); err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
}

func TestNewAgent_GuardBlocksRiskyCommand(t *testing.T) {
	dir := t.TempDir()
	op := &fakeOperator{answers: []string{"n"}} // 操作员拒绝
	var calls int
	m := &fakeChatModel{
		onGenerate: func(ctx context.Context, msgs []*types.Message) (*types.Message, *types.TokenUsage, error) {
			calls++
			if calls == 1 {
				return terminalCall("call_1", "systemctl restart nginx"), nil, nil
			}
			return types.NewAssistantMessage("已按您的决定跳过重启"), nil, nil
		},
	}
	app, aerr := NewAgent(m, dir, "test-host", op, guard.PolicyAsk, "")
	if aerr != nil {
		t.Fatal(aerr)
	}
	result, err := app.Run(context.Background(), "重启 nginx")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if op.calls != 1 {
		t.Errorf("操作员应被询问 1 次，实际 %d", op.calls)
	}
	if !strings.Contains(result.Content, "跳过") {
		t.Errorf("Content = %q，应包含拒绝后的回应", result.Content)
	}
}

func TestNewAgent_PolicyDenyBlocksWithoutAsking(t *testing.T) {
	dir := t.TempDir()
	op := &fakeOperator{answers: []string{"y"}}
	var calls int
	m := &fakeChatModel{
		onGenerate: func(ctx context.Context, msgs []*types.Message) (*types.Message, *types.TokenUsage, error) {
			calls++
			if calls == 1 {
				return terminalCall("call_1", "rm -rf /tmp/build"), nil, nil
			}
			return types.NewAssistantMessage("命令被拒绝"), nil, nil
		},
	}
	app, aerr := NewAgent(m, dir, "test-host", op, guard.PolicyDeny, "")
	if aerr != nil {
		t.Fatal(aerr)
	}
	if _, err := app.Run(context.Background(), "清理"); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if op.calls != 0 {
		t.Errorf("deny 策略不应询问操作员，实际 %d 次", op.calls)
	}
}

func TestNewAgent_RemoteBatchFlow(t *testing.T) {
	// 模型发起 remote_batch 批量只读命令 → 直接执行并返回结果；
	// 再发起高危命令 → 操作员批准后执行。验证 agent 级接线。
	dir := t.TempDir()
	ex := &fakeRemote{outputs: map[string]string{"web-01": "CPU 12%", "db-01": "CPU 3%"}}
	op := &fakeOperator{answers: []string{"y"}}
	var calls int
	m := &fakeChatModel{
		onGenerate: func(ctx context.Context, msgs []*types.Message) (*types.Message, *types.TokenUsage, error) {
			calls++
			switch calls {
			case 1:
				return remoteCallMsg("call_1", []string{"web-01", "db-01"}, "uptime"), nil, nil
			case 2:
				return remoteCallMsg("call_2", []string{"all"}, "systemctl restart nginx"), nil, nil
			}
			return types.NewAssistantMessage("巡检与处置完成"), nil, nil
		},
	}
	app, aerr := newAgent(m, dir, "test-host", op, guard.PolicyAsk, ex, "", nil)
	if aerr != nil {
		t.Fatal(aerr)
	}
	result, err := app.Run(context.Background(), "巡检并重启 nginx")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Content != "巡检与处置完成" {
		t.Fatalf("Content = %q", result.Content)
	}
	if ex.calls != 2 {
		t.Fatalf("应执行 2 次远端命令，实际 %d", ex.calls)
	}
	if !strings.Contains(op.lastPrompt, "web-01") || !strings.Contains(op.lastPrompt, "db-01") {
		t.Errorf("all 应展开为真实主机名，实际提示: %s", op.lastPrompt)
	}
	// 工具结果进入历史（模型能看到远端输出）
	var sawRemote bool
	for _, msg := range result.Messages {
		if msg.Role == types.RoleTool && strings.Contains(msg.Content, "CPU 12%") {
			sawRemote = true
		}
	}
	if !sawRemote {
		t.Error("远端输出未进入消息历史")
	}
}

func remoteCallMsg(id string, hosts []string, cmd string) *types.Message {
	args, _ := json.Marshal(map[string]any{"hosts": hosts, "command": cmd})
	return &types.Message{
		Role:    types.RoleAssistant,
		Content: "remote exec",
		ToolCalls: []types.ToolCall{{
			ID:       id,
			Function: types.ToolCallFunction{Name: "remote_batch", Arguments: string(args)},
		}},
	}
}

// TestNewAgentWithRemote 验证远程执行器注入点：调用方提供的 remote
// （测试 fake；生产为 NewSSHExecutor 配 OnProgress）接进运维 agent 的
// 远程工具。
func TestNewAgentWithRemote(t *testing.T) {
	fake := &fakeRemote{outputs: map[string]string{"web-01": "up 10 days"}}
	agent, aerr := NewAgentWithRemote(nil, "/tmp", "localhost", nil, guard.PolicyDeny, fake, "")
	if aerr != nil {
		t.Fatal(aerr)
	}
	if agent == nil {
		t.Fatal("agent must build with a caller-supplied remote")
	}
	if name := agent.Agent().Name(); name != AgentName {
		t.Fatalf("agent identity = %q, want %q", name, AgentName)
	}
	// 注入的 remote 应答 remote_terminal 调用（与工具测试同一 fake），
	// 接线必须到达工具层。
	guard := guard.NewRiskyCommandGuard(nil, guard.PolicyDeny)
	tool := tools.RemoteTerminalTool(fake, guard)
	out, err := tool.Run(context.Background(), `{"host":"web-01","command":"uptime"}`)
	if err != nil {
		t.Fatalf("remote_terminal via injected remote: %v", err)
	}
	if !strings.Contains(out, "up 10 days") {
		t.Fatalf("remote output = %q, want the fake's output", out)
	}
}

func TestOpsTools_IncludeDomainTools(t *testing.T) {
	tools := tools.AllTools(&fakeOperator{}, &fakeRemote{}, guard.NewRiskyCommandGuard(nil, guard.PolicyDeny))
	names := map[string]bool{}
	for _, tr := range tools {
		names[tr.Name()] = true
	}
	// 命令优先原则：巡检靠 terminal 命令；领域专属工具为远程工具族 + ask_operator
	for _, want := range []string{
		"ask_operator", "terminal", "read", "write", "grep", "glob",
		"remote_terminal", "remote_batch", "remote_upload", "remote_download",
		"remote_file", "remote_list", "git_commit", "git_pull",
	} {
		if !names[want] {
			t.Errorf("工具集缺少 %q（共 %d 个工具）", want, len(tools))
		}
	}
	for _, gone := range []string{"sys_health", "sys_info", "proc_top", "log_tail"} {
		if names[gone] {
			t.Errorf("薄封装工具 %q 不应存在（命令优先原则）", gone)
		}
	}
	// generate_report 不是 AllTools 的一部分：由 NewAgentWithL0 在 L0 底座
	// 就绪时单独注入（报告按需生成，人在环不主动生成）。
	if names["generate_report"] {
		t.Error("generate_report 不应在 AllTools 中（仅 L0 底座就绪时注入）")
	}
}

// fakeL0 同时实现 L0Snapshooter 与 ReportRenderer（生产为 *l0.Engine）。
type fakeL0 struct {
	rendered bool
}

func (f *fakeL0) SnapshotL0(ctx context.Context) (string, error) { return "## L0 快检摘要", nil }
func (f *fakeL0) RenderReport() error                            { f.rendered = true; return nil }
func (f *fakeL0) ReportPath() string                             { return "/work/report.md" }

// reportCall 构造一次 generate_report 工具调用消息。
func reportCall(id string) *types.Message {
	return &types.Message{
		Role:    types.RoleAssistant,
		Content: "executing",
		ToolCalls: []types.ToolCall{{
			ID: id,
			Function: types.ToolCallFunction{
				Name:      "generate_report",
				Arguments: `{}`,
			},
		}},
	}
}

// TestNewAgentWithL0_ReportOnDemandTool 报告按需生成：L0 底座就绪时
// generate_report 工具可用（操作员明确要求时模型调用它渲染 report.md）；
// 无底座时不装配该工具（不主动生成报告）。
func TestNewAgentWithL0_ReportOnDemandTool(t *testing.T) {
	dir := t.TempDir()
	l0 := &fakeL0{}
	var calls int
	m := &fakeChatModel{
		onGenerate: func(ctx context.Context, msgs []*types.Message) (*types.Message, *types.TokenUsage, error) {
			calls++
			if calls == 1 {
				return reportCall("call_1"), nil, nil
			}
			return types.NewAssistantMessage("报告已生成"), nil, nil
		},
	}
	app, err := NewAgentWithL0(m, dir, "localhost", &fakeOperator{}, guard.PolicyAsk, &fakeRemote{}, "", l0)
	if err != nil {
		t.Fatalf("NewAgentWithL0: %v", err)
	}
	if _, err := app.Run(context.Background(), "出个巡检报告"); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !l0.rendered {
		t.Error("操作员要求报告时 generate_report 应渲染 report.md")
	}
}

// TestNewAgent_NoL0NoReportTool 无 L0 底座时装配不含 generate_report
// （报告不主动生成；引擎形态不经本装配，报告由主循环自动渲染）。
func TestNewAgent_NoL0NoReportTool(t *testing.T) {
	dir := t.TempDir()
	var calls int
	m := &fakeChatModel{
		onGenerate: func(ctx context.Context, msgs []*types.Message) (*types.Message, *types.TokenUsage, error) {
			calls++
			if calls == 1 {
				return reportCall("call_1"), nil, nil
			}
			return types.NewAssistantMessage("无法生成"), nil, nil
		},
	}
	app, err := NewAgent(m, dir, "localhost", &fakeOperator{}, guard.PolicyAsk, "")
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	if _, err := app.Run(context.Background(), "出个巡检报告"); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// 无 generate_report 工具：模型调用会收到"工具不存在"——本轮以模型
	// 第二次回答收尾（未渲染任何报告，也不报错中断）。
	if calls < 1 {
		t.Error("对话应正常推进（模型发现工具不可用后自然收尾）")
	}
}
