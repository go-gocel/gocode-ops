package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-gocel/gocel-core/core/kernel"
	"github.com/go-gocel/gocel-core/types"
)

// fakeRegistrar 收集 OnMessagesBuilt 钩子（其余钩子空实现）。
type fakeRegistrar struct {
	messagesBuilt kernel.MessagesHook
}

func (f *fakeRegistrar) OnAgentStart(fn kernel.AgentStartHook) func() { return func() {} }
func (f *fakeRegistrar) OnAgentEnd(fn kernel.AgentEndHook) func()     { return func() {} }
func (f *fakeRegistrar) OnMessagesBuilt(fn kernel.MessagesHook) func() {
	f.messagesBuilt = fn
	return func() {}
}
func (f *fakeRegistrar) OnStepStart(fn kernel.StepHook) func()              { return func() {} }
func (f *fakeRegistrar) OnStepEnd(fn kernel.StepHook) func()                { return func() {} }
func (f *fakeRegistrar) OnModelCall(fn kernel.ModelCallHook) func()         { return func() {} }
func (f *fakeRegistrar) OnModelResult(fn kernel.ModelResultHookFunc) func() { return func() {} }
func (f *fakeRegistrar) OnToolCall(fn kernel.ToolCallHook) func()           { return func() {} }
func (f *fakeRegistrar) OnToolResult(fn kernel.ToolResultHookFunc) func()   { return func() {} }
func (f *fakeRegistrar) OnDecision(fn kernel.DecisionHook) func()           { return func() {} }

func TestAgentsMDModule_Inject(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "AGENTS.md")
	content := "# 自定义说明行\n- 环境为 3 节点 web 服务\n- 重点关注数据库节点\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	m := NewAgentsMDModule(path, nil)
	reg := &fakeRegistrar{}
	m.Register(reg)
	if reg.messagesBuilt == nil {
		t.Fatal("应注册 OnMessagesBuilt 钩子")
	}
	msgs := []*types.Message{types.NewSystemMessage("主提示")}
	_, out, err := reg.messagesBuilt(context.Background(), msgs)
	if err != nil {
		t.Fatalf("inject: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("消息数 = %d, want 2（主提示 + AGENTS.md）", len(out))
	}
	joined := out[1].Content
	if !strings.Contains(joined, "环境为 3 节点") || !strings.Contains(joined, "数据库节点") {
		t.Errorf("AGENTS.md 内容未注入: %q", joined)
	}
	// 文件内容原样注入（无说明块剥离约定）：# 行也在其中。
	if !strings.Contains(joined, "自定义说明行") {
		t.Errorf("文件内容应原样注入（不再剥离开头的 # 行）: %q", joined)
	}
}

func TestAgentsMDModule_MissingFileNoop(t *testing.T) {
	m := NewAgentsMDModule(filepath.Join(t.TempDir(), "nope.md"), nil)
	reg := &fakeRegistrar{}
	m.Register(reg)
	msgs := []*types.Message{types.NewSystemMessage("主提示")}
	_, out, err := reg.messagesBuilt(context.Background(), msgs)
	if err != nil {
		t.Fatalf("inject: %v", err)
	}
	if len(out) != 1 {
		t.Errorf("文件缺失应空转: %d 条消息", len(out))
	}
}

func TestAgentsMDModule_EmptyPathNoop(t *testing.T) {
	m := NewAgentsMDModule("", nil)
	if got := m.load(); got != "" {
		t.Errorf("空路径应返回空内容: %q", got)
	}
}

func TestAgentsMDModule_CommentOnlyTemplateNoop(t *testing.T) {
	// 空文件/全注释视为未配置，不注入（防未填写模板污染上下文）。
	dir := t.TempDir()
	path := filepath.Join(dir, "AGENTS.md")
	tpl := "# 环境信息约定（AGENTS.md）\n# 请填写环境预期与重点怀疑方向\n"
	if err := os.WriteFile(path, []byte(tpl), 0o644); err != nil {
		t.Fatal(err)
	}
	m := NewAgentsMDModule(path, nil)
	reg := &fakeRegistrar{}
	m.Register(reg)
	msgs := []*types.Message{types.NewSystemMessage("主提示")}
	_, out, err := reg.messagesBuilt(context.Background(), msgs)
	if err != nil {
		t.Fatalf("inject: %v", err)
	}
	if len(out) != 1 {
		t.Errorf("全注释模板应空转: %d 条消息", len(out))
	}
}

func TestAgentsMDModule_RendersTemplateVars(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "AGENTS.md")
	content := "巡检目标: {{hosts}}\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	m := NewAgentsMDModule(path, map[string]string{"hosts": "web-01, db-01"})
	if got := m.load(); !strings.Contains(got, "web-01, db-01") {
		t.Errorf("模板变量未渲染: %q", got)
	}
}
