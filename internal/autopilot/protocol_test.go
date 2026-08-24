package autopilot

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/go-gocel/gocel-core/core/kernel"
	"github.com/go-gocel/gocel-core/types"

	"github.com/go-gocel/gocode-ops/internal/common/remediate"
)

// fakeModel 可编排的 kernel.ChatModel：按调用次数返回预设消息。
// 并发安全：并行批次（worker 池）同时调用 Generate。
type fakeModel struct {
	mu        sync.Mutex
	replies   []string
	call      int
	prompts   []string // 收到的最后一条 user 消息（测试断言反馈回灌）
	msgCounts []int    // 每次 Generate 收到的消息数（断言阶段上下文不累积）
}

func newFakeModel(replies ...string) *fakeModel { return &fakeModel{replies: replies} }

func (f *fakeModel) CountTokens(ctx context.Context, msgs []*types.Message, opts ...kernel.GenOption) (int, error) {
	return 0, nil
}

func (f *fakeModel) Generate(ctx context.Context, msgs []*types.Message, opts ...kernel.GenOption) (*types.Message, *types.TokenUsage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgCounts = append(f.msgCounts, len(msgs))
	if len(msgs) > 0 {
		f.prompts = append(f.prompts, msgs[len(msgs)-1].Content)
	}
	var content string
	if f.call < len(f.replies) {
		content = f.replies[f.call]
	} else {
		content = `{"phase":"x","done":true,"covered":["cpu"],"findings":[]}`
	}
	f.call++
	return types.NewAssistantMessage(content), nil, nil
}

func (f *fakeModel) Stream(ctx context.Context, msgs []*types.Message, opts ...kernel.GenOption) (kernel.StreamReader, error) {
	return nil, nil
}

// ── 阶段小结解析 ──────────────────────────────────────────────────────

func TestParsePhaseSummary(t *testing.T) {
	content := `好的，我先检查系统状态。
{"phase":"baseline","done":true,"covered":["cpu","mem","disk"],
 "findings":[{"host":"web-01","domain":"svc","signal":"svc_failed","desc":"nginx 服务失败","status":"pending"}]}
以上是结果。`
	sum, err := parsePhaseSummary(content)
	if err != nil {
		t.Fatalf("parsePhaseSummary: %v", err)
	}
	if sum.Phase != "baseline" || !sum.Done {
		t.Errorf("sum = %+v", sum)
	}
	if len(sum.Covered) != 3 {
		t.Errorf("covered = %v", sum.Covered)
	}
	if len(sum.Findings) != 1 || sum.Findings[0].Signal != "svc_failed" {
		t.Errorf("findings = %+v", sum.Findings)
	}
}

func TestParsePhaseSummary_Invalid(t *testing.T) {
	if _, err := parsePhaseSummary("not json at all"); err == nil {
		t.Error("非法 JSON 应报错")
	}
}

func TestParsePhaseSummary_LenientJSON(t *testing.T) {
	// 模型输出常见瑕疵应被容错：全角引号、布尔写成字符串、尾随逗号。
	content := `{“phase”: “explore”, “done”: “true”, “covered”: [“env”,],
 “env”: {“os”: “Ubuntu 22.04”, “container”: “true”},}`
	sum, err := parsePhaseSummary(content)
	if err != nil {
		t.Fatalf("parsePhaseSummary 应容错: %v", err)
	}
	if !sum.Done {
		t.Error("done=\"true\" 字符串应解析为布尔 true")
	}
	if sum.Env == nil || !sum.Env.Container {
		t.Errorf("container=\"true\" 字符串应解析为布尔 true: %+v", sum.Env)
	}
	if len(sum.Covered) != 1 || sum.Covered[0] != "env" {
		t.Errorf("covered = %v", sum.Covered)
	}
}

func TestNormalizeJSON_MigratedToJsonx(t *testing.T) {
	// 语法修复能力已迁至 gocel/jsonx（单一来源），此处只保留
	// 行为级回归：通过 parseModelJSON 验证迁移后行为不退化。
	var m map[string]any
	in := `{"desc":"他说“好”，然后",}`
	if err := parseModelJSON(in, &m); err != nil {
		t.Fatalf("parseModelJSON 应容错: %v", err)
	}
	if m["desc"] != "他说“好”，然后" {
		t.Errorf("desc = %v", m["desc"])
	}
}

func TestPhaseSummary_Validate(t *testing.T) {
	ok := &PhaseSummary{Phase: "baseline", Done: true, Covered: []string{"cpu", "mem", "disk"}}
	if err := ok.validate("baseline", []string{"cpu", "disk"}); err != nil {
		t.Errorf("应通过: %v", err)
	}
	if err := ok.validate("baseline", []string{"security"}); err == nil {
		t.Error("缺少必须覆盖域应失败")
	}
	if err := (&PhaseSummary{Phase: "x", Done: false, Covered: []string{"cpu"}}).validate("x", nil); err == nil {
		t.Error("未声明完成应失败")
	}
	if err := (&PhaseSummary{Phase: "x", Done: true}).validate("x", nil); err == nil {
		t.Error("covered 为空应失败")
	}
}

// ── 处置方案契约 ──────────────────────────────────────────────────────

func TestParseResponsePlans(t *testing.T) {
	content := `{"plans":[{"finding_id":"f1","actions":[{"name":"restart","command":"systemctl restart nginx.service",
"rationale":"服务失败","verify":"systemctl is-active nginx.service","check_up":"active","rollback":"systemctl restore nginx.service"}]}]}`
	ps, err := parseResponsePlans(content)
	if err != nil {
		t.Fatalf("parseResponsePlans: %v", err)
	}
	if len(ps.Plans) != 1 || ps.Plans[0].FindingID != "f1" {
		t.Fatalf("plans = %+v", ps.Plans)
	}
	plan := &ps.Plans[0]
	if len(plan.Actions) != 1 || plan.Actions[0].Command != "systemctl restart nginx.service" {
		t.Errorf("plan = %+v", plan)
	}
	if bad := plan.Validate(); len(bad) != 0 {
		t.Errorf("完整三件套不应校验失败: %v", bad)
	}
}

// TestParseResponsePlans_Empty 空 plans 拒绝（批量契约必须有内容）。
func TestParseResponsePlans_Empty(t *testing.T) {
	if _, err := parseResponsePlans(`{"plans":[]}`); err == nil {
		t.Error("空 plans 应解析失败")
	}
}

// TestParseResponsePlans_BareArray 模型输出裸数组（顶层 [...] 而非
// {"plans":[...]}）时契约层适配：数组元素即 plans。
func TestParseResponsePlans_BareArray(t *testing.T) {
	content := `[{"finding_id":"f1","actions":[{"name":"restart","command":"systemctl restart nginx.service",
"rationale":"服务失败","verify":"systemctl is-active nginx.service","check_up":"active","rollback":"systemctl restore nginx.service"}]}]`
	ps, err := parseResponsePlans(content)
	if err != nil {
		t.Fatalf("裸数组应解析成功: %v", err)
	}
	if len(ps.Plans) != 1 || ps.Plans[0].FindingID != "f1" {
		t.Fatalf("plans = %+v", ps.Plans)
	}
}

// TestParseResponsePlans_BareEmptyArray 顶层空数组 [] 视同空 plans 拒绝。
func TestParseResponsePlans_BareEmptyArray(t *testing.T) {
	if _, err := parseResponsePlans(`[]`); err == nil {
		t.Error("空数组应解析失败（处置方案为空）")
	}
}

func TestParseResponsePlans_LenientJSON(t *testing.T) {
	// 处置方案输出带全角引号时应解析成功；字符串内全角逗号保持原样。
	content := `{“plans”: [{“finding_id”: “f1”, “actions”: [{“name”: “restart nginx”, “command”: “systemctl restart nginx.service”,
“rationale”: “服务失败，重启恢复”, “verify”: “systemctl is-active nginx.service”, “check_up”: “active”, “rollback”: “systemctl restore nginx.service”}]}]}`
	ps, err := parseResponsePlans(content)
	if err != nil {
		t.Fatalf("parseResponsePlans 应容错: %v", err)
	}
	plan := &ps.Plans[0]
	if len(plan.Actions) != 1 || plan.Actions[0].Command != "systemctl restart nginx.service" {
		t.Errorf("plan = %+v", plan)
	}
	if plan.Actions[0].Rationale != "服务失败，重启恢复" {
		t.Errorf("rationale 应保留原文: %q", plan.Actions[0].Rationale)
	}
	if bad := plan.Validate(); len(bad) != 0 {
		t.Errorf("完整三件套不应校验失败: %v", bad)
	}
}

func TestResponsePlan_ValidateMissingFields(t *testing.T) {
	cases := []remediate.PlanAction{
		{Name: "no-verify", Command: "x", Rationale: "r", CheckUp: "c", Rollback: "b"}, // 缺 verify
		{Name: "no-rollback", Command: "x", Rationale: "r", Verify: "v", CheckUp: "c"}, // 缺 rollback
		{Name: "no-rationale", Command: "x", Verify: "v", CheckUp: "c", Rollback: "b"}, // 缺 rationale
		{Name: "no-command", Rationale: "r", Verify: "v", CheckUp: "c", Rollback: "b"}, // 缺 command
	}
	for _, c := range cases {
		p := &remediate.Plan{Actions: []remediate.PlanAction{c}}
		if bad := p.Validate(); len(bad) == 0 {
			t.Errorf("%s 应校验失败", c.Name)
		}
	}
	if bad := (&remediate.Plan{}).Validate(); len(bad) == 0 {
		t.Error("空方案应校验失败")
	}
}

func TestTaskPrompt_ExploreDocumentsEnvSchema(t *testing.T) {
	// 输出契约必须给模型 env 的完整 schema（含布尔类型示例），
	// 否则模型只能猜字段与类型（container 被写成字符串的根因之一）。
	p := taskPrompt(PhaseSurvey, "x", "", 0)
	for _, want := range []string{`"container": false`, "同一根因"} {
		if !strings.Contains(p, want) {
			t.Errorf("任务提示缺少 %q", want)
		}
	}
}

func TestTaskPrompt_L0FactsAndDoubtRule(t *testing.T) {
	p := taskPrompt(PhaseSurvey, "x", "", 0)
	for _, want := range []string{"l0_facts", "疑点", "findings"} {
		if !strings.Contains(p, want) {
			t.Errorf("阶段提示缺少 %q", want)
		}
	}
}

func TestRespondTaskPrompt_FeedbackHint(t *testing.T) {
	// respondFeedback 由引擎拼入 goal，契约本身提示模型按失败原因修正。
	p := respondTaskPrompt("goal", "")
	for _, want := range []string{"rollback", "check_up", "自身通道安全"} {
		if !strings.Contains(p, want) {
			t.Errorf("处置契约缺少 %q", want)
		}
	}
}

// ── 阶段日志与提示 ────────────────────────────────────────────────────

func TestPhaseEventLine(t *testing.T) {
	cases := []struct {
		name string
		ev   *types.Event
		want string
		log  bool
	}{
		{"工具调用", types.ToolCallEvent("terminal", `{"command":"df -h"}`, "c1"),
			"[survey] 调用 terminal({\"command\":\"df -h\"})", true},
		{"工具成功", types.ToolResultEvent("terminal", "Filesystem 1K-blocks", "c1"),
			"[survey] ✔ terminal: Filesystem 1K-blocks", true},
		{"工具失败", types.ToolResultEvent("terminal", `{"error":"tool call blocked: ops 安全守卫: 高危命令"}`, "c1"),
			"[survey] ✗ terminal: {\"error\":\"tool call blocked: ops 安全守卫: 高危命令\"}", true},
		{"模型正文不进日志", &types.Event{Type: types.EventToken, Content: "巡检结果"}, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			line, ok := phaseEventLine(PhaseSurvey, c.ev)
			if ok != c.log {
				t.Fatalf("log = %v, want %v", ok, c.log)
			}
			if ok && line != c.want {
				t.Errorf("line = %q, want %q", line, c.want)
			}
		})
	}
}
