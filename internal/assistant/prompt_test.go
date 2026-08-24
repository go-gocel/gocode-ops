package assistant

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-gocel/gocode-ops/internal/autopilot"
	"github.com/go-gocel/gocode-ops/internal/common/guard"
	"github.com/go-gocel/gocode-ops/internal/common/l0"
	"github.com/go-gocel/gocode-ops/internal/common/model"
)

// 提示词分层：两种形态提示词独立成文（assistant.SystemPrompt /
// autopilot.SystemPrompt），共享规则与方法论构建块单一来源在 ops——
// 防产品间规则分裂。

// TestSharedOpsRules_AllFormsConsistent 两种形态的成文提示都包含共享规则块。
func TestSharedOpsRules_AllFormsConsistent(t *testing.T) {
	sys := SystemPrompt("web-01", "/tmp", guard.PolicyAsk)
	autop := autopilot.SystemPrompt()

	// 目标感知执行位置：remote_* 与清单别名规则两种形态一致；本机任务
	// 在本机执行（不总能优先远程）。
	for name, p := range map[string]string{"assistant": sys, "engine": autop} {
		if !strings.Contains(p, "remote_terminal") || !strings.Contains(p, "清单别名") {
			t.Errorf("%s 提示缺执行位置选择规则", name)
		}
		if !strings.Contains(p, "执行位置按目标选择") {
			t.Errorf("%s 提示缺目标感知规则", name)
		}
	}
	// 报告策略：报告按需生成只在助手提示（人在环，操作员显式要求时经
	// generate_report 工具）；引擎提示不含 generate_report（引擎报告由
	// 主循环自动渲染，无此工具）。
	if !strings.Contains(sys, "generate_report") {
		t.Error("助手提示应含 generate_report（报告按需生成）")
	}
	if strings.Contains(autop, "generate_report") {
		t.Error("引擎提示不应含 generate_report（报告由引擎自动渲染）")
	}
	// 凭证保密：system 级（assistant/engine）一致；respond 阶段契约继承 system。
	for name, p := range map[string]string{"assistant": sys, "engine": autop} {
		if !strings.Contains(p, "凭证") || !strings.Contains(p, "shadow") {
			t.Errorf("%s 提示缺凭证保密规则", name)
		}
	}
	// 通道安全：两种形态一致（单一来源 SharedOpsRules/ChannelSafetyRules）。
	for name, p := range map[string]string{"assistant": sys, "engine": autop} {
		if !strings.Contains(p, "自身通道安全") || !strings.Contains(p, "PermitRootLogin") {
			t.Errorf("%s 提示缺通道安全规则", name)
		}
	}
	// 守卫协作：不绕过。
	for name, p := range map[string]string{"assistant": sys, "engine": autop} {
		if !strings.Contains(p, "不要尝试绕过") {
			t.Errorf("%s 提示缺守卫协作规则", name)
		}
	}
}

// TestSharedOpsRules_SingleSource engine 与 assistant 的共享规则文本同源
// （不是各自抄写——改一处两处生效）。
func TestSharedOpsRules_SingleSource(t *testing.T) {
	sys := SystemPrompt("web-01", "/tmp", guard.PolicyAsk)
	autop := autopilot.SystemPrompt()
	// 共享规则块的标志段（remoteTargetRules 开头）必须在两处完整出现。
	marker := "## 目标与工具（最高优先级）"
	for name, p := range map[string]string{"assistant": sys, "engine": autop} {
		if !strings.Contains(p, marker) {
			t.Errorf("%s 提示应包含共享规则块起点 %q", name, marker)
		}
	}
}

// TestMethodologyRules_SingleSource 追查方法论单一来源：交互式运维助手与
// 全自动运维引擎共用同一段方法论文本（改一处两处生效）。
func TestMethodologyRules_SingleSource(t *testing.T) {
	sys := SystemPrompt("web-01", "/tmp", guard.PolicyAsk)
	autop := autopilot.SystemPrompt()
	for name, p := range map[string]string{"assistant": sys, "engine": autop} {
		for _, want := range []string{"## 追查方法论", "痕迹追踪", "根因闭环", "完整性核查"} {
			if !strings.Contains(p, want) {
				t.Errorf("%s 提示缺共享方法论 %q", name, want)
			}
		}
	}
}

// TestPrompts_IndependentDocuments 两种形态提示词独立成文：助手提示含
// 助手专属面（命令优先/部署与优化/任务处置 SOP），引擎提示不含；引擎
// 提示含引擎专属面（系统协作 SOP/协议骨架），助手提示不含。
func TestPrompts_IndependentDocuments(t *testing.T) {
	sys := SystemPrompt("web-01", "/tmp", guard.PolicyAsk)
	autop := autopilot.SystemPrompt()
	for _, want := range []string{"命令优先", "部署与优化", "任务处置 SOP", "交互与安全规则"} {
		if !strings.Contains(sys, want) {
			t.Errorf("助手提示缺专属面 %q", want)
		}
		if strings.Contains(autop, want) {
			t.Errorf("引擎提示不应含助手专属面 %q", want)
		}
	}
	for _, want := range []string{"资深 Linux 运维排障专家", "未知故障", "系统协作 SOP", "协议骨架"} {
		if !strings.Contains(autop, want) {
			t.Errorf("引擎提示缺专属面 %q", want)
		}
		if strings.Contains(sys, want) {
			t.Errorf("助手提示不应含引擎专属面 %q", want)
		}
	}
}

// TestLoadAssistantPrompt_Override 交互提示词覆盖：prompt.assistant.md
// 有效内容替换内置交互提示，模板变量渲染，交互专属规则追加（覆盖不丢
// 人在环约束）。
func TestLoadAssistantPrompt_Override(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(model.ConfigDir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	custom := "按我公司规范排查，目标: {{hosts}}\n"
	if err := os.WriteFile(model.AssistantPromptPath(dir), []byte(custom), 0o644); err != nil {
		t.Fatal(err)
	}
	got := loadAssistantPrompt(dir, "localhost", guard.PolicyAsk, map[string]string{"hosts": "web-01, db-01", "workdir": dir, "host": "localhost"})
	if !strings.Contains(got, "按我公司规范排查") {
		t.Errorf("prompt.assistant.md 应覆盖交互提示: %q", got)
	}
	if !strings.Contains(got, "web-01, db-01") {
		t.Errorf("模板变量未渲染: %q", got)
	}
	if !strings.Contains(got, "ask_operator") {
		t.Error("覆盖后应保留交互专属规则（ask_operator）")
	}
	// 覆盖只替换产品专属面：共享安全规则与追查方法论强制追加，不随覆盖丢失。
	for _, want := range []string{"## 目标与工具（最高优先级）", "凭证保密", "自身通道安全", "## 追查方法论", "根因闭环"} {
		if !strings.Contains(got, want) {
			t.Errorf("覆盖后应强制追加共享构建块 %q", want)
		}
	}
}

// TestLoadAssistantPrompt_UsesFileContentVerbatim 文件内容原样作为提示词
// 正文（不再剥离 # 行）：说明都在 helper.md 里，文件里写什么就是什么。
func TestLoadAssistantPrompt_UsesFileContentVerbatim(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(model.ConfigDir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	custom := "# 自定义说明行\n# 第二行\n\n按我公司规范排查\n"
	if err := os.WriteFile(model.AssistantPromptPath(dir), []byte(custom), 0o644); err != nil {
		t.Fatal(err)
	}
	got := loadAssistantPrompt(dir, "web-01", guard.PolicyAsk, nil)
	if !strings.Contains(got, "按我公司规范排查") {
		t.Errorf("文件正文应作为提示词: %q", got)
	}
	if !strings.Contains(got, "自定义说明行") {
		t.Errorf("文件内容应原样使用（不剥离任何行）: %q", got)
	}
}

// TestLoadAssistantPrompt_Fallback 无 prompt.assistant.md / 全注释时
// 回退内置交互提示。
func TestLoadAssistantPrompt_Fallback(t *testing.T) {
	dir := t.TempDir()
	got := loadAssistantPrompt(dir, "web-01", guard.PolicyAsk, nil)
	if !strings.Contains(got, "交互式运维助手") {
		t.Errorf("无 prompt.assistant.md 时应使用内置交互提示: %q", got)
	}
	if err := os.MkdirAll(model.ConfigDir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(model.AssistantPromptPath(dir), []byte("# 全是注释\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got = loadAssistantPrompt(dir, "web-01", guard.PolicyAsk, nil)
	if !strings.Contains(got, "交互式运维助手") {
		t.Error("全注释 prompt.assistant.md 应回退内置交互提示")
	}
}

// TestPromptBody_ReleasedContentIsBuiltinBody init 释放的正文 = 内置产品专属面：
// 含占位符与专属面、不含策略说明/共享构建块/说明头（文件即提示词正文，
// 不残留旧版模板的 # 说明头）。
func TestPromptBody_ReleasedContentIsBuiltinBody(t *testing.T) {
	body := PromptBody()
	for _, want := range []string{"{{host}}", "{{workdir}}", "交互式运维助手", "命令优先"} {
		if !strings.Contains(body, want) {
			t.Errorf("释放正文缺 %q", want)
		}
	}
	// 不含策略相关文本：交互与安全规则由运行时按策略追加（单一来源）。
	if strings.Contains(body, "当前策略为") {
		t.Error("释放正文不应内嵌策略说明（运行时按当前策略追加）")
	}
	// 不含共享规则/方法论：加载时强制追加（文件只承载产品专属面）。
	if strings.Contains(body, "## 目标与工具（最高优先级）") || strings.Contains(body, "## 追查方法论") {
		t.Error("释放正文不应内嵌共享构建块（加载时统一追加）")
	}
	if strings.HasPrefix(body, "#") {
		t.Error("释放正文不应含说明头（文件即提示词正文）")
	}
}

// TestLoadAssistantPrompt_ReleasedPromptIsBuiltin init 释放的正文文件加载后
// 即为内置 SystemPrompt：释放内容渲染占位符后 + 共享构建块与交互规则强制
// 追加——文件直接作为系统提示词，无需"改写才生效"。
func TestLoadAssistantPrompt_ReleasedPromptIsBuiltin(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(model.ConfigDir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(model.AssistantPromptPath(dir), []byte(PromptBody()), 0o644); err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{"host": "web-01", "workdir": dir, "hosts": "web-01"}
	got := loadAssistantPrompt(dir, "web-01", guard.PolicyAsk, vars)
	if got != SystemPrompt("web-01", dir, guard.PolicyAsk) {
		t.Error("init 释放的正文加载后应等于内置 SystemPrompt（文件即提示词）")
	}
	if strings.Contains(got, "{{") {
		t.Error("加载结果不应残留未渲染的模板变量")
	}
}

// TestLoadAssistantPrompt_ModifiedPromptOverrides 用户改写文件后，文件内容
// 直接作为系统提示词（文件即权威，不再回退内置）。
func TestLoadAssistantPrompt_ModifiedPromptOverrides(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(model.ConfigDir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	modified := strings.Replace(PromptBody(), "## 命令优先", "## 命令先行", 1)
	if err := os.WriteFile(model.AssistantPromptPath(dir), []byte(modified), 0o644); err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{"host": "web-01", "workdir": dir, "hosts": "web-01"}
	got := loadAssistantPrompt(dir, "web-01", guard.PolicyAsk, vars)
	if !strings.Contains(got, "命令先行") {
		t.Errorf("改写后的正文应直接生效: %q", got)
	}
	if strings.Contains(got, "命令优先") {
		t.Error("改写后的正文不应再含被替换的内容")
	}
	// 文件只承载产品专属面：共享构建块与交互规则强制追加。
	for _, want := range []string{"## 目标与工具（最高优先级）", "## 追查方法论", "ask_operator"} {
		if !strings.Contains(got, want) {
			t.Errorf("加载文件后应强制追加 %q", want)
		}
	}
}

// TestTemplateVars_InventoryAndFallback 模板变量：清单别名逗号连接；
// 无清单时回退本机显示名。
func TestTemplateVars_InventoryAndFallback(t *testing.T) {
	dir := t.TempDir()
	invPath := filepath.Join(dir, "hosts.yaml")
	content := `hosts:
  - name: web-01
    address: 10.0.0.11
    user: root
    key_file: ~/.ssh/id_ed25519
  - name: db-01
    address: 10.0.0.12
    user: ops
    password: "s3cret"
`
	if err := os.WriteFile(invPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	vars := l0.TemplateVars(dir, "localhost", invPath)
	if vars["hosts"] != "web-01, db-01" {
		t.Errorf("hosts = %q, want 清单别名逗号连接", vars["hosts"])
	}
	if vars["workdir"] != dir || vars["host"] != "localhost" {
		t.Errorf("vars = %v，workdir/host 应回填", vars)
	}
	vars = l0.TemplateVars(dir, "localhost", "")
	if vars["hosts"] != "localhost" {
		t.Errorf("无清单时 hosts = %q, want 本机显示名", vars["hosts"])
	}
}
