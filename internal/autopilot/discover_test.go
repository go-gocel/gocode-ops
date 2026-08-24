package autopilot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-gocel/gocode-ops/internal/common/env"
	"github.com/go-gocel/gocode-ops/internal/common/guard"
	"github.com/go-gocel/gocode-ops/internal/common/model"
)

func TestLoadPrompt_OverrideWithPromptMD(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(model.ConfigDir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	custom := "按我公司规范排查，重点是时间线追查\n"
	if err := os.WriteFile(model.EnginePromptPath(dir), []byte(custom), 0o644); err != nil {
		t.Fatal(err)
	}
	got := loadPrompt(dir, nil)
	if !strings.Contains(got, "按我公司规范排查") {
		t.Errorf("prompt.engine.md 应覆盖引擎专属面: %q", got)
	}
	// 覆盖只替换专属面：共享方法论强制追加，不随覆盖丢失。
	if !strings.Contains(got, "追查方法论") {
		t.Error("覆盖后应强制追加共享方法论")
	}
}

// TestLoadPrompt_UsesFileContentVerbatim 文件内容原样作为系统提示词正文
// （不再剥离 # 行）：说明都在 helper.md 里，文件里写什么就是什么。
func TestLoadPrompt_UsesFileContentVerbatim(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(model.ConfigDir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	custom := "# 自定义说明行\n# 第二行\n\n按我公司规范排查\n"
	if err := os.WriteFile(model.EnginePromptPath(dir), []byte(custom), 0o644); err != nil {
		t.Fatal(err)
	}
	got := loadPrompt(dir, nil)
	if !strings.Contains(got, "按我公司规范排查") {
		t.Errorf("文件正文应作为系统提示词: %q", got)
	}
	if !strings.Contains(got, "自定义说明行") {
		t.Errorf("文件内容应原样使用（不剥离任何行）: %q", got)
	}
}

func TestLoadPrompt_FallbackToBuiltin(t *testing.T) {
	got := loadPrompt(t.TempDir(), nil)
	if !strings.Contains(got, "追查方法论") {
		t.Errorf("无 prompt.engine.md 时应使用内置系统提示: %q", got)
	}
}

func TestLoadPrompt_EmptyPromptMD(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(model.ConfigDir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	// 空文件视为未配置，回退内置。
	if err := os.WriteFile(model.EnginePromptPath(dir), []byte("  \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := loadPrompt(dir, nil)
	if !strings.Contains(got, "追查方法论") {
		t.Error("空 prompt.engine.md 应回退内置提示")
	}
}

func TestLoadPrompt_CommentOnlyPromptMD(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(model.ConfigDir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	// 空文件/全注释视为未配置，回退内置。
	if err := os.WriteFile(model.EnginePromptPath(dir), []byte("# 提示词覆盖\n# 请在此填写\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := loadPrompt(dir, nil)
	if !strings.Contains(got, "追查方法论") {
		t.Error("全注释 prompt.engine.md 应回退内置提示")
	}
}

func TestLoadPrompt_RendersTemplateVars(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(model.ConfigDir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	custom := "巡检目标: {{hosts}} 工作目录: {{workdir}} 本机: {{host}}\n"
	if err := os.WriteFile(model.EnginePromptPath(dir), []byte(custom), 0o644); err != nil {
		t.Fatal(err)
	}
	got := loadPrompt(dir, map[string]string{"workdir": dir, "hosts": "web-01, db-01", "host": "localhost"})
	for _, want := range []string{"web-01, db-01", "工作目录: " + dir, "本机: localhost"} {
		if !strings.Contains(got, want) {
			t.Errorf("模板变量未渲染，缺少 %q: %q", want, got)
		}
	}
}

// TestSystemPrompt_ContainsSharedBlocks 引擎内置系统提示含引擎专属面
// （身份 + 系统协作 SOP：阶段职责边界/裁决/覆盖/三件套/收敛）与共享
// 规则/方法论构建块（单一来源在 ops）。
func TestSystemPrompt_ContainsSharedBlocks(t *testing.T) {
	p := SystemPrompt()
	for _, want := range []string{"资深 Linux 运维排障专家", "系统协作 SOP", "阶段职责边界", "协议骨架", "三件套", "## 目标与工具（最高优先级）", "## 追查方法论"} {
		if !strings.Contains(p, want) {
			t.Errorf("引擎系统提示缺 %q", want)
		}
	}
}

// TestPromptBody_ReleasedContentIsBuiltinBody init 释放的引擎正文 = 内置
// 专属面：不含共享构建块/说明头（文件即提示词正文）。
func TestPromptBody_ReleasedContentIsBuiltinBody(t *testing.T) {
	body := PromptBody()
	for _, want := range []string{"资深 Linux 运维排障专家", "系统协作 SOP"} {
		if !strings.Contains(body, want) {
			t.Errorf("释放正文缺 %q", want)
		}
	}
	// 不含共享构建块：加载时统一追加（文件只承载引擎专属面）。
	if strings.Contains(body, "## 目标与工具（最高优先级）") || strings.Contains(body, "## 追查方法论") {
		t.Error("释放正文不应内嵌共享构建块（加载时统一追加）")
	}
	if strings.HasPrefix(body, "#") {
		t.Error("释放正文不应含说明头（文件即提示词正文）")
	}
}

// TestLoadPrompt_ReleasedPromptIsBuiltin init 释放的引擎正文文件加载后即为
// 内置系统提示（文件即提示词，无需"改写才生效"）。
func TestLoadPrompt_ReleasedPromptIsBuiltin(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(model.ConfigDir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(model.EnginePromptPath(dir), []byte(PromptBody()), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := loadPrompt(dir, nil); got != SystemPrompt() {
		t.Error("init 释放的正文加载后应等于内置系统提示（文件即提示词）")
	}
}

// TestLoadPrompt_ModifiedPromptOverrides 用户改写文件后，文件内容直接作为
// 系统提示词（文件即权威，不再回退内置）。
func TestLoadPrompt_ModifiedPromptOverrides(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(model.ConfigDir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	modified := strings.Replace(PromptBody(), "## 系统协作 SOP", "## 公司协作规范", 1)
	if err := os.WriteFile(model.EnginePromptPath(dir), []byte(modified), 0o644); err != nil {
		t.Fatal(err)
	}
	got := loadPrompt(dir, nil)
	if !strings.Contains(got, "公司协作规范") {
		t.Errorf("改写后的正文应直接生效: %q", got)
	}
	// 文件只承载引擎专属面：共享构建块强制追加。
	for _, want := range []string{"## 目标与工具（最高优先级）", "## 追查方法论"} {
		if !strings.Contains(got, want) {
			t.Errorf("加载文件后应强制追加 %q", want)
		}
	}
}

func TestEngine_AgentsMDAutoDiscover(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WorkDir = t.TempDir()
	cfg.Local = false
	cfg.Hosts = []string{"web-01"}
	e, err := newEngine(cfg, newFakeModel(), &fakeL0Remote{}, &env.Env{HasSystemd: true, NProc: 8})
	if err != nil {
		t.Fatal(err)
	}
	// 未显式指定 AgentsMDPath 时自动指向 <工作目录>/.gocode/AGENTS.md。
	want := filepath.Join(model.ConfigDir(cfg.WorkDir), "AGENTS.md")
	if e.agentsmd.Path != want {
		t.Errorf("agentsmd.Path = %q, want %q（自动发现）", e.agentsmd.Path, want)
	}
}

func TestEngine_AgentsMDExplicitPath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WorkDir = t.TempDir()
	cfg.Local = false
	cfg.Hosts = []string{"web-01"}
	cfg.AgentsMDPath = "/custom/AGENTS.md"
	e, err := newEngine(cfg, newFakeModel(), &fakeL0Remote{}, &env.Env{HasSystemd: true, NProc: 8})
	if err != nil {
		t.Fatal(err)
	}
	if e.agentsmd.Path != "/custom/AGENTS.md" {
		t.Errorf("显式指定应优先: %q", e.agentsmd.Path)
	}
}

func TestEngine_GuardPolicyAuto(t *testing.T) {
	// 全自动运维引擎守卫恒为 PolicyAuto（无人值守）：与 Operator/Policy 无关。
	cfg := DefaultConfig()
	cfg.WorkDir = t.TempDir()
	cfg.Local = false
	cfg.Hosts = []string{"web-01"}
	e, err := NewEngine(cfg, newFakeModel(), &fakeL0Remote{})
	if err != nil {
		t.Fatal(err)
	}
	if e.guard.Policy != guard.PolicyAuto {
		t.Errorf("无人值守引擎守卫 = %q, want auto", e.guard.Policy)
	}
}
