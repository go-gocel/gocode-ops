package agent

import (
	"os"
	"testing"
)

func TestIsInitialized(t *testing.T) {
	dir := t.TempDir()
	if IsInitialized(dir) {
		t.Fatal("未 init 的工作目录不应判定为已初始化")
	}
	if err := os.MkdirAll(ConfigDir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if !IsInitialized(dir) {
		t.Fatal("存在 .gocode 目录应判定为已初始化")
	}
}

func TestHasEffectiveContent(t *testing.T) {
	if HasEffectiveContent("") || HasEffectiveContent("  \n\t\n") {
		t.Error("空文本应无有效内容")
	}
	if HasEffectiveContent("# 注释\n# 全部是注释\n") {
		t.Error("全注释文本应无有效内容")
	}
	if !HasEffectiveContent("# 标题\n- 真实内容\n") {
		t.Error("含正文的文本应有有效内容")
	}
}

func TestRenderVars_UnknownKept(t *testing.T) {
	got := RenderVars("{{workdir}}/{{nope}}", map[string]string{"workdir": "/srv/ops"})
	if got != "/srv/ops/{{nope}}" {
		t.Errorf("未知变量应原样保留: %q", got)
	}
}
