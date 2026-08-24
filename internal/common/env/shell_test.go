package env

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

// TestLocalShell_ResolvesAUsableShell 探测结果必须真实可用：用解析出的
// shell 试执行一条命令必须成功（Windows 无 Git Bash 时兜底 cmd.exe，
// "echo" 两个平台都可用）。
func TestLocalShell_ResolvesAUsableShell(t *testing.T) {
	spec := LocalShell()
	if spec.Name == "" {
		t.Fatal("LocalShell() 必须返回非空 shell 名")
	}
	ctx := context.Background()
	c := exec.CommandContext(ctx, spec.Name, append(append([]string{}, spec.Args...), "echo __LOCAL_SHELL_OK__")...)
	out, err := c.Output()
	if err != nil {
		t.Fatalf("探测到的 shell %q 不可执行: %v", spec.Name, err)
	}
	if !strings.Contains(string(out), "__LOCAL_SHELL_OK__") {
		t.Fatalf("探测到的 shell %q 输出异常: %q", spec.Name, string(out))
	}
}

// TestExecWithLocalShell 用探测 shell 执行命令（ExecLocal 的底层路径）。
func TestExecWithLocalShell(t *testing.T) {
	ctx := context.Background()
	c := execWithLocalShell(ctx, "echo hello-local; echo world")
	out, err := c.Output()
	if err != nil {
		t.Fatalf("execWithLocalShell: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "hello-local") || !strings.Contains(s, "world") {
		t.Fatalf("输出不完整: %q", s)
	}
}
