package env

import (
	"context"
	"testing"
)

func TestDetectEnv_RunsWithoutError(t *testing.T) {
	env := DetectEnv(context.Background())
	if env.NProc < 1 {
		t.Errorf("NProc = %d, 期望 >= 1", env.NProc)
	}
	// 探测不应恐慌；容器/裸机只是标记不同。
	if !env.IsContainer && !env.HasSystemd && !env.HasDocker {
		t.Log("环境无法归类（可能在精简容器中），但不应报错")
	}
}

func TestIsContainer_MarkerDetection(t *testing.T) {
	// /proc/1/cgroup 在 CI/容器里包含 docker/kubepods 标记；裸机不包含。
	// 这里只验证函数可执行且不崩溃。
	_ = isContainer()
}
