package env

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/go-gocel/gocode-ops/internal/common/model"
)

// Env 描述目标运行环境。探测结果决定检查清单实例化哪套命令集——
// 容器内没有 systemd，df/free 看到的是隔离视图，检查项需要按环境裁剪。
type Env struct {
	IsContainer bool // 运行在容器内（/proc/1/cgroup 含 docker/kubepods 等）
	HasSystemd  bool // systemd 可用（裸机/虚拟机常态）
	HasDocker   bool // docker/podman CLI 可用（宿主机场景，处置链备用）
	DockerCmd   string
	HasSS       bool // ss 可用（网络诊断备用）
	NProc       int  // 可见 CPU 核数（容器内为配额）
}

// DetectEnv 探测本机环境。
//
// 豁免说明（gocode/AGENTS.md 确定性验证豁免同类）：探测命令是固定只读
// 命令，模型不可控，带超时保护；失败时对应能力降级为 false，不报错。
func DetectEnv(ctx context.Context) *Env {
	env := &Env{NProc: runtime.NumCPU()}
	if env.NProc < 1 {
		env.NProc = 1
	}
	env.IsContainer = isContainer()
	env.HasSystemd = dirExists("/run/systemd/system")
	if cmd, ok := commandExists(ctx, "docker", "podman"); ok {
		env.HasDocker = true
		env.DockerCmd = cmd
	}
	if _, ok := commandExists(ctx, "ss"); ok {
		env.HasSS = true
	}
	return env
}

// DetectEnvInfo 由确定性探测生成最小环境画像（Explore 模型阶段失败时
// 兜底用；与 DetectEnv 同级确定性验证豁免——固定只读命令，带超时）。
// 字段缺省如实反映，来源在 Notes 标注，不假装模型级完整性。
func DetectEnvInfo(env *Env) *model.EnvInfo {
	info := &model.EnvInfo{
		Container: model.LenientBool(env.IsContainer),
		Notes:     "survey 模型阶段失败，env 由确定性探测兜底",
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		info.Hostname = h
	}
	if env.HasSystemd {
		info.ServiceMgr = "systemd"
	} else {
		info.ServiceMgr = "none"
	}
	if env.HasDocker {
		info.DockerCmd = env.DockerCmd
	}
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
				info.OS = strings.Trim(strings.TrimSpace(v), `"`)
				break
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "uname", "-r").Output(); err == nil {
		info.Kernel = strings.TrimSpace(string(out))
	}
	return info
}

// isContainer 通过 cgroup 路径判断是否运行在容器内。
func isContainer() bool {
	for _, p := range []string{"/proc/1/cgroup", "/proc/self/cgroup"} {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s := strings.ToLower(string(data))
		for _, marker := range []string{"docker", "kubepods", "containerd", "libpod", "lxc"} {
			if strings.Contains(s, marker) {
				return true
			}
		}
	}
	return false
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// commandExists 探测 PATH 中第一个可用的命令名。用 exec.LookPath 而非
// shell 内建 command -v——探测不依赖任何 shell（黑盒环境无 sh 也能探测）。
func commandExists(ctx context.Context, names ...string) (string, bool) {
	for _, name := range names {
		if p, err := exec.LookPath(name); err == nil && p != "" {
			return name, true
		}
	}
	return "", false
}
