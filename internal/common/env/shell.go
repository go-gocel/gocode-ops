package env

// 本地 shell 解析：不假设进程所在环境有 sh。gocode-ops 的本地执行链
// （ExecLocal/探测/gocel terminal 工具）历史上硬编码 "sh -c"——bash-only
// 容器、无 Git Bash 的 Windows 上整片失败（"整个程序趴窝"）。这里用
// 试执行式探测解析出可用 POSIX shell，探测结果注入 gocel context
// （shell.WithShellInContext）与本地执行点。
//
// 探测必须是"试执行"而非"查路径"：PATH 里的 bash.exe 可能是 WSL 启动器
// （C:\Windows\System32\bash.exe），LookPath 找到它并不代表 POSIX 语义可用。

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ShellSpec is the local shell execution spec: a command name plus an argument prefix.
// ShellSpec 是本地 shell 执行规格：命令名 + 执行参数前缀。
// Args 缺省为 ["-c"]（POSIX 语义：Name -c <command>）。
type ShellSpec struct {
	Name string   `json:"name"`
	Args []string `json:"args"`
}

// LocalShell returns the locally detected shell spec, cached per process after the first probe.
// LocalShell 返回本机探测到的 shell 规格（进程内缓存，探测一次）。
func LocalShell() ShellSpec {
	localShellOnce.Do(func() {
		localShell = detectLocalShell()
	})
	return localShell
}

var (
	localShellOnce sync.Once
	localShell     ShellSpec
)

// posixShellCandidates 探测优先级：$SHELL 显式偏好 → POSIX 标准链。
// Windows 上 bash 可能是 WSL 启动器（System32\bash.exe）——排在 sh
// 之后且经试执行验证，避免无 Git Bash 时误入 WSL 语义。
func posixShellCandidates() []string {
	cands := []string{"sh", "bash", "dash", "ksh", "zsh", "ash"}
	if runtime.GOOS == "windows" {
		// Git Bash/MSYS2 提供 sh；bash 兜底（可能解析到 WSL 启动器）。
		cands = []string{"sh", "bash"}
	}
	if env := strings.TrimSpace(os.Getenv("SHELL")); env != "" {
		if base := strings.TrimSuffix(filepath.Base(env), ".exe"); base != "" && base != "sh" {
			// 用户偏好置顶（zsh 用户的环境按 zsh 语义执行），仍要试执行验证。
			cands = append([]string{base}, cands...)
		}
	}
	return cands
}

// probeShellOK 试执行一个候选 shell：能跑且输出含探测标记才算可用。
// 固定只读命令（模型不可控），带 2s 超时，失败静默降级。
func probeShellOK(name string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, name, "-c", "echo __SHELL_PROBE_OK__")
	c.Env = []string{"PATH=" + os.Getenv("PATH")}
	out, err := c.Output()
	return err == nil && strings.Contains(string(out), "__SHELL_PROBE_OK__")
}

// detectLocalShell 探测本机可用 shell：第一个试执行成功的候选胜出；
// 全部失败回退 "sh -c"（保持历史错误语义——调用方会拿到可诊断的
// exec 错误，而不是静默换执行方式）。
func detectLocalShell() ShellSpec {
	seen := map[string]bool{}
	for _, name := range posixShellCandidates() {
		if seen[name] {
			continue
		}
		seen[name] = true
		if probeShellOK(name) {
			return ShellSpec{Name: name, Args: []string{"-c"}}
		}
	}
	if runtime.GOOS == "windows" {
		// Windows 原生兜底：cmd.exe 必然存在。POSIX 命令在 cmd 下大多
		// 失败，但工具链不再因"找不到 sh"整片趴窝，错误可读。
		return ShellSpec{Name: "cmd", Args: []string{"/C"}}
	}
	return ShellSpec{Name: "sh", Args: []string{"-c"}}
}

// execWithLocalShell 用探测到的本地 shell 构造执行命令
// （ExecLocal 与 gocel terminal 注入共用同一规格）。
func execWithLocalShell(ctx context.Context, cmd string) *exec.Cmd {
	spec := LocalShell()
	return exec.CommandContext(ctx, spec.Name, append(append([]string{}, spec.Args...), cmd)...)
}
