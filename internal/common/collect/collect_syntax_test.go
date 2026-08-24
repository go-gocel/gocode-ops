package collect

import (
	"os/exec"
	"strings"
	"testing"

	p "github.com/go-gocel/gocode-ops/internal/common/probe"
)

// TestCollectCommandRealShellSyntax 机制级防回归：采集命令必须通过真实
// shell 的语法校验（sh -n）。
//
// 背景（真实环境事故）：boundedProbe 曾直接包裹 for 循环生成
// `timeout -s KILL 20s for d in ...; do ...` —— for 是 shell 关键字，
// 整条 collect 命令在远端 sh 解析失败，L0 指标/状态/事实全部静默丢失
// （"指标 0 项"）。fake 执行器从不真实执行命令，单元测试只校验命令
// 字符串包含 marker，语法错误无法被发现——本测试用真实 shell 补上
// 这个盲区。
//
// 本地无 sh/bash 时跳过（Windows 开发机未装 Git Bash 的场景）。
func TestCollectCommandRealShellSyntax(t *testing.T) {
	shell := pickShell(t)
	if shell == "" {
		t.Skip("本机无 sh/bash，跳过真实 shell 语法校验")
	}
	env := &Env{HasSystemd: true, HasSS: true, HasDocker: true, NProc: 4}
	ms := Metrics(env)
	// 全量路径：例行指标 + 状态快照 + 例行安全事实。
	cmd := BuildMetricsCommand(env, ms)
	if err := shellSyntaxCheck(shell, cmd); err != nil {
		t.Fatalf("例行采集命令未通过 %s -n 语法校验: %v\n命令: %s", shell, err, truncateCmd(cmd))
	}
	// 显式路径：含下钻探针（suid_files_full/world_writable_full/big_files）。
	for _, probes := range [][]string{
		{"suid_files_full"},
		{"big_files"},
		{"world_writable_full"},
		{"suid_files", "world_writable", "tmp_dirs", "file_caps"},
	} {
		snapCmd := buildMetricsCommandSel(env, ms, nil, probes, []string{})
		if err := shellSyntaxCheck(shell, snapCmd); err != nil {
			t.Fatalf("定向采集命令（%v）未通过 %s -n 语法校验: %v\n命令: %s", probes, shell, err, truncateCmd(snapCmd))
		}
	}
	// 安全兜底路径（SecurityMetrics）。
	secCmd := buildMetricsCommandSel(env, ms, nil, nil, []string{})
	if err := shellSyntaxCheck(shell, secCmd); err != nil {
		t.Fatalf("Security 命令未通过 %s -n 语法校验: %v", shell, err)
	}
	// boundedProbe 关键字防护：直接包 for/while/case 必须 panic。
	for _, bad := range []string{"for d in a; do echo; done", "while true; do :; done", "case $x in a) ;; esac"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("boundedProbe 应拒绝 shell 关键字结构: %q", bad)
				}
			}()
			p.BoundedProbe(bad, 20)
		}()
	}
}

// pickShell 找一个可用的 POSIX shell（bash 优先，sh 兜底）。
func pickShell(t *testing.T) string {
	for _, name := range []string{"bash", "sh"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	t.Log("本机无 POSIX shell")
	return ""
}

// shellSyntaxCheck 用 `<shell> -n -c <cmd>` 对命令字符串做语法检查
// （不落盘：Windows 下 WSL bash 读不了 Windows 路径；-n -c 直接检查
// 字符串语法）。
func shellSyntaxCheck(shell, cmd string) error {
	out, err := exec.Command(shell, "-n", "-c", cmd).CombinedOutput()
	if err != nil {
		return &syntaxErr{shell: shell, detail: strings.TrimSpace(string(out))}
	}
	return nil
}

type syntaxErr struct {
	shell  string
	detail string
}

func (e *syntaxErr) Error() string {
	return e.shell + " -n: " + e.detail
}

// truncateCmd 截断命令用于报错展示。
func truncateCmd(cmd string) string {
	if len(cmd) <= 400 {
		return cmd
	}
	return cmd[:400] + "…（总长 " + itoa(len(cmd)) + "）"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
