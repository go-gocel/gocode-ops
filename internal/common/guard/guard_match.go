package guard

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-gocel/gocel/jsonx"
)

// guard_match.go — 规则命中与命令解析辅助：段切分/sudo 剥离/参数识别。

func matchRiskyRule(cmd string) *riskyRule {
	for i := range riskyRules {
		if riskyRules[i].dynamic && riskyRules[i].match(cmd, nil) {
			return &riskyRules[i]
		}
	}
	// 第一遍：原始命令逐段匹配（&&/||/;/换行 分隔）。
	if r := matchSegments(cmd); r != nil {
		return r
	}
	// 第二遍：整条命令先解包再逐段匹配——花括号命令组/子 shell/包装器
	// 在分段前剥离，`{ rm -rf /; }` 的段切分才不会把命令拆散导致首
	// token 失配（此前花括号组/尾随 & 形态整体绕过）。
	unwrapped := unwrapCommand(cmd)
	if strings.TrimSpace(unwrapped) != strings.TrimSpace(cmd) {
		if r := matchSegments(unwrapped); r != nil {
			return r
		}
	}
	return nil
}

// matchSegments 按段切分并逐段匹配常规规则（解包/剥 sudo 后取首 token）。
func matchSegments(cmd string) *riskyRule {
	for _, seg := range splitCommandSegments(cmd) {
		inner := unwrapCommand(seg)
		stripped := stripSudo(inner)
		tokens := strings.Fields(stripped)
		for i := range riskyRules {
			if !riskyRules[i].dynamic && riskyRules[i].match(stripped, tokens) {
				return &riskyRules[i]
			}
		}
	}
	return nil
}

// splitCommandSegments 按 &&/||/; 与裸换行拆分命令段。shell 中这些
// 分隔符（含换行）后的每条命令都会独立执行，必须逐段审计（如
// `df -h; rm -rf /` 的第二段、`echo hi\nrm -rf /` 的换行第二段——换行
// 不分段时第二行命令会被扁平化进首行参数、t[0] 失配而整体绕过）。
func splitCommandSegments(cmd string) []string {
	return segmentRe.Split(cmd, -1)
}

// segmentRe 匹配命令分隔符（引号内的分隔符无法静态区分，但拆分后各段
// 仍按 token 规则匹配，不会产生误拦；真正的危险段会被捕获）。
var segmentRe = regexp.MustCompile(`\s*(?:&&|\|\||;|\n)\s*`)

// unwrapCommand 逐层剥离命令包装，返回最内层实际执行的命令串。最多剥
// 4 层防死循环；剥离失败时原样返回（由常规规则按现状匹配）。
func unwrapCommand(cmd string) string {
	s := strings.TrimSpace(cmd)
	for i := 0; i < 4; i++ {
		s = stripSudo(strings.TrimSpace(s))
		// 尾随后台符（"cmd &"）：后台执行不影响命令本体审计。
		if strings.HasSuffix(s, "&") && !strings.HasSuffix(s, "&&") {
			s = strings.TrimSpace(strings.TrimSuffix(s, "&"))
		}
		if strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
			// 子 shell 括号包裹：( cmd )
			s = strings.TrimSpace(s[1 : len(s)-1])
			continue
		}
		if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
			// 花括号命令组：{ cmd; }（此前首 token 是 { 整体绕过）。
			s = strings.TrimSpace(s[1 : len(s)-1])
			continue
		}
		if c, ok := matchShellC(s); ok {
			s = c
			continue
		}
		if c, ok := matchSuC(s); ok {
			s = c
			continue
		}
		if c, ok := matchEchoPipe(s); ok {
			s = c
			continue
		}
		if c, ok := matchContainerExecC(s); ok {
			s = c
			continue
		}
		if c, ok := matchKubectlExecC(s); ok {
			s = c
			continue
		}
		if c, ok := stripExecPrefix(s); ok {
			s = c
			continue
		}
		if c, ok := stripLeadingWrapperArgs(s); ok {
			s = c
			continue
		}
		return s
	}
	return s
}

// stripLeadingWrapperArgs 剥掉 setsid/nice/timeout/stdbuf/ionice/watch
// 前置包装器及其参数（flag 序列 + 数值参数），返回命令本体。包装器后
// 首 token 是 flag 或数字时继续剥，直到遇到命令——`timeout 5 rm -rf /`
// 此前首 token 是 5、`setsid rm -rf /` 首 token 是 setsid，root-delete
// 等 token 规则整体绕过。非包装器形态原样返回。
func stripLeadingWrapperArgs(s string) (string, bool) {
	fields := strings.Fields(s)
	if len(fields) < 2 || !isOneOf(fields[0], "setsid", "nice", "timeout", "stdbuf", "ionice", "watch") {
		return "", false
	}
	i := 1
	for i < len(fields) {
		tok := fields[i]
		switch {
		case isEnvAssign(tok):
			i++
		case strings.HasPrefix(tok, "-"):
			i++
			// 已知带值 flag：吞掉紧随的值（watch -n 5 / timeout -k 5 / -s 信号）。
			name := tok
			if eq := strings.IndexByte(tok, '='); eq > 0 {
				name = tok[:eq]
			}
			if isOneOf(name, "-n", "-k", "-s", "-t", "-w", "-o", "--timeout", "--signal", "--kill-after", "--interval") && i < len(fields) {
				i++
			}
		case isAllDigits(strings.TrimSuffix(strings.TrimSuffix(tok, "s"), "m")):
			i++ // timeout 秒数 / nice 优先级
		default:
			return strings.Join(fields[i:], " "), true
		}
	}
	return "", true
}

// stripSudo 去掉命令开头的 sudo（含 sudo -u user 等旗标）与前导环境
// 变量赋值（FOO=x sudo …：环境前缀不影响命令语义，剥掉后规则才能匹配
// 到真实命令，否则首 token 是 FOO=x 整体绕过）。
func stripSudo(cmd string) string {
	fields := strings.Fields(cmd)
	for len(fields) > 0 && isEnvAssign(fields[0]) {
		fields = fields[1:]
	}
	for len(fields) > 0 && fields[0] == "sudo" {
		fields = fields[1:]
		for len(fields) > 0 && strings.HasPrefix(fields[0], "-") {
			flag := fields[0]
			fields = fields[1:]
			if flag == "--" {
				break
			}
			if isOneOf(flag, "-u", "--user", "-g", "--group", "-h", "--host", "-C", "--close-from", "-p", "--prompt", "-U", "--other-user") {
				if len(fields) > 0 {
					fields = fields[1:]
				}
			}
		}
	}
	return strings.Join(fields, " ")
}

// isEnvAssign 判断 token 是否为 shell 环境变量赋值（NAME=value）。
func isEnvAssign(tok string) bool {
	i := strings.IndexByte(tok, '=')
	return i > 0 && !strings.ContainsAny(tok[:i], " \t\"'")
}

// isAffirmative 判断操作员的确认回答。
func isAffirmative(ans string) bool {
	switch strings.ToLower(strings.TrimSpace(ans)) {
	case "y", "yes", "1", "是", "可以", "允许", "同意", "批准", "确认":
		return true
	}
	return false
}

// ── 规则匹配辅助 ───────────────────────────────────────────────────────

func baseName(s string) string { return filepath.Base(s) }

func isOneOf(s string, set ...string) bool {
	for _, v := range set {
		if s == v {
			return true
		}
	}
	return false
}

func isAllDigits(s string) bool {
	return strings.Trim(s, "0123456789") == ""
}

// firstTokenIn 匹配命令第一个 token 属于 set。
func firstTokenIn(set ...string) func(string, []string) bool {
	return func(_ string, t []string) bool {
		return len(t) > 0 && isOneOf(baseName(t[0]), set...)
	}
}

func containsFlag(args []string, flag string) bool {
	for _, tok := range args {
		if tok == flag {
			return true
		}
	}
	return false
}

// firewallMutates 判断 iptables 系列是否存在变更类参数（-A/-I/-D/-P/-F 等）。
func firewallMutates(args []string) bool {
	for _, tok := range args {
		switch tok {
		case "-A", "-I", "-D", "-R", "-P", "-F", "-X", "-Z", "-N", "-E",
			"--append", "--insert", "--delete", "--replace", "--policy",
			"--flush", "--delete-chain", "--new-chain", "--rename-chain", "--zero":
			return true
		}
	}
	return false
}

// nftMutates 判断 nft 是否存在变更类子命令。
func nftMutates(args []string) bool {
	for _, tok := range args {
		switch tok {
		case "add", "insert", "replace", "delete", "create", "flush", "rename", "reset":
			return true
		}
	}
	return false
}

// unmarshalArgs 解码工具参数 JSON；安全守卫必须能读懂带轻微瑕疵的模型
// 参数才能正确裁决（容错解析单一来源：gocel-core/core/jsonx）。
// 无法修复的输入仍拒绝——不静默放行。
func unmarshalArgs(argsJSON string, v any) error {
	if strings.TrimSpace(argsJSON) == "" {
		return nil
	}
	if err := jsonx.Unmarshal([]byte(argsJSON), v); err != nil {
		return fmt.Errorf("ops: 工具参数无法解析: %w", err)
	}
	return nil
}
