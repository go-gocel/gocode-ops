package guard

import (
	"regexp"
	"strings"
)

// guard_parse.go — 命令词法还原：引号拼接/解释器 -c/解码管道等绕写法的归一化解析。

func normalizeCred(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'', '"', '`':
			continue
		case '.':
			if i > 0 && s[i-1] == '/' && i+1 < len(s) && s[i+1] == '/' {
				i++ // 吞掉 "/./" 中的 "./"
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// ── 包装命令解包与动态执行检测 ─────────────────────────────────────────
//
// 规则匹配基于首 token，`bash -c '...'`、`echo ... | sh` 等包装会整体绕过。
// 修复策略：先把命令拆成段（&&/||/; 分隔，每条都要审计），再对每段逐层
// 剥离包装（sudo、sh -c、su -c、docker exec、env 前缀等），取最内层真实
// 命令参与规则匹配；无法静态还原内容的执行方式（解码管道、解释器 -c）
// 由 dynamic 规则用原始命令串硬性拦截。

// quoteBody 提取以引号开头的字符串内容（单/双引号均可），未闭合返回 false。
func quoteBody(s string) (string, bool) {
	if len(s) < 2 {
		return "", false
	}
	q := s[0]
	if q != '\'' && q != '"' {
		return "", false
	}
	if end := strings.IndexByte(s[1:], q); end >= 0 {
		return s[1 : 1+end], true
	}
	return "", false
}

// splitQuoted 按空白切分命令 token，引号包裹的部分作为整体保留（引号
// 保留在 token 内，供 quoteBody 提取内容）。
func splitQuoted(s string) []string {
	var out []string
	var cur strings.Builder
	inQ := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQ != 0 {
			cur.WriteByte(c)
			if c == inQ {
				inQ = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			inQ = c
			cur.WriteByte(c)
		case ' ', '\t':
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// matchShellC 匹配 `sh/bash/dash/zsh/ksh/ash [flags] -c '<命令>'` 包裹
// （含路径与 busybox sh 两 token 形式），返回引号内的命令内容。
func matchShellC(s string) (string, bool) {
	fields := splitQuoted(s)
	if len(fields) < 2 {
		return "", false
	}
	i := 0
	switch baseName(fields[0]) {
	case "busybox":
		if len(fields) < 3 || baseName(fields[1]) != "sh" {
			return "", false
		}
		i = 2
	case "sh", "bash", "dash", "zsh", "ksh", "ash":
		i = 1
	default:
		return "", false
	}
	for ; i < len(fields); i++ {
		if fields[i] == "-c" {
			if i >= len(fields)-1 {
				return "", false
			}
			return quoteBody(fields[i+1])
		}
		if !strings.HasPrefix(fields[i], "-") {
			return "", false // -c 前出现非 flag token，不是包裹形态
		}
	}
	return "", false
}

// matchSuC 匹配 `su [flags] -c '<命令>'` 包裹。
func matchSuC(s string) (string, bool) {
	fields := splitQuoted(s)
	if len(fields) < 2 || baseName(fields[0]) != "su" {
		return "", false
	}
	for i := 1; i < len(fields); i++ {
		if fields[i] == "-c" {
			if i >= len(fields)-1 {
				return "", false
			}
			return quoteBody(fields[i+1])
		}
		if !strings.HasPrefix(fields[i], "-") {
			return "", false
		}
	}
	return "", false
}

// matchEchoPipe 匹配 `echo/printf '<内容>' | [sudo] sh [-c '<命令>']`：
// 内容静态可知，解包后按正常命令审计；管道后带 sh -c 时取后者。
func matchEchoPipe(s string) (string, bool) {
	fields := splitQuoted(s)
	if len(fields) < 4 || !isOneOf(fields[0], "echo", "printf") {
		return "", false
	}
	body, ok := quoteBody(fields[1])
	if !ok || fields[2] != "|" {
		return "", false
	}
	rhs := fields[3:]
	j := 0
	if j < len(rhs) && rhs[j] == "sudo" {
		j++
	}
	if j >= len(rhs) || !isOneOf(baseName(rhs[j]), "sh", "bash") {
		return "", false
	}
	for k := j + 1; k < len(rhs); k++ {
		if rhs[k] == "-c" && k+1 < len(rhs) {
			if c, ok := quoteBody(rhs[k+1]); ok {
				return c, true
			}
			return "", false
		}
	}
	return body, true
}

// matchContainerExecC 匹配 `docker exec [flags] <容器> sh -c '<命令>'`。
func matchContainerExecC(s string) (string, bool) {
	fields := splitQuoted(s)
	if len(fields) < 5 || fields[0] != "docker" || fields[1] != "exec" {
		return "", false
	}
	i := 2
	for i < len(fields) && strings.HasPrefix(fields[i], "-") {
		i++
	}
	if i+3 >= len(fields) || !isOneOf(baseName(fields[i+1]), "sh", "bash") || fields[i+2] != "-c" {
		return "", false
	}
	return quoteBody(fields[i+3])
}

// matchKubectlExecC 匹配 `kubectl exec [flags] <pod> -- sh -c '<命令>'`。
func matchKubectlExecC(s string) (string, bool) {
	fields := splitQuoted(s)
	if len(fields) < 6 || fields[0] != "kubectl" || fields[1] != "exec" {
		return "", false
	}
	i := 2
	for i < len(fields) && strings.HasPrefix(fields[i], "-") {
		i++
	}
	if i >= len(fields)-4 || fields[i+1] != "--" || !isOneOf(baseName(fields[i+2]), "sh", "bash") || fields[i+3] != "-c" {
		return "", false
	}
	return quoteBody(fields[i+4])
}

// matchInterpC 匹配 `python3/perl/ruby [flags] -c/-e '<代码>'`，返回代码内容。
func matchInterpC(s string) (string, bool) {
	fields := splitQuoted(s)
	if len(fields) < 3 || !isOneOf(baseName(fields[0]), "python", "python3", "perl", "ruby") {
		return "", false
	}
	i := 1
	for ; i < len(fields); i++ {
		if isOneOf(fields[i], "-c", "-e") {
			break
		}
		if !strings.HasPrefix(fields[i], "-") {
			return "", false
		}
	}
	if i >= len(fields)-1 {
		return "", false
	}
	return quoteBody(fields[i+1])
}

// stripExecPrefix 剥掉 env/nohup/time/command/exec 前缀（可带 VAR= 赋值）。
func stripExecPrefix(s string) (string, bool) {
	fields := strings.Fields(s)
	i := 0
	for i < len(fields) {
		if !isOneOf(fields[i], "env", "nohup", "time", "command", "exec") {
			break
		}
		i++
		for i < len(fields) && strings.Contains(fields[i], "=") && !strings.HasPrefix(fields[i], "-") {
			i++
		}
	}
	if i == 0 {
		return "", false
	}
	return strings.Join(fields[i:], " "), true
}

// decodePipeRe 匹配 base64/xxd/openssl 解码后管道给 sh/bash 的执行模式。
var decodePipeRe = regexp.MustCompile(`(?i)(?:^|[;&|]\s*)(?:base64|b64decode)\b[^\n]*?(?:-d|--decode)[^\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b|(?:^|[;&|]\s*)xxd\b[^\n]*?\s-r[^\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b|(?:^|[;&|]\s*)openssl\b[^\n]*?(?:enc|base64)\b[^\n]*?(?:-d|--decode)[^\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b`)

// interpDangerRe 匹配解释器代码内的破坏性 API 调用特征（仅匹配执行类
// API；纯打印字符串不拦）。
var interpDangerRe = regexp.MustCompile(`(?i)os\.system|os\.popen|subprocess|shutil\.rmtree|os\.remove|os\.unlink|os\.exec|(?:eval|exec|system)\s*\(`)

// RiskyCommandGuard 是运维安全守卫模块：在 BeforeToolCall 钩子中拦截
// terminal 里的高危命令。硬性禁止命令直接拒绝；可批准命令按策略处置
// （ask=向操作员确认 / allow=放行 / deny=拒绝）。
//
// 并发安全：gocel 框架并发执行同一响应的多个工具调用（ExecToolsConcurrent），
// 并行 worker 池也会并发触发守卫——approved/autoAllow/allowAll 是共享
// 可变状态，全部操作加锁。
