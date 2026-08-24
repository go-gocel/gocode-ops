package remediate

// pkill.go — pkill/pgrep 处置自保：自通道误杀检查、模式重写、自动修复。

import (
	"fmt"
	"regexp"
	"strings"
)

// pkillFRe pkill/pgrep -f 模式提取（引号内模式）。
var pkillFRe = regexp.MustCompile(`(?:pkill|pgrep)\s+-f\s+['"]([^'"]+)['"]`)

// pkillSelfCheck pkill/pgrep -f 自杀预检：-f 全命令行匹配，执行 shell
// 自身的命令行若可被模式命中即自杀（退出码 143，处置失败且环境残留）。
// 两条命中路径：
//  1. 模式能匹配自身字面（未用 `pa[t]tern` 防自匹配技巧）；
//  2. 模式字面（去 [x] 括号）出现在命令其他部分（如 rm 的路径参数）——
//     R22 实测 `rm /tmp/keepalive.sh; pkill -f 'keepalive[.]sh'` 自杀。
//
// 返回拒绝原因；空串=通过。
func pkillSelfCheck(cmd string) string {
	for _, m := range pkillFRe.FindAllStringSubmatch(cmd, -1) {
		pat := m[1]
		re, err := regexp.Compile(pat)
		if err != nil {
			continue // 无法解析的模式不静态判定（执行侧守卫兜底）
		}
		if re.MatchString(pat) {
			return fmt.Sprintf("pkill/pgrep -f 模式 %q 未用 [x] 防自匹配（模式能匹配自身字面，执行 shell 会被 -f 命中自杀，退出码 143）——请改用 'pa[t]tern' 形式或显式 PID", pat)
		}
		lit := strings.NewReplacer("[", "", "]", "").Replace(pat)
		rest := strings.Replace(cmd, m[0], "", 1)
		if strings.Contains(rest, lit) {
			return fmt.Sprintf("pkill/pgrep -f 模式 %q 的字面 %q 也出现在命令其他参数中（-f 会命中执行 shell 自身导致自杀）——请先 kill 显式 PID，再单独执行删除/重启命令", pat, lit)
		}
	}
	return ""
}

// bracketPattern 模式首字面字符括号化（[x] 防自匹配的标准做法）：
// 正则语义不变（单字符类），但执行 shell 命令行里的字面不再被模式
// 命中。首个字符是正则元字符（锚点/转义/量词等）时跳过，取首个字面
// 字符；模式已以 [ 开头（首字符已括号化）或无字面字符可括号化时
// 原样返回。
func bracketPattern(pat string) string {
	if strings.HasPrefix(pat, "[") {
		return pat
	}
	for i, r := range pat {
		if strings.ContainsRune(`^$\\.+*?()[]{}|`, r) {
			continue
		}
		return pat[:i] + "[" + string(r) + "]" + pat[i+len(string(r)):]
	}
	return pat
}

// rewritePkillPatterns 把命令中全部 pkill/pgrep -f 模式首字符括号化
// （机械防自匹配，语义不变）。
func rewritePkillPatterns(cmd string) string {
	return pkillFRe.ReplaceAllStringFunc(cmd, func(m string) string {
		sub := pkillFRe.FindStringSubmatch(m)
		if len(sub) != 2 {
			return m
		}
		return strings.Replace(m, sub[1], bracketPattern(sub[1]), 1)
	})
}

// splitTopLevel 按顶层分隔符（; && || 换行）拆分命令：引号内（单双引号）
// 的字符不分隔——模型常把"删文件 + 杀进程"合并为一条动作命令，
// 而跨段字面是 -f 自匹配的根源（同一 shell 命令行包含模式字面），
// 拆段后每段独立 exec，段间字面不共处同一命令行。
func splitTopLevel(cmd string) []string {
	var segs []string
	start := 0
	quote := byte(0)
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == ';' || c == '\n':
			if s := strings.TrimSpace(cmd[start:i]); s != "" {
				segs = append(segs, s)
			}
			start = i + 1
		case c == '&' && i+1 < len(cmd) && cmd[i+1] == '&':
			if s := strings.TrimSpace(cmd[start:i]); s != "" {
				segs = append(segs, s)
			}
			start = i + 2
			i++
		case c == '|' && i+1 < len(cmd) && cmd[i+1] == '|':
			if s := strings.TrimSpace(cmd[start:i]); s != "" {
				segs = append(segs, s)
			}
			start = i + 2
			i++
		}
	}
	if s := strings.TrimSpace(cmd[start:]); s != "" {
		segs = append(segs, s)
	}
	return segs
}

// PkillAutoFix mechanically rewrites commands that carry pkill/pgrep -f
// self-kill risk into safely executable command segments.
// PkillAutoFix 把含 pkill/pgrep -f 自杀风险的命令机械改写为可安全执行
// 的命令段（处置自由度与执行安全兼得——引擎已确认问题存在，拒绝只会
// 把已确认的处置卡死：评测实测 9090/8088 后门因 pkill 拒绝 3 轮达限
// 悬置）。改写策略：
//  1. 无自杀风险 → 原命令单段执行；
//  2. 模式括号化后单段可安全执行 → 改写后的命令单段执行；
//  3. 模式字面仍出现在同段其他部分（如 rm 路径）→ 按顶层分隔符拆段，
//     每段独立 exec（跨段字面不再共处同一 shell 命令行）；
//  4. 改写不了（无字面字符可括号化且拆段后仍自匹配）→ ok=false，
//     调用方转人工建议（fail-closed 兜底）。
func PkillAutoFix(cmd string) ([]string, bool) {
	if pkillSelfCheck(cmd) == "" {
		return []string{cmd}, true
	}
	fixed := rewritePkillPatterns(cmd)
	if pkillSelfCheck(fixed) == "" {
		return []string{fixed}, true
	}
	// 拆段基于已括号化的命令：否则无括号模式在段内仍自匹配（如
	// "pkill -f 'nginx'" 拆出后依旧自杀）。
	segs := splitTopLevel(fixed)
	if len(segs) == 0 {
		return nil, false
	}
	for _, s := range segs {
		if pkillSelfCheck(s) != "" {
			return nil, false
		}
	}
	return segs, true
}
