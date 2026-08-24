package remediate

// verify.go — 处置验证：退出码/恒真验证/预检满足/错误行识别/check-up 匹配。

import (
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// parseExitCode 从输出尾部解析 "[exit: N]" 退出码尾注（remote.go
// formatCommandResult 追加，恒在截断后输出末尾）。ok=false 表示输出
// 无尾注（非远程执行器或旧格式）。
func parseExitCode(out string) (int, bool) {
	if i := strings.LastIndex(out, "[exit: "); i >= 0 {
		rest := out[i+len("[exit: "):]
		if j := strings.IndexByte(rest, ']'); j > 0 {
			if n, err := strconv.Atoi(strings.TrimSpace(rest[:j])); err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

// tautologicalVerify 恒真验证检测：verify 命令中某个以 `;`/换行分隔的
// 语句段以 echo/printf 开头、其输出参数与 check_up 相同，且该段不以
// &&/|| 门控在状态检查之后——状态检查失败也照常输出标记，恒真验证
// 在结构上不算恢复证据。
func tautologicalVerify(verify, checkUp string) bool {
	cu := strings.TrimSpace(checkUp)
	if cu == "" {
		return false
	}
	for _, seg := range strings.FieldsFunc(verify, func(r rune) bool { return r == ';' || r == '\n' }) {
		seg = strings.TrimSpace(seg)
		var prefix string
		switch {
		case strings.HasPrefix(seg, "echo "):
			prefix = "echo "
		case strings.HasPrefix(seg, "printf "):
			prefix = "printf "
		default:
			continue
		}
		// echo/printf 的参数字面量（去引号）与 check_up 相同即恒真。
		arg := strings.TrimSpace(seg[len(prefix):])
		arg = strings.Trim(arg, `"'`)
		if arg == cu {
			return true
		}
	}
	return false
}

// precheckObjectToken 从 finding Key 提取处置对象关键词（预检 verify
// 必须引用它，否则判据脱靶——verify 验证的是与对象无关的东西，如
// "sshd -t && echo OK" 只验语法不验配置行，恒真于处置对象）。
// 规则：取 key 最后一个字段；路径取 basename；隐藏文件去前导点；
// 过短（<3 rune）或无 Key 返回 ""（不强制）。
func precheckObjectToken(key string) string {
	fields := strings.Fields(key)
	if len(fields) == 0 {
		return ""
	}
	tok := fields[len(fields)-1]
	if i := strings.LastIndex(tok, "/"); i >= 0 {
		tok = tok[i+1:]
	}
	tok = strings.TrimPrefix(tok, ".")
	tok = strings.Trim(tok, `"'`)
	if utf8.RuneCountInString(tok) < 3 {
		return ""
	}
	return strings.ToLower(tok)
}

// minPhraseLen 短语匹配阈值（rune 数）：check_up 长度 ≥ 阈值时按
// "输出包含该短语"匹配（模型自然写法，如 "syntax is ok" 是输出行的
// 一部分）；短于阈值时按"完整行相等"匹配（防 "inactive" 误配
// "active" 这类子串陷阱）。
const minPhraseLen = 8

// verifyErrorPrefixes 验证输出失败行的前缀清单（小写）：以这些词开头
// 的行不作为 check_up 恢复证据——错误文本里的同名短语不得冒充验证
// 通过。前缀判定保守：只命中"明确以失败语义开头"的行，正常巡检输出
// （如 "0 errors"、"Active: failed"）不受影响。
var verifyErrorPrefixes = []string{
	"error", "fatal", "fail", "cannot", "can't", "unable",
	"no such file", "not found", "permission denied", "command not found",
	"refused", "denied", "invalid", "ignored",
}

// toolErrRe 匹配工具前缀错误行（"sed: cannot rename..."、"cp: cannot
// stat..."、"gcc: error:..."）——标准工具把错误打印成 <tool>: <错误词>
// 的格式，前缀不在错误词清单里（R15 实测：sed -i 对挂载文件重命名
// 失败输出 "sed: cannot rename ..."，被 `; echo` 掩蔽后误标已处置）。
// "Active: failed" 不受影响（failed 不在词表）。
var toolErrRe = regexp.MustCompile(`^[A-Za-z0-9_.+-]+:\s+(cannot|can't|error|fatal|unable|no such file|not found|permission denied|refused|denied|invalid)\b`)

// ldSoPreloadErrRe 动态链接器预载失败噪声行：ld.so 在进程启动阶段
// 尝试预载 /etc/ld.so.preload 指向的库失败时打印，先于任何命令逻辑
// 执行、与命令结果无关——R21 实测攻击者注入 ld.so.preload 后每条
// 命令 stderr 刷此噪声，处置动作被"错误行即失败"误判（R7 同哲学：
// 动态链接器报错是环境噪声，不是命令执行结果）。
var ldSoPreloadErrRe = regexp.MustCompile(`^error: ld\.so: object '.*' from /etc/ld\.so\.preload cannot be preloaded`)

// isErrorLine 判定输出中的失败行：前缀清单 + 工具前缀格式
// （见 verifyErrorPrefixes/toolErrRe）。执行路径与验证路径同一套语义：
// 错误行不作恢复证据 → 处置动作输出含错误行即执行失败。
func isErrorLine(line string) bool {
	l := strings.ToLower(strings.TrimSpace(line))
	if ldSoPreloadErrRe.MatchString(l) {
		return false // 环境噪声（动态链接器预载失败），非命令失败证据
	}
	for _, p := range verifyErrorPrefixes {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return toolErrRe.MatchString(l)
}

// firstErrorLine 返回输出中第一条错误行（无则空串）。
func firstErrorLine(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if isErrorLine(line) {
			return line
		}
	}
	return ""
}

// checkUpMatches 判定验证输出是否满足 check_up 契约（宽容化匹配）：
//   - 多行 want：每行按顺序在输出中找到完整行相等；
//   - 单行 want ≥ minPhraseLen：某非错误行包含该短语（子串匹配）；
//   - 单行 want < minPhraseLen：完整行相等（TrimSpace 后，精确）。
//
// 所有匹配模式都跳过失败行（isErrorLine）：错误输出不算恢复证据——
// 失败命令的报错文本里出现 check_up 同名短语不得冒充验证通过
// （run2 实测 ld.so 报错行/用户删除失败行含目标名可命中短语）。
//
// 原"完整行相等"语义把模型常见的短语/多行写法全部判失败——处置实际
// 成功却被验证契约卡住（run7：nginx syntax is ok / 644\nroot / 127.0.0.1:6379）。
func checkUpMatches(out, want string) bool {
	want = strings.TrimSpace(want)
	if want == "" {
		return false
	}
	if strings.Contains(want, "\n") {
		// 多行：每行按顺序完整行匹配。
		wantLines := strings.Split(want, "\n")
		idx := 0
		for _, line := range strings.Split(out, "\n") {
			if isErrorLine(line) {
				continue
			}
			if strings.TrimSpace(line) == strings.TrimSpace(wantLines[idx]) {
				idx++
				if idx == len(wantLines) {
					return true
				}
			}
		}
		return false
	}
	if len([]rune(want)) >= minPhraseLen {
		for _, line := range strings.Split(out, "\n") {
			if !isErrorLine(line) && strings.Contains(line, want) {
				return true
			}
		}
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		if isErrorLine(line) {
			continue
		}
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}
