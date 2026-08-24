package l0

// engine_tokens.go — 词元切分：路径/词/数字 token（漂移归属与上下文预算用）。

import (
	"regexp"
)

// WordTokens extracts word/number tokens of length >= 4 from a string (distinctiveness for attribution matching).
// WordTokens 提取长度 ≥4 的单词/数字 token（归属匹配的区分度：太短的
// token 如 rm/sed/80 会误匹配无关动作）。
func WordTokens(s string) []string {
	var out []string
	for _, t := range tokenSplitRe.FindAllString(s, -1) {
		if len(t) >= 4 {
			out = append(out, t)
		}
	}
	return out
}

var tokenSplitRe = regexp.MustCompile(`[A-Za-z0-9_]{1,}`)

// numTokenRe 提取 ≥3 位数字 token（PID/端口）的规则。
var numTokenRe = regexp.MustCompile(`[0-9]{3,}`)

// NumTokens extracts numeric tokens of at least 3 digits (PIDs/ports).
// NumTokens 提取 ≥3 位数字 token（PID/端口）：归属校验的区分度足够
// （证据的 PID 118 与动作 kill -9 118 的对应关系）。
func NumTokens(s string) []string {
	return numTokenRe.FindAllString(s, -1)
}

// reChaseRedetect 待查项重追查触发阈值：同信号被 L0 连续重检出该轮数
// 后，即使模型首轮裁决"证据不足待查"也再次追查——痕迹持续存在即异常
// 持续存在，首轮裁决不定不等于可以无限搁置（R5 实测模型确认面窄时
// 剩余项全部悬置即收敛）。maxRechase 单线索重追查上限（防模型反复
// 不定的无限循环）。
