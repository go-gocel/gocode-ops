package collect

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// collect_out.go — 输出处理：节头剥离、片段切分、长度截断。

func firstWords(s string, n int) string {
	fields := strings.Fields(s)
	if len(fields) <= n {
		return s
	}
	return strings.Join(fields[:n], " ") + "…"
}

// StripSectionHeader removes the leading "## host" section header from a remote Exec result.
// StripSectionHeader 去掉远程 Exec 返回的 "## host\n" 分段头（单台调用）。
func StripSectionHeader(out string) string {
	if strings.HasPrefix(out, "## ") {
		if i := strings.IndexByte(out, '\n'); i >= 0 {
			return out[i+1:]
		}
	}
	return out
}

// cpuUsage 由本轮 /proc/stat 与上一轮采样计算使用率；loadavg 解析 Load1。

var fragRe = regexp.MustCompile(`(?m)^__M_([A-Za-z0-9_]+)__\r?$`)

// splitFragments 按标记切分拼接命令的输出（探针完成哨兵已由
// splitFragmentsEx 处理；本函数只返回片段）。
func splitFragments(out string) map[string]string {
	frags, _ := splitFragmentsEx(out)
	return frags
}

// splitFragmentsEx 按标记切分拼接命令的输出，并检测探针完成哨兵
// （probeIncompleteMark）：片段含哨兵行 → 该探针未完整完成
// （incomplete[id]=true，覆盖语义 partial）——超时/失败的枚举结果
// 不得被当"扫描无结果"（design-v2.md §二：partial 不产结论、不进
// 缓存、不进基线）。哨兵行从片段内容剔除，不污染 Raw/上下文。
func splitFragmentsEx(out string) (map[string]string, map[string]bool) {
	frags := map[string]string{}
	incomplete := map[string]bool{}
	idxs := fragRe.FindAllStringSubmatchIndex(out, -1)
	for i, m := range idxs {
		id := out[m[2]:m[3]]
		start := m[1]
		end := len(out)
		if i+1 < len(idxs) {
			end = idxs[i+1][0]
		}
		content := out[start:end]
		if strings.Contains(content, probeIncompleteMark) {
			incomplete[id] = true
			// 剔除哨兵行（保留其余内容：部分完成的枚举结果仍可作
			// 证据进上下文，但覆盖标记为 partial）。
			var keep []string
			for _, line := range strings.Split(content, "\n") {
				if strings.TrimSpace(line) != probeIncompleteMark {
					keep = append(keep, line)
				}
			}
			content = strings.Join(keep, "\n")
		}
		frags[id] = strings.TrimSpace(content)
	}
	return frags, incomplete
}

// TruncateStr keeps the first n bytes of s and appends an ellipsis when s is longer.
// TruncateStr 保留前 n 个字节、超长加省略号。截断不切断多字节 UTF-8
// 字符（此前按裸字节截断会把中文/emoji 切半，产生非法 UTF-8——日志
// 文件因此被工具判定为二进制，grep 默认拒绝）。
func TruncateStr(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	// 回退到完整 rune 边界（n>0 保证索引合法；n 处若恰为 rune 起点则不动）。
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}
