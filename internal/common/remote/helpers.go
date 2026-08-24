package remote

// helpers.go — 远程执行辅助：输出截断/字节格式化/主机排序/权限解析。

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// maxCollectOut 单命令收集上限（读取时截断，只防内存；展示另有 perHostCap 截断）。
const maxCollectOut = 1 << 20

// truncate 保留前 n 个 rune，超长加省略号（输出块节流截断）。
func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "…"
}

// humanBytes 人类可读的字节数。
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// sortHosts 排序去重（供守卫提示与测试使用）。
func sortHosts(hosts []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// parseFileMode 解析八进制权限字符串（"0644" → 0o644）。
func parseFileMode(s string) (os.FileMode, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("mode 必须是八进制字符串（如 \"0644\"），收到 %q", s)
	}
	return os.FileMode(v), nil
}
