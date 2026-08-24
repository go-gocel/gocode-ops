package probe

// fsutil.go — 探针域行工具（原子写与通用截断已统一到 common/fsutil）。

import "strings"

// firstLine 返回首行（截断输出取标题行用）。
func firstLine(s string) string {
	if i := strings.IndexByte(s, 10); i >= 0 {
		return s[:i]
	}
	return s
}

// normKey 规范化对象键（去空白、小写、折叠空白为单空格）——去重键归一。
func normKey(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(s))), " ")
}
