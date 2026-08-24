package collect

// fsutil.go — 采集域私有工具（原子写与通用截断已统一到 common/fsutil）。

import "strings"

// normKey 规范化对象键（去空白、小写、折叠空白为单空格）——去重键归一。
func normKey(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(s))), " ")
}

// fragmentMark 生成探针片段唯一标记（采集器按标记切分输出）。
func fragmentMark(id string) string { return "__M_" + id + "__" }

// containsStr 字符串切片包含判断。
func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// containsInt 整数切片包含判断。
func containsInt(list []int, n int) bool {
	for _, v := range list {
		if v == n {
			return true
		}
	}
	return false
}

// probeIncompleteMark 探针未完整完成哨兵（与 probe 包同值；采集输出处理用）。
const probeIncompleteMark = "__PROBE_INCOMPLETE__"
