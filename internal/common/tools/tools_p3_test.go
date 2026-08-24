package tools

// tools_p3_test.go — P3 修复回归测试：上传 mode 特殊位白名单。

import "testing"

func TestParseFileMode_RejectsPrivilegeBits(t *testing.T) {
	// setuid/setgid 拒绝（模型可控的上传不得携带提权位）。
	for _, bad := range []string{"4755", "6755", "4777", "2755"} {
		if _, err := parseFileMode(bad); err == nil {
			t.Errorf("提权位 mode %q 应被拒绝", bad)
		}
	}
	// 常规权限与 sticky 位允许。
	for _, ok := range []string{"0644", "0755", "0600", "0700", "1777"} {
		if _, err := parseFileMode(ok); err != nil {
			t.Errorf("常规 mode %q 不应被拒绝: %v", ok, err)
		}
	}
}
