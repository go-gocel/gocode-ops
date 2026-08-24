package collect

import (
	"testing"
	"unicode/utf8"
)

// TestTruncateStr_UTF8Safe 截断不得切断多字节 UTF-8 字符：中文/emoji
// 被切半会产生非法 UTF-8（日志文件被工具判定为二进制、grep 拒绝）。
// 回归：此前按裸字节截断 s[:n]，"…" 等三字节字符常被切半。
func TestTruncateStr_UTF8Safe(t *testing.T) {
	cases := []struct {
		name string
		in   string
		n    int
	}{
		{"中文边界", "运维智能体巡检报告", 7}, // 落在第 3 个汉字中间
		{"中文+省略号", "已确认故障（处置成功）", 13},
		{"emoji", "✅ 收敛完成：连续 2 轮无新线索", 9}, // emoji 4 字节
		{"混合", "L0 采集 ops-target: 指标 8 项，状态探针 10 项", 20},
		{"短串不截", "短", 100},
		{"恰好边界", "abcde", 5},
		{"空串", "", 0},
		{"零长度截断", "abc", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := TruncateStr(c.in, c.n)
			if !utf8.ValidString(got) {
				t.Fatalf("TruncateStr(%q, %d) = %q 非法 UTF-8", c.in, c.n, got)
			}
			if c.n == 0 && got != "" {
				t.Fatalf("TruncateStr(%q, 0) = %q, want 空串", c.in, got)
			}
			if len(c.in) > c.n && got == c.in {
				t.Fatalf("TruncateStr(%q, %d) 未截断", c.in, c.n)
			}
			if len(c.in) <= c.n && got != c.in {
				t.Fatalf("TruncateStr(%q, %d) = %q, want 原串", c.in, c.n, got)
			}
			// 字节长度不得超过上限（+省略号 3 字节）
			if len(got) > c.n+3 {
				t.Fatalf("TruncateStr(%q, %d) 长度 %d 超限", c.in, c.n, len(got))
			}
		})
	}
}

// TestTruncateStr_Stable 同输入同截断长度结果稳定（无随机性）。
func TestTruncateStr_Stable(t *testing.T) {
	in := "隐藏 SUID 提权 /var/lib/.find（非常规提权载体，需裁决是否预期）"
	for i := 1; i < len(in); i++ {
		a := TruncateStr(in, i)
		b := TruncateStr(in, i)
		if a != b {
			t.Fatalf("TruncateStr(%q, %d) 不稳定: %q vs %q", in, i, a, b)
		}
	}
}
