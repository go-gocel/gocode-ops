package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/go-gocel/termagent/pkg/util"
)

// ── 文本/尺寸工具 ────────────────────────────────────────────────────

// truncate 按显示宽度截断（复用 termagent util：UTF-8/ANSI 安全，
// 中文按 2 列宽计算）。修复历史缺陷：按字节切片会从多字节字符中间
// 切开，中文工具参数/错误消息显示乱码。
func truncate(s string, n int) string {
	return util.Truncate(s, n)
}

// padTo 填充/截断到目标高度。
func padTo(view string, height, width int) string {
	lines := splitLines(view)
	if len(lines) > height {
		lines = lines[:height]
	}
	for len(lines) < height {
		lines = append(lines, "")
	}
	out := ""
	for i, line := range lines {
		if i > 0 {
			out += "\n"
		}
		out += padRight(line, width)
	}
	return out
}

func splitLines(s string) []string {
	var lines []string
	cur := ""
	for _, r := range s {
		if r == '\n' {
			lines = append(lines, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	lines = append(lines, cur)
	return lines
}

func padRight(s string, width int) string {
	w := ansi.StringWidth(s)
	if w >= width {
		return ansi.Truncate(s, width, "…")
	}
	return s + strings.Repeat(" ", width-w)
}

// humanSize 人类可读的字节数（进度提示用）。
func humanSize(n int64) string {
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

// humanDuration 人类可读的耗时（<1s 显示 "<1s"，>=1h 显示 h/m/s）。
func humanDuration(d time.Duration) string {
	if d < time.Second {
		return "<1s"
	}
	s := int(d.Seconds())
	if s < 60 {
		return fmt.Sprintf("%ds", s)
	}
	if s < 3600 {
		return fmt.Sprintf("%dm%02ds", s/60, s%60)
	}
	return fmt.Sprintf("%dh%02dm", s/3600, (s%3600)/60)
}

// progressBar 短 ASCII 进度条：█ 填充 + ░ 轨道（percent 0.0~1.0 钳制）。
// 用于工具表格状态列等窄场景（列宽 8 时 "████ 100%" 恰好放得下）。
func progressBar(percent float64, width int) string {
	if width < 1 {
		width = 1
	}
	if percent < 0 {
		percent = 0
	}
	if percent > 1 {
		percent = 1
	}
	filled := int(percent*float64(width) + 0.5)
	if filled > width {
		filled = width
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// leftRight 左右对齐单行：left 靠左、right 靠右；超宽时先截断右侧
// （右侧是次要信息），仍超再截左侧。ANSI 样式宽度由 StringWidth 感知。
func leftRight(left, right string, width int) string {
	lb, rb := ansi.StringWidth(left), ansi.StringWidth(right)
	if width > 0 && lb+rb > width {
		if room := width - lb; room >= 1 {
			right = ansi.Truncate(right, room, "…")
		} else {
			right = ""
			left = ansi.Truncate(left, width, "…")
		}
	}
	pad := 0
	if width > 0 {
		pad = width - lb - ansi.StringWidth(right)
	}
	if pad < 0 {
		pad = 0
	}
	return left + strings.Repeat(" ", pad) + right
}
