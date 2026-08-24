package main

import (
	tea "github.com/charmbracelet/bubbletea"
)

// Key builds a tea.KeyMsg from a key string in tea.KeyMsg.String() format
// (e.g. "down", "ctrl+c", "shift+enter", "alt+2", or a literal rune like "据").
// Key 将按键字符串（tea.KeyMsg.String() 格式）构造为 tea.KeyMsg 测试消息。
func Key(s string) tea.Msg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "space", " ":
		return tea.KeyMsg{Type: tea.KeySpace}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "left":
		return tea.KeyMsg{Type: tea.KeyLeft}
	case "right":
		return tea.KeyMsg{Type: tea.KeyRight}
	case "home":
		return tea.KeyMsg{Type: tea.KeyHome}
	case "end":
		return tea.KeyMsg{Type: tea.KeyEnd}
	case "pgup":
		return tea.KeyMsg{Type: tea.KeyPgUp}
	case "pgdown":
		return tea.KeyMsg{Type: tea.KeyPgDown}
	case "ctrl+c":
		return tea.KeyMsg{Type: tea.KeyCtrlC}
	case "ctrl+p":
		return tea.KeyMsg{Type: tea.KeyCtrlP}
	case "ctrl+up":
		return tea.KeyMsg{Type: tea.KeyCtrlUp}
	case "ctrl+down":
		return tea.KeyMsg{Type: tea.KeyCtrlDown}
	case "ctrl+right":
		return tea.KeyMsg{Type: tea.KeyCtrlRight}
	case "ctrl+left":
		return tea.KeyMsg{Type: tea.KeyCtrlLeft}
	}
	// 其余输入（"shift+enter"、"alt+2"、单字符/多字符文本）以原样 runes
	// 构造，String() 返回与输入一致的字符串，组件按 String() 匹配即可识别。
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

// Keys builds a list of key messages from key strings.
// Keys 将多个按键字符串批量构造为消息列表。
func Keys(ss ...string) []tea.Msg {
	msgs := make([]tea.Msg, 0, len(ss))
	for _, s := range ss {
		msgs = append(msgs, Key(s))
	}
	return msgs
}

// Resize builds a tea.WindowSizeMsg with the given dimensions.
// Resize 构造指定尺寸的窗口大小消息。
func Resize(w, h int) tea.WindowSizeMsg {
	return tea.WindowSizeMsg{Width: w, Height: h}
}
