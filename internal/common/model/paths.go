package model

import (
	"os"
	"path/filepath"
	"strings"
)

// 工作目录配置约定：所有可复用配置统一存放在工作目录内的隐藏目录
// .gocode/ 下——清单、环境信息约定、提示词覆盖、使用手册。init 一次
// 生成完整模板，整个目录可以随工作目录打包复用。
//
// 这是 gocode-ops 配置发现的单一来源：CLI 与引擎都从这里的函数取路径，
// 不在各自包内拼路径，避免路径约定分裂。

// ConfigDirName is the name of the config directory inside the working directory.
// ConfigDirName 工作目录内的配置目录名。
const ConfigDirName = ".gocode"

// ConfigDir returns the config directory path (.gocode) inside the working directory.
// ConfigDir 返回工作目录内的配置目录路径（.gocode）。
func ConfigDir(workDir string) string { return filepath.Join(workDir, ConfigDirName) }

// InventoryPath returns the remote host inventory path (where credentials live, 0600, invisible to the model).
// InventoryPath 远程主机清单路径（凭证所在，0600，模型不可见）。
func InventoryPath(workDir string) string { return filepath.Join(ConfigDir(workDir), "hosts.yaml") }

// AgentsMDPath returns the environment-agreement file path (AGENTS.md; injected into the model context when present).
// AgentsMDPath 环境信息约定文件路径（AGENTS.md，存在即注入模型上下文）。
func AgentsMDPath(workDir string) string { return filepath.Join(ConfigDir(workDir), "AGENTS.md") }

// AssistantPromptPath returns the interactive assistant system prompt file path (prompt.assistant.md; init releases the built-in text, loaded directly as the system prompt). Independent of EnginePromptPath.
// AssistantPromptPath 交互式运维助手系统提示词文件路径（prompt.assistant.md，
// init 释放内置正文，加载直接作为系统提示词）。与 EnginePromptPath 相互独立。
func AssistantPromptPath(workDir string) string {
	return filepath.Join(ConfigDir(workDir), "prompt.assistant.md")
}

// EnginePromptPath returns the autonomous engine system prompt file path (prompt.engine.md; init releases the built-in text, loaded directly as the system prompt). Independent of AssistantPromptPath.
// EnginePromptPath 全自动运维引擎系统提示词文件路径（prompt.engine.md，
// init 释放内置正文，加载直接作为系统提示词）。与 AssistantPromptPath 相互独立。
func EnginePromptPath(workDir string) string {
	return filepath.Join(ConfigDir(workDir), "prompt.engine.md")
}

// HelperPath returns the usage manual path (helper.md, the full usage guide released by init).
// HelperPath 使用手册路径（helper.md，init 释放的完整使用说明）。
func HelperPath(workDir string) string { return filepath.Join(ConfigDir(workDir), "helper.md") }

// ThemePath returns the TUI theme palette path (theme.json; loaded when present; optional).
// ThemePath TUI 主题调色板路径（theme.json，存在即加载；可选）。
func ThemePath(workDir string) string { return filepath.Join(ConfigDir(workDir), "theme.json") }

// SessionsDir returns the session export directory (.gocode/sessions, where session/command exports are written).
// SessionsDir 会话导出目录（.gocode/sessions，退出/命令导出落盘处）。
func SessionsDir(workDir string) string { return filepath.Join(ConfigDir(workDir), "sessions") }

// IsInitialized reports whether the working directory has been initialized (the .gocode config directory exists).
// IsInitialized 判断工作目录是否已经 init（存在 .gocode 配置目录）。
func IsInitialized(workDir string) bool {
	info, err := os.Stat(ConfigDir(workDir))
	return err == nil && info.IsDir()
}

// RenderVars renders template variables {{key}} in prompt override files and AGENTS.md.
// RenderVars 渲染模板变量 {{key}}：提示词覆盖文件与 AGENTS.md 中可用的
// 变量（workdir/hosts/host），未知变量原样保留（拼写错误自查可见）。
func RenderVars(s string, vars map[string]string) string {
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s
}

// HasEffectiveContent reports whether the text contains effective content (non-comment, non-blank lines).
// HasEffectiveContent 判断文本是否含有效内容（非注释、非空行）。
// 空文件/全注释文件视为"未配置"，不参与注入/覆盖，避免把空模板
// 当真实内容使用。
func HasEffectiveContent(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		return true
	}
	return false
}
