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

// ConfigDirName 工作目录内的配置目录名。
const ConfigDirName = ".gocode"

// ConfigDir 返回工作目录内的配置目录路径（.gocode）。
func ConfigDir(workDir string) string { return filepath.Join(workDir, ConfigDirName) }

// InventoryPath 远程主机清单路径（凭证所在，0600，模型不可见）。
func InventoryPath(workDir string) string { return filepath.Join(ConfigDir(workDir), "hosts.yaml") }

// AgentsMDPath 环境信息约定文件路径（AGENTS.md，存在即注入模型上下文）。
func AgentsMDPath(workDir string) string { return filepath.Join(ConfigDir(workDir), "AGENTS.md") }

// AssistantPromptPath 交互式运维助手系统提示词文件路径（prompt.assistant.md，
// init 释放内置正文，加载直接作为系统提示词）。与 EnginePromptPath 相互独立。
func AssistantPromptPath(workDir string) string {
	return filepath.Join(ConfigDir(workDir), "prompt.assistant.md")
}

// EnginePromptPath 全自动运维引擎系统提示词文件路径（prompt.engine.md，
// init 释放内置正文，加载直接作为系统提示词）。与 AssistantPromptPath 相互独立。
func EnginePromptPath(workDir string) string {
	return filepath.Join(ConfigDir(workDir), "prompt.engine.md")
}

// HelperPath 使用手册路径（helper.md，init 释放的完整使用说明）。
func HelperPath(workDir string) string { return filepath.Join(ConfigDir(workDir), "helper.md") }

// ThemePath TUI 主题调色板路径（theme.json，存在即加载；可选）。
func ThemePath(workDir string) string { return filepath.Join(ConfigDir(workDir), "theme.json") }

// SessionsDir 会话导出目录（.gocode/sessions，退出/命令导出落盘处）。
func SessionsDir(workDir string) string { return filepath.Join(ConfigDir(workDir), "sessions") }

// IsInitialized 判断工作目录是否已经 init（存在 .gocode 配置目录）。
func IsInitialized(workDir string) bool {
	info, err := os.Stat(ConfigDir(workDir))
	return err == nil && info.IsDir()
}

// RenderVars 渲染模板变量 {{key}}：提示词覆盖文件与 AGENTS.md 中可用的
// 变量（workdir/hosts/host），未知变量原样保留（拼写错误自查可见）。
func RenderVars(s string, vars map[string]string) string {
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s
}

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
