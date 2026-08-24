package main

// cmd_init.go — init 子命令：生成 .gocode/ 配置目录与模板。

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/go-gocel/gocode-ops/internal/common/model"
)

// newInitConfigCmd 在工作目录初始化 .gocode/ 配置目录并释放模板：
// hosts.yaml（凭证清单，0600）、AGENTS.md（环境信息约定，创建空文件，
// 空文件视为未配置）、prompt.assistant.md（交互系统提示词正文，加载直接
// 作为系统提示词）、prompt.engine.md（引擎系统提示词正文，加载直接作为
// 系统提示词）、helper.md（完整使用手册，总是刷新为内置版本）。已存在的
// 文件不覆盖（helper.md 除外）。一次 init 即完整的运行前配置入口，整个
// .gocode/ 目录可随工作目录打包复用。
func newInitConfigCmd(rf *rootFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "初始化工作目录（生成 .gocode/ 配置目录与模板）",
		Args:  cobra.NoArgs, // 多余参数静默忽略会误导（P2 修复）
		RunE: func(c *cobra.Command, args []string) error {
			cfgDir := model.ConfigDir(rf.workDir)
			written := 0
			skipped := 0
			for _, w := range []struct {
				path     string
				mode     os.FileMode
				tpl      string
				override bool // true=总是刷新为内置版本
			}{
				{model.InventoryPath(rf.workDir), 0o600, inventoryTemplate, false},
				{model.AgentsMDPath(rf.workDir), 0o644, "", false},
				{model.AssistantPromptPath(rf.workDir), 0o644, assistantPromptBody(), false},
				{model.EnginePromptPath(rf.workDir), 0o644, autopilotPromptBody(), false},
				{model.HelperPath(rf.workDir), 0o644, helperManual, true},
			} {
				ok, err := writeFileOpt(w.path, w.mode, w.tpl, w.override)
				if err != nil {
					return err
				}
				if ok {
					written++
				} else {
					skipped++
				}
			}
			fmt.Printf("已初始化 %s（生成 %d 个模板，跳过 %d 个已存在文件）:\n  %s\n  %s\n  %s\n  %s\n  %s\n",
				cfgDir, written, skipped,
				model.InventoryPath(rf.workDir), model.AgentsMDPath(rf.workDir),
				model.AssistantPromptPath(rf.workDir), model.EnginePromptPath(rf.workDir),
				model.HelperPath(rf.workDir))
			fmt.Println("使用说明见 .gocode/helper.md；编辑 hosts.yaml 后即可使用远程能力。")
			return nil
		},
	}
}

// writeFileOpt 写模板文件：override=false 时已存在不覆盖；
// override=true 时总是刷新为内置版本（helper.md 随二进制更新）。
func writeFileOpt(path string, mode os.FileMode, tpl string, override bool) (bool, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return false, fmt.Errorf("创建目录失败: %w", err)
		}
	}
	if !override {
		if _, err := os.Stat(path); err == nil {
			return false, nil // 已存在不覆盖
		}
	}
	if err := os.WriteFile(path, []byte(tpl), mode); err != nil {
		return false, fmt.Errorf("写入失败: %w", err)
	}
	return true, nil
}

// ── TUI 会话 ─────────────────────────────────────────────────────────
