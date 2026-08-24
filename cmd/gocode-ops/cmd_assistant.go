package main

// cmd_assistant.go — 交互式运维助手运行入口（会话封装/任务执行）。

import (
	_ "embed"
	"fmt"

	"github.com/go-gocel/gocode-ops/internal/common/model"
	"github.com/go-gocel/gocode-ops/internal/common/remote"
)

// notInitHint 未 init 时的引导提示（工作目录缺少 .gocode 配置目录）。
func notInitHint(dir string) string {
	return fmt.Sprintf("工作目录 %s 尚未初始化（缺少 .gocode/ 配置目录），建议先执行: gocode-ops init -d %s", dir, dir)
}

// discoverEngineConfig 组装引擎配置并按清单自动发现目标（交互式运维助手与全自动运维引擎共用）：
// 工作目录 .gocode/hosts.yaml 存在且含主机时巡检远程主机（清单全部），
// 否则巡检本机。快检间隔等节奏参数由 model.DefaultEngineConfig 提供
// 唯一默认值，CLI 不暴露覆盖入口（与 rootFlags 精简哲学一致：脚本场景
// 参数不失控）。
func discoverEngineConfig(workDir, invPath string) model.EngineConfig {
	cfg := model.DefaultEngineConfig()
	cfg.WorkDir = workDir
	cfg.InventoryPath = invPath
	if views, err := remote.ListInventory(invPath); err == nil && len(views) > 0 {
		cfg.Local = false
		for _, v := range views {
			cfg.Hosts = append(cfg.Hosts, v.Name)
		}
	}
	return cfg
}
