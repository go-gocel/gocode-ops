package l0

// engine_vars.go — 提示词模板变量：环境/清单/期望状态 → {{变量}} 渲染字典。

import (
	"sort"
	"strings"
)

func EngineTemplateVars(cfg EngineConfig) map[string]string {
	targets := cfg.Hosts
	if len(targets) == 0 {
		targets = []string{cfg.LocalHost}
	}
	return map[string]string{
		"workdir": cfg.WorkDir,
		"hosts":   strings.Join(targets, ", "),
		"host":    cfg.LocalHost,
	}
}

// ── 引擎嵌入接口（全自动运维引擎组合本底座的访问面）───────────────────

// Workspace 返回共享工作区（findings/基线/阶段记录）。

func cacheAgeNote(hm *HostMetric) string {
	if len(hm.FactAge) == 0 {
		return ""
	}
	ages := make([]string, 0, len(hm.FactAge))
	for id, age := range hm.FactAge {
		ages = append(ages, id+"="+age)
	}
	sort.Strings(ages)
	return "（重探针缓存: " + strings.Join(ages, ", ") + "）"
}

// KeyNote finding 对象子键标注（漂移源/违规对象——排查"哪条线索"用，
// 引擎日志与底座日志共用同一格式）。

// TemplateVars 计算模板变量（提示词覆盖文件 / AGENTS.md 的 {{...}} 渲染）：
// workdir=工作目录、hosts=巡检目标清单（逗号连接，无清单时为本机显示名）、
// host=本机显示名。invPath 为远程主机清单路径（可为空）。
func TemplateVars(workDir, host, invPath string) map[string]string {
	targets := []string{}
	if invPath != "" {
		if views, err := ListInventory(invPath); err == nil {
			for _, v := range views {
				targets = append(targets, v.Name)
			}
		}
	}
	if len(targets) == 0 {
		targets = []string{host}
	}
	return map[string]string{
		"workdir": workDir,
		"hosts":   strings.Join(targets, ", "),
		"host":    host,
	}
}
