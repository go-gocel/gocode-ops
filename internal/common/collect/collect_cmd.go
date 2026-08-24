package collect

import (
	"fmt"
	"strings"
)

// collect_cmd.go — 采集命令构建：指标→单条 shell 命令（按环境裁剪 skip/事实/状态段）。

func BuildMetricsCommand(env *Env, ms []Metric) string {
	return buildMetricsCommandSkip(env, ms, nil)
}

// buildMetricsCommandSkip 同 buildMetricsCommand，但跳过 skip 中的探针
// ID（重探针 TTL 缓存命中时不再执行，缓存输出由采集器并入解析流）。
func buildMetricsCommandSkip(env *Env, ms []Metric, skip map[string]bool) string {
	return buildMetricsCommandSel(env, ms, skip, nil, nil)
}

// buildMetricsCommandSel 组装采集命令（全量与定向共用）：
//   - ms：指标清单；
//   - skip：TTL 缓存命中跳过集合；
//   - facts：nil=包含全部安全事实，非 nil=只包含清单内的事实（定向复检）；
//   - states：nil=包含全部状态快照，非 nil=只包含清单内的快照
//     （定向复检传空切片——漂移由基线机制负责，不参与复检）。
func buildMetricsCommandSel(env *Env, ms []Metric, skip map[string]bool, facts, states []string) string {
	has := func(list []string, id string) bool {
		if list == nil {
			return true
		}
		for _, v := range list {
			if v == id {
				return true
			}
		}
		return false
	}
	var parts []string
	appendFrag := func(id, frag string) {
		if skip[id] {
			return
		}
		parts = append(parts, fmt.Sprintf("echo %s; { %s; } 2>/dev/null", fragmentMark(id), frag))
	}
	for _, m := range ms {
		appendFrag(m.ID, m.Fragment(env))
	}
	// 状态快照探针（配置漂移检测）：顺带采集，解析在 parseOutput 单独提取
	// （摘要不解析为数值）。
	for _, sp := range StateProbes(env) {
		if has(states, sp.ID) {
			appendFrag(sp.ID, sp.Fragment(env))
		}
	}
	// 安全域事实枚举（机制 1）：每轮确定性采集，原始数据进上下文 + 归属规则。
	// facts==nil=例行集：只含 S0 信号 + S1 定点（成本有界）——下钻探针
	// （全盘枚举形态）被例行过滤排除；非 nil=显式清单（collect_probe
	// 定向调用/复检）从全注册表解析，下钻探针可被显式请求执行。
	for _, fp := range SecurityFacts(env) {
		if has(facts, fp.ID) {
			if facts == nil && fp.Class > FactTargeted {
				continue
			}
			appendFrag(fp.ID, fp.Fragment(env))
		}
	}
	appendFrag("cpu", "cat /proc/stat")
	appendFrag("load", "cat /proc/loadavg")
	return strings.Join(parts, "; ")
}

// collectOneCached 采集单台主机：重探针 TTL 内命中时从命令剔除并复用
// 缓存输出（缓存片段以标记形式并入采集输出，解析与归属路径不感知缓存），
// 超期/无缓存时实采并更新缓存。FactRefreshInterval<=0 时缓存禁用。
