package probe

// metrics.go — 指标清单构造（单一来源：数值指标探针）。
// MetricsForIDs 把探针 ID 集合转成采集 Metric 清单（数值指标探针
// 单一来源：Metrics + SecurityMetrics；事实探针走 CollectProbes 的
// factIDs 通道）。处置后确定性复检与认知定向采集共用。
func MetricsForIDs(env *Env, ids map[string]bool) []Metric {
	var ms []Metric
	for _, m := range Metrics(env) {
		if ids[m.ID] {
			ms = append(ms, m)
		}
	}
	for _, m := range SecurityMetrics(env) {
		if ids[m.ID] {
			ms = append(ms, m)
		}
	}
	return ms
}
