package collect

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// collect_cache.go — 采集缓存与输出落库：重探针 TTL 缓存、输出解析、原始覆盖记录。

func (c *Collector) collectOneCached(ctx context.Context, host, baseCmd string, ms []Metric) HostMetric {
	heavy := heavyFactIDs()
	cmd := baseCmd
	var cached strings.Builder
	reused := map[string]bool{}
	ages := map[string]string{}
	// 覆盖语义/缓存跳过的共享状态（cache 块内填充，run 后消费）。
	skip := map[string]bool{}
	if c.cfg.FactRefreshInterval > 0 {
		// 在锁内快照本机缓存（factCache 为共享 map，禁止锁外读写）。
		c.mu.Lock()
		hostCache := c.factCache[host]
		c.mu.Unlock()
		for _, fp := range SecurityFacts(c.env) {
			if !heavy[fp.ID] {
				continue
			}
			c.mu.Lock()
			c.cacheTotal++
			c.mu.Unlock()
			if f, ok := hostCache[fp.ID]; ok && time.Since(f.at) <= c.cfg.FactRefreshInterval {
				fmt.Fprintf(&cached, "%s\n%s\n", fragmentMark(fp.ID), f.out)
				skip[fp.ID] = true
				reused[fp.ID] = true
				ages[fp.ID] = time.Since(f.at).Round(time.Second).String()
				c.mu.Lock()
				c.cacheHits++
				c.mu.Unlock()
			}
		}
		if len(skip) > 0 {
			cmd = buildMetricsCommandSkip(c.env, ms, skip)
		}
	}
	out, err := c.run(ctx, host, cmd, c.cfg.CollectTimeout)
	// 有输出即可解析（子命令失败可容忍：/proc 缺失、命令不存在等）；
	// 完全无输出才算采集失败（sh 不可用、SSH 连不上等）。
	if err != nil && strings.TrimSpace(out) == "" {
		hm := HostMetric{Host: host, Metrics: map[string]map[string]float64{}, Errors: map[string]string{"collect": err.Error()}}
		// 覆盖语义：采集层失败 → 例行集事实标 partial（不完整结果不得
		// 作结论/放行复检/进缓存；collect_anomaly 由 judgeHost 覆盖）。
		inCmd := map[string]bool{}
		for _, fp := range SecurityFacts(c.env) {
			if fp.Class <= FactTargeted && !skip[fp.ID] {
				inCmd[fp.ID] = true
			}
		}
		hm.FactCoverage = c.coverageFor(err, inCmd, nil, reused)
		return hm
	}
	if cached.Len() > 0 {
		out = cached.String() + out
	}
	hm := HostMetric{Host: host, Metrics: map[string]map[string]float64{}}
	if len(ages) > 0 {
		hm.FactAge = ages
	}
	frags, incomplete := splitFragmentsEx(out)
	// 覆盖语义：例行轮命令 = 例行集（S0/S1，下钻排除）减去缓存命中；
	// 采集层失败/探针哨兵 → partial。
	inCmd := map[string]bool{}
	for _, fp := range SecurityFacts(c.env) {
		if fp.Class <= FactTargeted && !skip[fp.ID] {
			inCmd[fp.ID] = true
		}
	}
	hm.FactCoverage = c.coverageFor(err, inCmd, incomplete, reused)
	c.parseOutput(&hm, out, ms)
	// 实采的重探针片段写入缓存（空输出也缓存："扫描无结果"同样是有效
	// 结果，不必下一轮重扫）；本轮缓存命中的不刷新时间戳——TTL 从最近
	// 一次实采起算，到期自然重扫（否则每轮命中会滑动 TTL，永不重扫）。
	// 不完整结果（采集层失败/探针哨兵）绝不进缓存（partial 不得被当
	// full 复用——"超时空输出当扫描无结果"是假阴性源）。
	if c.cfg.FactRefreshInterval > 0 {
		// 整段在 c.mu 下执行，与 invalidateFactCache 保护口径一致。
		c.mu.Lock()
		for _, fp := range SecurityFacts(c.env) {
			if !heavy[fp.ID] || reused[fp.ID] {
				continue
			}
			if err != nil || incomplete[fp.ID] {
				continue
			}
			if frag, ok := frags[fp.ID]; ok {
				if c.factCache[host] == nil {
					c.factCache[host] = map[string]cachedFact{}
				}
				c.factCache[host][fp.ID] = cachedFact{out: frag, at: time.Now()}
			}
		}
		c.mu.Unlock()
	}
	return hm
}

// parseOutput 把命令输出按标记切分并解析进 HostMetric（指标/CPU/状态
// 快照/安全事实四类）。
func (c *Collector) parseOutput(hm *HostMetric, out string, ms []Metric) {
	frags, _ := splitFragmentsEx(out)
	for _, m := range ms {
		frag := frags[m.ID]
		if frag == "" {
			// 标记存在但内容为空：探针已运行、无命中（如零失败服务）。
			// 空标记与"探针未运行"（无标记、frags 缺键）语义不同——
			// 处置后复检据此区分"探针健康"与"探针无数据"（无数据是
			// 假放行源：探针失败被当线索消失）。
			if _, ok := frags[m.ID]; ok {
				hm.Metrics[m.ID] = map[string]float64{}
			}
			continue
		}
		vals, err := m.Parse(frag)
		if err != nil {
			hm.SetError(m.ID, err.Error())
			continue
		}
		if len(vals) > 0 {
			hm.Metrics[m.ID] = vals
			hm.SetRaw(m.ID, frag)
		}
	}
	if f := frags["cpu"]; f != "" {
		hm.CPU = c.cpuUsage(hm.Host, f, frags["load"])
	}
	// 状态快照提取（配置漂移检测）：摘要原样保留，供跨轮对比。
	// 空输出也落键（空串）：探针目标为空目录/空文件时不得缺键——否则
	// 首次真实变化被 stateDrift 的“首轮无基线”分支跳过（R15-R17 三轮
	// state_sudoersd 漂移均被吞：基线时 /etc/sudoers.d/ 为空目录输出空串，
	// 键被缺省，后续新增文件首次出现被当首轮快照）。
	for _, sp := range StateProbes(c.env) {
		frag, ok := frags[sp.ID]
		if !ok {
			continue // 采集失败（无标记段）：不伪造空键，避免下一轮误报漂移
		}
		if hm.State == nil {
			hm.State = map[string]string{}
		}
		hm.State[sp.ID] = strings.TrimSpace(frag)
	}
	// 安全域事实枚举（机制 1）：原始文本存 Raw（归属规则 + 模型上下文管道）。
	for _, fp := range SecurityFacts(c.env) {
		if frag := frags[fp.ID]; frag != "" {
			hm.SetRaw(fp.ID, frag)
		}
	}
}

// Exec（测试 fake）。
