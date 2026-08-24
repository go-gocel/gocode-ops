package collect

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// maxCollectOut 单主机快检原始输出截断上限（防止异常主机刷爆内存）。
const maxCollectOut = 128 << 10

// Collector executes check lists and parses them into a structured snapshot.
// Collector 负责执行检查清单并解析为结构化快照。本地与远程共用同一套
// 检查逻辑；CPU 使用率通过 /proc/stat 两次采样的增量计算（容器/裸机通用）。
type Collector struct {
	cfg     EngineConfig
	env     *Env
	remote  RemoteExecutor // nil 时仅本机
	prevCPU map[string]*cpuStat
	// cpuMu 保护 prevCPU（轮内多主机并行采集各自 goroutine 增量读写，
	// 无锁并发写 map 触发 Go 运行时 fatal——与 factCache 的 mu 同源问题）。
	cpuMu sync.Mutex
	// factCache 重探针（heavyFactIDs）每台主机最近一次采集输出：TTL 内
	// 复用（事实枚举型探针，非数值指标/漂移快照）。
	factCache map[string]map[string]cachedFact
	// mu 保护缓存与统计（多主机并行采集）。
	mu         sync.Mutex
	cacheHits  int
	cacheTotal int
	// roundMu 串行化整轮采集：预热轮（引擎启动后台）与任务快检轮可能
	// 并发，共享状态（factCache/prevCPU/统计）整轮串行访问；轮内多主机
	// 仍并行。
	roundMu sync.Mutex
}

// cachedFact 重探针单次采集输出与采集时间。
type cachedFact struct {
	out string
	at  time.Time
}

// NewCollector creates a collector.
// NewCollector 创建采集器。
func NewCollector(cfg EngineConfig, env *Env, remote RemoteExecutor) *Collector {
	return &Collector{cfg: cfg, env: env, remote: remote, prevCPU: map[string]*cpuStat{}, factCache: map[string]map[string]cachedFact{}}
}

// heavyFactIDs 重探针集合：单次采集代价高（全盘 find/getcap 递归），
// 输出是事实枚举（进模型上下文 + 归属规则产线索），允许 TTL 内复用。
// 漂移快照（stateProbes）与数值指标（Metrics）不在此列，每轮实采。
// 下钻变体（suid_files_full/world_writable_full）同样重：显式调用
// （collect_probe/复检）后结果在 TTL 内复用，不重复全盘。
func heavyFactIDs() map[string]bool {
	return map[string]bool{
		"big_files":           true, // find / -xdev -size +500M（下钻，实测单次 ~46s）
		"file_caps":           true, // getcap -r 关键目录
		"suid_files":          true, // find 标准目录 -perm -4000（定点）
		"suid_files_full":     true, // find / -xdev -perm -4000（下钻全盘）
		"world_writable":      true, // find 世界可写对象（定点）
		"world_writable_full": true, // find 世界可写对象（下钻含数据面）
		"tmp_dirs":            true, // 临时目录文件计数
	}
}

// FactCacheStats returns heavy-probe cache statistics (hits/total) of the
// latest round, for logging.
// FactCacheStats 返回最近一轮采集的重探针缓存统计（命中/总数，日志用）。
func (c *Collector) FactCacheStats() (hits, total int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cacheHits, c.cacheTotal
}

// InvalidateFactCache invalidates the heavy-probe cache of the given host
// (call after remediation).
// InvalidateFactCache 失效指定主机的重探针缓存（处置执行后调用）：
// 复检必须实采验证对象确实消失，不能复用处置前 TTL 内的旧输出——
// 否则“已删除对象仍命中缓存”会让复检误判未处置（被迫跳过复检）。
func (c *Collector) InvalidateFactCache(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.factCache, host)
}

// maxCollectParallel 单轮采集的并发主机数上限（池化语义：目标主机再多
// 也按上限排队采集，不产生 per-host 无界 goroutine 风暴）。
const maxCollectParallel = 8

// Collect collects all target hosts in parallel (local + remote) and returns
// a structured snapshot.
// Collect 并行采集全部目标主机（本地 + 远程），返回结构化快照。
func (c *Collector) Collect(ctx context.Context) (*Snapshot, error) {
	return c.CollectMetrics(ctx, Metrics(c.env))
}

// CollectMetrics collects all targets with the given probe list (custom lists
// used by the Security fallback).
// CollectMetrics 按给定探针清单采集全部目标（Security 兜底用自定义清单）。
func (c *Collector) CollectMetrics(ctx context.Context, ms []Metric) (*Snapshot, error) {
	targets := c.Targets()
	if len(targets) == 0 {
		return nil, fmt.Errorf("ops: 没有巡检目标（Local=false 且 Hosts 为空）")
	}
	// 整轮串行（预热与任务快检并发时共享状态安全）；轮内多主机按池并行。
	c.roundMu.Lock()
	defer c.roundMu.Unlock()
	base := BuildMetricsCommand(c.env, ms)

	c.mu.Lock()
	c.cacheHits, c.cacheTotal = 0, 0
	c.mu.Unlock()
	results := make([]HostMetric, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxCollectParallel)
	for i, host := range targets {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = c.collectOneCached(ctx, host, base, ms)
		}(i, host)
	}
	wg.Wait()
	return &Snapshot{At: time.Now().UTC(), Hosts: results}, nil
}

// CollectProbes performs targeted collection of the given metrics and
// security fact probes.
// CollectProbes 定向采集：只采集指定指标与安全事实探针（处置后确定性
// 复检用——比全量快检轻量一个数量级：不含状态快照、不含未涉及的
// 重探针全盘扫描）。factIDs 为空切片=不采集任何事实；重探针（如
// big_files）在 TTL 内复用缓存，语义与全量路径一致。
func (c *Collector) CollectProbes(ctx context.Context, ms []Metric, factIDs []string) (*Snapshot, error) {
	targets := c.Targets()
	if len(targets) == 0 {
		return nil, fmt.Errorf("ops: 没有巡检目标（Local=false 且 Hosts 为空）")
	}
	c.roundMu.Lock()
	defer c.roundMu.Unlock()
	base := buildMetricsCommandSel(c.env, ms, nil, factIDs, []string{})

	c.mu.Lock()
	c.cacheHits, c.cacheTotal = 0, 0
	c.mu.Unlock()
	results := make([]HostMetric, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxCollectParallel)
	for i, host := range targets {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = c.collectProbesOne(ctx, host, base, ms, factIDs)
		}(i, host)
	}
	wg.Wait()
	return &Snapshot{At: time.Now().UTC(), Hosts: results}, nil
}

// collectProbesOne 定向采集单台主机：与 collectOneCached 同构，但只
// 处理 factIDs 内的重探针缓存（命中并入解析流，语义与全量一致）。
func (c *Collector) collectProbesOne(ctx context.Context, host, baseCmd string, ms []Metric, factIDs []string) HostMetric {
	heavy := heavyFactIDs()
	cmd := baseCmd
	var cached strings.Builder
	reused := map[string]bool{}
	ages := map[string]string{}
	skip := map[string]bool{}
	if c.cfg.FactRefreshInterval > 0 {
		// 在锁内快照本机缓存（factCache 为共享 map，禁止锁外读写，
		// 否则多主机并行采集触发 concurrent map read/write）。
		c.mu.Lock()
		hostCache := c.factCache[host]
		c.mu.Unlock()
		for _, id := range factIDs {
			if !heavy[id] {
				continue
			}
			c.mu.Lock()
			c.cacheTotal++
			c.mu.Unlock()
			if f, ok := hostCache[id]; ok && time.Since(f.at) <= c.cfg.FactRefreshInterval {
				fmt.Fprintf(&cached, "%s\n%s\n", fragmentMark(id), f.out)
				skip[id] = true
				reused[id] = true
				ages[id] = time.Since(f.at).Round(time.Second).String()
				c.mu.Lock()
				c.cacheHits++
				c.mu.Unlock()
			}
		}
		if len(skip) > 0 {
			cmd = buildMetricsCommandSel(c.env, ms, skip, factIDs, []string{})
		}
	}
	out, err := c.run(ctx, host, cmd, c.cfg.CollectTimeout)
	// 有输出即可解析（子命令失败可容忍：/proc 缺失、命令不存在等）；
	// 完全无输出才算采集失败（sh 不可用、SSH 连不上等）。
	if err != nil && strings.TrimSpace(out) == "" {
		hm := HostMetric{Host: host, Metrics: map[string]map[string]float64{}, Errors: map[string]string{"collect": err.Error()}}
		// 覆盖语义：采集层失败 → 命令内事实标 partial（不完整结果不得
		// 作结论/放行复检/进缓存；collect_anomaly 由 judgeHost 覆盖）。
		inCmd := map[string]bool{}
		for _, id := range factIDs {
			if !skip[id] {
				inCmd[id] = true
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
	// 覆盖语义（design-v2.md §二）：覆盖度是事实的一部分，沿管道传递
	// ——采集层失败/探针哨兵 → partial（不完整枚举不得当结论）。
	inCmd := map[string]bool{}
	for _, id := range factIDs {
		if !skip[id] {
			inCmd[id] = true
		}
	}
	hm.FactCoverage = c.coverageFor(err, inCmd, incomplete, reused)
	c.parseOutput(&hm, out, ms)
	// 实采重探针写缓存（与全量路径同规则：命中不刷新时间戳）。
	// 整段在 c.mu 下执行，与 invalidateFactCache 保护口径一致。
	// 不完整结果（采集层失败/探针哨兵）绝不进缓存——partial 不得
	// 被当 full 在 TTL 内复用（假阴性源）。
	if c.cfg.FactRefreshInterval > 0 {
		c.mu.Lock()
		for _, id := range factIDs {
			if !heavy[id] || reused[id] {
				continue
			}
			if err != nil || incomplete[id] {
				continue
			}
			if frag, ok := frags[id]; ok {
				if c.factCache[host] == nil {
					c.factCache[host] = map[string]cachedFact{}
				}
				c.factCache[host][id] = cachedFact{out: frag, at: time.Now()}
			}
		}
		c.mu.Unlock()
	}
	return hm
}

// coverageFor 计算本轮事实覆盖语义：
//   - 采集层失败（err!=nil）：命令内事实可能被截断 → partial；缓存
//     命中项是历史完整结果 → full；未请求项 → skipped；
//   - 完成：命令内探针按完成哨兵分 partial/full；命令外（例行轮未含
//     的下钻项/显式清单未请求）→ skipped（设计决策，非故障）。
func (c *Collector) coverageFor(err error, inCmd, incomplete, reused map[string]bool) map[string]string {
	cover := map[string]string{}
	for _, fp := range SecurityFacts(c.env) {
		id := fp.ID
		switch {
		case err != nil:
			switch {
			case inCmd[id]:
				cover[id] = "partial"
			case reused[id]:
				cover[id] = "full"
			default:
				cover[id] = "skipped"
			}
		case !inCmd[id]:
			cover[id] = "skipped"
		case incomplete[id]:
			cover[id] = "partial"
		default:
			cover[id] = "full"
		}
	}
	return cover
}

// Targets returns the target host list: the local host first, then remote
// aliases.
// Targets 返回目标主机列表：本机（LocalHost）在前，远程别名在后。
func (c *Collector) Targets() []string {
	var t []string
	if c.cfg.Local {
		t = append(t, c.cfg.LocalHost)
	}
	t = append(t, c.cfg.Hosts...)
	return t
}

// buildMetricsCommand 把探针清单拼成一条命令：每项输出用唯一标记包裹，
// 一次执行取回全部指标（1 次本地 exec / 1 次远程 SSH）。cpu/load 片段
// 恒附加（CPU 增量采样与负载证据，清单未含时解析自然跳过）。
// 每个片段统一包一层 `{ ...; } 2>/dev/null`：采集值是确定性 stdout——
// 动态链接器报错（LD_PRELOAD 注入）、find 权限告警等 stderr 噪声不得
// 进入摘要/事实字段（R7 实测 LD_PRELOAD 噪声污染 state_crontab/
// big_files/tmp_dirs 造成误报与漂移摘要失真）。
// BuildMetricsCommand 组装探针清单的采集命令（确定性快检；测试与
// 全自动运维引擎复检共用）。

// Env returns the collection environment (used by the core engine for
// context injection).
// Env 返回采集环境（core 引擎注入上下文用）。
func (c *Collector) Env() *Env { return c.env }
