package autopilot

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-gocel/gocode-ops/internal/common/model"
	"github.com/go-gocel/gocode-ops/internal/common/workspace"
)

// S2 上板基线周期刷新（design-v2.md §二）：全盘枚举探针
// （suid_files_full/big_files）"上板一次全量建基线，例行只做漂移检测"——
// 例行轮绝不重扫全盘（2.3T/7000 万 inode 根分区全盘 find 即事故源）。
//
// 刷新节奏（常量单一来源：workspace.InventoryRefresh/InventoryRetry）：
// 上板（无基线）立即采集；覆盖不完整（partial）按短周期重试
// （大文件系统上全盘扫描超时是常态，重试节奏防每轮空转）；基线建立后
// 按长周期刷新。刷新比对基线新增条目 → 漂移线索（交 DeepDive 裁决，
// 与 L0 线索同管道）。

// inventoryProbes S2 上板基线探针规格（探针 ID → 漂移线索信号/名称）。
// 漂移线索复用现有信号词表（去重键一致，DeepDive 裁决管道一致）。
var inventoryProbes = map[string]struct {
	signal string
	name   string
}{
	"suid_files_full": {signal: "suid_files", name: "SUID 文件全盘清单"},
	"big_files":       {signal: "oversized_file", name: "大文件清单"},
}

// syncInventory S2 上板基线同步（确定性，产漂移线索）：逐探针检查各
// 主机基线新鲜度 → 需要刷新的主机定向采集（先失效重探针缓存，保证
// 实采）→ 覆盖完整则上板/比对，partial 则记录重试节奏。
// 单轮最多 2 次定向采集（每探针 1 次，覆盖全部目标）；基线新鲜时零开销。
func (e *Engine) syncInventory(ctx context.Context) {
	for probeID, spec := range inventoryProbes {
		need := e.staleInventoryHosts(probeID)
		if len(need) == 0 {
			continue
		}
		// 失效重探针缓存：刷新必须实采（TTL 内旧结果会掩盖变化）。
		for host := range need {
			e.core.InvalidateFactCache(host)
		}
		snap, err := e.core.CollectProbes(ctx, nil, []string{probeID})
		if err != nil {
			e.logf("S2 上板采集失败（%s）: %v，下轮重试", probeID, err)
			continue
		}
		for i := range snap.Hosts {
			hm := &snap.Hosts[i]
			if !need[hm.Host] {
				continue
			}
			if cov := hm.FactCoverage[probeID]; cov != "full" {
				// 不完整枚举绝不当基线：只记录重试节奏。
				e.ws().PutInventory(hm.Host, probeID, &workspace.FactInventory{
					At: time.Now().UTC(), Partial: true,
				})
				e.logf("S2 上板 %s[%s] 覆盖不完整（%s），记录重试节奏（%s 后）", probeID, hm.Host, cov, workspace.InventoryRetry)
				continue
			}
			entries := inventoryEntries(probeID, hm.Raw[probeID])
			old := e.ws().GetInventory(hm.Host, probeID)
			if old == nil || old.Partial {
				e.ws().PutInventory(hm.Host, probeID, &workspace.FactInventory{
					At: time.Now().UTC(), Entries: entries,
				})
				e.logf("S2 上板 %s[%s]：基线建立（%d 条目）", probeID, hm.Host, len(entries))
				continue
			}
			// 刷新比对：新增条目 → 漂移线索（删除条目良性，不产线）。
			var added []string
			for k := range entries {
				if _, ok := old.Entries[k]; !ok {
					added = append(added, k)
				}
			}
			if len(added) > 0 {
				sort.Strings(added)
				var leads []*model.Finding
				for _, k := range added {
					f := model.NewFinding(hm.Host, "security", spec.signal,
						fmt.Sprintf("S2 上板基线漂移：%s 新增条目 %s（%s）——全盘枚举非例行，需裁决是否预期", spec.name, k, entries[k]))
					f.Key = k
					f.Source = model.SourceL0
					leads = append(leads, f)
				}
				if err := e.ws().AddFindings(leads); err != nil {
					e.logf("S2 漂移线索入库失败: %v", err)
				}
				e.logf("S2 漂移 %s[%s]：新增 %d 条目 → %d 条线索（如 %s）", probeID, hm.Host, len(added), len(leads), added[0])
			}
			e.ws().PutInventory(hm.Host, probeID, &workspace.FactInventory{
				At: time.Now().UTC(), Entries: entries,
			})
		}
	}
}

// staleInventoryHosts 返回需要刷新上板基线的主机集合：
//   - 无基线记录 → 立即可上板；
//   - partial 记录 → 按重试节奏（短周期）；
//   - 完整基线 → 按刷新周期（长周期）。
func (e *Engine) staleInventoryHosts(probeID string) map[string]bool {
	need := map[string]bool{}
	for _, host := range e.core.Targets() {
		inv := e.ws().GetInventory(host, probeID)
		switch {
		case inv == nil:
			need[host] = true
		case inv.Partial:
			if time.Since(inv.At) >= workspace.InventoryRetry {
				need[host] = true
			}
		default:
			if time.Since(inv.At) >= workspace.InventoryRefresh {
				need[host] = true
			}
		}
	}
	return need
}

// inventoryEntries 把探针原始输出解析成上板基线条目（路径 → 摘要）：
//   - suid_files_full：每行一个路径；
//   - big_files：每行 "<size> <path...>"。
func inventoryEntries(probeID, raw string) map[string]string {
	entries := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch probeID {
		case "big_files":
			if i := strings.IndexByte(line, ' '); i > 0 {
				entries[strings.TrimSpace(line[i+1:])] = strings.TrimSpace(line[:i])
			}
		default:
			entries[line] = "suid"
		}
	}
	return entries
}
