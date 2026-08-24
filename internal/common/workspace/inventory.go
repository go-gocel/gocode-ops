package workspace

import (
	"time"
)

// S2 上板基线刷新节奏（design-v2.md §二，单一来源——引擎同步与报告
// 标注共用）：
//   - InventoryRefresh 完整基线刷新周期；
//   - InventoryRetry 覆盖不完整（partial）的重试节奏——大文件系统上
//     全盘扫描超时是常态，按短周期重试，防每轮空转。
const (
	InventoryRefresh = 24 * time.Hour
	InventoryRetry   = 2 * time.Hour
)

// FactInventory S2 上板基线（design-v2.md §二：枚举事实"上板一次全量建
// 基线，例行只做漂移检测"）。
//
// 全盘枚举探针（suid_files_full/big_files）的例行替代：上板/周期刷新时
// 才全盘扫描（成本有界：远端 timeout + 完成哨兵，超时即 partial），
// 例行轮绝不重扫全盘。刷新比对新增条目 → 漂移线索（交 DeepDive 裁决）。
// 覆盖不完整（partial）的记录仅作重试节奏（Partial=true、无条目），
// 绝不当基线使用——空基线会把下次刷新的全部条目误报为"新增"。
type FactInventory struct {
	At      time.Time         `json:"at"`
	Partial bool              `json:"partial,omitempty"` // 上次采集不完整：非基线，仅作重试节奏
	Entries map[string]string `json:"entries"`           // 条目 → 摘要（如路径 → 大小/类型）
}

// GetInventory 返回主机某探针的上板基线（nil=未上板/无记录）。
func (w *Workspace) GetInventory(host, probeID string) *FactInventory {
	w.mu.Lock()
	defer w.mu.Unlock()
	byProbe := w.Inventory[host]
	if byProbe == nil {
		return nil
	}
	inv := byProbe[probeID]
	if inv == nil {
		return nil
	}
	cp := *inv
	cp.Entries = cloneStringMap(inv.Entries)
	return &cp
}

// PutInventory 写入主机某探针的上板基线（含"未上板"的 partial 重试记录）。
func (w *Workspace) PutInventory(host, probeID string, inv *FactInventory) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.Inventory == nil {
		w.Inventory = map[string]map[string]*FactInventory{}
	}
	byProbe := w.Inventory[host]
	if byProbe == nil {
		byProbe = map[string]*FactInventory{}
		w.Inventory[host] = byProbe
	}
	cp := *inv
	cp.Entries = cloneStringMap(inv.Entries)
	byProbe[probeID] = &cp
	return w.save("fact_inventory.json", w.Inventory)
}

// InventorySnapshot 返回上板基线快照（报告覆盖声明用；加锁深拷贝）。
func (w *Workspace) InventorySnapshot() map[string]map[string]*FactInventory {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make(map[string]map[string]*FactInventory, len(w.Inventory))
	for host, byProbe := range w.Inventory {
		probes := make(map[string]*FactInventory, len(byProbe))
		for id, inv := range byProbe {
			cp := *inv
			cp.Entries = cloneStringMap(inv.Entries)
			probes[id] = &cp
		}
		out[host] = probes
	}
	return out
}

func cloneStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
