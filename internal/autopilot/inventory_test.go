package autopilot

import (
	"context"
	"testing"
	"time"

	"github.com/go-gocel/gocode-ops/internal/common/model"
)

// S2 上板基线机制测试（design-v2.md §二）：全盘枚举探针上板一次建基线、
// 周期刷新比对产漂移线索；例行轮绝不重扫全盘；不完整枚举绝不当基线。

// TestSyncInventory_OnboardingBaseline 上板：全量扫描一次建基线，不产
// 线索（基线即现状，漂移从刷新开始才有意义）。
func TestSyncInventory_OnboardingBaseline(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: healthyOut}
	remote.markerOutputs = map[string][]string{
		"suid_files_full": {"__M_suid_files_full__\n/usr/bin/suid1\n/var/lib/.find\n"},
		"big_files":       {"__M_big_files__\n"},
	}
	e, _, _ := testEngineProtocol(t, nil, remote)
	e.syncInventory(context.Background())
	inv := e.ws().GetInventory("web-01", "suid_files_full")
	if inv == nil || inv.Partial {
		t.Fatalf("上板应建立完整基线: %+v", inv)
	}
	if len(inv.Entries) != 2 {
		t.Errorf("基线条目 = %d, want 2: %+v", len(inv.Entries), inv.Entries)
	}
	if len(e.ws().Pending()) != 0 {
		t.Errorf("上板不应产漂移线索: %+v", e.ws().Pending())
	}
	// 大文件空清单也是有效基线（空输出=扫描无结果）。
	if b := e.ws().GetInventory("web-01", "big_files"); b == nil || b.Partial || len(b.Entries) != 0 {
		t.Errorf("big_files 空基线应有效: %+v", b)
	}
}

// TestSyncInventory_RefreshDriftLead 周期刷新：基线后新增条目 → 漂移
// 线索（复用信号词表 suid_files，Key=新路径，交 DeepDive 裁决）。
func TestSyncInventory_RefreshDriftLead(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: healthyOut}
	remote.markerOutputs = map[string][]string{
		"suid_files_full": {"__M_suid_files_full__\n/usr/bin/suid1\n/var/lib/.find\n"},
		"big_files":       {"__M_big_files__\n"},
	}
	e, _, _ := testEngineProtocol(t, nil, remote)
	e.syncInventory(context.Background())
	// 基线置旧（超过刷新周期 24h）→ 下次同步触发刷新。
	inv := e.ws().GetInventory("web-01", "suid_files_full")
	inv.At = time.Now().Add(-25 * time.Hour)
	if err := e.ws().PutInventory("web-01", "suid_files_full", inv); err != nil {
		t.Fatal(err)
	}
	// 环境变化：新增一个非标准位置 SUID（攻击者落地特征）。
	remote.markerOutputs["suid_files_full"] = []string{"__M_suid_files_full__\n/usr/bin/suid1\n/var/lib/.find\n/var/lib/.new_suid\n"}
	e.syncInventory(context.Background())
	found := false
	for _, f := range e.ws().Pending() {
		if f.Signal == "suid_files" && f.Key == "/var/lib/.new_suid" {
			found = true
			if f.Source != model.SourceL0 {
				t.Errorf("漂移线索来源应为 l0: %q", f.Source)
			}
		}
	}
	if !found {
		t.Errorf("刷新应产漂移线索（新增条目）: %+v", e.ws().Pending())
	}
	// 基线已更新：再刷新同环境不再重复产线（同 key 去重 + 基线已含）。
	inv2 := e.ws().GetInventory("web-01", "suid_files_full")
	if _, ok := inv2.Entries["/var/lib/.new_suid"]; !ok {
		t.Error("刷新后基线应包含新增条目")
	}
}

// TestSyncInventory_PartialNeverBaseline 覆盖不完整（哨兵/超时）：
// 记录 partial 重试节奏（非基线）——空基线会把下次刷新全部条目误报
// 为"新增"；重试节奏内不重复采集（防每轮空转）。
func TestSyncInventory_PartialNeverBaseline(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: healthyOut}
	remote.markerOutputs = map[string][]string{
		"suid_files_full": {"__M_suid_files_full__\n/var/lib/.find\n__PROBE_INCOMPLETE__\n"},
		"big_files":       {"__M_big_files__\n"},
	}
	e, _, _ := testEngineProtocol(t, nil, remote)
	e.syncInventory(context.Background())
	inv := e.ws().GetInventory("web-01", "suid_files_full")
	if inv == nil || !inv.Partial {
		t.Fatalf("不完整采集应记录 partial（非基线）: %+v", inv)
	}
	if len(inv.Entries) != 0 {
		t.Error("partial 记录不得携带条目（绝不当作基线）")
	}
	calls := len(remote.calls)
	// 重试节奏内（2h）不重复采集。
	e.syncInventory(context.Background())
	if len(remote.calls) != calls {
		t.Error("partial 重试节奏内不应重复采集（防每轮空转）")
	}
	// 超过重试节奏后重试。
	inv.At = time.Now().Add(-3 * time.Hour)
	if err := e.ws().PutInventory("web-01", "suid_files_full", inv); err != nil {
		t.Fatal(err)
	}
	remote.markerOutputs["suid_files_full"] = []string{"__M_suid_files_full__\n/usr/bin/suid1\n"}
	e.syncInventory(context.Background())
	inv2 := e.ws().GetInventory("web-01", "suid_files_full")
	if inv2 == nil || inv2.Partial {
		t.Fatalf("重试成功后应建立完整基线: %+v", inv2)
	}
}

// TestSyncInventory_FreshBaselineNoRescan 基线新鲜时零开销（不采集）。
func TestSyncInventory_FreshBaselineNoRescan(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: healthyOut}
	remote.markerOutputs = map[string][]string{
		"suid_files_full": {"__M_suid_files_full__\n/a\n"},
		"big_files":       {"__M_big_files__\n"},
	}
	e, _, _ := testEngineProtocol(t, nil, remote)
	e.syncInventory(context.Background())
	calls := len(remote.calls)
	e.syncInventory(context.Background())
	if len(remote.calls) != calls {
		t.Error("基线新鲜时不应重新采集（例行轮零开销）")
	}
}
