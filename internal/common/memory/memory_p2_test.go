package memory

// memory_p2_test.go — P2 修复回归测试：跨进程合并只增不减（经验库
// 并行写不再互相覆盖）。

import (
	"testing"
)

func TestMergeExperience_Monotonic(t *testing.T) {
	// 内存：本进程记录 3 次命中（Action 模板）。
	mem := &Experience{Entries: []ExperienceEntry{{
		Signal: "svc_failed", Host: "web-01", Pattern: "nginx",
		Count: 3, Action: "systemctl restart nginx", Outcome: "remediated",
		Misreports: 1, Confidence: 0.66, LastSeen: "2030-01-01T00:00:00Z",
	}}}
	// 磁盘：对方进程的旧视图（2 次命中，字段更少）。
	disk := &Experience{Entries: []ExperienceEntry{{
		Signal: "svc_failed", Host: "web-01", Pattern: "nginx",
		Count: 2, Outcome: "remediated", LastSeen: "2029-01-01T00:00:00Z",
	}}}
	mergeExperience(mem, disk)
	if mem.Entries[0].Count != 3 {
		t.Fatalf("Count 不得被对方旧视图回退: %d", mem.Entries[0].Count)
	}
	if mem.Entries[0].Action != "systemctl restart nginx" {
		t.Fatalf("Action 不得被对方旧视图清掉: %q", mem.Entries[0].Action)
	}

	// 反向：磁盘有更多历史（对方先跑过）→ 并入磁盘的计数。
	mem2 := &Experience{Entries: []ExperienceEntry{{
		Signal: "svc_failed", Host: "web-01", Pattern: "nginx",
		Count: 1, Outcome: "dismissed", LastSeen: "2031-01-01T00:00:00Z",
	}}}
	disk2 := &Experience{Entries: []ExperienceEntry{{
		Signal: "svc_failed", Host: "web-01", Pattern: "nginx",
		Count: 5, Action: "systemctl restart nginx", Outcome: "remediated",
		LastSeen: "2028-01-01T00:00:00Z",
	}}}
	mergeExperience(mem2, disk2)
	if mem2.Entries[0].Count != 5 {
		t.Fatalf("对方更多历史应并入: %d", mem2.Entries[0].Count)
	}

	// 磁盘独有条目追加（不丢任何一方）。
	mem3 := &Experience{}
	disk3 := &Experience{Entries: []ExperienceEntry{{
		Signal: "ssh_root_login", Host: "db-01", Pattern: "root",
		Count: 1, Outcome: "remediated", LastSeen: "2030-01-01T00:00:00Z",
	}}}
	mergeExperience(mem3, disk3)
	if len(mem3.Entries) != 1 {
		t.Fatalf("磁盘独有条目应追加: %d", len(mem3.Entries))
	}
}
