package probe

import (
	"testing"
)

// TestJudgeSuidOwners_UnownedProducesLead 非包来源 SUID 产线（后门特征）。
func TestJudgeSuidOwners_UnownedProducesLead(t *testing.T) {
	hm := &HostMetric{
		Host: "web-01",
		Raw: map[string]string{
			"suid_owners": "/usr/bin/passwd|shadow-utils\n/usr/bin/upd|UNOWNED\n/usr/bin/su|coreutils\n/var/lib/.sysupdate|UNOWNED\nbad-line-no-pipe\n",
		},
	}
	out := judgeSuidOwners(hm)
	if len(out) != 2 {
		t.Fatalf("应产 2 条未归属线索，got %d: %+v", len(out), out)
	}
	keys := map[string]bool{}
	for _, a := range out {
		keys[a.Key] = true
		if a.Signal() != "suid_unowned" {
			t.Errorf("信号应为 suid_unowned，got %s", a.Signal())
		}
	}
	if !keys["/usr/bin/upd"] || !keys["/var/lib/.sysupdate"] {
		t.Errorf("应命中 /usr/bin/upd 与 /var/lib/.sysupdate，got %v", keys)
	}
}

// TestJudgeSuidOwners_AllOwnedNoLead 全部包归属 → 不产线（发行版默认 SUID）。
func TestJudgeSuidOwners_AllOwnedNoLead(t *testing.T) {
	hm := &HostMetric{
		Host: "web-01",
		Raw: map[string]string{
			"suid_owners": "/usr/bin/passwd|shadow-utils\n/usr/bin/su|coreutils\n/usr/bin/sudo|sudo\n",
		},
	}
	if out := judgeSuidOwners(hm); len(out) != 0 {
		t.Fatalf("全部包归属不应产线，got %+v", out)
	}
}

// TestJudgeSuidOwners_NoDataSkip 归属工具全无（探针空数据）→ 跳过不误报。
func TestJudgeSuidOwners_NoDataSkip(t *testing.T) {
	hm := &HostMetric{Host: "web-01"} // Raw 无 suid_owners
	if out := judgeSuidOwners(hm); len(out) != 0 {
		t.Fatalf("无数据应跳过，got %+v", out)
	}
	hm2 := &HostMetric{Host: "web-01", Raw: map[string]string{"suid_owners": ""}}
	if out := judgeSuidOwners(hm2); len(out) != 0 {
		t.Fatalf("空数据应跳过，got %+v", out)
	}
}

// TestJudgeSuidOwners_RpmErrorTextIsUnowned rpm -qf 对非包文件把错误
// 消息写到 stdout（"not owned by any package"/"不属于任何软件包"）——
// 探针端按退出码归 UNOWNED，judge 端对错误文本再识别（双保险）。
func TestJudgeSuidOwners_RpmErrorTextIsUnowned(t *testing.T) {
	hm := &HostMetric{
		Host: "web-01",
		Raw: map[string]string{
			"suid_owners": "/usr/bin/passwd|shadow-utils\n/usr/bin/upd|file /usr/bin/upd is not owned by any package\n/usr/bin/x|文件 /usr/bin/x 不属于任何软件包\n/usr/bin/y|dpkg-query: no path found matching pattern\n",
		},
	}
	out := judgeSuidOwners(hm)
	if len(out) != 3 {
		t.Fatalf("错误文本应判未归属（3 条），got %d: %+v", len(out), out)
	}
	for _, a := range out {
		if a.Signal() != "suid_unowned" {
			t.Errorf("信号应为 suid_unowned，got %s", a.Signal())
		}
	}
}

// TestJudgeSuidOwners_MalformedLineSkipped 畸形行（无分隔符/空归属）跳过。
func TestJudgeSuidOwners_MalformedLineSkipped(t *testing.T) {
	hm := &HostMetric{
		Host: "web-01",
		Raw: map[string]string{
			"suid_owners": "/usr/bin/foo\n/usr/bin/bar|\n/usr/bin/baz| \n",
		},
	}
	out := judgeSuidOwners(hm)
	// /usr/bin/bar| 与 /usr/bin/baz| （空归属）应产线；无分隔符行跳过。
	if len(out) != 2 {
		t.Fatalf("空归属应产线（2 条），无分隔符行跳过，got %d: %+v", len(out), out)
	}
}
