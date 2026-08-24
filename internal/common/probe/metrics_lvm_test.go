package probe

import "testing"

// LVM 探针解析测试（lvs 输出为确定性纯函数）。

func TestParseLvsUsage(t *testing.T) {
	out := `root|vg00|21474836480|10737418240
var|vg00|10737418240|10380902400
thin|vg00|10737418240|-
`
	got, err := parseLvsUsage(out)
	if err != nil {
		t.Fatalf("parseLvsUsage: %v", err)
	}
	want := map[string]float64{
		"vg00/root": 50,
		"vg00/var":  96.7,
	}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (%v)", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] < v-0.1 || got[k] > v+0.1 {
			t.Errorf("%s = %.2f, want %.1f", k, got[k], v)
		}
	}
}

func TestParseLvsUsageNoData(t *testing.T) {
	// 无 lvs 工具：空输出 → 无数据（不产线、不报错）。
	got, err := parseLvsUsage("")
	if err != nil || len(got) != 0 {
		t.Errorf("空输出应无数据，got %v err %v", got, err)
	}
	// 全部非法行（非标准列数/数值）→ 无数据。
	got, err = parseLvsUsage("junk line without pipes\n")
	if err != nil || len(got) != 0 {
		t.Errorf("非法行应无数据，got %v err %v", got, err)
	}
}
