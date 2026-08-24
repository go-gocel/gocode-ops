package probe

// desired_p2_test.go — P2 修复回归测试：期望偏差的数据可用性门控
// （探针采集失败/无数据不得批量误报 missing_service 等）。

import "testing"

func TestDevExpect_NoDataSkips(t *testing.T) {
	spec := ExpectSpec{Services: []string{"nginx"}, Ports: []int{8080}, Users: []string{"ops"}}

	// 有数据（覆盖 full + Raw 有内容）：缺失项照常报。
	hmFull := &HostMetric{
		Host:         "web-01",
		Raw:          map[string]string{"svc_units": "sshd.service\n", "listen_ports": "0.0.0.0:22\n", "uid0_users": "root\n"},
		FactCoverage: map[string]string{"svc_units": "full", "listen_ports": "full", "uid0_users": "full"},
	}
	out := devExpect(hmFull, spec)
	if len(out) != 3 {
		t.Fatalf("有数据时应报 3 项缺失: %+v", out)
	}

	// 探针失败（Raw 空 + 覆盖 partial）：不得把"无数据"当"服务缺失"。
	hmPartial := &HostMetric{
		Host:         "web-01",
		Raw:          map[string]string{},
		FactCoverage: map[string]string{"svc_units": "partial", "listen_ports": "partial", "uid0_users": "partial"},
	}
	if out := devExpect(hmPartial, spec); len(out) != 0 {
		t.Fatalf("覆盖不完整不得批量误报: %+v", out)
	}

	// 覆盖位缺失（旧数据形态）：Raw 空视为无数据跳过。
	hmNoCov := &HostMetric{Host: "web-01", Raw: map[string]string{}}
	if out := devExpect(hmNoCov, spec); len(out) != 0 {
		t.Fatalf("无数据不得批量误报: %+v", out)
	}
}

func TestDevExpect_FullCoverageEmptyRaw(t *testing.T) {
	// 覆盖 full 但 Raw 为空（探针运行、零命中——如 svc_units 无任何
	// 服务）：视为有数据，缺失照报（覆盖语义与 JudgeSecurityFacts 同源）。
	spec := ExpectSpec{Services: []string{"nginx"}}
	hm := &HostMetric{
		Host:         "web-01",
		Raw:          map[string]string{},
		FactCoverage: map[string]string{"svc_units": "full"},
	}
	out := devExpect(hm, spec)
	if len(out) != 1 || out[0].Kind != "missing_service" {
		t.Fatalf("full 覆盖空结果应报缺失: %+v", out)
	}
}
