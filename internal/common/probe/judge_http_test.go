package probe

import (
	"strings"
	"testing"
)

// Web 服务健康面判定测试（演练 R5 快检进化）：站点不可达/非 2xx 产
// 线索，且按 Web 服务单元门控（无 Web 服务的主机不产线）。

func TestParseHTTPHealth(t *testing.T) {
	// 健康：2xx/3xx → 无数据。
	if got, err := parseHTTPHealth("200"); err != nil || len(got) != 0 {
		t.Errorf("200 应无数据，got %v err %v", got, err)
	}
	if got, err := parseHTTPHealth("301"); err != nil || len(got) != 0 {
		t.Errorf("301 应无数据，got %v err %v", got, err)
	}
	// 异常：4xx/5xx → code。
	got, err := parseHTTPHealth("502")
	if err != nil || got["code"] != 502 {
		t.Errorf("502 应报 code=502，got %v err %v", got, err)
	}
	// 不可达：NONE/空 → none。
	if got, err := parseHTTPHealth("NONE"); err != nil || got["none"] != 1 {
		t.Errorf("NONE 应报 none=1，got %v err %v", got, err)
	}
	if got, err := parseHTTPHealth(""); err != nil || got["none"] != 1 {
		t.Errorf("空输出应报 none=1，got %v err %v", got, err)
	}
	// 异常输出：无数据不臆断。
	if got, err := parseHTTPHealth("garbage"); err != nil || len(got) != 0 {
		t.Errorf("异常输出应无数据，got %v err %v", got, err)
	}
}

func TestJudgeHTTPHealth(t *testing.T) {
	judge := func(metrics map[string]float64, enabledUnits string) []Anomaly {
		hm := &HostMetric{
			Host: "web-01",
			Metrics: map[string]map[string]float64{
				"mem":         {"avail_pct": 50},
				"http_health": metrics,
			},
			Raw: map[string]string{"enabled_units": enabledUnits},
		}
		return Judge(&Snapshot{Hosts: []HostMetric{*hm}}, DefaultThresholds())
	}
	// 站点不可达 + 有启用 nginx → 产 site_down 线索。
	out := judge(map[string]float64{"none": 1}, "sshd.service\nnginx.service\n")
	if len(out) != 1 || out[0].Signal() != "site_down" || out[0].Key != "none" {
		t.Fatalf("应产 site_down(none) 线索，got %+v", out)
	}
	// 502 + 有启用 nginx → 产 site_down(code) 线索。
	out = judge(map[string]float64{"code": 502}, "nginx.service\n")
	if len(out) != 1 || out[0].Signal() != "site_down" || out[0].Value != 502 {
		t.Fatalf("应产 site_down(code=502) 线索，got %+v", out)
	}
	// 无 Web 服务单元：NONE 不产线（数据驱动门控）。
	if out := judge(map[string]float64{"none": 1}, "sshd.service\n"); len(out) != 0 {
		t.Fatalf("无 Web 服务不应产线，got %+v", out)
	}
	// enabled_units 数据缺失：不产线（门控依据缺失，不臆断）。
	hm := &HostMetric{Host: "h", Metrics: map[string]map[string]float64{
		"mem":         {"avail_pct": 50},
		"http_health": {"none": 1},
	}}
	if out := Judge(&Snapshot{Hosts: []HostMetric{*hm}}, DefaultThresholds()); len(out) != 0 {
		t.Fatalf("enabled_units 缺失不应产线，got %+v", out)
	}
	// 健康站点（http_health 无数据段）：不产线。
	if out := judge(nil, "nginx.service\n"); len(out) != 0 {
		t.Fatalf("健康站点不应产线，got %+v", out)
	}
	_ = strings.TrimSpace // 保持 strings 导入（webServiceActive 依赖在 judge.go）
}
