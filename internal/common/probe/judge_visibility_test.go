package probe

import "testing"

// 目标零可见性判定（采集完整性）：指标/状态/事实全空且无采集错误 →
// target_no_data 线索——"无数据"与"健康"必须区分（PAM 拒绝等通道
// 异常在 exec 容错下表现为"正常但零数据"，静默缺失不得被当全绿）。

func TestJudgeHost_ZeroVisibilityLeads(t *testing.T) {
	// 完全无数据且无错误：产 target_no_data。
	hm := &HostMetric{Host: "web-01", Metrics: map[string]map[string]float64{}}
	out := Judge(&Snapshot{Hosts: []HostMetric{*hm}}, DefaultThresholds())
	if len(out) != 1 {
		t.Fatalf("零可见性应产 1 条线索，got %d: %+v", len(out), out)
	}
	if out[0].Signal() != "target_no_data" {
		t.Errorf("信号 = %s, want target_no_data", out[0].Signal())
	}

	// 有 collect 错误：走既有 collect_anomaly，不重复产 target_no_data。
	hmErr := &HostMetric{Host: "web-01", Metrics: map[string]map[string]float64{}, Errors: map[string]string{"collect": "全部失败"}}
	out = Judge(&Snapshot{Hosts: []HostMetric{*hmErr}}, DefaultThresholds())
	if len(out) != 1 || out[0].Signal() != "collect_anomaly" {
		t.Errorf("采集失败应只产 collect_anomaly，got %+v", out)
	}

	// 有指标数据（哪怕少量）：不产 target_no_data。
	hmData := &HostMetric{Host: "web-01", Metrics: map[string]map[string]float64{"mem": {"avail_pct": 50}}}
	out = Judge(&Snapshot{Hosts: []HostMetric{*hmData}}, DefaultThresholds())
	for _, a := range out {
		if a.Signal() == "target_no_data" {
			t.Errorf("有数据不应产 target_no_data: %+v", out)
		}
	}

	// 有状态快照（配置漂移面）：同样不产。
	hmState := &HostMetric{Host: "web-01", Metrics: map[string]map[string]float64{}, State: map[string]string{"state_sshd": "x"}}
	out = Judge(&Snapshot{Hosts: []HostMetric{*hmState}}, DefaultThresholds())
	for _, a := range out {
		if a.Signal() == "target_no_data" {
			t.Errorf("有状态快照不应产 target_no_data: %+v", out)
		}
	}
}
