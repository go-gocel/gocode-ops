package tools

// 交互式运维助手认知工具测试：期望声明（update_desired）、定向采集
// （collect_probe）、守卫背书回调（OnApproved → 档案沉淀）。

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// fakePC 测试用定向采集器。
type fakePC struct {
	snap *Snapshot
}

func (f *fakePC) CollectProbes(ctx context.Context, ms []Metric, factIDs []string) (*Snapshot, error) {
	return f.snap, nil
}

// TestUpdateDesiredTool 期望声明工具：add/remove 端口与服务。
func TestUpdateDesiredTool(t *testing.T) {
	dir := t.TempDir()
	tool := UpdateDesiredTool(dir)

	run := func(action, kind, host, value string) string {
		args, _ := json.Marshal(map[string]string{
			"action": action, "kind": kind, "host": host, "value": value,
		})
		msg, err := tool.Run(context.Background(), string(args))
		if err != nil {
			t.Fatalf("%s %s %s: %v", action, kind, value, err)
		}
		return msg
	}

	if msg := run("add", "port", "web-01", "8080"); !strings.Contains(msg, "已声明") {
		t.Errorf("add port 返回不符: %s", msg)
	}
	run("add", "service", "web-01", "nginx")
	run("add", "no_user", "web-01", "backdoor")

	d, err := LoadDesired(dir)
	if err != nil || d == nil {
		t.Fatalf("加载期望失败: %v", err)
	}
	exp := d.Hosts["web-01"].Expect
	if len(exp.Ports) != 1 || exp.Ports[0] != 8080 {
		t.Errorf("期望端口不符: %v", exp.Ports)
	}
	if len(exp.Services) != 1 || exp.Services[0] != "nginx" {
		t.Errorf("期望服务不符: %v", exp.Services)
	}
	if len(exp.NoUsers) != 1 || exp.NoUsers[0] != "backdoor" {
		t.Errorf("禁项用户不符: %v", exp.NoUsers)
	}

	// remove 撤销。
	if msg := run("remove", "port", "web-01", "8080"); !strings.Contains(msg, "已撤销") {
		t.Errorf("remove port 返回不符: %s", msg)
	}
	d, _ = LoadDesired(dir)
	if len(d.Hosts["web-01"].Expect.Ports) != 0 {
		t.Errorf("撤销后端口应清空: %v", d.Hosts["web-01"].Expect.Ports)
	}
	// 非法参数。
	if _, err := tool.Run(context.Background(), `{"action":"add","kind":"port","host":"h","value":"abc"}`); err == nil {
		t.Error("非法端口应报错")
	}
	if _, err := tool.Run(context.Background(), `{"action":"bogus","kind":"port","host":"h","value":"80"}`); err == nil {
		t.Error("非法 action 应报错")
	}
	if _, err := tool.Run(context.Background(), `{"action":"add","kind":"nope","host":"h","value":"x"}`); err == nil {
		t.Error("非法 kind 应报错")
	}
}

// TestCollectProbeTool 定向采集工具：按探针过滤输出。
func TestCollectProbeTool(t *testing.T) {
	pc := &fakePC{snap: &Snapshot{Hosts: []HostMetric{
		{Host: "web-01", Raw: map[string]string{
			"listen_ports": "LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*",
			"suid_files":   "/usr/bin/su",
		}},
		{Host: "web-02", Raw: map[string]string{"listen_ports": "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"}},
	}}}
	tool := CollectProbeTool(pc)
	args, _ := json.Marshal(map[string]string{"host": "web-01", "probes": "listen_ports"})
	msg, err := tool.Run(context.Background(), string(args))
	if err != nil {
		t.Fatalf("collect_probe: %v", err)
	}
	if !strings.Contains(msg, "8080") || strings.Contains(msg, "web-02") {
		t.Errorf("定向采集应只含目标主机与指定探针: %s", msg)
	}
	// 未知探针报错。
	args, _ = json.Marshal(map[string]string{"host": "web-01", "probes": "bogus"})
	if _, err := tool.Run(context.Background(), string(args)); err == nil {
		t.Error("未知探针应报错")
	}
}
