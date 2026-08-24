package probe

import "testing"

// 服务面判定测试：Service 无后端端点 → 线索（pod 全 Running 时
// 工作负载探针看不到的服务面故障）。

func TestJudgeK8sSvcBackends_NoBackend(t *testing.T) {
	hm := &HostMetric{
		Host: "web-01",
		Raw: map[string]string{
			"k8s_svcs": "default      web-svc      ClusterIP   10.96.0.10   80/TCP    12h\n" +
				"default      app-svc      ClusterIP   10.96.0.11   8080/TCP   8m\n" +
				"default      ext-svc      ExternalName <none>        <none>    12h\n" +
				"kube-system  kubernetes   ClusterIP   10.96.0.1     443/TCP    12h\n",
			"k8s_endpoints": "default      web-svc      10.244.1.5:80    12h\n" +
				"default      app-svc      <none>           8m\n" +
				"default      ext-svc      <none>           12h\n",
		},
	}
	out := JudgeK8sFacts(hm)
	// app-svc 无端点 → 1 条；web-svc 有端点、ext-svc ExternalName、
	// kubernetes 默认服务 → 排除。
	if len(out) != 1 {
		t.Fatalf("应产 1 条（app-svc 无后端），got %d: %+v", len(out), out)
	}
	if out[0].Signal() != "k8s_svc_no_backend" || out[0].Key != "default/app-svc" {
		t.Errorf("信号/对象键错误: %s/%s", out[0].Signal(), out[0].Key)
	}
}

func TestJudgeK8sSvcBackends_AllBacked(t *testing.T) {
	hm := &HostMetric{
		Host: "web-01",
		Raw: map[string]string{
			"k8s_svcs":      "default      web-svc      ClusterIP   10.96.0.10   80/TCP    12h\n",
			"k8s_endpoints": "default      web-svc      10.244.1.5:80    12h\n",
		},
	}
	if out := JudgeK8sFacts(hm); len(out) != 0 {
		t.Fatalf("全部有后端不应产线，got %+v", out)
	}
}

func TestJudgeK8sSvcBackends_DataDriven(t *testing.T) {
	// 无 svc 数据（非集群主机）→ 跳过。
	if out := JudgeK8sFacts(&HostMetric{Host: "h"}); len(out) != 0 {
		t.Fatalf("无数据应跳过，got %+v", out)
	}
	// 有 svc 无 endpoints 数据 → 跳过（配对数据缺失不臆断）。
	hm := &HostMetric{Host: "h", Raw: map[string]string{
		"k8s_svcs": "default      web-svc      ClusterIP   10.96.0.10   80/TCP    12h\n",
	}}
	if out := JudgeK8sFacts(hm); len(out) != 0 {
		t.Fatalf("endpoints 数据缺失应跳过，got %+v", out)
	}
}

func TestJudgeK8sSvcBackends_HeadlessSkipped(t *testing.T) {
	// Headless（ClusterIP=None）无端点属正常（按需解析）。
	hm := &HostMetric{
		Host: "web-01",
		Raw: map[string]string{
			"k8s_svcs":      "default      headless-svc   ClusterIP   None         80/TCP    12h\n",
			"k8s_endpoints": "default      headless-svc   <none>        12h\n",
		},
	}
	if out := JudgeK8sFacts(hm); len(out) != 0 {
		t.Fatalf("Headless 无端点应跳过，got %+v", out)
	}
}
