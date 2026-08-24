package probe

import (
	"strings"
	"testing"
)

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

// TestJudgeK8sSvcBackends_ClassifyDrift 服务面形态归类：selector 漂移
// （存在标签匹配 Pod 但端点为空）与无匹配后端两类根因方向。
func TestJudgeK8sSvcBackends_ClassifyDrift(t *testing.T) {
	hm := &HostMetric{
		Host: "web-01",
		Raw: map[string]string{
			"k8s_svcs": "default      web-svc      ClusterIP   10.96.0.10   80/TCP    12h\n" +
				"default      app-svc      ClusterIP   10.96.0.11   8080/TCP   8m\n",
			"k8s_endpoints": "default      web-svc      10.244.1.5:80    12h\n" +
				"default      app-svc      <none>           8m\n",
			"k8s_svc_selectors": "default/web-svc {\"app\":\"webapp\"}\n" +
				"default/app-svc {\"app\":\"webapp-drift\"}\n",
			"k8s_pod_labels": "default/webapp-abc {\"app\":\"webapp\"}\n" +
				"default/webapp-def {\"app\":\"webapp\"}\n" +
				"default/other-x {\"app\":\"other\"}\n",
		},
	}
	out := JudgeK8sFacts(hm)
	if len(out) != 1 {
		t.Fatalf("应产 1 条（app-svc 无后端且 selector 漂移），got %d: %+v", len(out), out)
	}
	a := out[0]
	if a.Signal() != "k8s_svc_no_backend" || a.Key != "default/app-svc" {
		t.Errorf("信号/对象键错误: %s/%s", a.Signal(), a.Key)
	}
	// selector app=webapp-drift 无匹配 Pod → 归类"无匹配后端"。
	if !strings.Contains(a.Desc, "无匹配 Pod") {
		t.Errorf("应归类为无匹配后端，desc=%s", a.Desc)
	}
	// 对照组：web-svc 有端点不产线；app-svc 归类准确。
	// 漂移形态：selector 匹配 Pod 但端点为空。
	hm.Raw["k8s_svc_selectors"] = "default/app-svc {\"app\":\"webapp\"}\n"
	out = JudgeK8sFacts(hm)
	if len(out) != 1 || !strings.Contains(out[0].Desc, "selector 漂移") {
		t.Errorf("应归类为 selector 漂移，got %+v", out)
	}
}

// TestJudgeK8sSvcBackends_ClassifyDegrade 形态数据缺失时降级通用线索
// （不臆断、不吞既有判定）。
func TestJudgeK8sSvcBackends_ClassifyDegrade(t *testing.T) {
	hm := &HostMetric{
		Host: "web-01",
		Raw: map[string]string{
			"k8s_svcs":      "default      app-svc      ClusterIP   10.96.0.11   8080/TCP   8m\n",
			"k8s_endpoints": "default      app-svc      <none>           8m\n",
			// 无 k8s_svc_selectors/k8s_pod_labels 数据段：降级通用线索。
		},
	}
	out := JudgeK8sFacts(hm)
	if len(out) != 1 || out[0].Signal() != "k8s_svc_no_backend" {
		t.Fatalf("应降级产通用线索，got %+v", out)
	}
	// 数据段为异常格式（非标签形态）→ 整段不可信，同样降级。
	hm.Raw["k8s_svc_selectors"] = "default/app-svc garbage\n"
	if out := JudgeK8sFacts(hm); len(out) != 1 || !strings.Contains(out[0].Desc, "无后端端点") {
		t.Fatalf("异常格式应降级通用线索，got %+v", out)
	}
}

// TestParseK8sSelectorList 标签/选择器形态解析：JSON 对象（现代
// kubectl）、Go map 形态（旧版）、空选择器、异常格式降级。
func TestParseK8sSelectorList(t *testing.T) {
	// JSON 形态（现代 kubectl 实测输出）。
	got := parseK8sSelectorList("default/web-svc {\"app\":\"webapp\"}\ndefault/no-sel \n")
	if len(got) != 2 {
		t.Fatalf("len=%d, got %v", len(got), got)
	}
	if got["default/web-svc"]["app"] != "webapp" {
		t.Errorf("selector 解析错误: %v", got["default/web-svc"])
	}
	if len(got["default/no-sel"]) != 0 {
		t.Errorf("空 selector 应为空表: %v", got["default/no-sel"])
	}
	// Go map 形态（旧版 kubectl）。
	got = parseK8sSelectorList("default/web-svc map[app:webapp]\ndefault/no-sel map[]\n")
	if len(got) != 2 || got["default/web-svc"]["app"] != "webapp" {
		t.Errorf("Go map 形态解析错误: %v", got)
	}
	// 多键 JSON 形态。
	got = parseK8sSelectorList("a/x {\"app\":\"webapp\",\"tier\":\"front\"}\n")
	if len(got) != 1 || got["a/x"]["app"] != "webapp" || got["a/x"]["tier"] != "front" {
		t.Errorf("多键解析错误: %v", got)
	}
	if parseK8sSelectorList("") != nil {
		t.Error("空数据段应返回 nil（降级）")
	}
	if parseK8sSelectorList("default/bad no-map-format\n") != nil {
		t.Error("异常格式应返回 nil（降级）")
	}
}

// TestCountMatchingPods selector 等值匹配语义：全部键值命中才计数。
func TestCountMatchingPods(t *testing.T) {
	labels := map[string]map[string]string{
		"a": {"app": "webapp", "tier": "front"},
		"b": {"app": "webapp"},
		"c": {"app": "other"},
	}
	if n := countMatchingPods(map[string]string{"app": "webapp"}, labels); n != 2 {
		t.Errorf("app=webapp 应匹配 2 个，got %d", n)
	}
	if n := countMatchingPods(map[string]string{"app": "webapp", "tier": "front"}, labels); n != 1 {
		t.Errorf("双键应匹配 1 个，got %d", n)
	}
	if n := countMatchingPods(map[string]string{"app": "none"}, labels); n != 0 {
		t.Errorf("无匹配应 0，got %d", n)
	}
}

// TestJudgeK8sPVCs 存储面判定：PVC 未绑定产线索，SC 缺失归类；
// Bound/无数据段跳过。
func TestJudgeK8sPVCs(t *testing.T) {
	hm := &HostMetric{
		Host: "web-01",
		Raw: map[string]string{
			"k8s_pvcs": "default   db-data   Bound   pvc-1   100Mi   RWO   local-path   <unset>   30m\n" +
				"default   db2-data   Pending   <none>   <none>   <none>   no-such-sc   <unset>   2m\n" +
				"default   slow-data  Pending   <none>   <none>   <none>   local-path   <unset>   2m\n",
			"k8s_scs": "local-path   rancher.io/local-path   Delete   WaitForFirstConsumer   false   40m\n",
		},
	}
	out := JudgeK8sFacts(hm)
	if len(out) != 2 {
		t.Fatalf("应产 2 条（两个 Pending PVC），got %d: %+v", len(out), out)
	}
	for _, a := range out {
		if a.Signal() != "k8s_pvc_abnormal" {
			t.Errorf("信号错误: %s", a.Signal())
		}
		switch a.Key {
		case "default/db2-data":
			if !strings.Contains(a.Desc, "no-such-sc") || !strings.Contains(a.Desc, "不存在") {
				t.Errorf("SC 缺失应归类配置错误: %s", a.Desc)
			}
		case "default/slow-data":
			if !strings.Contains(a.Desc, "供给失败") {
				t.Errorf("SC 存在仍 Pending 应归类供给类: %s", a.Desc)
			}
		default:
			t.Errorf("意外对象键 %s", a.Key)
		}
	}
	// SC 清单缺失：降级通用线索（不吞判定）。
	hm2 := &HostMetric{Host: "web-01", Raw: map[string]string{
		"k8s_pvcs": "default   db2-data   Pending   <none>   <none>   <none>   no-such-sc   <unset>   2m\n",
	}}
	out = JudgeK8sFacts(hm2)
	if len(out) != 1 || !strings.Contains(out[0].Desc, "未绑定") {
		t.Fatalf("SC 缺失应降级通用线索，got %+v", out)
	}
	// 无数据段跳过。
	if out := JudgeK8sFacts(&HostMetric{Host: "h"}); len(out) != 0 {
		t.Fatalf("无数据应跳过，got %+v", out)
	}
}

// TestJudgeK8sNodeSched 调度面判定：节点不可调度/NoSchedule 污点产
// 线索；干净节点/无数据段跳过。
func TestJudgeK8sNodeSched(t *testing.T) {
	hm := &HostMetric{
		Host: "web-01",
		Raw: map[string]string{
			"k8s_node_unsched": "node-1 \nnode-2 true\n",
			"k8s_node_taints":  "node-1 \nnode-2 [{\"effect\":\"NoSchedule\",\"key\":\"dedicated\",\"value\":\"test\"}]\n",
		},
	}
	out := JudgeK8sFacts(hm)
	var unsched, tainted bool
	for _, a := range out {
		if a.Metric == "k8s_node_unsched" && a.Key == "node-2" {
			unsched = true
		}
		if a.Metric == "k8s_node_taints" && strings.HasSuffix(a.Key, "dedicated=test") {
			tainted = true
			if !strings.Contains(a.Desc, "NoSchedule") {
				t.Errorf("污点线索应含 effect: %s", a.Desc)
			}
		}
	}
	if !unsched {
		t.Errorf("不可调度节点应产线索: %+v", out)
	}
	if !tainted {
		t.Errorf("NoSchedule 污点应产线索: %+v", out)
	}
	// 干净节点：不产线。
	clean := &HostMetric{Host: "web-01", Raw: map[string]string{
		"k8s_node_unsched": "node-1 \n",
		"k8s_node_taints":  "node-1 <nil>\n",
	}}
	if out := JudgeK8sFacts(clean); len(out) != 0 {
		t.Fatalf("干净节点不应产线，got %+v", out)
	}
	// 无数据段跳过。
	if out := JudgeK8sFacts(&HostMetric{Host: "h"}); len(out) != 0 {
		t.Fatalf("无数据应跳过，got %+v", out)
	}
}

// TestParseK8sTaints 污点 JSON 形态解析：空/<nil>/正常/异常。
func TestParseK8sTaints(t *testing.T) {
	if ts, ok := parseK8sTaints(""); !ok || len(ts) != 0 {
		t.Errorf("空应解析为空表: %v %v", ts, ok)
	}
	if ts, ok := parseK8sTaints("<nil>"); !ok || len(ts) != 0 {
		t.Errorf("<nil> 应解析为空表: %v %v", ts, ok)
	}
	ts, ok := parseK8sTaints(`[{"effect":"NoSchedule","key":"dedicated","value":"test"}]`)
	if !ok || len(ts) != 1 || ts[0].Effect != "NoSchedule" || ts[0].Key != "dedicated" || ts[0].Value != "test" {
		t.Errorf("JSON 污点解析错误: %v %v", ts, ok)
	}
	if _, ok := parseK8sTaints("garbage"); ok {
		t.Error("异常格式应 ok=false")
	}
}
