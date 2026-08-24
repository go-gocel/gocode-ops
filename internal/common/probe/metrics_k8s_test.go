package probe

import (
	"strings"
	"testing"
)

// k8s 探针解析与归属判定测试（kubectl 输出解析为确定性纯函数）。

func TestParseK8sPods(t *testing.T) {
	out := `default nginx-7c9b5d6f8-abcde 1/1 Running 0 3h
kube-system coredns-565d847f94-9v2k4 1/1 Running 0 3h
default crash-app-6f9f7c9f9-zz123 0/1 CrashLoopBackOff 5 12m
default err-app-6f9f7c9f9-qq999 0/1 ImagePullBackOff 2 5m
kube-system calico-node-xxxxx 1/1 Running 0 3h
default old-job-abc 0/1 Completed 0 2d
default pending-app-6f9f7c9f9-pp111 0/1 Pending 0 1m
default readyfail-6f9f7c9f9-zz999 0/1 Running 0 2m
`
	got, err := parseK8sPods(out)
	if err != nil {
		t.Fatalf("parseK8sPods: %v", err)
	}
	want := map[string]float64{
		"default/crash-app-6f9f7c9f9-zz123":   1,
		"default/err-app-6f9f7c9f9-qq999":     1,
		"default/pending-app-6f9f7c9f9-pp111": 1,
		// Running 0/1：readiness 探针失败（只按 STATUS 判定会漏掉）。
		"default/readyfail-6f9f7c9f9-zz999": 1,
	}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (%v)", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}

func TestParseK8sPodsHealthy(t *testing.T) {
	out := "default nginx-7c9b5d6f8-abcde 1/1 Running 0 3h\nkube-system coredns-565d847f94-9v2k4 1/1 Running 0 3h\n"
	got, err := parseK8sPods(out)
	if err != nil {
		t.Fatalf("parseK8sPods: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("健康环境应无数据，got %v", got)
	}
	// 无 kubectl：空输出同样无数据（不产线、不报错）。
	got, err = parseK8sPods("")
	if err != nil || len(got) != 0 {
		t.Errorf("空输出应无数据，got %v err %v", got, err)
	}
}

func TestParseK8sDeploys(t *testing.T) {
	out := `default nginx 2/2 2 2 3h
default api 1/3 1 3 12m
kube-system coredns 2/2 2 2 3h
default noavail 2/2 2 0 5m
default roll 1/3 1 1 5m
`
	got, err := parseK8sDeploys(out)
	if err != nil {
		t.Fatalf("parseK8sDeploys: %v", err)
	}
	want := map[string]float64{
		"default/api":  2, // ready 1 < desired 3
		"default/roll": 2, // ready 1 < desired 3（available=1 时旧实现恒假漏报）
	}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (%v)", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}

func TestParseK8sNodes(t *testing.T) {
	out := `master-1   Ready    control-plane   3h   v1.28.2
worker-1   Ready    <none>           3h   v1.28.2
worker-2   NotReady <none>           1h   v1.28.2
`
	got, err := parseK8sNodes(out)
	if err != nil {
		t.Fatalf("parseK8sNodes: %v", err)
	}
	if len(got) != 1 || got["worker-2"] != 1 {
		t.Errorf("NotReady 节点应只有 worker-2，got %v", got)
	}
}

// TestParseK8sImgPull 镜像拉取失败类 Pod 独立归类：ImagePullBackOff/
// ErrImagePull/ImageInspectError 等状态 → k8s_img_pull 信号；非镜像
// 面异常（CrashLoopBackOff/Pending）不混入该信号（由 k8s_pod_abnormal
// 覆盖）；健康/空输出不产线。
func TestParseK8sImgPull(t *testing.T) {
	out := `default nginx-7c9b5d6f8-abcde 1/1 Running 0 3h
default err-app-6f9f7c9f9-qq999 0/1 ImagePullBackOff 2 5m
default badimg-6f9f7c9f9-aa111 0/1 ErrImagePull 1 2m
default badname-6f9f7c9f9-bb222 0/1 InvalidImageName 0 1m
default crash-app-6f9f7c9f9-zz123 0/1 CrashLoopBackOff 5 12m
default pending-app-6f9f7c9f9-pp111 0/1 Pending 0 1m
default old-job-abc 0/1 Completed 0 2d
`
	got, err := parseK8sImgPull(out)
	if err != nil {
		t.Fatalf("parseK8sImgPull: %v", err)
	}
	want := map[string]float64{
		"default/err-app-6f9f7c9f9-qq999": 1,
		"default/badimg-6f9f7c9f9-aa111":  1,
		"default/badname-6f9f7c9f9-bb222": 1,
	}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (%v)", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	// 健康/空输出：无数据不产线。
	healthy := "default a 1/1 Running 0 1h\nkube-system b 1/1 Running 0 1h\n"
	if got, err = parseK8sImgPull(healthy); err != nil || len(got) != 0 {
		t.Errorf("健康输出应无数据，got %v err %v", got, err)
	}
	if got, err = parseK8sImgPull(""); err != nil || len(got) != 0 {
		t.Errorf("空输出应无数据，got %v err %v", got, err)
	}
}

// TestJudgeK8sImgPull 判定层：镜像拉取失败 Pod 产 k8s_img_pull 线索，
// 空数据段跳过（补健康指标规避零可见性检查）。
func TestJudgeK8sImgPull(t *testing.T) {
	hm := &HostMetric{
		Host: "k8s-master",
		Metrics: map[string]map[string]float64{
			"k8s_imgpull": {"default/err-app-6f9f7c9f9-qq999": 1},
		},
	}
	out := Judge(&Snapshot{Hosts: []HostMetric{*hm}}, DefaultThresholds())
	found := false
	for _, a := range out {
		if a.Metric == "k8s_imgpull" && a.Signal() == "k8s_img_pull" {
			found = true
		}
	}
	if !found {
		t.Fatalf("应产 k8s_img_pull 线索，got %+v", out)
	}
	// 无 k8s 数据段（非集群主机）：不产线。
	if out := Judge(&Snapshot{Hosts: []HostMetric{{Host: "plain", Metrics: map[string]map[string]float64{"mem": {"avail_pct": 50}}}}}, DefaultThresholds()); len(out) != 0 {
		t.Errorf("无数据应不产线，got %v", out)
	}
}

func TestJudgeK8sFacts(t *testing.T) {
	hm := &HostMetric{
		Host: "k8s-master",
		Raw: map[string]string{
			"k8s_secrets": `default my-app-secret   Opaque   3h
default tls-cert        kubernetes.io/tls   3h
kube-system kubeconfig-secret Opaque 3h
default public-config   Opaque   3h
`,
			"k8s_deploy_env": `default/api: DB_PASSWORD MYSQL_ROOT_PASSWORD HOSTNAME PORT
default/web: NGINX_PORT 
`,
		},
	}
	out := JudgeK8sFacts(hm)
	if len(out) != 4 {
		t.Fatalf("线索数 = %d, want 4: %+v", len(out), out)
	}
	for _, a := range out {
		if a.Metric != "k8s_secrets" && a.Metric != "k8s_deploy_env" {
			t.Errorf("未知 metric %s", a.Metric)
		}
	}
	// 无数据段（非集群主机）：不产线。
	empty := JudgeK8sFacts(&HostMetric{Host: "plain"})
	if len(empty) != 0 {
		t.Errorf("无数据应不产线，got %v", empty)
	}
	// partial 覆盖：不完整枚举不得驱动归属规则。
	partial := JudgeK8sFacts(&HostMetric{Host: "h", Raw: map[string]string{"k8s_secrets": "default a-secret Opaque 3h"}, FactCoverage: map[string]string{"k8s_secrets": "partial"}})
	if len(partial) != 0 {
		t.Errorf("partial 覆盖不应产线，got %v", partial)
	}
}

// TestK8sProbeGuard 探针命令形态：无 kubectl 短路、有 kubectl 正常执行、
// 超时护栏与缺失降级（|| true 不产 partial）。
func TestK8sProbeGuard(t *testing.T) {
	frag := k8sProbe("kubectl get pods -A --no-headers 2>/dev/null", 20)
	for _, want := range []string{"command -v kubectl", "|| true", "timeout -s KILL 20s"} {
		if !strings.Contains(frag, want) {
			t.Errorf("探针应含 %q: %s", want, frag)
		}
	}
}
