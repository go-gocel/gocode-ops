package probe

// judge_k8s.go — k8s 安全事实归属判定：敏感配置对象（Secret/ConfigMap
// 名称级）与 Deployment 环境变量名（字段名级）。值不明文进入引擎——
// 判定只产"对象存在且名称可疑"的线索，是否真明文由 DeepDive 定向下钻
// 核查。数据驱动：目标无 kubectl/非集群主机无数据段即跳过（不产线）。

import (
	"fmt"
	"regexp"
	"strings"
)

// k8sSensitiveRe 敏感对象名/字段名匹配：密码/令牌/密钥类关键词。
// 名称级判定（不读取值），覆盖 Secret/ConfigMap 名称与 env 字段名。
var k8sSensitiveRe = regexp.MustCompile(`(?i)(pass|pwd|secret|token|api_?key|access_?key|credential|private_?key|auth_?key)`)

// JudgeK8sFacts performs data-driven attribution judgment and skips
// when the corresponding data segment is absent.
// JudgeK8sFacts 数据驱动归属判定：无对应数据段即跳过。
func JudgeK8sFacts(hm *HostMetric) []Anomaly {
	var out []Anomaly
	// Secret/ConfigMap 名称级敏感对象（kubectl get secrets,configmaps
	// -A --no-headers：NAMESPACE NAME TYPE ...）。名称含敏感词 → 线索
	//（下钻核查是否明文存储敏感值；对象名本身不是凭证值，进上下文
	// 无害）。
	if raw := hm.rawCov("k8s_secrets"); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			if !k8sSensitiveRe.MatchString(fields[1]) {
				continue
			}
			name := fields[0] + "/" + fields[1]
			out = append(out, Anomaly{Host: hm.Host, Metric: "k8s_secrets", Key: name, Severity: SevWarn,
				Desc: fmt.Sprintf("k8s 敏感配置对象 %s（名称含敏感词）——需核查是否明文存储敏感值", name)})
		}
	}
	// Deployment 环境变量名级明文排查（jsonpath 输出格式：
	// "ns/name: ENV1 ENV2 ..."）。字段名含敏感词 → 线索（值不明文
	// 进入引擎；模型下钻时才读取值判断是否应改 Secret 引用）。
	if raw := hm.rawCov("k8s_deploy_env"); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			obj, envs, ok := strings.Cut(line, ": ")
			if !ok || obj == "" {
				continue
			}
			for _, env := range strings.Fields(envs) {
				if !k8sSensitiveRe.MatchString(env) {
					continue
				}
				out = append(out, Anomaly{Host: hm.Host, Metric: "k8s_deploy_env", Key: obj + ":" + env, Severity: SevWarn,
					Desc: fmt.Sprintf("Deployment %s 环境变量 %s 名称含敏感词——明文 env 排查对象（是否应改 Secret 引用）", obj, env)})
			}
		}
	}
	out = append(out, judgeK8sSvcBackends(hm)...)
	return out
}

// judgeK8sSvcBackends 服务面判定：ClusterIP/LoadBalancer 类型的
// Service 无后端端点 → 线索（服务 502/无可用后端，业务面故障——
// pod 可能全部 Running，工作负载探针看不到）。配对 k8s_svcs 与
// k8s_endpoints 同名（ns/name）；任一数据缺失则跳过（数据驱动）。
// 排除：ExternalName（无集群端点语义）、Headless（无 ClusterIP，
// 端点按需解析）、kube-system/kubernetes 默认服务。
func judgeK8sSvcBackends(hm *HostMetric) []Anomaly {
	svcRaw := hm.rawCov("k8s_svcs")
	epRaw := hm.rawCov("k8s_endpoints")
	if svcRaw == "" || epRaw == "" {
		return nil
	}
	// endpoints：NAMESPACE NAME ENDPOINTS AGE → ns/name → 端点串。
	eps := map[string]string{}
	for _, line := range strings.Split(epRaw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		key := fields[0] + "/" + fields[1]
		eps[key] = fields[2]
	}
	var out []Anomaly
	for _, line := range strings.Split(svcRaw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		ns, name, typ, clusterIP := fields[0], fields[1], fields[2], fields[3]
		// 跳过默认服务/无端点语义类型。
		if ns == "kube-system" && name == "kubernetes" {
			continue
		}
		if typ == "ExternalName" || typ == "Headless" || clusterIP == "None" || clusterIP == "<none>" {
			continue
		}
		ep, ok := eps[ns+"/"+name]
		if !ok {
			continue // 无同名 endpoints 记录：数据面缺失，跳过（不臆断）
		}
		if ep == "<none>" || ep == "" || strings.HasPrefix(ep, "None") {
			out = append(out, Anomaly{Host: hm.Host, Metric: "k8s_svcs", Key: ns + "/" + name, Severity: SevWarn,
				Desc: fmt.Sprintf("k8s Service %s/%s 无后端端点（endpoints=<none>）——服务不可用（selector 不匹配/label 漂移/后端被摘除）", ns, name)})
		}
	}
	return out
}
