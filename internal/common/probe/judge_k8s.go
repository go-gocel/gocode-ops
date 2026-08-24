package probe

// judge_k8s.go — k8s 安全事实归属判定：敏感配置对象（Secret/ConfigMap
// 名称级）与 Deployment 环境变量名（字段名级）。值不明文进入引擎——
// 判定只产"对象存在且名称可疑"的线索，是否真明文由 DeepDive 定向下钻
// 核查。数据驱动：目标无 kubectl/非集群主机无数据段即跳过（不产线）。

import (
	"encoding/json"
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
	out = append(out, judgeK8sPVCs(hm)...)
	return out
}

// judgeK8sSvcBackends 服务面判定：ClusterIP/LoadBalancer 类型的
// Service 无后端端点 → 线索（服务 502/无可用后端，业务面故障——
// pod 可能全部 Running，工作负载探针看不到）。配对 k8s_svcs 与
// k8s_endpoints 同名（ns/name）；任一数据缺失则跳过（数据驱动）。
// 排除：ExternalName（无集群端点语义）、Headless（无 ClusterIP，
// 端点按需解析）、kube-system/kubernetes 默认服务。
//
// 故障形态归类（演练 R2 快检进化，机制层）：配齐 k8s_svc_selectors
// 与 k8s_pod_labels 数据段时，按 selector 与 Pod 标签匹配情况区分
// 两类根因方向——"selector 漂移（有匹配 Pod 但端点为空）"与
// "无匹配后端（selector 指向的标签没有对应 Pod）"；数据段缺失时
// 回退通用线索（不臆断，DeepDive 下钻归类）。
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
	// 形态归类数据（可选段）：svc selector 与 pod 标签（ns/name →
	// 标签表），缺失时降级通用线索。
	selectors := parseK8sSelectorList(hm.rawCov("k8s_svc_selectors"))
	podLabels := parseK8sSelectorList(hm.rawCov("k8s_pod_labels"))
	classify := selectors != nil && podLabels != nil
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
			desc := fmt.Sprintf("k8s Service %s/%s 无后端端点（endpoints=<none>）——服务不可用（selector 不匹配/label 漂移/后端被摘除）", ns, name)
			if classify {
				if sel, hasSel := selectors[ns+"/"+name]; hasSel && len(sel) > 0 {
					if n := countMatchingPods(sel, podLabels); n > 0 {
						desc = fmt.Sprintf("k8s Service %s/%s 无后端端点但存在 %d 个标签匹配的 Pod——selector 漂移/端点控制器异常（服务面故障，非后端缺失）", ns, name, n)
					} else {
						desc = fmt.Sprintf("k8s Service %s/%s 无后端端点且 selector 无匹配 Pod（%v）——后端缺失/label 不一致（服务面故障）", ns, name, sel)
					}
				}
			}
			out = append(out, Anomaly{Host: hm.Host, Metric: "k8s_svcs", Key: ns + "/" + name, Severity: SevWarn,
				Desc: desc})
		}
	}
	return out
}

// parseK8sSelectorList 解析 kubectl jsonpath 输出的标签/选择器清单行：
// "ns/name <标签形态>"（现代 kubectl 为 JSON 对象 {"k":"v"}，旧版为
// Go map 形态 map[k:v]；空选择器输出空串）。返回 ns/name → 键值表；
// 数据段缺失/任一行异常格式返回 nil（调用方降级，不臆断）。
func parseK8sSelectorList(raw string) map[string]map[string]string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	out := map[string]map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		obj, val, ok := strings.Cut(line, " ")
		if !ok {
			// 无选择器/标签的行（空选择器 jsonpath 输出 "obj"）：空表。
			obj, val = line, ""
		}
		if obj == "" {
			return nil
		}
		lbls, ok := parseK8sLabelMap(strings.TrimSpace(val))
		if !ok {
			return nil
		}
		out[obj] = lbls
	}
	return out
}

// parseK8sLabelMap 解析单个标签/选择器值：JSON 对象形态（{"k":"v"}）、
// Go map 形态（map[k:v]）、空（空串/map[] → 空表）。
func parseK8sLabelMap(s string) (map[string]string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "map[]" {
		return map[string]string{}, true
	}
	if strings.HasPrefix(s, "{") {
		var m map[string]string
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			return nil, false
		}
		return m, true
	}
	if strings.HasPrefix(s, "map[") {
		m := map[string]string{}
		for _, kv := range strings.Fields(strings.TrimSuffix(strings.TrimPrefix(s, "map["), "]")) {
			k, v, ok := strings.Cut(kv, ":")
			if !ok {
				return nil, false
			}
			m[k] = v
		}
		return m, true
	}
	return nil, false
}

// countMatchingPods 统计标签满足 selector 全部键值对的 Pod 数
// （K8s selector 语义：等值匹配，全部键值须命中）。
func countMatchingPods(sel map[string]string, podLabels map[string]map[string]string) int {
	n := 0
	for _, labels := range podLabels {
		matched := true
		for k, v := range sel {
			if labels[k] != v {
				matched = false
				break
			}
		}
		if matched {
			n++
		}
	}
	return n
}

// judgeK8sPVCs 存储面判定（演练 R3 快检进化）：PVC 状态非 Bound →
// 线索（存储域故障：Pod 挂载等待/ContainerCreating 的确定性根因
// 方向）。配齐 k8s_scs 数据段时按"引用的 StorageClass 是否存在于
// 集群"归类：SC 缺失 → 配置错误类；SC 存在仍非 Bound → 供给/配额
// 类。数据驱动：k8s_pvcs 缺失跳过；SC 清单缺失降级通用线索。
func judgeK8sPVCs(hm *HostMetric) []Anomaly {
	raw := hm.rawCov("k8s_pvcs")
	if raw == "" {
		return nil
	}
	scNames := map[string]bool{}
	if scRaw := hm.rawCov("k8s_scs"); scRaw != "" {
		for _, line := range strings.Split(scRaw, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 1 && fields[0] != "" {
				scNames[fields[0]] = true
			}
		}
	}
	var out []Anomaly
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		ns, name, status := fields[0], fields[1], fields[2]
		if status == "Bound" || status == "" {
			continue
		}
		desc := fmt.Sprintf("k8s PVC %s/%s 未绑定（STATUS=%s）——存储域故障（Pod 将卡在 ContainerCreating）", ns, name, status)
		// STORAGECLASS 列（fields[6]）：显式引用且集群无该 SC → 归类。
		if len(fields) >= 7 && fields[6] != "" && len(scNames) > 0 {
			if !scNames[fields[6]] {
				desc = fmt.Sprintf("k8s PVC %s/%s 未绑定（STATUS=%s）且引用的 StorageClass %q 不存在——存储配置错误（SC 缺失/名称拼写错误）", ns, name, status, fields[6])
			} else {
				desc = fmt.Sprintf("k8s PVC %s/%s 未绑定（STATUS=%s，StorageClass %q 存在）——供给失败/配额不足/底层存储不可用", ns, name, status, fields[6])
			}
		}
		out = append(out, Anomaly{Host: hm.Host, Metric: "k8s_pvcs", Key: ns + "/" + name, Severity: SevWarn,
			Desc: desc})
	}
	return out
}
