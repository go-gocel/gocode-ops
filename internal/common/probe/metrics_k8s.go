package probe

// metrics_k8s.go — Kubernetes 探针族（目标主机 kubectl 可用时自动生效）：
//   - 数值指标：异常 Pod / 未就绪 Deployment / NotReady 节点（对象级键，
//     参与去重与处置后复检）；
//   - 安全事实：对象级状态清单 / 资源配额 / 敏感配置对象（名称级——
//     值绝不进引擎与模型上下文，由 DeepDive 定向下钻核查是否明文）。
//
// 命令自带 `command -v kubectl` 守卫：目标主机无 kubectl 时短路为空
// 输出、零 API 开销，不依赖本机环境探测（kubectl 在远端 master 上时
// 同样自动生效）；有 kubectl 时受 timeout 护栏保护（API server 不可达
// 时 kubectl 会挂住，不得拖垮整轮采集）。kubeconfig 由 kubectl 二进制
// 自行加载，探针不触碰任何凭证路径。

import (
	"strconv"
	"strings"
)

// k8sProbe 生成带 kubectl 可用性守卫 + 超时护栏 + 缺失降级的探针命令：
//   - 无 kubectl → 空输出、退出码 0（"无数据"，不产 partial 噪音）；
//   - kubectl 挂住 → timeout 击杀 → 完成哨兵（partial，覆盖如实标注）；
//   - 正常 → 原样输出。
//
// cmd 内不得包含单引号（外层 sh -c '...' 包裹）；需要引号的探针
// （jsonpath）自行构造。
func k8sProbe(cmd string, secs int) string {
	return BoundedProbe("sh -c 'command -v kubectl >/dev/null 2>&1 && "+cmd+" || true'", secs)
}

// k8sMetrics 返回 k8s 数值指标（每轮采集；非集群主机自动无数据）。
func k8sMetrics() []Metric {
	return []Metric{
		{ID: "k8s_pod_abnormal", Name: "异常 Pod 数", Warn: 1, Crit: 3,
			Fragment: func(*Env) string {
				return k8sProbe("kubectl get pods -A --no-headers 2>/dev/null", 20)
			},
			Parse: parseK8sPods,
		},
		// 镜像拉取失败类 Pod 独立归类（演练 R1 快检进化）：k8s_pod_abnormal
		// 只报"异常 Pod"，不区分失败形态；本指标把 ImagePullBackOff/
		// ErrImagePull 等镜像面失败直接归类为独立信号（k8s_img_pull），
		// 快检层面即给出根因方向（镜像不存在/仓库不可达/凭据缺失/
		// 格式错误），DeepDive 只需确认具体镜像与修复动作。对象级键
		// ns/pod 参与处置后复检（镜像修正后 Pod 脱离该状态即收敛）。
		{ID: "k8s_imgpull", Name: "镜像拉取失败 Pod", Warn: 1, Crit: 1,
			Fragment: func(*Env) string {
				return k8sProbe("kubectl get pods -A --no-headers 2>/dev/null", 20)
			},
			Parse: parseK8sImgPull,
		},
		{ID: "k8s_deploy_unready", Name: "未就绪 Deployment", Warn: 1, Crit: 3,
			Fragment: func(*Env) string {
				return k8sProbe("kubectl get deploy -A --no-headers 2>/dev/null", 20)
			},
			Parse: parseK8sDeploys,
		},
		{ID: "k8s_node_notready", Name: "NotReady 节点", Warn: 1, Crit: 3,
			Fragment: func(*Env) string {
				return k8sProbe("kubectl get nodes --no-headers 2>/dev/null", 20)
			},
			Parse: parseK8sNodes,
		},
	}
}

// parseK8sPods 解析 kubectl get pods -A --no-headers：STATUS 非健康态
// （Running/Completed/Succeeded/Terminating）的 pod → "ns/name" → 1；
// Running 但 READY 就绪数不足（readiness 探针失败/服务实际不可用——
// 只按 STATUS 判定会漏掉最高频的 k8s 故障形态）→ "ns/name" → 缺失就绪数。
// 全健康返回空 map（无数据，不产线）。
func parseK8sPods(out string) (map[string]float64, error) {
	res := map[string]float64{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// READY 列（就绪/期望）：Running 但就绪不足 = 服务实际不可用。
		if fields[3] == "Running" {
			ready, desired := splitReady(fields[2])
			if ready >= 0 && desired > 0 && ready < desired {
				res[fields[0]+"/"+fields[1]] = float64(desired - ready)
				continue
			}
		}
		switch fields[3] {
		case "Running", "Completed", "Succeeded", "Terminating":
			continue
		}
		res[fields[0]+"/"+fields[1]] = 1
	}
	if len(res) == 0 {
		return nil, nil
	}
	return res, nil
}

// parseK8sDeploys 解析 kubectl get deploy -A --no-headers
// （NAMESPACE NAME READY UP-TO-DATE AVAILABLE AGE）：READY 就绪副本
// 数 < 期望副本数（READY 列分母）→ "ns/name" → 缺失副本数。
// （旧实现比较 ready < available——k8s 语义 AVAILABLE⊆READY，available
// 恒 ≤ ready，该比较恒假，未就绪 Deployment 永不产线。）
func parseK8sDeploys(out string) (map[string]float64, error) {
	res := map[string]float64{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		ready, desired := splitReady(fields[2])
		// AVAILABLE 列（fields[4]）已不需参与判定（AVAILABLE⊆READY 恒
		// 满足）；保留解析校验以容忍截断/异常行。
		if _, err := strconv.Atoi(fields[4]); err != nil {
			continue
		}
		if ready < 0 || desired < 0 {
			continue
		}
		if ready < desired {
			res[fields[0]+"/"+fields[1]] = float64(desired - ready)
		}
	}
	if len(res) == 0 {
		return nil, nil
	}
	return res, nil
}

// parseK8sNodes 解析 kubectl get nodes --no-headers：STATUS 非 Ready →
// 节点名 → 1。
func parseK8sNodes(out string) (map[string]float64, error) {
	res := map[string]float64{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[1] != "Ready" {
			res[fields[0]] = 1
		}
	}
	if len(res) == 0 {
		return nil, nil
	}
	return res, nil
}

// splitReady 解析 "2/2" 形式的就绪计数，返回 (ready, desired)；
// 非法输入返回 (-1, -1)。
func splitReady(s string) (int, int) {
	a, b, ok := strings.Cut(s, "/")
	if !ok {
		return -1, -1
	}
	x, err1 := strconv.Atoi(a)
	y, err2 := strconv.Atoi(b)
	if err1 != nil || err2 != nil {
		return -1, -1
	}
	return x, y
}

// k8sImgPullStatuses 镜像拉取失败类 STATUS 集合：kubectl 对拉取失败的
// 确定性状态标记（镜像不存在/仓库不可达/凭据缺失/格式错误等全部汇聚
// 为这几类状态，Pod 停留在该状态直到镜像问题解决）。
var k8sImgPullStatuses = map[string]bool{
	"ImagePullBackOff":  true,
	"ErrImagePull":      true,
	"ImageInspectError": true,
	"ErrImageNeverPull": true,
	"InvalidImageName":  true,
}

// parseK8sImgPull 解析 kubectl get pods -A --no-headers：STATUS 属
// 镜像拉取失败类 → "ns/pod" → 1。与 parseK8sPods 共用同一探针输出，
// 但按失败形态归类（信号 k8s_img_pull），使快检直接给出根因方向。
// 全健康返回空 map（无数据，不产线）。
func parseK8sImgPull(out string) (map[string]float64, error) {
	res := map[string]float64{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if k8sImgPullStatuses[fields[3]] {
			res[fields[0]+"/"+fields[1]] = 1
		}
	}
	if len(res) == 0 {
		return nil, nil
	}
	return res, nil
}

// k8sSecurityFacts 返回 k8s 安全事实探针（例行采集，原始数据进模型
// 上下文 + 归属规则产线索）。敏感配置只到名称/字段名级：Secret/
// ConfigMap 的数据值与 env 值不明文进入引擎（凭证零泄露面扩展——
// 下钻由 DeepDive 定向执行）。
func k8sSecurityFacts() []Metric {
	return []Metric{
		{ID: "k8s_pods", Name: "Pod 状态清单",
			Fragment: func(*Env) string {
				return k8sProbe("kubectl get pods -A --no-headers 2>/dev/null", 20)
			}},
		{ID: "k8s_deploys", Name: "Deployment 清单",
			Fragment: func(*Env) string {
				return k8sProbe("kubectl get deploy -A --no-headers 2>/dev/null", 20)
			}},
		{ID: "k8s_nodes", Name: "节点清单",
			Fragment: func(*Env) string {
				return k8sProbe("kubectl get nodes --no-headers 2>/dev/null", 20)
			}},
		{ID: "k8s_quota", Name: "资源配额（resourcequota）",
			Fragment: func(*Env) string {
				return k8sProbe("kubectl get resourcequota -A --no-headers 2>/dev/null", 20)
			}},
		{ID: "k8s_secrets", Name: "Secret/ConfigMap 名称清单（敏感配置）",
			Fragment: func(*Env) string {
				return k8sProbe("kubectl get secrets,configmaps -A --no-headers 2>/dev/null", 20)
			}},
		// Deployment 环境变量名清单：jsonpath 含引号，无法套用 k8sProbe
		// 的单引号包裹——直接构造双引号 sh -c（内部转义 \"）；env 的
		// 值不输出，只列字段名（敏感名由归属规则产线，明文与否由
		// DeepDive 下钻判断）。
		{ID: "k8s_deploy_env", Name: "Deployment 环境变量名清单（明文 env 排查）",
			Fragment: func(*Env) string {
				return BoundedProbe(`sh -c "command -v kubectl >/dev/null 2>&1 && kubectl get deploy -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}: {range .spec.template.spec.containers[*].env[*]}{.name} {end}{\"\\n\"}{end}' 2>/dev/null || true"`, 20)
			}},
		{ID: "k8s_events", Name: "异常事件（Warning）",
			Fragment: func(*Env) string {
				return k8sProbe("kubectl get events -A --field-selector type=Warning --no-headers 2>/dev/null | head -n 30", 20)
			}},
		// 服务面（Service/Endpoints）：pod 全 Running 但服务无后端端点
		// 是比赛 k8s 高频故障（selector 错/label 被改/endpoints 摘除）
		// ——工作负载探针看不到，服务面判定靠本对探针配对：
		// k8s_svcs（svc 清单）+ k8s_endpoints（端点清单），判定层按
		// 同名配对，ClusterIP/LoadBalancer 服务无端点 → 线索。
		{ID: "k8s_svcs", Name: "Service 清单",
			Fragment: func(*Env) string {
				return k8sProbe("kubectl get svc -A --no-headers 2>/dev/null", 20)
			}},
		{ID: "k8s_endpoints", Name: "Endpoints 清单",
			Fragment: func(*Env) string {
				return k8sProbe("kubectl get endpoints -A --no-headers 2>/dev/null", 20)
			}},
		// 服务面故障形态归类数据（演练 R2 快检进化）：Service selector
		// 与 Pod 标签逐对象采集——服务无后端时判定层据此区分"selector
		// 漂移（存在标签匹配的 Pod 但端点为空）"与"无匹配后端（selector
		// 指向的标签没有对应 Pod）"两类根因方向。jsonpath 含引号，套用
		// BoundedProbe 双引号包裹（与 k8s_deploy_env 同形态）。
		{ID: "k8s_svc_selectors", Name: "Service selector 清单",
			Fragment: func(*Env) string {
				return BoundedProbe(`sh -c "command -v kubectl >/dev/null 2>&1 && kubectl get svc -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name} {.spec.selector}{\"\\n\"}{end}' 2>/dev/null || true"`, 20)
			}},
		{ID: "k8s_pod_labels", Name: "Pod 标签清单",
			Fragment: func(*Env) string {
				return BoundedProbe(`sh -c "command -v kubectl >/dev/null 2>&1 && kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name} {.metadata.labels}{\"\\n\"}{end}' 2>/dev/null || true"`, 20)
			}},
		// 存储面（演练 R3 快检进化）：PVC 状态清单 + StorageClass 清单
		// ——判定层按"未绑定 PVC 引用的 SC 是否存在于集群"归类根因
		// 方向（SC 缺失/供给失败/配额等）。对象级键参与处置后复检。
		{ID: "k8s_pvcs", Name: "PVC 状态清单",
			Fragment: func(*Env) string {
				return k8sProbe("kubectl get pvc -A --no-headers 2>/dev/null", 20)
			}},
		{ID: "k8s_scs", Name: "StorageClass 清单",
			Fragment: func(*Env) string {
				return k8sProbe("kubectl get storageclass --no-headers 2>/dev/null", 20)
			}},
	}
}
