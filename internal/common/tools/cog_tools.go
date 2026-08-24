package tools

// cog_tools.go — 认知工具族：collect_probe/recall/update_desired/LoadDossier。
//
// 交互式运维助手的认知工具（人在环形态的接入面）：
//   - collect_probe：定向确定性采集（排查缺证据时补证据，比拼 terminal
//     更可靠）；engine 侧有同能力实现，本文件是 ops 层的通用版（助手用）；
//   - recall：经验库 + 主机档案检索（"这台机器以前怎么处理的"）；
//   - update_desired：操作员声明期望（"这个端口是正常的"→ 加入期望
//     白名单，不再误报）——人教助手认识环境；
//   - LoadDossier：只读读取主机档案（任务上下文注入用）。
//
// 安全边界：collect_probe 走探针白名单（只读）；update_desired 只改
// 期望状态文件（数据不是代码）；recall 只读记忆。

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-gocel/gocel-core/core/kernel"
	"github.com/go-gocel/gocel-core/core/tool"

	"github.com/go-gocel/gocode-ops/internal/common/collect"
)

// ProbeCollector 定向采集能力（l0.Engine 实现；测试可注入 fake）。
type ProbeCollector interface {
	CollectProbes(ctx context.Context, ms []Metric, factIDs []string) (*Snapshot, error)
}

// CollectProbeTool 定向采集工具：大脑/助手缺证据时请求确定性采集
// 指定探针（listen_ports/suid_files/… 或 all）。
func CollectProbeTool(pc ProbeCollector) kernel.Tool {
	return tool.MustToolFromFunc(
		func(ctx context.Context, args struct {
			Host   string `json:"host" description:"目标主机别名（与 remote_terminal 一致）"`
			Probes string `json:"probes" description:"探针 ID 列表（逗号分隔）；all=全部安全事实探针。可用：listen_ports,listen_udp,uid0_users,svc_units,suid_files,suid_files_full,world_writable,world_writable_full,big_files,mounts,cron_chain,user_crons,ssh_chain,auth_chain,sysctl_keys,shell_init_hooks,rc_local,env_global,ld_so_conf,ld_preload,file_caps,estab_conns,arp_neighbors,net_identity,empty_passwords,journald_cfg,tmp_dirs,resolv_conf,kernel_modules,promisc_ifaces,udev_rules,at_jobs,systemd_custom,selinux_status,immutable_files,login_trail（*_full 为全盘下钻变体，代价高，仅定向复采时使用）"`
		}) (string, error) {
			if pc == nil {
				return "", errors.New("collect_probe 不可用（未接入确定性底座）")
			}
			return collectProbeRun(ctx, pc, args.Host, args.Probes)
		},
		tool.WithToolName("collect_probe"),
		tool.WithToolDescription("定向确定性采集指定探针（与 L0 快检同源，只读、白名单）。追查中缺证据时使用：给出目标主机与探针 ID，返回该探针的原始采集输出——比自行拼 terminal 命令可靠。"),
	)
}

// collectProbeRun 共享实现（engine 侧也可复用）：解析探针 ID → 定向
// 采集 → 按主机格式化输出。
func collectProbeRun(ctx context.Context, pc ProbeCollector, host, probes string) (string, error) {
	env := DetectEnv(ctx)
	probes = strings.TrimSpace(probes)
	if probes == "" {
		return "", errors.New("collect_probe: probes 必填（逗号分隔探针 ID 或 all）")
	}
	factSet := map[string]bool{}
	metricSet := map[string]bool{}
	if probes == "all" {
		for _, f := range SecurityFacts(env) {
			factSet[f.ID] = true
		}
	} else {
		for _, name := range strings.Split(probes, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			found := false
			for _, f := range SecurityFacts(env) {
				if f.ID == name {
					factSet[name] = true
					found = true
				}
			}
			for _, m := range append(Metrics(env), SecurityMetrics(env)...) {
				if m.ID == name {
					metricSet[name] = true
					found = true
				}
			}
			if !found {
				return "", fmt.Errorf("collect_probe: 未知探针 %q", name)
			}
		}
	}
	var ms []Metric
	for id := range metricSet {
		for _, m := range append(Metrics(env), SecurityMetrics(env)...) {
			if m.ID == id {
				ms = append(ms, m)
			}
		}
	}
	facts := make([]string, 0, len(factSet))
	for id := range factSet {
		facts = append(facts, id)
	}
	snap, err := pc.CollectProbes(ctx, ms, facts)
	if err != nil {
		return "", fmt.Errorf("collect_probe: 采集失败: %w", err)
	}
	var b strings.Builder
	total := 0
	omitted := 0
	for i := range snap.Hosts {
		hm := &snap.Hosts[i]
		if host != "" && hm.Host != host {
			continue
		}
		for id, msg := range hm.Errors {
			fmt.Fprintf(&b, "## %s 探针 %s 采集失败: %s\n", hm.Host, id, msg)
		}
		// 上下文护栏（P2 修复）：大探针（全盘下钻 big_files_full 等）
		// 原始输出可达 ~1MB，直接灌模型上下文会挤爆窗口——单探针
		// 截断 + 总量上限，超限如实标注（静默截断会误导"已见全部"）。
		for id := range factSet {
			if raw := hm.Raw[id]; raw != "" {
				part := collect.TruncateStr(raw, collectProbePerProbeCap)
				total += len(part)
				if total > collectProbeTotalCap {
					omitted++
					continue
				}
				fmt.Fprintf(&b, "## %s %s\n%s\n", hm.Host, id, part)
			}
		}
		for id := range metricSet {
			if raw := hm.Raw[id]; raw != "" {
				part := collect.TruncateStr(raw, collectProbePerProbeCap)
				total += len(part)
				if total > collectProbeTotalCap {
					omitted++
					continue
				}
				fmt.Fprintf(&b, "## %s %s\n%s\n", hm.Host, id, part)
			}
		}
	}
	if omitted > 0 {
		fmt.Fprintf(&b, "…其余 %d 段探针输出超出总上限已省略（单探针 %d 字节，总量 %d 字节；需要完整数据请缩小探针范围）\n", omitted, collectProbePerProbeCap, collectProbeTotalCap)
	}
	if b.Len() == 0 {
		return "(采集完成：指定探针无输出——该探针无命中或主机无数据)", nil
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

// collectProbePerProbeCap 单探针输出截断上限（8KB：与展示路径单主机
// 上限同量级；大探针只给头部证据）。
const collectProbePerProbeCap = 8 << 10

// collectProbeTotalCap collect_probe 工具结果总量上限（64KB：与展示
// 路径批量预算同量级，防多探针/多主机输出挤爆上下文窗口）。
const collectProbeTotalCap = 64 << 10

// RecallTool 经验检索工具（助手版）：查经验库 + 主机档案。
func RecallTool(mem *Memory) kernel.Tool {
	return tool.MustToolFromFunc(
		func(ctx context.Context, args struct {
			Signal string `json:"signal" description:"信号名或主题（如 unattributed_listen、suid_files、端口 9090、nginx）；空=该主机全部档案"`
			Host   string `json:"host,omitempty" description:"可选：限定主机（省略=全局经验）"`
		}) (string, error) {
			if mem == nil {
				return "（记忆不可用）", nil
			}
			var out []string
			if args.Signal != "" {
				out = append(out, mem.Recall(args.Signal, args.Host, 5)...)
			}
			if args.Host != "" {
				if d := mem.DossierBrief(args.Host); d != "" {
					out = append(out, "## 主机档案 "+args.Host+"\n"+d)
				}
			}
			if len(out) == 0 {
				return "（无相关经验/档案——这是一台新机器或首次处理该问题）", nil
			}
			return strings.Join(out, "\n"), nil
		},
		tool.WithToolName("recall"),
		tool.WithToolDescription("检索历史经验与主机档案：该信号/主题在本机或全局的既往处置、命中次数、误报率，以及目标主机的历史操作/恢复模式/易错点。开始排查前先查——同类问题直接复用经验；操作员会越用越准（每次批准的操作都会沉淀进档案）。"),
	)
}

// UpdateDesiredTool 期望状态声明工具：操作员教助手认识环境。
// action=add/remove；kind=port/service/user/no_port/no_user/no_suid/
// no_world_writable；value=对象（端口数字/服务名/用户名/路径）。
func UpdateDesiredTool(workDir string) kernel.Tool {
	return tool.MustToolFromFunc(
		func(ctx context.Context, args struct {
			Action string `json:"action" description:"add=声明为期望（白名单/必须项）；remove=撤销声明"`
			Kind   string `json:"kind" description:"port=必须监听端口；service=必须运行服务；user=必须存在账户；no_port=禁止监听端口；no_user=禁止账户；no_suid=禁止 SUID 的路径；no_world_writable=禁止世界可写的路径"`
			Host   string `json:"host" description:"目标主机别名"`
			Value  string `json:"value" description:"对象值：端口为数字，其余为名称/路径"`
		}) (string, error) {
			return updateDesiredRun(workDir, args.Action, args.Kind, args.Host, args.Value)
		},
		tool.WithToolName("update_desired"),
		tool.WithToolDescription("声明/撤销目标主机的期望状态：当操作员确认某对象是正常的（如端口、服务、账户）时，用 add 加入期望白名单——引擎/助手此后不再报该偏差；确认某对象不该存在时用 no_* 类型声明禁止。这是操作员把业务知识教给助手的方式。"),
	)
}

// updateDesiredRun 实现：加载期望状态 → 修改 → 保存。
func updateDesiredRun(workDir, action, kind, host, value string) (string, error) {
	action = strings.TrimSpace(strings.ToLower(action))
	kind = strings.TrimSpace(strings.ToLower(kind))
	host = strings.TrimSpace(host)
	value = strings.TrimSpace(value)
	if action != "add" && action != "remove" {
		return "", errors.New("update_desired: action 必须是 add 或 remove")
	}
	if host == "" || value == "" {
		return "", errors.New("update_desired: host 与 value 必填")
	}
	d, err := LoadDesired(workDir)
	if err != nil {
		return "", err
	}
	if d == nil {
		d = &DesiredState{Hosts: map[string]HostDesire{}}
	}
	if d.Hosts == nil {
		d.Hosts = map[string]HostDesire{}
	}
	des := d.Hosts[host]
	exp := &des.Expect
	var list *[]string
	var intList *[]int
	switch kind {
	case "port":
		n, err := strconv.Atoi(value)
		if err != nil || n <= 0 || n > 65535 {
			return "", errors.New("update_desired: port 需要 1-65535 的数字")
		}
		intList = &exp.Ports
		if action == "add" {
			if !containsInt(*intList, n) {
				*intList = append(*intList, n)
			}
		} else {
			*intList = removeInt(*intList, n)
		}
	case "no_port":
		n, err := strconv.Atoi(value)
		if err != nil || n <= 0 || n > 65535 {
			return "", errors.New("update_desired: no_port 需要 1-65535 的数字")
		}
		intList = &exp.NoPorts
		if action == "add" {
			if !containsInt(*intList, n) {
				*intList = append(*intList, n)
			}
		} else {
			*intList = removeInt(*intList, n)
		}
	case "service":
		list = &exp.Services
	case "user":
		list = &exp.Users
	case "no_user":
		list = &exp.NoUsers
	case "no_suid":
		list = &exp.NoSUID
	case "no_world_writable":
		list = &exp.NoWorldWritable
	default:
		return "", fmt.Errorf("update_desired: 未知 kind %q（port/service/user/no_port/no_user/no_suid/no_world_writable）", kind)
	}
	if list != nil {
		if action == "add" {
			if !containsStr(*list, value) {
				*list = append(*list, value)
			}
		} else {
			*list = removeStr(*list, value)
		}
	}
	d.Hosts[host] = des
	if err := SaveDesired(workDir, d); err != nil {
		return "", err
	}
	verb := "已声明"
	if action == "remove" {
		verb = "已撤销"
	}
	return fmt.Sprintf("%s：%s %s = %s（主机 %s 的期望状态已更新）", verb, kind, value, displayKind(kind), host), nil
}

func displayKind(k string) string {
	switch k {
	case "port":
		return "必须监听端口"
	case "service":
		return "必须运行服务"
	case "user":
		return "必须存在账户"
	case "no_port":
		return "禁止监听端口"
	case "no_user":
		return "禁止账户"
	case "no_suid":
		return "禁止 SUID 路径"
	case "no_world_writable":
		return "禁止世界可写路径"
	}
	return k
}

func removeStr(list []string, v string) []string {
	var out []string
	for _, s := range list {
		if s != v {
			out = append(out, s)
		}
	}
	return out
}

func removeInt(list []int, v int) []int {
	var out []int
	for _, n := range list {
		if n != v {
			out = append(out, n)
		}
	}
	return out
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func containsInt(list []int, n int) bool {
	for _, v := range list {
		if v == n {
			return true
		}
	}
	return false
}
