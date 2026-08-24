package probe

import (
	"fmt"
	"strings"
)

// FactClass 探针成本分层（design-v2.md §二：探针规格书的成本先验）。
// 例行轮只采 S0/S1；S2 上板/刷新/信号触发；S3 显式下钻。
// 写不出代价上界的探针不允许上线——全盘枚举（find / -xdev 形态）无界，
// 只允许作为 S3 下钻（显式调用、带远端 timeout 包裹、partial 语义）。
type FactClass int

const (
	FactSignal    FactClass = iota // S0: O(1)，每轮
	FactTargeted                   // S1: 有界（定点目录/固定文件），每轮
	FactEnumerate                  // S2: 上板/刷新/信号触发（预留）
	FactDrilldown                  // S3: 下钻（显式 collect_probe，可 partial）
)

// Metric 一项可解析的巡检指标。
//
// 设计原则：命令只读；输出解析全部用 Go 实现（不依赖 grep/sed/awk，
// 精简容器同样可跑）；每项输出带唯一标记，采集器按标记切分后交给
// Parse。Parse 返回 键→数值 的映射（如 disk 指标：挂载点→使用率）。
type Metric struct {
	ID   string // 唯一标识（事件/报告用）
	Name string // 人可读名称
	// Fragment 返回命令片段（按环境裁剪；输出前后由采集器包裹标记）。
	// 可能无界的探针必须自带 `timeout` 包裹与完成哨兵（见 boundedProbe），
	// 并在规格中声明 Class=FactDrilldown。
	Fragment func(env *Env) string
	// Parse 解析片段输出。返回空 map 表示无数据（如容器内无 systemd）。
	Parse func(out string) (map[string]float64, error)
	// Warn/Crit 阈值：值 ≥ Warn 告警，≥ Crit 严重。
	Warn float64
	Crit float64
	// FailDown 为 true 时语义反转：值 ≤ Warn/Crit 才告警（如可用内存）。
	FailDown bool
	// Class 成本分层（安全事实探针规格书：例行/定点/枚举/下钻）。
	// 零值=FactSignal（数值指标恒为 O(1) 信号级）。
	Class FactClass
}

// probeIncompleteMark 探针未完整完成哨兵：探针命令被 timeout 终止或
// 异常退出时输出该行（在片段内、`__M_<id>__` 标记之后）——采集器
// 据此把该探针覆盖标为 partial，绝不把不完整枚举当"扫描无结果"。
// 格式与片段标记（__M_...__）互斥，不会被 splitFragments 误切。
const probeIncompleteMark = "__PROBE_INCOMPLETE__"

// BoundedProbe 给可能无界的探针命令加成本护栏：远端 timeout 包裹 +
// 完成哨兵。timeout 直接子进程即探针命令本身（管道首段），超时整条
// 命令被杀，不留孤儿（碎片内无中间 sh）；异常退出（超时/失败）输出
// 哨兵行，采集器标 partial。命令自身必须只读。
//
// 约束：cmd 必须是**单条命令**，不得以 shell 关键字（for/while/case）
// 开头——`timeout 20s for ...` 是语法错误（真实环境事故：tmp_dirs 曾
// 用 timeout 包 for 循环，整条 collect 命令在远端 sh 解析失败，L0 指标/
// 状态/事实全部丢失且无错误提示）。循环类片段须用 `sh -c '...'` 包裹
// 后再传入。
func BoundedProbe(cmd string, secs int) string {
	trimmed := strings.TrimSpace(cmd)
	for _, kw := range []string{"for ", "while ", "case ", "until ", "if ", "{ "} {
		if strings.HasPrefix(trimmed, kw) {
			panic("boundedProbe: 不能直接包裹 shell 关键字结构（" + kw + "），请用 sh -c '...' 包裹: " + trimmed)
		}
	}
	return fmt.Sprintf("{ timeout -s KILL %ds %s; } 2>/dev/null; [ $? -eq 0 ] || echo %s", secs, cmd, probeIncompleteMark)
}

// fragmentMark 生成形如 __M_<id>__ 的输出标记。
func fragmentMark(id string) string { return "__M_" + id + "__" }

// Metrics 按环境返回检查清单（全部只读命令）。
func Metrics(env *Env) []Metric {
	list := []Metric{
		{ID: "mem", Name: "内存可用率", Warn: 10, Crit: 5, FailDown: true,
			Fragment: func(*Env) string { return "cat /proc/meminfo" },
			Parse:    parseMemInfo,
		},
		{ID: "disk", Name: "磁盘使用率", Warn: 85, Crit: 95,
			Fragment: func(*Env) string { return "df -Pk" },
			Parse:    parseDF("capacity"),
		},
		{ID: "inode", Name: "inode 使用率", Warn: 85, Crit: 95,
			Fragment: func(*Env) string { return "df -iP" },
			Parse:    parseDF("capacity"),
		},
		{ID: "zombie", Name: "僵尸进程数", Warn: 1, Crit: 5,
			Fragment: func(*Env) string { return "ps -eo stat" },
			Parse:    parseZombie,
		},
		// 单进程 CPU 占用：CPU 型故障（死循环/挖矿/失控任务）的整体 CPU
		// 均值可能被多核摊平不越阈值，但单进程占用是对象级确定性痕迹。
		// ps 快照轻量，每轮必采。
		{ID: "proc_top", Name: "单进程CPU占用", Warn: 90, Crit: 150,
			Fragment: func(*Env) string { return "ps -eo pid=,comm=,pcpu= --sort=-pcpu | head -n 3" },
			Parse:    parseProcTop,
		},
		// 内核事件痕迹：OOM/Kill/panic 是内核级故障必留痕的确定性证据
		// （模型可能从不看 dmesg）。仅取末尾 200 行：长运行主机的历史
		// 事件不淹没当前窗口。
		// 不可博弈（P0 修复）：走 journald 内核日志（journalctl -k）而非
		// dmesg 环形缓冲——`dmesg -c` 可被任意 root 清空（引擎自身曾
		// 用其"清除"OOM 证据），journald 的 --since 窗口只能被
		// journalctl --rotate/--vacuum 影响（已被守卫证据面拦截），
		// 处置"证据"不再能假装处置"故障"。journalctl 不可用（精简
		// 环境）时输出为空，与 dmesg 受限同语义（静默降级不产线）。
		{ID: "kernel_events", Name: "内核事件痕迹", Warn: 1, Crit: 5,
			Fragment: func(*Env) string {
				return "journalctl -k --since '30 minutes ago' --no-pager 2>/dev/null | tail -n 200"
			},
			Parse: parseKernelEvents,
		},
		// 网卡收发错误：链路/驱动劣化的确定性痕迹（坏缆/半双工/驱动 bug），
		// 常规巡检最容易漏的物理层信号。/proc/net/dev 只读且恒存在。
		{ID: "net_if_errors", Name: "网卡收发错误", Warn: 1, Crit: 10,
			Fragment: func(*Env) string { return "cat /proc/net/dev" },
			Parse:    parseNetDevErrors,
		},
		// 系统时钟（epoch 秒）：跨主机时间偏差检测的观测侧——引擎侧
		// 在判定层与目标时间对比（skew 超限产 clock_skew 线索）。
		// 时间同步状态（timedatectl NTPSynchronized）只反映"同步标志"，
		// 挡不住 hv_utils/hypervisor 类把错误时钟标为已同步的场景
		// （P0 修复：chaos-r1 时钟拨慢 8 分钟未被检出），epoch 对比
		// 是"时钟是否真的准"的客观判定。
		{ID: "clock", Name: "系统时钟", Warn: 90, Crit: 300,
			Fragment: func(*Env) string { return "date +%s" },
			Parse:    parseClock,
		},
		// 交换分区使用率：内存压力转移的确定性痕迹（swap 依赖是 OOM
		// 前兆）。无 swap 的主机（SwapTotal=0）返回空 map 不产数据。
		{ID: "swap", Name: "交换分区使用率", Warn: 50, Crit: 80,
			Fragment: func(*Env) string { return "cat /proc/meminfo" },
			Parse:    parseSwap,
		},
		// 二进制已被删除的存活进程：恶意进程"换壳"驻留（先删文件再运行）
		// 的确定性痕迹；升级残留也在此列（由 DeepDive 裁决是否预期）。
		// ls -l /proc/*/exe 的 " (deleted)" 后缀是内核给出的权威标记。
		{ID: "proc_deleted", Name: "已删除二进制进程数", Warn: 1, Crit: 10,
			Fragment: func(*Env) string { return "ls -l /proc/[0-9]*/exe 2>/dev/null" },
			Parse:    parseProcDeleted,
		},
		// D 状态（不可中断睡眠）进程：IO/NFS 挂死、卡 IO 的确定性痕迹——
		// IO 等待不可见时唯一客观信号（CPU 全绿但业务卡死的典型场景）。
		// 对象级键（pid(comm)）与 proc_top 同风格：同 PID 持续挂死才是
		// 对象级痕迹，PID 变化由下一轮以新线索覆盖。
		{ID: "proc_dstate", Name: "D状态进程数", Warn: 1, Crit: 5,
			Fragment: func(*Env) string { return "ps -eo stat=,pid=,comm=" },
			Parse:    parseDState,
		},
		// 文件描述符使用率：fd 耗尽故障（accept 失败/too many open files）
		// 的确定性痕迹。/proc/sys/fs/file-nr 单文件 O(1) 读取。
		{ID: "file_desc", Name: "文件描述符使用率", Warn: 80, Crit: 95,
			Fragment: func(*Env) string { return "cat /proc/sys/fs/file-nr" },
			Parse:    parseFileNR,
		},
	}
	if env.HasSystemd {
		list = append(list, Metric{ID: "svc_failed", Name: "失败服务数", Warn: 1, Crit: 3,
			Fragment: func(*Env) string { return "systemctl --failed --no-legend" },
			Parse:    parseCountLines,
		})
		// 启用但未运行的服务：运行态对照是巡检基线的标准项——停服类
		// 故障（服务被 stop、坏配置起不来）不越 failed 阈值，靠该对照
		// 确定性检出（是否预期由 DeepDive 裁决）。模板单元（*@.service）
		// is-active 恒为空串，排除——实例未运行时计数才有意义
		// （R21 实测 getty@.service 模板被计入伪线索）。
		list = append(list, Metric{ID: "svc_inactive", Name: "启用但未运行服务数", Warn: 1, Crit: 3,
			Fragment: func(*Env) string {
				return "systemctl list-unit-files --state=enabled --type=service --no-legend 2>/dev/null | awk '{print $1}' | while read u; do case \"$u\" in *@.service) continue;; esac; st=$(systemctl is-active \"$u\" 2>/dev/null); [ \"$st\" = \"active\" ] || echo \"$u $st\"; done"
			},
			Parse: parseCountLines,
		})
		// 日志错误计数："故障必留痕"的确定性落点——模型漏看日志时
		// 引擎仍能检出"近期有错误日志"，由 DeepDive 裁决是否真故障。
		// 窗口 10 分钟为监控常见窗口（Prometheus rate 同类）。
		// journalctl 无条目时的占位行不计数（R21 实测误计 1 条伪线索）。
		list = append(list, Metric{ID: "log_errors", Name: "近期错误日志数", Warn: 1, Crit: 20,
			Fragment: func(*Env) string {
				return "journalctl -p err --since '10 minutes ago' --no-pager 2>/dev/null | grep -v '^-- No entries --$'"
			},
			Parse: parseCountLines,
		})
	}
	if env.HasDocker {
		list = append(list, Metric{ID: "container", Name: "停止容器数", Warn: 1, Crit: 3,
			Fragment: func(*Env) string { return "docker ps -a --format '{{.Names}}|{{.Status}}'" },
			Parse:    parseDockerPS,
		})
	}
	// Kubernetes 面（目标主机 kubectl 可用时自动产出数据，见 metrics_k8s.go）：
	// 异常 Pod / 未就绪 Deployment / NotReady 节点——命令自带可用性守卫，
	// 非集群主机零开销。
	list = append(list, k8sMetrics()...)
	// LVM 面（磁盘扩容场景数据面，见 metrics_lvm.go）：逻辑卷使用率。
	list = append(list, lvmMetrics()...)
	return list
}

// parseMemInfo 解析 /proc/meminfo：返回 {"avail_pct": 可用内存百分比}。
