// EngineConfig 是公用内核的配置。WorkDir 必填；Local 与 Hosts 至少其一。
//
// 公用内核是 全自动运维引擎与交互式运维助手共享的问题处理核心：全自动运维引擎在内核上
// 叠加确定性协议推进机制（L0 快检 → 判定 → 追查 → 处置 → 报告），
// 无人干预自动收敛；交互式运维助手复用同一套 L0/findings/基线/报告
// （SnapshotL0/l0_snapshot 工具），人在环驱动。
// 守卫策略由各侧注入（助手：Operator + Policy；引擎：PolicyAuto）。
package model

import "time"

// Thresholds 异常判定阈值。语义：除 FailDown 指标外，值越大越差。
//
// 数值来源：行业常见静态告警水位（Prometheus/Zabbix 默认规则区间），
// 非测量校准值。L0 是确定性层——静态阈值保证判定可复现、可审计；
// 按环境校准只需改这一处单一来源（本包 DefaultThresholds）。
type Thresholds struct {
	// CPU 使用率百分比（/proc/stat 增量采样）：
	// 持续高负载常见告警水位（Prometheus cpu 使用率规则区间 80-90 warn）。
	CPUWarn float64 // 默认 80
	CPUCrit float64 // 默认 95
	// MemAvailWarn/Crit 可用内存百分比，越低越差：
	// 可用内存 10%/5% 是 Linux 内存压力常见水位（swap/OOM 临界）。
	MemWarn float64 // 默认 10
	MemCrit float64 // 默认 5
	// DiskUseWarn/Crit 磁盘/inode 使用率百分比：
	// 85% warn（容量规划常用启动线）/95% crit（即将写满）是常见水位。
	DiskWarn  float64 // 默认 85
	DiskCrit  float64 // 默认 95
	InodeWarn float64 // 默认 85
	InodeCrit float64 // 默认 95
	// ZombieWarn/Crit 僵尸进程数量：健康环境应为 0，出现即提示（泄漏
	// 迹象），5 个以上告警（父进程未收割，常见于异常程序）。
	ZombieWarn int // 默认 1
	ZombieCrit int // 默认 5
	// SvcFailWarn/Crit systemctl --failed 数量（仅 systemd 环境）：
	// 1 个失败单位即提示，3 个告警（服务连锁失败特征）。
	SvcFailWarn int // 默认 1
	SvcFailCrit int // 默认 3
	// SvcInactiveWarn/Crit 启用但未运行的服务数（systemd 环境）：
	// 运行态对照——停服/配置坏起不来的服务不越 failed 阈值，靠对照检出。
	SvcInactiveWarn int // 默认 1
	SvcInactiveCrit int // 默认 3

	// LogErrorsWarn/Crit 最近 10 分钟错误日志条数（systemd 环境）：
	// 有任何错误即提示（痕迹源），20 条+为错误风暴（服务崩溃/熔断特征）。
	LogErrorsWarn int // 默认 1
	LogErrorsCrit int // 默认 20

	// SuidWarn/Crit SUID 文件数量（Security 兜底探针）：正常系统也有
	// 少量 SUID（passwd/su 等），检出即产线索由 DeepDive 裁决；
	// 50+ 为明显异常（提权载体批量落地特征）。
	SuidWarn int // 默认 1
	SuidCrit int // 默认 50
	// WorldWritableWarn/Crit /etc /usr /opt 下世界可写文件数量：
	// 世界可写是可被任意用户篡改的弱配置，检出即线索。
	WorldWritableWarn int // 默认 1
	WorldWritableCrit int // 默认 50
	// SSHRootLoginWarn/Crit sshd_config 允许 root 直接登录：
	// 业界共识的弱配置（CIS benchmark 2.2.2 要求禁用）。
	SSHRootLoginWarn int // 默认 1
	SSHRootLoginCrit int // 默认 1

	// ProcTopWarn/Crit 单进程 CPU 占用（%CPU，多核可超 100）：
	// 单进程 >90% 持续占用是 CPU 型故障/挖矿/死循环的确定性痕迹；
	// 150% 为明显失控（多核满载特征）。只读 ps 快照，每轮必采。
	ProcTopWarn float64 // 默认 90
	ProcTopCrit float64 // 默认 150
	// KernelEventsWarn/Crit 内核事件痕迹（dmesg 末尾 200 行内
	// OOM/Kill/panic/BUG 行数）：健康环境应为 0，出现即产线索
	// （内核级故障必留痕）；5 条+为持续内核异常。
	KernelEventsWarn int // 默认 1
	KernelEventsCrit int // 默认 5
	// NetErrWarn/Crit 网卡收发错误计数（/proc/net/dev 累计值）：
	// 健康链路应为 0，非零即链路/驱动异常痕迹；10+ 为明显劣化。
	NetErrWarn int // 默认 1
	NetErrCrit int // 默认 10
	// SwapWarn/Crit 交换分区使用率（%）：>50% 为内存压力转移迹象
	// （性能劣化），>80% 为 swap 依赖（OOM 前兆）。
	SwapWarn float64 // 默认 50
	SwapCrit float64 // 默认 80
	// ProcDeletedWarn/Crit 二进制已被删除的存活进程数（/proc/*/exe
	// 显示 " (deleted)"）：正常环境应为 0（升级残留常见但应裁决），
	// 10+ 为恶意进程换壳/隐蔽驻留特征。
	ProcDeletedWarn int // 默认 1
	ProcDeletedCrit int // 默认 10
	// DStateWarn/Crit D 状态（不可中断睡眠）进程数：IO/NFS 挂死、
	// 卡 IO 的确定性痕迹（CPU 全绿但业务卡死的典型场景）——1 个即
	// 提示（健康环境为 0），5 个告警（IO 面系统性挂死特征）。
	DStateWarn int // 默认 1
	DStateCrit int // 默认 5
	// FDWarn/FDCrit 文件描述符使用率（%）：/proc/sys/fs/file-nr
	// 已分配/上限——80% 为 fd 耗尽前兆（accept 失败/too many open
	// files 特征），95% 告警（连接/文件句柄即将不可用）。
	FDWarn float64 // 默认 80
	FDCrit float64 // 默认 95
}

// DefaultThresholds 返回默认阈值。
func DefaultThresholds() Thresholds {
	return Thresholds{
		CPUWarn: 80, CPUCrit: 95,
		MemWarn: 10, MemCrit: 5,
		DiskWarn: 85, DiskCrit: 95,
		InodeWarn: 85, InodeCrit: 95,
		ZombieWarn: 1, ZombieCrit: 5,
		SvcFailWarn: 1, SvcFailCrit: 3,
		SvcInactiveWarn: 1, SvcInactiveCrit: 3,
		LogErrorsWarn: 1, LogErrorsCrit: 20,
		SuidWarn: 1, SuidCrit: 50,
		WorldWritableWarn: 1, WorldWritableCrit: 50,
		SSHRootLoginWarn: 1, SSHRootLoginCrit: 1,
		ProcTopWarn: 90, ProcTopCrit: 150,
		KernelEventsWarn: 1, KernelEventsCrit: 5,
		NetErrWarn: 1, NetErrCrit: 10,
		SwapWarn: 50, SwapCrit: 80,
		ProcDeletedWarn: 1, ProcDeletedCrit: 10,
		DStateWarn: 1, DStateCrit: 5,
		FDWarn: 80, FDCrit: 95,
	}
}

// EngineConfig 是公用内核（L0 确定性层/工作区/报告）的配置。WorkDir
// 必填；Local 与 Hosts 至少其一。全自动运维引擎的额外配置（处置/验证/
// 阶段超时与全局时限）见 autopilot.Config。
type EngineConfig struct {
	// WorkDir 工作目录：报告、发现、基线、阶段记录、审计落盘处。
	WorkDir string
	// LocalHost 本机显示名（默认取 hostname）。
	LocalHost string
	// Local 是否巡检本机。
	Local bool
	// Hosts 远程主机别名清单（须存在于 InventoryPath 指向的清单）；
	// 为空且 Local=false 时启动报错。
	Hosts []string
	// InventoryPath 远程主机清单路径（凭证所在，模型不可见）。
	InventoryPath string

	// CollectTimeout 单轮快检超时：批量只读探针一次执行，30s 覆盖
	// 慢盘/弱网络主机的常规上限（SSH 命令执行常见 30-60s 超时实践）。
	CollectTimeout time.Duration // 默认 30s
	// FactRefreshInterval 重探针（大文件全盘扫描/文件能力位/世界可写/临时
	// 目录洪泛）的刷新间隔：TTL 内复用上一轮采集输出。0=禁用缓存
	// （每轮实采，确定性最强）。默认 5m。
	FactRefreshInterval time.Duration

	// Thresholds 判定阈值。
	Thresholds Thresholds

	// AgentsMDPath 环境信息约定文件（AGENTS.md）；空=不注入。
	AgentsMDPath string
}

// DefaultEngineConfig 返回公用内核默认配置。
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		Local:               true,
		CollectTimeout:      30 * time.Second,
		FactRefreshInterval: 5 * time.Minute,
		Thresholds:          DefaultThresholds(),
	}
}
