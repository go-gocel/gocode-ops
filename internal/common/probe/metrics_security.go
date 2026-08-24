package probe

import "strings"

// metrics_security.go — 安全域指标与安全事实探针（SSH 策略/权限/可疑行为/持久化痕迹）。

// SecurityMetrics returns the security-domain numeric metric probes,
// such as SUID file count and SSH root login policy.
// SecurityMetrics 返回安全域数值指标探针清单（SSH root 直登策略/SUID 文件计数等）。
func SecurityMetrics(env *Env) []Metric {
	list := []Metric{
		{ID: "suid_files", Name: "SUID 文件数", Warn: 1, Crit: 50,
			// -xdev 限制单文件系统：/proc /sys 独立挂载自动排除。
			// 全盘形态带 timeout 护栏（成本有界；大文件系统上超时即
			// partial，不完整结果不得当结论）。
			Fragment: func(*Env) string {
				return BoundedProbe("find / -xdev -type f -perm -4000 2>/dev/null", 120)
			},
			Parse: parseCountLines,
		},
	}
	if env.HasSS {
		list = append(list, Metric{ID: "ssh_root_login", Name: "SSH 允许 root 直登", Warn: 1, Crit: 1,
			// 只读主配置文件（含 Include 文件则读不到，兜底近似可接受）。
			Fragment: func(*Env) string { return "cat /etc/ssh/sshd_config 2>/dev/null" },
			Parse:    parseSSHRootLogin,
		})
	}
	return list
}

// parseSSHRootLogin 解析 sshd_config 的 root 登录策略：仅当
// PermitRootLogin yes 且 PasswordAuthentication 未显式禁用（即 root
// 密码直登面开放）时返回 count=1——root 密钥直登（prohibit-password/
// without-password）是等保认可的形态，不算弱配置；管理通道保护由
// 守卫自影响审查负责（引擎不会把 root 密码通道改成自己都连不上的
// 状态）。只匹配非注释行的首关键字。
func parseSSHRootLogin(out string) (map[string]float64, error) {
	prl, pwd := "", ""
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		switch fields[0] {
		case "PermitRootLogin":
			prl = fields[1]
		case "PasswordAuthentication":
			pwd = fields[1]
		}
	}
	if prl == "yes" && pwd != "no" {
		return map[string]float64{"count": 1}, nil
	}
	return map[string]float64{"count": 0}, nil
}

// SecurityFacts returns the exported security-fact probe list, referenced
// by the cognitive tool collect_probe and prompt vocabularies; the single
// source remains securityFacts.
// securityFacts 安全域事实枚举探针（机制 1：事实保障——大脑必须看见）。
//
// 每轮 L0 确定性采集，原始数据同时走两条管道：
//   - 进模型上下文（L0Facts）：模型不可跳过事实，判定权仍在模型；
//   - 归属规则产 pending 线索（judgeSecurityFacts）：无法归属到已知
//     服务单元/阈值超限的事实 → 线索，DeepDive 验证后裁决。
//
// 只枚举事实、不做判定；规则是归属/阈值型（任何端口、账号、文件被
// 同一机制覆盖），不是针对特定故障的检测。
// SecurityFacts 导出安全事实探针清单（认知工具 collect_probe 与提示词
// 词表引用；单一来源仍是 securityFacts）。
func SecurityFacts(env *Env) []Metric { return securityFacts(env) }

// securityFacts 返回安全事实探针清单（归属规则/偏差计算/认知定向采集
// 共用——单一来源）。模型上下文管道（publishL0Facts）与 collect_probe
// 的 "all" 也基于本清单。
func securityFacts(env *Env) []Metric {
	list := []Metric{
		{ID: "listen_ports", Name: "监听端口（含进程）",
			Fragment: func(*Env) string {
				return "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"
			}},
		// UDP 监听面：listen_ports 只覆盖 TCP——RPC/SNMP/NTP 及后门
		// UDP 服务（DNS 毒化/放大攻击载体）是无 TCP 形态的暴露面。
		// 归属规则与 TCP 同机制（unattributed_listen_udp，独立信号防
		// 同地址:端口互吞）。ss 不可用时 netstat 兜底（无 users 列，
		// 归属规则跳过，原始输出仍进上下文）。
		{ID: "listen_udp", Name: "UDP 监听端口（含进程）",
			Fragment: func(*Env) string {
				return "ss -ulnp 2>/dev/null || netstat -ulnp 2>/dev/null"
			}},
		{ID: "uid0_users", Name: "uid=0 用户",
			Fragment: func(*Env) string {
				return "awk -F: '$3==0{print $1\":\"$7}' /etc/passwd 2>/dev/null"
			}},
		{ID: "big_files", Name: "大文件（>500M，下钻）",
			// 阈值 500M 是通用水位（单文件异常占用），非针对特定路径。
			// S3 下钻探针：例行轮不采（全盘 find 代价与文件系统规模
			// 无界，2.3T/7000 万 inode 实测单次远超采集预算）——由
			// 磁盘漂移信号触发显式 collect_probe 调用；带远端 timeout
			// 护栏与完成哨兵，超时结果按 partial 处理（不完整枚举
			// 不得当"扫描无结果"）。输出上限由采集器 128K 截断兜底
			// （无 sort|head 管道——管道会把退出码掩蔽成尾命令的，
			// 完成哨兵会失明）。
			Class: FactDrilldown,
			Fragment: func(*Env) string {
				return BoundedProbe("find / -xdev -type f -size +500M -printf '%s %p\\n' 2>/dev/null", 300)
			}},
		{ID: "estab_conns", Name: "活跃连接（对端）",
			Fragment: func(*Env) string {
				return "ss -tn state established 2>/dev/null | awk 'NR>1{print $4\"->\"$5}' | sort | uniq -c | sort -rn | head -15"
			}},
		// 网络邻接面（ARP）：静态（PERMANENT）邻居条目是邻接面投毒载体——
		// 正常学习到的条目随生命周期变化，静态条目只有人为/攻击者写入
		// （R21 实测静态 ARP 投毒无任何确定性可见面）。事实进上下文 +
		// 归属规则产线。
		{ID: "arp_neighbors", Name: "ARP 邻居表",
			Fragment: func(*Env) string {
				return "ip neigh show 2>/dev/null"
			}},
		{ID: "mounts", Name: "挂载点",
			Fragment: func(*Env) string { return "mount 2>/dev/null | awk '{print $1, $3, $5}'" }},
		// 关键内核参数（CIS 类安全基线标准项）：硬基线下安全参数不可见
		// 是持续漏检面（R6-R10 连续五轮同面）——基线覆盖网络安全加固
		// 标准项，与具体漏检项解耦。
		{ID: "sysctl_keys", Name: "关键内核参数（安全基线）",
			Fragment: func(*Env) string {
				return "sysctl net.ipv4.ip_forward kernel.core_pattern kernel.dmesg_restrict kernel.randomize_va_space kernel.kptr_restrict fs.protected_regular fs.protected_hardlinks fs.protected_symlinks net.ipv4.conf.all.accept_source_route net.ipv4.conf.all.rp_filter vm.dirty_ratio 2>/dev/null"
			}},
		{ID: "tmp_dirs", Name: "临时目录文件数（超水位）",
			// 阈值 2000 为通用水位：标准临时目录树不应堆积数千文件
			// （inode 消耗/隐藏落地的特征，子目录洪泛同样覆盖）；
			// 只输出超阈值目录。S1 定点：目录固定、带 timeout 护栏
			// （洪泛目录计数可能超预算）。循环结构经 sh -c 包裹——
			// timeout 直接包裹 for 是语法错误（真实环境事故：整条
			// collect 命令解析失败，L0 全部数据丢失）。
			Class: FactTargeted,
			Fragment: func(*Env) string {
				return BoundedProbe("sh -c 'for d in /dev/shm /tmp /var/tmp; do n=$(find \"$d\" -xdev -type f 2>/dev/null | wc -l); [ \"$n\" -gt 2000 ] 2>/dev/null && echo \"$d $n\"; done'", 20)
			}},
		// 登录链/横幅链下载执行注入：shell 启动文件 + 登录横幅文件族。
		// 登录链持久化的通用特征：启动文件含 curl|wget 管道执行。
		// 覆盖 bash 登录链全部候选：bash_profile/bash_login/.profile 与
		// 全局 /etc/profile（R24 实测 .profile 漏检——root login shell
		// 无 .bash_profile 时回退读 .profile，是第四处持久化藏身处）。
		{ID: "shell_init_hooks", Name: "登录链下载执行注入",
			Fragment: func(*Env) string {
				// 持久化形态全覆盖：curl/wget 管道执行、/dev/tcp 反连、
				// base64 解码执行（R24 实测 .profile 藏 python b64decode
				// 第四处持久化——旧模式只匹配 curl|wget 管道，其余形态
				// 静默失明）。文件名输出由 DeepDive 追查具体内容。
				return "grep -lE '(curl|wget)[^|]*\\|[[:space:]]*(ba)?sh|/dev/tcp/|b64decode|base64[[:space:]]+-d' /etc/profile /etc/profile.d/* /etc/bashrc /root/.bashrc /root/.bash_profile /root/.bash_login /root/.profile /etc/issue /etc/issue.net /etc/issue.d/* /etc/motd /etc/motd.d/* 2>/dev/null"
			}},
		{ID: "file_caps", Name: "文件能力位（提权载体）",
			// 权限面巡检的完整项：SUID 位与文件能力位是 Linux 两类文件型
			// 提权载体（迭代 7）——能力位此前只有一次性兜底探针未覆盖，
			// 本事实每轮确定性采集，全部载体进模型上下文，由 DeepDive
			// 裁决是否预期。S1 定点：只扫可执行目录（/opt 为应用/数据根，
			// 例行不递归——数据目录可能无界，见 world_writable 同理由；
			// 数据面能力位走 suid_files_full/world_writable_full 下钻）。
			Class: FactTargeted,
			Fragment: func(*Env) string {
				return BoundedProbe("getcap -r /usr/bin /usr/sbin /usr/libexec /bin /sbin /etc /root 2>/dev/null", 20)
			}},
		{ID: "suid_files", Name: "SUID 文件（标准目录，提权载体）",
			// SUID 与文件能力位同类（文件型提权载体）：全盘枚举（旧
			// find / -xdev 形态）在 2.3T/7000 万 inode 根分区远超采集
			// 预算且超时孤儿堆积（真实环境事故）——例行改为 S1 定点：
			// 只扫标准二进制目录（有界 + timeout 护栏 + 完成哨兵）。
			// 非标准位置的完整枚举走 suid_files_full（S3 下钻：显式
			// collect_probe / 处置复检），归属规则对下钻结果同样生效。
			Class: FactTargeted,
			Fragment: func(*Env) string {
				return BoundedProbe("find /usr/bin /usr/sbin /bin /sbin /usr/lib /usr/lib64 /usr/libexec -xdev -type f -perm -4000 -printf '%p\\n' 2>/dev/null", 20)
			}},
		{ID: "suid_owners", Name: "SUID 文件包归属（标准目录，提权后门判定）",
			// 确定性归属校验：标准目录 SUID 与包数据库比对（rpm → dpkg
			// → apk 按发行版探测，全无则无数据跳过——数据驱动不误报）。
			// 动机：标准目录 SUID 单独列出交给模型裁决依赖模型注意力，
			// 伪装名的非包 SUID（如 /usr/bin/upd = bash 副本）会被漏过；
			// 包归属是发行版无关的确定性机制——非包来源 SUID 即后门
			// 特征。行格式 <路径>|<归属>，归属查询失败/不属于任何包
			// 记 UNOWNED，判定层产线。
			Class: FactTargeted,
			Fragment: func(*Env) string {
				return BoundedProbe(`sh -c "h=''; command -v rpm >/dev/null 2>&1 && h=rpm; [ -z \"\$h\" ] && command -v dpkg >/dev/null 2>&1 && h=dpkg; [ -z \"\$h\" ] && command -v apk >/dev/null 2>&1 && h=apk; [ -z \"\$h\" ] && exit 0; for f in \$(find /usr/bin /usr/sbin /bin /sbin /usr/lib /usr/lib64 /usr/libexec -xdev -type f -perm -4000 -printf '%p\\n' 2>/dev/null); do o=''; case \"\$h\" in rpm) o=\$(rpm -qf \"\$f\" 2>/dev/null) && [ -n \"\$o\" ] || o=UNOWNED;; dpkg) o=\$(dpkg -S \"\$f\" 2>/dev/null | cut -d: -f1) && [ -n \"\$o\" ] || o=UNOWNED;; apk) o=\$(apk info -W \"\$f\" 2>/dev/null | sed -n 's/.*owned by //p') && [ -n \"\$o\" ] || o=UNOWNED;; esac; [ -n \"\$o\" ] || o=UNOWNED; echo \"\$f|\$o\"; done"`, 30)
			}},
		{ID: "business_ports", Name: "业务端口清单（监听中且非管理面进程）",
			// 等保合规 × 业务连续性的桥：管理面收窄（默认拒绝/来源
			// 限制）只允许影响管理端口，业务端口必须保持可用。本事实
			// 确定性识别"业务面"：监听中的 TCP 端口 − 管理面进程
			// （sshd/chronyd/auditd 等通用短名单）= 业务端口清单
			// （行格式 <端口>|<进程>，发行版无关）。加固方案必须显式
			// 覆盖清单中每个端口；处置后引擎按本清单做业务面校验——
			// 非处置目标的业务端口消失 = 业务中断（等保收窄锁死业务
			// 流量的静默事故，自通道校验不感知）→ 强制回滚。
			Class: FactTargeted,
			Fragment: func(*Env) string {
				return BoundedProbe(`ss -tlnp 2>/dev/null | sed -n 's/.*:\([0-9]\{1,5\}\)[[:space:]].*users:(("\([^"]*\)".*/\1|\2/p' | sort -u | grep -vE '\|(sshd|chronyd|ntpd|auditd|rsyslogd|syslog-ng|systemd|dbus-daemon|NetworkManager|firewalld|polkitd|crond|atd|tuned|irqbalance|agetty|login|cupsd|rpcbind|postfix)$'`, 20)
			}},
		{ID: "suid_files_full", Name: "SUID 文件全盘枚举（下钻）",
			// S3 下钻：全根扫描（显式调用才执行）。带远端 timeout 护栏
			// 与完成哨兵——超时即 partial（覆盖不完整不得当结论）。
			Class: FactDrilldown,
			Fragment: func(*Env) string {
				return BoundedProbe("find / -xdev -type f -perm -4000 -printf '%p\\n' 2>/dev/null", 300)
			}},
		// 世界可写对象（真实文件/目录、配置与日志面、排除粘滞位与
		// 符号链接）：0777 目录（如日志目录放宽）是可写面异常的统一归属
		// 型事实。符号链接恒为 0777，必须排除（否则数十条噪音）。
		// S1 定点：只查配置/日志面目录（/opt 为应用/数据根——minio 数据
		// 目录等数据面可能无界，例行不递归，数据面走 world_writable_full
		// 下钻）；带 timeout 护栏。
		{ID: "world_writable", Name: "世界可写对象（配置/日志面）",
			Class: FactTargeted,
			Fragment: func(*Env) string {
				return BoundedProbe("find /etc /var/log /usr/local /srv -xdev \\( -type f -o -type d \\) -perm -002 ! -perm -1000 2>/dev/null", 20)
			}},
		{ID: "world_writable_full", Name: "世界可写对象全量（下钻）",
			// S3 下钻：含 /opt 数据面（显式调用才执行）。
			Class: FactDrilldown,
			Fragment: func(*Env) string {
				return BoundedProbe("find /etc /var/log /opt /usr/local /srv -xdev \\( -type f -o -type d \\) -perm -002 ! -perm -1000 2>/dev/null", 300)
			}},
		// 认证链（PAM）：内容进上下文 + pam_permit 万能模块产线。
		// 覆盖全部 /etc/pam.d/*：认证链完整性要求不漏任何一个服务文件
		// （R21 实测 pam.d/passwd 的 pam_permit 不在原五文件清单内被漏检）。
		{ID: "auth_chain", Name: "PAM 认证链",
			Fragment: func(*Env) string {
				return "for f in /etc/pam.d/*; do echo \"== $f\"; grep -v '^\\s*#' \"$f\" 2>/dev/null; done"
			}},
		// SSH 配置链（sshd 本体 + drop-in）：弱化指令基线归属规则。
		// grep -h：多文件输出不带文件名前缀——否则每行都带
		// "/etc/ssh/sshd_config:" 前缀，归属规则永远无法命中（R21 实测
		// ssh_chain 基线规则自迭代 18 起从未真实产线，GatewayPorts 漏检）。
		{ID: "ssh_chain", Name: "SSH 配置链有效行",
			Fragment: func(*Env) string {
				return "grep -hvE '^\\s*(#|$)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null"
			}},
		// 日志基础设施容量（journald）：容量水位 ≤2M 是事件快速丢弃特征
		// （默认按磁盘 10% 分配——1M 属病态值；R6 conf.d 投毒之后的
		// 通用水位规则，本体/drop-in 同看）。
		{ID: "journald_cfg", Name: "journald 容量配置",
			Fragment: func(*Env) string {
				return "grep -hE '^(RuntimeMaxUse|SystemMaxUse)=' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null"
			}},
		// 计划任务链：crontab 本体/目录族内容——下载执行模式归属规则。
		{ID: "cron_chain", Name: "计划任务链",
			Fragment: func(*Env) string {
				return "cat /etc/crontab /etc/anacrontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* 2>/dev/null | grep -vE '^\\s*(#|$)'"
			}},
		// sudo 授权链：万能免密/危险 Defaults 归属规则（同样 -h：多文件
		// 不带文件名前缀，否则归属规则在 sudoers.d 有文件时失明）。
		{ID: "sudo_chain", Name: "sudo 授权链有效行",
			Fragment: func(*Env) string {
				return "grep -hvE '^\\s*(#|$)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null"
			}},
		// 网络身份链：/etc/hosts 公网 IP 映射归属规则。
		{ID: "net_identity", Name: "网络身份链（hosts）",
			Fragment: func(*Env) string {
				return "grep -vE '^\\s*(#|$)' /etc/hosts 2>/dev/null"
			}},
		// 空密码账户（CIS 基线：任何账户不得有空密码字段——本地/远程
		// 无认证登录面）。shadow 内容只由引擎确定性读取，不进模型原文，
		// 规则只产“账户名”级线索。
		{ID: "empty_passwords", Name: "空密码账户",
			Fragment: func(*Env) string {
				return "awk -F: '$2==\"\"{print $1}' /etc/shadow 2>/dev/null"
			}},
		// 预加载注入面（策略偏差数据源）：/etc/ld.so.preload 内容——
		// 期望状态策略 no_ld_preload 的观测侧（归属规则不产线，纯供
		// 偏差计算与上下文）。
		{ID: "ld_preload", Name: "LD_PRELOAD 预加载文件",
			Fragment: func(*Env) string {
				return "cat /etc/ld.so.preload 2>/dev/null"
			}},
		// DNS 配置面：/etc/resolv.conf 被篡改是 DNS 劫持的典型落点
		// （nameserver 指向攻击者）。无归属规则（无基线难判预期与否）——
		// 纯进上下文 + state_resolv 漂移快照负责变化检测。
		{ID: "resolv_conf", Name: "DNS 配置（resolv.conf）",
			Fragment: func(*Env) string {
				return "cat /etc/resolv.conf 2>/dev/null"
			}},
		// 用户计划任务面：cron_chain 只覆盖系统面（/etc/crontab 与
		// /etc/cron.*）——用户 crontab（/var/spool/cron）是持久化
		// 藏身的另一面（下载执行归属规则与 cron_chain 同一模式）。
		{ID: "user_crons", Name: "用户计划任务链",
			Fragment: func(*Env) string {
				return "cat /var/spool/cron/* /var/spool/cron/crontabs/* 2>/dev/null | grep -vE '^\\s*(#|$)'"
			}},
		// SysV 启动链：/etc/rc.local 在 systemd 时代仍被 rc-local.service
		// 执行——老式持久化面（开机执行注入）。下载执行形态归属规则。
		{ID: "rc_local", Name: "rc.local 启动链",
			Fragment: func(*Env) string {
				return "cat /etc/rc.local 2>/dev/null"
			}},
		// 全局环境变量面：/etc/environment 对全用户登录会话生效——
		// PATH 劫持/LD_PRELOAD 环境变量注入的持久化落点（登录链
		// 注入的第三种形态：不碰 shell 启动文件也能劫持）。
		{ID: "env_global", Name: "全局环境变量（environment）",
			Fragment: func(*Env) string {
				return "cat /etc/environment 2>/dev/null"
			}},
		// 动态链接器配置链：/etc/ld.so.conf 及其 include 目录——库搜索
		// 路径注入面（LD_PRELOAD 的持久化兄弟形态：非标准路径进搜索链
		// 即任意库劫持）。归属规则：白名单（/usr/lib*/lib*/usr/local/lib）
		// 之外路径产线。
		{ID: "ld_so_conf", Name: "动态链接器配置链",
			Fragment: func(*Env) string {
				return "cat /etc/ld.so.conf /etc/ld.so.conf.d/*.conf 2>/dev/null"
			}},
		// 内核模块清单：恶意内核模块加载（rootkit/内核后门）的痕迹面。
		// 无黑名单规则（模块名黑白难判、噪音大）——全量清单进上下文
		// 由模型裁决 + state_kmods 漂移快照兜底"新模块加载即痕"。
		{ID: "kernel_modules", Name: "内核模块清单",
			Fragment: func(*Env) string {
				return "cat /proc/modules 2>/dev/null"
			}},
		// 混杂模式网卡：PROMISC = 抓包监听特征（嗅探/流量窃听/旁路
		// 采集）。ip -br link 的 <> 标志区含 PROMISC 时归属规则产线
		// （虚拟化/监控主机由 DeepDive 裁决是否预期）。
		{ID: "promisc_ifaces", Name: "混杂模式网卡",
			Fragment: func(*Env) string {
				return "ip -br link 2>/dev/null"
			}},
		// udev 规则链：设备事件持久化面（rootkit 用 udev 规则在设备
		// 事件时执行载荷/提权）。归属规则：RUN/PROGRAM 指向可写目录
		// 即产线（/lib 下的发行版默认规则不在此列——只读 /etc 与
		// /run 覆盖面）。
		{ID: "udev_rules", Name: "udev 规则链",
			Fragment: func(*Env) string {
				return "cat /etc/udev/rules.d/*.rules /run/udev/rules.d/*.rules 2>/dev/null"
			}},
		// at 一次性任务面：计划任务的旁路（攻击者用 at 逃过 cron 检查
		// 面）。进上下文 + state_at 漂移兜底（任务新增即痕）。
		{ID: "at_jobs", Name: "at 任务队列",
			Fragment: func(*Env) string {
				return "atq 2>/dev/null; ls /var/spool/at/ /var/spool/atd/ 2>/dev/null"
			}},
		// 自定义 systemd 单元面：/etc/systemd/system 下的单元文件与
		// .d 覆盖（override.conf）是持久化藏身处——攻击者写 .service
		// 或 override 劫持既有服务。进上下文 + state_systemd_custom
		// 漂移兜底（新增单元文件即痕）。maxdepth 2 含 .d 覆盖文件；
		// -type f 排除 .wants/.requires 目录的发行版符号链接（噪音）。
		// find 定点带 timeout 护栏 + 完成哨兵（规格书约束）。
		{ID: "systemd_custom", Name: "自定义 systemd 单元",
			Class: FactTargeted,
			Fragment: func(*Env) string {
				return BoundedProbe("find /etc/systemd/system -maxdepth 2 -type f -printf '%p\\n' 2>/dev/null", 20)
			}},
		// SELinux 状态：防护面关闭（Permissive/Disabled）是攻击面
		// 扩大的确定性事实。归属规则产 warn 线索（未启用 SELinux 的
		// 发行版无输出不产线；启用后放宽由 DeepDive 裁决）。
		{ID: "selinux_status", Name: "SELinux 状态",
			Fragment: func(*Env) string {
				return "getenforce 2>/dev/null || cat /sys/fs/selinux/enforce 2>/dev/null"
			}},
		// 关键配置文件 immutable 位（chattr +i）：防篡改加固与恶意
		// 防删（篡改者锁死文件防恢复）两面。lsattr 定点关键文件，
		// 含 i 属性产线（DeepDive 裁决加固 vs 恶意）。
		{ID: "immutable_files", Name: "关键文件 immutable 属性",
			Fragment: func(*Env) string {
				return "lsattr -d /etc/passwd /etc/shadow /etc/ssh/sshd_config /etc/sudoers /etc/crontab /etc/ld.so.preload /etc/hosts 2>/dev/null"
			}},
		// 最近登录痕迹：成功登录会话列表（入侵痕迹进上下文——模型
		// 裁决异常来源/时间；last 依赖 wtmp，精简容器无数据不产线）。
		{ID: "login_trail", Name: "最近登录痕迹",
			Fragment: func(*Env) string {
				return "last -n 20 2>/dev/null"
			}},
	}
	if env.HasSystemd {
		// 运行中服务单元：监听端口归属判定的依据（sshd.service→sshd）。
		list = append(list, Metric{ID: "svc_units", Name: "运行中服务单元",
			Fragment: func(*Env) string {
				return "systemctl list-units --type=service --state=running --no-legend 2>/dev/null | awk '{print $1}'"
			}})
	}
	// Kubernetes 面（目标主机 kubectl 可用时自动产出数据）：对象级状态/
	// 配额/敏感配置（名称级，值不进引擎），见 metrics_k8s.go。
	list = append(list, k8sSecurityFacts()...)
	// LVM 拓扑（VG/LV 尺寸与剩余空间，扩容决策数据面），见 metrics_lvm.go。
	list = append(list, lvmFacts()...)
	// 等保常规加固检查（密码策略/时间同步/umask/审计日志/防火墙默认
	// 策略），见 metrics_hardening.go。
	list = append(list, hardeningFacts()...)
	return list
}

// stateProbeFragment 返回状态快照探针的采集命令（漂移线索定位用——
// 模型知道变化源是哪个文件/命令才能裁决变化是否预期）。
