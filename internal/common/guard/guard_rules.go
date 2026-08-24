package guard

import (
	"path"
	"regexp"
	"strings"
)

// guard_rules.go — 高危命令规则集：硬性禁止/可批准规则与命中正则（机械强制，非提示词约束）。

type riskyRule struct {
	name    string // 规则名
	explain string // 面向操作员的风险说明
	hard    bool   // 硬性禁止：即使操作员同意也不放行
	// dynamic 标记内容无法静态还原的执行方式（解码管道、解释器 -c 等）：
	// 用原始命令串匹配，不参与解包后的常规匹配。
	dynamic bool
	match   func(stripped string, tokens []string) bool
}

// riskyRules 按顺序匹配，先命中先生效：硬性禁止规则必须排在可批准规则
// 之前（例如 rm -rf / 同时命中 recursive-delete，但 root-delete 在先）。
var riskyRules = []riskyRule{
	// ── 硬性禁止：凭证零泄露（模型不得接触任何凭证材料）──
	{
		name: "credential-read", hard: true,
		explain: "凭证文件/私钥——严禁进入模型上下文（防泄露给外部大模型）；请由操作员本机自行处理",
		match: func(s string, _ []string) bool {
			// 词法归一后再匹配一遍：/etc/sha""dow、/e'tc'/shadow、/etc/./shadow
			// 等引号拼接/点段写法拼回原路径后同样拦截（防子串绕过）。
			return credentialPathRe.MatchString(s) || credentialPathRe.MatchString(normalizeCred(s))
		},
	},
	{
		name: "ssh-self-connect", hard: true,
		explain: "请使用 remote_terminal 工具执行远程命令（凭证由本机保管，不经模型）；ssh/scp/sftp 会绕过审计与守卫",
		match: func(_ string, t []string) bool {
			if len(t) == 0 {
				return false
			}
			switch baseName(t[0]) {
			case "ssh", "scp", "sftp", "sshpass", "ssh-copy-id":
				return true
			case "rsync":
				// 仅拦截含远端目标的 rsync（user@host: 或 ::）
				return strings.Contains(strings.Join(t, " "), "@") || strings.Contains(strings.Join(t, " "), "::")
			}
			return false
		},
	},
	{
		name: "plaintext-password", hard: true,
		explain: "命令中出现明文密码（数据库客户端 -p/-a 后接密码或 user:pass@URL）——严禁进入模型上下文",
		match: func(s string, t []string) bool {
			if len(t) > 0 {
				bin := baseName(t[0])
				if isOneOf(bin, "mysql", "mysqldump", "mysqladmin", "mariadb",
					"psql", "pg_dump", "pg_restore", "mongo", "mongosh", "clickhouse-client") {
					for _, tok := range t[1:] {
						if strings.HasPrefix(tok, "-p") && len(tok) > 2 && !isAllDigits(tok[2:]) {
							return true // mysql -psecret 等（-p5432 端口写法不拦）
						}
					}
				}
				if bin == "redis-cli" {
					for _, tok := range t[1:] {
						if strings.HasPrefix(tok, "-a") && len(tok) > 2 {
							return true // redis-cli -asecret
						}
					}
				}
			}
			return urlUserPassRe.MatchString(s)
		},
	},

	// ── 硬性禁止：数据不可恢复 / 系统不可用 ──
	{
		name: "root-delete", hard: true, explain: "删除根目录/家目录（不可恢复）",
		match: func(_ string, t []string) bool {
			if len(t) < 2 || baseName(t[0]) != "rm" {
				return false
			}
			for _, tok := range t[1:] {
				// 变体归一：rm -rf /.、rm -rf //、rm -rf /./ 与 rm -rf / 同义
				// （此前只匹配裸 "/"，变体退化为可批准的 recursive-delete，
				// 硬禁止语义失效）。
				if path.Clean(tok) == "/" || path.Clean(tok) == "/*" || tok == "~" {
					return true
				}
			}
			return false
		},
	},
	{
		name: "mkfs", hard: true, explain: "格式化文件系统（数据不可恢复）",
		match: func(_ string, t []string) bool {
			return len(t) > 0 && strings.HasPrefix(baseName(t[0]), "mkfs")
		},
	},
	{
		name: "dd-device", hard: true, explain: "dd 直接写入块设备（数据不可恢复）",
		match: func(_ string, t []string) bool {
			if len(t) == 0 || baseName(t[0]) != "dd" {
				return false
			}
			for _, tok := range t[1:] {
				if strings.HasPrefix(tok, "of=/dev/sd") ||
					strings.HasPrefix(tok, "of=/dev/hd") ||
					strings.HasPrefix(tok, "of=/dev/vd") ||
					strings.HasPrefix(tok, "of=/dev/xvd") ||
					strings.HasPrefix(tok, "of=/dev/nvme") ||
					strings.HasPrefix(tok, "of=/dev/mmcblk") ||
					strings.HasPrefix(tok, "of=/dev/mapper") {
					return true
				}
			}
			return false
		},
	},
	{
		name: "device-redirect", hard: true, explain: "重定向写入块设备（数据不可恢复）",
		match: func(s string, _ []string) bool { return deviceRedirectRe.MatchString(s) },
	},
	{
		name: "disk-wipe", hard: true, explain: "擦除磁盘元数据/整盘（数据不可恢复）",
		match: firstTokenIn("wipefs", "blkdiscard"),
	},
	{
		name: "fork-bomb", hard: true, explain: "fork 炸弹（系统不可用）",
		match: func(s string, _ []string) bool { return forkBombRe.MatchString(s) },
	},

	// ── 硬性禁止：内容不可静态还原的动态执行（混淆绕过的最后防线）──
	{
		name: "decode-pipe-shell", hard: true, dynamic: true,
		explain: "base64/xxd/openssl 解码后管道执行——内容无法审计，正常运维无此用法",
		match:   func(s string, _ []string) bool { return decodePipeRe.MatchString(s) },
	},
	{
		name: "xargs-exec", hard: true, dynamic: true,
		explain: "xargs 代执行 shell——批量代执行内容无法静态审计，正常运维无此用法",
		match:   func(s string, _ []string) bool { return xargsExecRe.MatchString(s) },
	},
	{
		name: "subst-exec", hard: true, dynamic: true,
		explain: "命令替换获取内容后执行（sh -c $(curl/wget…)）——内容无法审计，正常运维无此用法",
		match:   func(s string, _ []string) bool { return substExecRe.MatchString(s) },
	},
	{
		name: "interp-c-dangerous", hard: true, dynamic: true,
		explain: "解释器 -c/-e 内嵌破坏性代码（os.system/subprocess 等）",
		match: func(s string, _ []string) bool {
			body, ok := matchInterpC(s)
			return ok && interpDangerRe.MatchString(body)
		},
	},
	{
		name: "eval-exec", hard: true,
		explain: "eval 动态执行（内容无法静态审计，正常运维无此用法）",
		match:   firstTokenIn("eval"),
	},

	// ── 硬性禁止：系统不可用（宕机类，任何策略都拒绝）──
	{
		name: "reboot", hard: true, explain: "系统重启/关机（服务器宕机）",
		match: func(_ string, t []string) bool {
			if len(t) == 0 {
				return false
			}
			switch baseName(t[0]) {
			case "reboot", "shutdown", "halt", "poweroff":
				return true
			case "init", "telinit":
				return len(t) > 1 && (t[1] == "0" || t[1] == "6")
			case "systemctl":
				// systemctl reboot/poweroff/halt/kexec 与裸命令同义（宕机类）。
				for _, tok := range t[1:] {
					if strings.HasPrefix(tok, "-") {
						continue
					}
					return isOneOf(tok, "reboot", "poweroff", "halt", "kexec")
				}
			}
			return false
		},
	},

	// ── 可批准：常见运维变更，按策略放行/确认 ──
	{
		name: "service-lifecycle", explain: "服务生命周期变更（start/stop/restart/mask/enable/disable 等）",
		match: func(_ string, t []string) bool {
			if len(t) < 2 || baseName(t[0]) != "systemctl" {
				return false
			}
			for _, tok := range t[1:] {
				if strings.HasPrefix(tok, "-") {
					continue
				}
				return isOneOf(tok,
					"start", "stop", "restart", "try-restart", "reload", "reload-or-restart",
					"kill", "mask", "unmask", "enable", "disable", "isolate", "emergency",
					"rescue", "halt", "poweroff", "reboot", "kexec", "switch-root", "set-default")
			}
			return false
		},
	},
	{
		name: "legacy-service", explain: "SysV 服务启停（service 命令）",
		match: func(_ string, t []string) bool {
			if len(t) < 3 || baseName(t[0]) != "service" {
				return false
			}
			return isOneOf(t[2], "start", "stop", "restart", "reload", "force-reload", "kill")
		},
	},
	{
		name: "kill", explain: "终止进程（kill/pkill/killall）",
		match: firstTokenIn("kill", "pkill", "killall", "killall5"),
	},
	{
		name: "user-admin", explain: "用户/账号管理",
		match: firstTokenIn("useradd", "usermod", "userdel", "adduser", "deluser",
			"passwd", "chpasswd", "chage", "groupadd", "groupdel", "groupmod", "gpasswd"),
	},
	{
		name: "su-exec", explain: "以其他用户身份执行命令（su -c）",
		match: func(_ string, t []string) bool {
			return len(t) > 0 && baseName(t[0]) == "su" &&
				(containsFlag(t[1:], "-c") || containsFlag(t[1:], "--command"))
		},
	},
	{
		name: "package-mgmt", explain: "安装/卸载/升级软件包",
		match: func(_ string, t []string) bool {
			if len(t) < 2 {
				return false
			}
			bin := baseName(t[0])
			switch bin {
			case "apt", "apt-get":
				return isOneOf(t[1], "install", "remove", "purge", "autoremove", "upgrade", "dist-upgrade", "full-upgrade")
			case "yum", "dnf":
				return isOneOf(t[1], "install", "remove", "erase", "update", "upgrade", "downgrade", "autoremove")
			case "apk":
				return isOneOf(t[1], "add", "del", "upgrade", "update")
			case "zypper":
				return isOneOf(t[1], "install", "remove", "update", "dist-upgrade", "patch")
			case "pacman":
				return isOneOf(t[1], "-S", "-R", "-U", "-Sy", "-Su", "-Syu", "-Sc")
			case "pip", "pip3":
				return isOneOf(t[1], "install", "uninstall")
			}
			return false
		},
	},
	{
		name: "firewall", explain: "防火墙规则变更",
		match: func(_ string, t []string) bool {
			if len(t) == 0 {
				return false
			}
			switch baseName(t[0]) {
			case "iptables", "ip6tables":
				return firewallMutates(t[1:])
			case "nft":
				return nftMutates(t[1:])
			case "ufw":
				return len(t) > 1 && isOneOf(t[1], "enable", "disable", "reset", "reload",
					"delete", "allow", "deny", "limit", "default")
			case "firewall-cmd":
				return containsFlag(t[1:], "--permanent") || containsFlag(t[1:], "--reload") ||
					containsFlag(t[1:], "--complete-reload")
			}
			return false
		},
	},
	{
		name: "partition", explain: "磁盘分区操作",
		match: firstTokenIn("fdisk", "cfdisk", "sfdisk", "gdisk", "sgdisk", "parted"),
	},
	// ── 证据面（P0 修复）：清除/旋转证据的操作。排查对象是故障本身，
	// 不是故障留下的日志——dmesg -c 清空内核环形缓冲、journalctl 轮转/
	// 清理日志会让探针"看着痊愈"而故障仍在（chaos-r1 实测：引擎用
	// dmesg -c 清除 OOM 证据假装处置）。规则为可批准类：交互形态可经
	// 操作员确认执行；auto 形态经风险审查（guard_impact evidence 面）
	// 与处置契约校验双重拦截。
	{
		name: "dmesg-clear", explain: "清空内核环形缓冲（dmesg -c/-C）——清除内核故障证据，故障排查期间禁止；查看用 dmesg（不带 -c）",
		match: func(_ string, t []string) bool {
			if len(t) == 0 || baseName(t[0]) != "dmesg" {
				return false
			}
			for _, tok := range t[1:] {
				if tok == "-c" || tok == "-C" || tok == "--clear" || tok == "--read-clear" {
					return true
				}
			}
			return false
		},
	},
	{
		name: "journal-evidence", explain: "轮转/清理 journald 日志（--rotate/--vacuum*）——清除系统日志证据，故障排查期间禁止",
		match: func(_ string, t []string) bool {
			if len(t) == 0 || baseName(t[0]) != "journalctl" {
				return false
			}
			for _, tok := range t[1:] {
				if tok == "--rotate" || tok == "--vacuum" || tok == "--vacuum-size" ||
					tok == "--vacuum-time" || tok == "--vacuum-files" || tok == "--flush" {
					return true
				}
			}
			return false
		},
	},
	{
		name: "umount-system-dir", explain: "卸载标准系统目录下的挂载点（/var/log、/var/spool、/root、/etc、/home 等）——日志/配置挂载卸载会改变证据面与业务日志落点，需人工确认",
		match: func(_ string, t []string) bool {
			if len(t) == 0 || baseName(t[0]) != "umount" {
				return false
			}
			for _, tok := range t[1:] {
				if strings.HasPrefix(tok, "-") {
					continue
				}
				if maskedSystemDir(tok) {
					return true
				}
			}
			return false
		},
	},
	{
		name: "mount", explain: "挂载/卸载文件系统",
		match: firstTokenIn("mount", "umount", "swapon", "swapoff"),
	},
	{
		name: "recursive-delete", explain: "递归删除文件（rm -r）",
		match: func(_ string, t []string) bool {
			if len(t) < 2 || baseName(t[0]) != "rm" {
				return false
			}
			for _, tok := range t[1:] {
				if strings.HasPrefix(tok, "-") && strings.Contains(tok, "r") {
					return true // -r / -rf / -fr / --recursive
				}
			}
			return false
		},
	},
	{
		name: "inplace-edit", explain: "原地修改文件（sed/awk/perl -i）",
		match: func(_ string, t []string) bool {
			if len(t) < 2 {
				return false
			}
			bin := baseName(t[0])
			if bin != "sed" && bin != "awk" && bin != "perl" {
				return false
			}
			for _, tok := range t[1:] {
				if tok == "-i" || tok == "--in-place" || tok == "-inplace" ||
					tok == "-i.bak" || strings.HasPrefix(tok, "-i.") {
					return true
				}
			}
			return false
		},
	},
	{
		name: "tee-system", explain: "向系统目录写入文件（tee）",
		match: func(_ string, t []string) bool {
			for i, tok := range t {
				if baseName(tok) != "tee" {
					continue
				}
				for _, p := range t[i+1:] {
					if strings.HasPrefix(p, "/etc/") || strings.HasPrefix(p, "/usr/") ||
						strings.HasPrefix(p, "/var/lib/") || strings.HasPrefix(p, "/boot/") ||
						strings.HasPrefix(p, "/root/") {
						return true
					}
				}
			}
			return false
		},
	},
	{
		name: "remote-exec", explain: "执行远程下载的脚本（curl|wget 管道给 sh）",
		match: func(s string, _ []string) bool { return remotePipeRe.MatchString(s) },
	},
	{
		name: "crontab", explain: "修改计划任务",
		match: func(_ string, t []string) bool {
			return len(t) > 1 && baseName(t[0]) == "crontab" && t[1] != "-l" && t[1] != "--list"
		},
	},
	{
		name: "docker", explain: "容器/镜像操作（stop/rm/rmi/prune 等）",
		match: func(_ string, t []string) bool {
			if len(t) < 2 {
				return false
			}
			bin := baseName(t[0])
			if bin != "docker" && bin != "podman" {
				return false
			}
			if isOneOf(t[1], "stop", "kill", "rm", "rmi", "prune", "restart", "pause", "unpause", "down") {
				return true
			}
			return t[1] == "compose" && len(t) > 2 &&
				isOneOf(t[2], "down", "stop", "rm", "restart", "kill")
		},
	},
	{
		name: "recursive-chmod", explain: "递归修改权限/属主（-R）",
		match: func(_ string, t []string) bool {
			if len(t) < 2 {
				return false
			}
			bin := baseName(t[0])
			if bin != "chmod" && bin != "chown" && bin != "chgrp" && bin != "chattr" {
				return false
			}
			for _, tok := range t[1:] {
				if strings.HasPrefix(tok, "-") && strings.Contains(tok, "R") {
					return true
				}
			}
			return false
		},
	},
	{
		name: "script-exec", explain: "执行脚本文件/heredoc（内容不可静态审计，需确认）",
		match: func(s string, t []string) bool {
			if len(t) == 0 {
				return false
			}
			bin := baseName(t[0])
			switch bin {
			case "sh", "bash", "zsh", "dash", "ksh", "ash", "source", ".":
			default:
				// ./script.sh 等直接执行形态（shell 脚本直接运行）。python/perl
				// 等解释器脚本不拦（模型生成脚本再执行的常规用法），只拦 shell 系。
				if !strings.Contains(t[0], "/") || !strings.HasSuffix(strings.ToLower(t[0]), ".sh") {
					return false
				}
				return true
			}
			// heredoc 形态：sh <<EOF …（内容在命令串内，无法静态审计）。
			if strings.Contains(s, "<<") {
				return true
			}
			// 文件参数形态：bash fix.sh / source profile / . ./env.sh。
			for _, tok := range t[1:] {
				if strings.HasPrefix(tok, "-") {
					continue
				}
				return true
			}
			return false
		},
	},
	{
		name: "symlink-create", explain: "创建符号链接（可指向任意界外文件）",
		match: func(_ string, t []string) bool {
			if len(t) < 2 || baseName(t[0]) != "ln" {
				return false
			}
			for _, tok := range t[1:] {
				if tok == "-s" || tok == "--symbolic" || tok == "-sf" || tok == "-snf" {
					return true
				}
			}
			return false
		},
	},
	{
		name: "write-system-path", explain: "重定向写入系统目录（/etc、/usr、cron、/root、/proc、/sys 等——配置/计划任务/内核参数落盘）",
		match: func(s string, _ []string) bool { return writeSysPathRe.MatchString(s) },
	},
	{
		name: "sysctl-write", explain: "修改内核参数（sysctl -w，运行时生效）",
		match: func(_ string, t []string) bool {
			if len(t) < 2 || baseName(t[0]) != "sysctl" {
				return false
			}
			for _, tok := range t[1:] {
				if tok == "-w" || tok == "--write" {
					return true
				}
			}
			return false
		},
	},
	{
		name: "privilege-chmod", explain: "设置 setuid/setgid/sticky 提权位（chmod 4/6/7xxx 或 u+s 符号形态）",
		match: func(_ string, t []string) bool {
			if len(t) < 2 || baseName(t[0]) != "chmod" {
				return false
			}
			for _, tok := range t[1:] {
				if strings.HasPrefix(tok, "-") {
					continue
				}
				// 4 位八进制模式：首字符 4/6/7 = setuid/setgid/sticky 组合
				// （3 位模式 755 是 0755，无特殊位，不拦）。
				if len(tok) == 4 && isAllDigits(tok) && strings.ContainsRune("467", rune(tok[0])) {
					return true
				}
				// 符号形态：u+s / g+s / +s / =s。
				if strings.Contains(tok, "+s") || strings.Contains(tok, "=s") {
					return true
				}
				break
			}
			return false
		},
	},
}

// maskedSystemDir 证据面标准目录（与 probe 挂载掩盖清单同族）：日志/
	// 计划任务/凭证/配置目录卸载 = 证据面变更，需人工确认。
func maskedSystemDir(p string) bool {
	clean := path.Clean(p)
	for _, d := range []string{"/var/log", "/var/spool", "/root", "/etc", "/home", "/var/lib"} {
		if clean == d || strings.HasPrefix(clean, d+"/") {
			return true
		}
	}
	return false
}

// credentialPathRe 匹配命令/路径中的凭证材料（私钥、shadow、云凭据、
// 数据库密码文件、主机清单等）。含裸目录形态（"~/.ssh"、".gocode" 结尾
// 不带尾随斜杠——传输工具 local_dir 与目录列举的典型形态；仅带斜杠
// 形态会漏掉"写入凭证目录"本身）。
var credentialPathRe = regexp.MustCompile(`(?i)(/\.ssh/|\.ssh/|(?:^|[/\\])\.ssh$|/etc/shadow|/etc/gshadow|/etc/security/opasswd|/\.gocode/|\.gocode/|(?:^|[/\\])\.gocode$|\.aws/|\.azure/|\.kube/|\.my\.cnf|\.pgpass|\.netrc|\.pem|\.key\b|\.p12|\.pfx|id_rsa|id_dsa|id_ecdsa|id_ed25519)`)

// urlUserPassRe 匹配 URL 内嵌明文凭证（scheme://user:pass@host）。
var urlUserPassRe = regexp.MustCompile(`://[^/@\s]+:[^/@\s]+@`)

// deviceRedirectRe 匹配 `>/dev/sdX` 之类的重定向写入（sh -c 常见写法）。
// 后缀允许数字（nvme0n1/mmcblk0），并覆盖 virtio（vd）、xvd 与 mapper。
var deviceRedirectRe = regexp.MustCompile(`(^|[;&|()\s])\s*>+\s*/dev/(sd|hd|vd|nvme|mmcblk|xvd)[a-z0-9]+|(^|[;&|()\s])\s*>+\s*/dev/mapper/`)

// forkBombRe 匹配通用 fork 炸弹形态 `f(){ f|f&};f`（含 `:(){ :|:& };:`）。
var forkBombRe = regexp.MustCompile(`\(\s*\)\s*\{[^}\n]*\|[^}\n]*&[^}\n]*\}`)

// xargsExecRe 匹配 xargs 代执行 shell（xargs -I{} sh -c {}）。
var xargsExecRe = regexp.MustCompile(`(?i)\bxargs\b[^\n;]*\b(?:sh|bash|zsh|dash|ksh|ash)\b`)

// substExecRe 匹配 sh -c "$(curl/wget/base64/...)" 命令替换获取内容后执行。
// 覆盖下载类（curl/wget/aria2c/nc/netcat）与解码类（base64/xxd/openssl）
// ——解码内容同样无法静态审计（`sh -c "$(base64 -d <<< ...)"` 形态没有
// 管道，decode-pipe-shell 不命中，必须由命令替换规则兜住）。
var substExecRe = regexp.MustCompile(`(?i)(?:sh|bash|zsh|dash|ksh|ash)(?:\s+-[a-z]+)*\s+-c\s+[^;\n]*\$\([^)\n]*(?:curl|wget|aria2c|nc\b|netcat|base64|xxd|openssl)`)

// remotePipeRe 匹配 curl|wget 管道给 (ba)sh 的执行模式。
var remotePipeRe = regexp.MustCompile(`(?i)(curl|wget|aria2c)\b[^;\n]*\|\s*(sudo\s+)?(ba)?sh\b`)

// writeSysPathRe 匹配重定向写入系统目录（echo/cat/printf > 系统路径；
// tee-system 规则只覆盖 tee 命令，重定向形态此前无规则）。/dev/null
// 是丢弃输出的合法写法，不拦（真实设备写入由 deviceRedirectRe 兜住）。
var writeSysPathRe = regexp.MustCompile(`>+\s*(?:/etc/|/usr/|/var/spool/cron|/root/|/boot/|/proc/|/sys/|/run/)`)

// normalizeCred 凭证检测前的词法归一：剥离引号拼接（/etc/sha""dow、
// /e'tc'/shadow 拼回 /etc/shadow）、路径点段（/etc/./shadow → /etc/shadow）
