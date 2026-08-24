package probe

import (
	"github.com/go-gocel/gocode-ops/internal/common/fsutil"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// judge_weak.go — 弱配置判定辅助：SSH 策略行/sudo 规则/环境注入/挂载掩蔽/SUID 目录判定。

func parseSizeMB(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	unit := 1.0
	num := s
	up := strings.ToUpper(s)
	switch {
	case strings.HasSuffix(up, "G"):
		unit, num = 1024, s[:len(s)-1]
	case strings.HasSuffix(up, "M"):
		num = s[:len(s)-1]
	case strings.HasSuffix(up, "K"):
		unit, num = 1.0/1024, s[:len(s)-1]
	default:
		unit = 1.0 / 1024 / 1024 // 无后缀 = 字节（systemd 语义）
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(num), 64)
	if err != nil || v < 0 {
		return 0, false
	}
	return v * unit, true
}

// sshWeakRe 提取 SSH 弱化指令候选（关键字级，具体判定在 sshWeakViolation）。
var sshWeakRe = regexp.MustCompile(`(?i)^(PermitEmptyPasswords|IgnoreRhosts|PermitTunnel|PermitUserEnvironment|PrintLastLog|ClientAliveCountMax|KexAlgorithms|Ciphers|MaxAuthTries|MaxSessions|LoginGraceTime|MaxStartups|AuthorizedKeysFile|Subsystem|LogLevel|GatewayPorts)\b`)

// sshWeakViolation 判定 SSH 有效行是否弱化基线违规（CIS 2.2 系列硬基线）：
// 空密码/rhosts 信任/隧道/用户环境/登录痕迹关闭/会话保活关闭/弱 KEX/
// 弱加密/认证尝试放宽/会话数放宽/登录宽限期放宽/并发放宽/授权文件
// 改道/sftp 子系统替换/调试日志。
func sshWeakViolation(line string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 || !sshWeakRe.MatchString(line) {
		return "", false
	}
	key := strings.ToLower(fields[0])
	val := strings.Join(fields[1:], " ")
	switch key {
	case "permitemptypasswords", "permittunnel", "permituserenvironment":
		if strings.EqualFold(strings.TrimSpace(fields[1]), "yes") {
			return key + " yes", true
		}
	case "gatewayports":
		// SSH 隧道网关（CIS 2.x 硬基线：应为 no——开启即任意端口转发
		// 出口，内网可达性经 SSH 隧道外泄）。
		if strings.EqualFold(strings.TrimSpace(fields[1]), "yes") {
			return key + " yes", true
		}
	case "ignorerhosts", "printlastlog":
		if strings.EqualFold(strings.TrimSpace(fields[1]), "no") {
			return key + " no", true
		}
	case "clientalivecountmax":
		if strings.TrimSpace(fields[1]) == "0" {
			return key + " 0", true
		}
	case "kexalgorithms":
		if weakKexRe.MatchString(val) {
			return "弱 KEX 算法 " + fsutil.TruncateStr(val, 60), true
		}
	case "ciphers":
		if weakCipherRe.MatchString(val) {
			return "弱加密算法 " + fsutil.TruncateStr(val, 60), true
		}
	case "maxauthtries", "maxsessions":
		if n, err := strconv.Atoi(strings.TrimSpace(fields[1])); err == nil && n > 10 {
			return key + " " + fields[1] + "（基线 ≤10）", true
		}
	case "logingracetime":
		if n, err := strconv.Atoi(strings.TrimSpace(fields[1])); err == nil && n > 120 {
			return key + " " + fields[1] + "（基线 ≤120s）", true
		}
	case "maxstartups":
		if p := strings.SplitN(strings.TrimSpace(fields[1]), ":", 2)[0]; p != "" {
			if n, err := strconv.Atoi(p); err == nil && n > 10 {
				return key + " " + fields[1] + "（基线首值 ≤10）", true
			}
		}
	case "authorizedkeysfile":
		// 授权文件必须恰好等于默认单路径（.ssh/authorized_keys 或 root 的
		// 绝对路径等价）——攻击者保留默认路径再追加后门密钥文件（实测
		// ".ssh/authorized_keys /root/.ssh/.evil-keys" 双路径）时，"包含
		// 默认即正常"的旧规则被绕过（R24 实测：判定层盲区导致处置后
		// 确定性复检假放行）。多路径/替换路径一律违规。
		if !authorizedKeysDefaultOnly(val) {
			return key + " " + fsutil.TruncateStr(val, 60) + "（非默认授权文件）", true
		}
	case "subsystem":
		if len(fields) >= 3 && strings.EqualFold(fields[1], "sftp") &&
			!strings.HasPrefix(strings.TrimSpace(fields[2]), "/usr/libexec/openssh/sftp-server") {
			return "sftp 子系统替换 " + fields[2], true
		}
	case "loglevel":
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(fields[1])), "DEBUG") {
			return "loglevel " + fields[1] + "（调试日志泄露面）", true
		}
	}
	return "", false
}

// authorizedKeysDefaultOnly 授权文件路径是否恰好等于 sshd 默认单路径：
// 相对形态 .ssh/authorized_keys（sshd 默认，相对用户 home）或 root 的
// 绝对路径等价 /root/.ssh/authorized_keys。多路径（攻击者追加后门密钥
// 文件）、替换路径、其他绝对路径一律非默认（R24 实测双路径绕过）。
func authorizedKeysDefaultOnly(val string) bool {
	paths := strings.Fields(val)
	if len(paths) != 1 {
		return false
	}
	p := paths[0]
	if p == ".ssh/authorized_keys" {
		return true
	}
	dir, base := path.Split(p)
	d := strings.TrimSuffix(dir, "/")
	return base == "authorized_keys" && (d == "/root/.ssh" || d == "~/.ssh")
}

// weakKexRe 弱密钥交换算法（历史遗留/破解面）。
var weakKexRe = regexp.MustCompile(`(?i)(sha1|group1|group-exchange-sha1)`) // weakCipherRe 弱加密算法（CBC 遗留/破解面）。
var weakCipherRe = regexp.MustCompile(`(?i)(3des|blowfish|arcfour|-cbc\b|cast128)`)

// cronExecRe 计划任务条目管道到 shell 的执行注入模式。
var cronExecRe = regexp.MustCompile(`\|\s*(/usr/bin/|/bin/)?(ba)?sh\b`)

// persistExecRe 持久化执行注入形态（rc.local/启动链内容行判定）：
// 与 shell_init_hooks 采集侧 grep 模式同族——下载即执行、反连、
// 解码执行。模式与具体载荷解耦（通用痕迹形态）。
var persistExecRe = regexp.MustCompile(`(?i)(curl|wget|aria2c|nc\b|netcat)\b[^|]*\|\s*(ba)?sh\b|/dev/tcp/|b64decode|base64[[:space:]]+-d`)

// envInjectRe 全局环境变量 LD_* 注入：LD_PRELOAD/LD_LIBRARY_PATH/
// LD_AUDIT 对动态链接器生效（全会话库劫持面）。
var envInjectRe = regexp.MustCompile(`(?i)(^|\s)(LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT|LD_DEBUG)=`)

// envPathSuspiciousRe 全局 PATH 指向可写目录（命令劫持面）：/tmp、
// /dev/shm、/var/tmp、/home 下的目录对任意用户可写。
var envPathSuspiciousRe = regexp.MustCompile(`(?i)(^|\s)PATH=(.*[:"])?(/tmp|/dev/shm|/var/tmp|/home/)[^":]*`)

// udevInjectRe udev 规则执行体指向可写目录：RUN/RUN+/PROGRAM 的赋值
// 目标含 /tmp、/dev/shm、/var/tmp、/home 即设备事件持久化注入面
// （发行版默认规则在 /lib/udev/rules.d，不在此探针覆盖面内）。
// 不锚定行首——udev 规则是 KERNEL=="...", RUN+="..." 结构，执行体
// 关键字出现在行中。
var udevInjectRe = regexp.MustCompile(`(?i)(RUN|PROGRAM)(\+)?=.*(/tmp|/dev/shm|/var/tmp|/home/)`)

// standardLibDir 动态链接器搜索路径是否发行版标准库目录（白名单）：
// /usr/lib*、/lib*、/usr/local/lib*。其余路径（/tmp、/var、/opt、
// /root、相对路径等）即异常注入面。
func standardLibDir(p string) bool {
	for _, prefix := range []string{"/usr/local/lib", "/usr/lib", "/lib"} {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}

// sudoWeakViolation sudo 授权链弱化基线：万能免密（NOPASSWD 覆盖
// 全部命令）或危险 Defaults 键（跨 tty 凭据共享/环境继承）。
func sudoWeakViolation(line string) bool {
	if strings.Contains(line, "NOPASSWD:") {
		rest := strings.ToUpper(line[strings.Index(line, "NOPASSWD:"):])
		if strings.Contains(rest, "ALL") {
			return true
		}
	}
	if strings.HasPrefix(line, "Defaults") {
		for _, bad := range []string{"!tty_tickets", "!env_reset", "!secure_path", "!mail_always"} {
			if strings.Contains(line, bad) {
				return true
			}
		}
	}
	return false
}

// isPublicIPv4 判定 IPv4 字面量是否为公网地址（私有/回环/链路本地/
// 运营商级 NAT 之外的即公网）。
func isPublicIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	var b [4]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
		b[i] = n
	}
	switch {
	case b[0] == 127, b[0] == 10:
		return false
	case b[0] == 172 && b[1] >= 16 && b[1] <= 31:
		return false
	case b[0] == 192 && b[1] == 168:
		return false
	case b[0] == 169 && b[1] == 254:
		return false
	case b[0] == 100 && b[1] >= 64 && b[1] <= 127:
		return false // 运营商级 NAT
	case b[0] == 0, b[0] >= 224:
		return false // 本网络/组播/保留
	}
	return true
}

// containerRootfs 判断 mounts 原始输出是否为容器根文件系统形态：
// overlay（或 docker 常见根挂载）覆盖 "/" 即容器（宿主根通常为
// 真实设备如 /dev/sdaN /dev/nvme0n1pN）。用于容器运行时挂载的
// 环境感知豁免（不可用作唯一判定，数据缺失时返回 false 保守产线）。
func containerRootfs(mountsRaw string) bool {
	for _, line := range strings.Split(mountsRaw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if fields[1] == "/" && (fields[2] == "overlay" || strings.HasPrefix(fields[0], "overlay")) {
			return true
		}
	}
	return false
}

// parseMountLines 解析 mount 输出（采集侧已 awk 为 源 目标 类型 三列）。
func parseMountLines(raw string) []mountEntry {
	var out []mountEntry
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		out = append(out, mountEntry{src: fields[0], target: fields[1], fstype: fields[2]})
	}
	return out
}

// mountEntry 一条挂载记录。
type mountEntry struct {
	src, target, fstype string
}

// maskedMountDirs 挂载掩盖判定的标准系统目录（保守清单：日志/计划
// 任务/凭证目录被挂载覆盖即疑点；/tmp /dev/shm /run 是 systemd 容器
// 标准 tmpfs，/etc 下有 docker 标准 bind 挂载（resolv.conf/hosts/
// hostname），均不在此列避免常态误报）。
var maskedMountDirs = []string{"/var/log", "/var/spool", "/root"}

func maskedMount(target string) bool {
	for _, d := range maskedMountDirs {
		if strings.HasPrefix(target, d) {
			return true
		}
	}
	return false
}

// suidStandardDirs SUID 常规栖息目录（发行版默认 SUID 均在此列）。
// 保守清单：只排除标准二进制目录，/usr/lib 等可被攻击者利用的
// 隐藏路径不排除（R22 实测隐藏路径 SUID 漏检）。
var suidStandardDirs = []string{"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/libexec/"}

// suidStandardDir 判断 SUID 文件是否位于标准二进制目录（发行版默认
// SUID 栖息地，不产归属线索）。
func suidStandardDir(p string) bool {
	for _, d := range suidStandardDirs {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

// isBindSource 挂载源是否为另一挂载点路径（bind 挂载特征）：源以 /
// 开头且非设备文件（/dev/）。tmpfs/overlay 等伪文件系统源为关键字
// （tmpfs/overlay），不误标。
func isBindSource(src string) bool {
	return strings.HasPrefix(src, "/") && !strings.HasPrefix(src, "/dev/")
}

// judgeMap 单键指标的阈值判定。
