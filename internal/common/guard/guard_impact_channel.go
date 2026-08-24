package guard

// guard_impact_channel.go — 自影响审查·管理通道面：认证/服务/防火墙/网络/用户变更是否会锁死自身连接。

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/go-gocel/gocode-ops/internal/common/model"
)

// sshdConfRe 命中 sshd/pam 认证配置路径。
var sshdConfRe = regexp.MustCompile(`(?:sshd_config|/etc/ssh/|/etc/pam\.d/|/etc/pam_pkcs11/)`)

// writeOpRe 写操作动词（sed -i / tee / cp / 重定向 / install / truncate）。
var writeOpRe = regexp.MustCompile(`(?:^|\s)(?:sed|tee|cp|install|truncate)\b|(?:^|[;&|>\s])(?:echo|printf|cat|sh|bash)\s+[^|]*>`)

// authDirective 认证指令的禁用/启用形态。净效果按「后写覆盖先写」判定：
// 同一条指令最后一次出现决定落盘值——sed 把禁用改写为启用（s/no/yes/）
// 时启用在后 → 净效果启用（修复面放行）；启用改写为禁用或追加禁用 →
// 净效果禁用（切断面拒绝）。禁用形态只出现在 sed 模式侧、启用在后时
// 不构成落盘内容。
type authDirective struct {
	name    string
	disable *regexp.Regexp // 禁用形态（prl 类含捕获组，取最后一个匹配值）
	enable  *regexp.Regexp // 启用形态
}

// authDirectives 通道认证指令表（PermitRootLogin / 密码 / 密钥 / 其它认证）。
var authDirectives = []authDirective{
	{
		name:    "PermitRootLogin",
		disable: regexp.MustCompile(`PermitRootLogin\s+(no|without-password|prohibit-password|forced-commands-only)`),
		enable:  regexp.MustCompile(`PermitRootLogin\s+yes`),
	},
	{
		name:    "PasswordAuthentication",
		disable: regexp.MustCompile(`PasswordAuthentication\s+no`),
		enable:  regexp.MustCompile(`PasswordAuthentication\s+yes`),
	},
	{
		name:    "PubkeyAuthentication",
		disable: regexp.MustCompile(`PubkeyAuthentication\s+no`),
		enable:  regexp.MustCompile(`PubkeyAuthentication\s+yes`),
	},
	{
		name:    "other-auth",
		disable: regexp.MustCompile(`(?:ChallengeResponseAuthentication|KbdInteractiveAuthentication|UsePAM)\s+no`),
		enable:  regexp.MustCompile(`(?:ChallengeResponseAuthentication|KbdInteractiveAuthentication|UsePAM)\s+yes`),
	},
}

// lastReIndex / lastReMatch 正则最后一次出现的位置与完整匹配（含分组）。
func lastReIndex(re *regexp.Regexp, s string) int {
	locs := re.FindAllStringIndex(s, -1)
	if len(locs) == 0 {
		return -1
	}
	return locs[len(locs)-1][0]
}

func lastReMatch(re *regexp.Regexp, s string) []string {
	ms := re.FindAllStringSubmatch(s, -1)
	if len(ms) == 0 {
		return nil
	}
	return ms[len(ms)-1]
}

// authNetEffect 逐指令计算净效果：禁用形态最后一次出现晚于启用形态 →
// 净禁用。返回 prl 取值（PermitRootLogin 禁用形态的捕获组）与三个布尔。
func authNetEffect(cmd string) (prl []string, hasPwdNo, hasPubNo, hasOtherNo bool) {
	for _, d := range authDirectives {
		di := lastReIndex(d.disable, cmd)
		ei := lastReIndex(d.enable, cmd)
		if di < 0 || di <= ei {
			continue // 无禁用形态，或启用在后（净效果启用，修复面）
		}
		switch d.name {
		case "PermitRootLogin":
			prl = lastReMatch(d.disable, cmd)
		case "PasswordAuthentication":
			hasPwdNo = true
		case "PubkeyAuthentication":
			hasPubNo = true
		case "other-auth":
			hasOtherNo = true
		}
	}
	return
}

// assessChannelAuth 修改 sshd/pam 认证配置且净效果禁用登录方式。
// 对称例外：净效果禁用的恰好不是引擎当前认证方式时通道保留（如密钥登录 +
// 仅禁密码 → 放行），按连接事实逐台判定；净效果启用（修复面）一律放行。
func assessChannelAuth(cmd string, facts map[string]model.ConnFact) *model.ImpactRisk {
	if !writeOpRe.MatchString(cmd) || !sshdConfRe.MatchString(cmd) {
		return nil
	}
	prl, hasPwdNo, hasPubNo, hasOtherNo := authNetEffect(cmd)
	if prl == nil && !hasPwdNo && !hasPubNo && !hasOtherNo {
		return nil
	}
	for _, f := range facts {
		if channelBroken(f, prl, hasPwdNo, hasPubNo, hasOtherNo) {
			return &model.ImpactRisk{
				Category: impactChannelAuth,
				Reason:   fmt.Sprintf("修改 sshd/pam 认证配置并禁用了主机 %s 当前的登录方式（%s），引擎及操作员的 SSH 通道将被切断", f.Host, f.Auth),
				Advice:   "先为引擎配置保留的登录方式（hosts.yaml 配置 key_file 并注入公钥，或用 prohibit-password 保留密钥通道），再收紧认证；如需完全禁用请在人工会话中执行",
			}
		}
	}
	return nil
}

// channelBroken 判断动作是否切断该主机当前的登录通道。
func channelBroken(f model.ConnFact, prl []string, hasPwdNo, hasPubNo, hasOtherNo bool) bool {
	switch f.Auth {
	case "key":
		if hasPubNo || hasOtherNo {
			return true
		}
		if prl == nil {
			return false
		}
		// PermitRootLogin no / forced-commands-only 完全禁止或限制 root 密钥。
		return f.User == "root" && (prl[1] == "no" || prl[1] == "forced-commands-only")
	default: // password / none
		if hasPwdNo || hasOtherNo {
			return true
		}
		// 任何 PermitRootLogin 收紧都禁止 root 密码登录。
		if prl != nil && f.User == "root" {
			return true
		}
		return false
	}
}

// ── 通道面：sshd 监听端口变更 ────────────────────────────────────────

// portDirectiveRe 匹配命令中出现的 Port 指令值（含 sed 模式/替换两侧
// 与追加写入——认证指令同类处理；取最后一次出现为净效果：sed 把端口
// 改回当前端口属修复面放行，改成其他端口即断通道）。注释形态
// "#Port 22" 也会被匹配，但其值等于默认端口 22，在连接端口为 22 时
// 天然放行；连接端口非 22 时由净效果判定兜住。
var portDirectiveRe = regexp.MustCompile(`Port\s+(\d+)`)

// assessChannelPort 修改 sshd 配置且监听端口净效果改为非当前管理端口
// → 拒绝（任何策略；改回/保持当前端口 = 修复面放行）。
func assessChannelPort(cmd string, facts map[string]model.ConnFact) *model.ImpactRisk {
	if !writeOpRe.MatchString(cmd) || !sshdConfRe.MatchString(cmd) {
		return nil
	}
	matches := portDirectiveRe.FindAllStringSubmatch(cmd, -1)
	if len(matches) == 0 {
		return nil
	}
	last := matches[len(matches)-1][1]
	ports := map[string]bool{}
	for _, f := range facts {
		if f.Port != "" {
			ports[f.Port] = true
		}
	}
	if len(ports) == 0 {
		ports["22"] = true // 无连接事实时按 SSH 默认端口判定
	}
	if ports[last] {
		return nil // 净效果保持/改回当前管理端口：通道保留
	}
	return &model.ImpactRisk{
		Category: impactChannelPort,
		Reason:   fmt.Sprintf("修改 sshd 监听端口为 %s（当前管理端口 %s），引擎及操作员的 SSH 通道将被切断", last, sortedPorts(ports)),
		Advice:   "不要更改 sshd 监听端口；如需更换请先在防火墙/安全组放行新端口并保留当前端口连接",
	}
}

// ── 通道面：SSH 服务停用 ───────────────────────────────────────────

var sshSvcRe = regexp.MustCompile(`^(?:sshd|ssh|sshd\.service|ssh\.service|sshd\.socket|ssh\.socket)$`)

// assessChannelService 停用/屏蔽 sshd 服务，或杀死 sshd 主进程。
func assessChannelService(cmd, bin string, tokens []string) *model.ImpactRisk {
	switch bin {
	case "systemctl":
		for i, tok := range tokens {
			if i == 0 || strings.HasPrefix(tok, "-") {
				continue
			}
			if isOneOf(tok, "stop", "disable", "mask", "kill") {
				for _, svc := range tokens[i+1:] {
					if sshSvcRe.MatchString(strings.TrimSuffix(svc, ".service")) {
						return &model.ImpactRisk{
							Category: impactChannelService,
							Reason:   fmt.Sprintf("停用/屏蔽 SSH 服务（%s），引擎经 SSH 管理该主机，将立即失联", svc),
							Advice:   "先部署替代管理通道（密钥/备用端口/带外管理），再停用 SSH 服务；或保留服务只在人工会话中操作",
						}
					}
				}
			}
		}
	case "service":
		if len(tokens) >= 2 && sshSvcRe.MatchString(strings.TrimSuffix(tokens[1], ".service")) &&
			(len(tokens) < 3 || isOneOf(tokens[2], "stop", "kill")) {
			return &model.ImpactRisk{
				Category: impactChannelService,
				Reason:   "停止 SSH 服务（" + tokens[1] + "），引擎的管理通道将被切断",
				Advice:   "先部署替代管理通道，再停用 SSH 服务；或保留服务只在人工会话中操作",
			}
		}
	case "pkill", "killall":
		for _, tok := range tokens[1:] {
			if tok == "sshd" {
				return &model.ImpactRisk{
					Category: impactChannelService,
					Reason:   "杀死 sshd 主进程，引擎的管理通道将被切断",
					Advice:   "不要直接杀 sshd；如要重启服务请用 systemctl restart sshd（验证会确认服务恢复）",
				}
			}
		}
	}
	return nil
}

// ── 通道面：防火墙阻断管理端口 ─────────────────────────────────────

// firewallBlockRe 防火墙阻断动作（iptables/nft DROP/REJECT、ufw deny、
// firewall-cmd remove / 默认 zone 收窄为拒绝）。只读查询（-L/-n）不命中；
// 放行动作（ACCEPT/allow）不命中。
var firewallBlockRe = regexp.MustCompile(
	`(?:-A\s+INPUT|-I\s+INPUT|--append\s+INPUT|--insert\s+INPUT)[^;]*?-j\s+(?:DROP|REJECT)|` +
		`-P\s+INPUT\s+(?:DROP|REJECT)|` +
		`-j\s+(?:DROP|REJECT)|` +
		`ufw\s+(?:deny|limit|reject)|` +
		`ufw\s+default\s+deny|` +
		`firewall-cmd\s+.*--remove-(?:service|port|rich-rule)|` +
		`firewall-cmd\s+.*--set-default-zone=(?:drop|deny|block)\b|` +
		`nft\s+.*\b(?:drop|reject)\b`)

// unrestrictedSourceRe 伪来源限定：-s 0.0.0.0/0（或 any/anywhere/::/0）
// 等同未限定来源——"只放行白名单 + 拒绝其余"的收窄形态，会把业务流量
// 与未列来源一并锁死（历史实测事故：管理面收窄锁死全部业务端口）。
var unrestrictedSourceRe = regexp.MustCompile(`-s\s+(?:0\.0\.0\.0(?:/0)?|::(?:/0)?|any|anywhere)\b`)

// ufwFromAnyRe ufw 的 `from <来源>` 通配形态（from any/0.0.0.0）= 全入站
// 收窄，等同无来源限定。
var ufwFromAnyRe = regexp.MustCompile(`ufw\s+\S+\s+from\s+(?:any|0\.0\.0\.0(?:/0)?|::(?:/0)?)\b`)

// hasUnrestrictedSource 命令是否无有效来源限定（全入站阻断的等价形态）：
// 无 -s/saddr，或 -s 值为通配（0.0.0.0/0 等）。带具体来源的 DROP 是
// 封禁特定攻击源（修复面，放行）。ufw 的 `from <来源>` 是显式来源限定
// （ufw deny from 1.2.3.4 = 封禁特定攻击源，修复面；此前不识 from
// 关键字把来源限定误判为全入站收窄而拒绝）。
func hasUnrestrictedSource(cmd string) bool {
	if strings.Contains(cmd, "ufw") && strings.Contains(cmd, " from ") {
		// ufw `from <来源>`：具体来源=封禁特定攻击源（放行）；
		// `from any` 通配来源=全入站收窄（维持拒绝）。
		return ufwFromAnyRe.MatchString(cmd)
	}
	if !strings.Contains(cmd, "-s ") && !strings.Contains(cmd, "saddr") {
		return true
	}
	return unrestrictedSourceRe.MatchString(cmd)
}

// isRepairingFirewall 删除防火墙阻断规则的动作（iptables -D/--delete、
// nft delete rule、ufw delete deny）——只会移除阻断、打开通道，属修复面
// 放行；其余命中 firewallBlockRe 的动作（新增阻断、默认 DROP、移除放行
// 项）维持拒绝。按 token 判定，避免 -t filter 等带参选项干扰。
func isRepairingFirewall(tokens []string) bool {
	for i, tok := range tokens {
		switch baseName(tok) {
		case "iptables", "ip6tables":
			for _, t := range tokens[i+1:] {
				if t == "-D" || t == "--delete" {
					return true
				}
			}
		case "nft":
			for j := i + 1; j+1 < len(tokens); j++ {
				if tokens[j] == "delete" && tokens[j+1] == "rule" {
					return true
				}
			}
		case "ufw":
			for j := i + 1; j+1 < len(tokens); j++ {
				if tokens[j] == "delete" && isOneOf(tokens[j+1], "deny", "limit", "reject") {
					return true
				}
			}
		}
	}
	return false
}

// assessChannelFirewall 防火墙规则阻断引擎管理端口（22 或清单连接端口）。
func assessChannelFirewall(cmd, bin string, tokens []string, facts map[string]model.ConnFact) *model.ImpactRisk {
	if !firewallBlockRe.MatchString(cmd) {
		return nil
	}
	if isRepairingFirewall(tokens) {
		return nil // 修复面：删除阻断规则只会打开通道
	}
	// 管理端口：22（SSH 默认/服务名 ssh）+ 清单连接端口。
	ports := map[string]bool{"22": true, "ssh": true}
	for _, f := range facts {
		if f.Port != "" {
			ports[f.Port] = true
		}
	}
	// 显式阻断引擎端口 → 风险。
	if containsPort(cmd, ports) {
		return &model.ImpactRisk{
			Category: impactChannelFirewall,
			Reason:   "防火墙规则阻断引擎管理端口（" + sortedPorts(ports) + "），SSH 通道将被切断",
			Advice:   "先确认防火墙放行引擎管理端口（22 或清单配置的端口）再收紧规则；如需收紧请在人工会话中执行",
		}
	}
	// 未提及具体端口但默认策略丢弃（-P INPUT DROP 等）→ 同样断通道。
	if strings.Contains(cmd, "-P") && strings.Contains(cmd, "DROP") {
		return &model.ImpactRisk{
			Category: impactChannelFirewall,
			Reason:   "防火墙默认策略改为 DROP，将切断引擎管理通道",
			Advice:   "先加入放行引擎管理端口的规则再改默认策略；如需收紧请在人工会话中执行",
		}
	}
	// 无显式端口、无有效来源限定（无 -s/saddr，或 -s 为 0.0.0.0/0 等
	// 通配）的全入站 DROP/REJECT：默认拒绝一切入站的来源收窄（即使
	// 命令前置了白名单放行）——会静默锁死所有未列来源与全部业务端口。
	// 自通道校验只能验证引擎自身来源（引擎 IP 被白名单放行后校验恒
	// 通过），验不了"业务流量被锁死"（历史实测：管理面收窄锁死正常
	// 服务端口，业务中断且引擎无感知）。带具体来源的 DROP 是封禁特定
	// 攻击来源（修复面，放行）。
	if hasUnrestrictedSource(cmd) {
		return &model.ImpactRisk{
			Category: impactChannelFirewall,
			Reason:   "防火墙新增全入站 DROP/REJECT（无有效来源限定）——默认拒绝一切入站，锁死白名单外的全部来源与业务端口（自通道校验只能验证引擎自身来源）",
			Advice:   "等保'默认拒绝'只针对管理面：管理端口（22 等）限制管理来源即可，业务端口（web/db 等当前监听中的服务端口）必须按业务需要放行；来源收窄须显式枚举全部合法来源（运维网段/多管理员）并先验证可达",
		}
	}
	return nil
}

// ── 通道面：网络断开 ───────────────────────────────────────────────

// netDownRe 断开网络接口/连接的动作（up/添加路由等不命中）。
var netDownRe = regexp.MustCompile(
	`ip\s+link\s+set\s+\S+\s+down\b|` +
		`ip\s+addr\s+flush\b|` +
		`ip\s+route\s+del\b|` +
		`ifdown\s+\S+|` +
		`nmcli\s+(?:device\s+disconnect|connection\s+down)\b|` +
		`systemctl\s+(?:stop|disable|mask)\s+(?:NetworkManager|network)\b`)

func assessChannelNetwork(cmd, bin string, tokens []string) *model.ImpactRisk {
	if netDownRe.MatchString(cmd) {
		return &model.ImpactRisk{
			Category: impactChannelNetwork,
			Reason:   "断开网络接口/连接，引擎管理通道将被切断",
			Advice:   "网络变更请逐项小步执行并确认通道可达；断开性操作请在人工会话中执行",
		}
	}
	return nil
}

// ── 通道面：锁定/删除当前登录用户 ─────────────────────────────────

// assessChannelUser 删除/锁定/禁登录当前连接用户（userdel backdoor 等
// 非当前用户的操作不受影响）。
func assessChannelUser(cmd, bin string, tokens []string, facts map[string]model.ConnFact) *model.ImpactRisk {
	target := ""
	harm := false
	switch bin {
	case "userdel", "deluser":
		harm = true
		for _, tok := range tokens[1:] {
			if !strings.HasPrefix(tok, "-") && tok != "" {
				target = tok
				break
			}
		}
	case "passwd":
		for _, tok := range tokens[1:] {
			switch {
			case isOneOf(tok, "-l", "--lock"):
				harm = true
			case strings.HasPrefix(tok, "-"):
			default:
				target = tok
			}
		}
	case "usermod":
		for _, tok := range tokens[1:] {
			switch {
			case isOneOf(tok, "-L", "--lock", "-e", "--expiredate", "-p", "--password"):
				harm = true // 改密码同样会切断当前登录凭据（P1 修复）
			case tok == "-s" || tok == "--shell":
				harm = true // 改 shell 可能禁登录（nologin）
			case strings.HasPrefix(tok, "-"):
			default:
				target = tok
			}
		}
	case "chage":
		for _, tok := range tokens[1:] {
			switch {
			case strings.HasPrefix(tok, "-E"):
				harm = true
			case strings.HasPrefix(tok, "-"):
			default:
				target = tok
			}
		}
	default:
		return nil
	}
	if !harm || target == "" {
		return nil
	}
	for _, f := range facts {
		if f.User != "" && target == f.User {
			return &model.ImpactRisk{
				Category: impactChannelUser,
				Reason:   fmt.Sprintf("对当前登录用户 %q 执行删除/锁定/禁登录，引擎（以及操作员）将无法再登录该主机", target),
				Advice:   "先建立备用管理账号（或解锁确认），再处理当前用户；如需禁用请在人工会话中执行",
			}
		}
	}
	return nil
}

// ── 工具链面：删除/卸载引擎诊断依赖（分级）────────────────────────
//
// 只拦"破坏执行能力"的删除：工具链目录自身（整目录）、系统可执行文件
// （bin/sbin/libexec 下）、核心库（动态链接器/libc/NSS/PAM/SSH 加密/
// systemd 支撑/bash terminfo）。非核心库文件（如 /usr/lib 下被植入的
// 恶意 .so）删除属修复面，落入常规变更面由策略调节。
