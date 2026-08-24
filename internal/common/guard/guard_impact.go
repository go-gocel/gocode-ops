package guard

// 守卫 · 命令风险审查 —— 自身影响面。
//
// 守卫（RiskyCommandGuard）是命令风险审查的执行者，两者互相配合：
// 命令风险审查统一判定命令是否允许执行（reviewCommandRisk，见
// guard.go），按风险面分层：
//
//	自身影响面  —— 断自身通道（guard_impact_channel.go）/ 毁工具链
//	               （guard_impact_toolchain.go）→ 拒绝（hard）
//	目标危害面  —— 宕机/不可恢复（rm -rf /、mkfs、dd 设备、reboot）→ 拒绝（hard）
//	凭证泄露面  —— shadow/私钥/明文密码 → 拒绝（hard）
//	混淆绕过面  —— 解码管道/危险代码 → 拒绝（hard）
//	常规变更面  —— kill/userdel/service 等 → 由 ask/allow/deny/auto 策略调节
//
// 自身影响面与高危策略无关——"断自身通道 / 毁自身工具链"损害的是 agent
// 的执行能力本身（交互式运维助手会把操作员也断在远端，全自动运维引擎会中断处置），
// 因此任何策略（ask/allow/deny/auto）下都拒绝执行，只给安全替代建议。
// 判定依据是通用事实（连接用户、认证方式、管理端口），不是针对某个
// 环境的特判；一套机制同时覆盖交互式运维助手与全自动运维引擎（经验互通）。
//
// 通道面分级（迭代 5）：审查只拦"切断通道/破坏工具链"的动作，不拦
// "修复/消除通道干扰"的动作——后者落入常规变更面，由 ask/allow/deny/
// auto 策略调节（auto 策略下照常自动处置）。修复面判据：
//   - 认证配置：同指令"后写覆盖先写"净效果判定——sed 把禁用改写为启用
//     （恢复被投毒配置）放行，禁用在后或纯禁用写入拒绝；
//   - 防火墙：删除阻断规则（iptables -D / nft delete rule / ufw delete
//     deny）只会打开通道，放行；新增阻断/默认 DROP 拒绝；
//   - 工具链：只拦发行版工具链目录/系统可执行文件/核心库（动态链接
//     器/libc/NSS/PAM/SSH 加密/systemd 支撑等）；/usr/local 本地安装区、
//     非核心库文件（如被植入的恶意 .so）删除属修复面，落入常规变更面。
//
// 原则：fail-closed。宁可把命令转人工建议，也不让 agent 自断后路；
// 但禁用信号只出现在被替换的模式侧时不构成落盘内容，不算切断。

import (
	"strings"

	"github.com/go-gocel/gocode-ops/internal/common/model"
)

const (
	impactChannelAuth     = "channel-auth"
	impactChannelService  = "channel-service"
	impactChannelFirewall = "channel-firewall"
	impactChannelNetwork  = "channel-network"
	impactChannelUser     = "channel-user"
	impactChannelPort     = "channel-port"
	impactToolchain       = "toolchain"
)

// assessSelfImpact 对一条命令做自身影响面审查。facts 是该命令的目标主机
// 连接事实（本地命令可传 nil：认证/服务/防火墙面只针对远程通道，工具链
// 面本地同样适用）。返回 nil 表示无风险。
func assessSelfImpact(cmd string, facts map[string]model.ConnFact) *model.ImpactRisk {
	if strings.TrimSpace(cmd) == "" {
		return nil
	}
	for _, seg := range splitCommandSegments(cmd) {
		inner := unwrapCommand(seg)
		stripped := stripSudo(inner)
		if risk := assessSegment(stripped, facts); risk != nil {
			return risk
		}
	}
	return nil
}

// assessSegment 审查单个命令段（已剥 sudo/包装）。
func assessSegment(cmd string, facts map[string]model.ConnFact) *model.ImpactRisk {
	tokens := strings.Fields(cmd)
	if len(tokens) == 0 {
		return nil
	}
	bin := baseName(tokens[0])

	// 通道面：仅对远程目标生效（facts 非 nil 且命令目标在清单内）。
	if len(facts) > 0 {
		if risk := assessChannelAuth(cmd, facts); risk != nil {
			return risk
		}
		if risk := assessChannelPort(cmd, facts); risk != nil {
			return risk
		}
		if risk := assessChannelService(cmd, bin, tokens); risk != nil {
			return risk
		}
		if risk := assessChannelFirewall(cmd, bin, tokens, facts); risk != nil {
			return risk
		}
		if risk := assessChannelNetwork(cmd, bin, tokens); risk != nil {
			return risk
		}
		if risk := assessChannelUser(cmd, bin, tokens, facts); risk != nil {
			return risk
		}
	}
	if risk := assessEvidence(cmd, bin, tokens); risk != nil {
		return risk
	}
	return assessToolchain(cmd, bin, tokens)
}

// assessEvidence 证据面审查（P0 修复）：清除/旋转/卸载证据的操作在
// 自动形态下一律拒绝——"处置证据"不等于"处置故障"，dmesg -c 曾把
// 未修复的 OOM 循环伪装成已收敛（chaos-r1 实测）。交互形态可由操作员
// 确认后执行（规则层为可批准类）；auto 形态在此硬拒并转人工建议。
func assessEvidence(cmd, bin string, tokens []string) *model.ImpactRisk {
	switch bin {
	case "dmesg":
		for _, tok := range tokens[1:] {
			if tok == "-c" || tok == "-C" || tok == "--clear" || tok == "--read-clear" {
				return &model.ImpactRisk{
					Category: "evidence",
					Reason:   "dmesg -c/-C 清空内核环形缓冲——清除内核故障证据，处置证据不等于处置故障；排查期间证据必须保留",
					Advice:   "用 dmesg（不带 -c）只读查看内核日志；如需清除历史噪音请在故障闭环且人工审批后执行",
				}
			}
		}
	case "journalctl":
		for _, tok := range tokens[1:] {
			if tok == "--rotate" || tok == "--vacuum" || tok == "--vacuum-size" ||
				tok == "--vacuum-time" || tok == "--vacuum-files" {
				return &model.ImpactRisk{
					Category: "evidence",
					Reason:   "journalctl 轮转/清理（--rotate/--vacuum*）——清除系统日志证据；处置证据不等于处置故障",
					Advice:   "只读查询用 journalctl --since/--no-pager 不带轮转参数；日志清理属人工审批项",
				}
			}
		}
	case "umount":
		for _, tok := range tokens[1:] {
			if strings.HasPrefix(tok, "-") {
				continue
			}
			if maskedSystemDir(tok) {
				return &model.ImpactRisk{
					Category: "evidence",
					Reason:   "umount 标准系统目录挂载点（" + tok + "）——日志/配置挂载卸载改变证据面与日志落点",
					Advice:   "保留挂载，改为处置挂载内的异常内容（清日志/杀写入进程）；确需卸载属人工审批项",
				}
			}
		}
	}
	return nil
}

// ── 通道面：认证配置 ────────────────────────────────────────────────
