package guard

// guard_impact_toolchain.go — 自影响审查·工具链面：核心二进制/库/包移除是否破坏自身执行能力。

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/go-gocel/gocode-ops/internal/common/model"
)

// toolchainDirRe 工具链目录自身（/usr/bin、/usr/lib 等整目录删除）。
var toolchainDirRe = regexp.MustCompile(`(?:^|/)(?:usr/)?(?:s?bin|lib(?:64)?|libexec)$`)

// toolchainExecRe 系统可执行文件路径（bin/sbin/libexec 下任意文件）。
var toolchainExecRe = regexp.MustCompile(`(?:^|/)(?:usr/)?(?:s?bin|libexec)/`)

// toolchainLibRe 库目录内路径（lib/lib64/usr/lib/usr/lib64 下文件）。
var toolchainLibRe = regexp.MustCompile(`(?:^|/)(?:usr/)?lib(?:64)?/`)

// coreLibRe 引擎执行/通道依赖的核心库：动态链接器与基础运行库、名称
// 解析栈（NSS）、认证栈（PAM）、SSH 加密库、systemd 支撑库、bash 的
// terminfo。删除这些库会立即破坏引擎的诊断与执行能力。
var coreLibRe = regexp.MustCompile(
	`(?:^|/)(?:ld-linux|ld-musl|libc\.so|libcrypt|libdl\.so|libm\.so|` +
		`libpthread|libresolv|librt\.so|libutil|libnsl|libnss_|libpam|` +
		`libssl\.so|libcrypto\.so|libsystemd(?:-shared|\.so)|libudev\.so|libz\.so|libtinfo)`)

// coreToolPkgs 引擎诊断/执行依赖的软件包（卸载即破坏自身能力）。
var coreToolPkgs = []string{
	"bash", "sh", "coreutils", "util-linux", "procps", "procps-ng", "grep",
	"sed", "awk", "gawk", "mawk", "perl", "python3", "curl", "wget",
	"psmisc", "iproute", "iproute2", "nettools", "lsof", "net-tools",
	"openssh-server", "openssh-clients", "openssh", "systemd", "tar",
	"findutils", "openssl", "ca-certificates",
}

// pkgRemoveRe 包管理器卸载动作。
var pkgRemoveRe = regexp.MustCompile(
	`(?:yum|dnf)\s+(?:remove|erase)\b|` +
		`apt(?:-get)?\s+remove\b|` +
		`apt(?:-get)?\s+purge\b|` +
		`apk\s+del\b|` +
		`zypper\s+remove\b|` +
		`pacman\s+-R\b|` +
		`rpm\s+-e\b|` +
		`dpkg\s+-r\b`)

func assessToolchain(cmd, bin string, tokens []string) *model.ImpactRisk {
	// 删除/移动系统可执行文件与核心库（分级，见文件头）。
	if isOneOf(bin, "rm", "mv", "unlink") {
		for _, tok := range tokens[1:] {
			if strings.HasPrefix(tok, "-") {
				continue
			}
			// /usr/local 是本地第三方安装区（也是植入脚本常驻区）——
			// 引擎依赖在发行版目录，删除其内容不破坏引擎能力，属修复面，
			// 落入常规变更面由策略调节（R6 实测：删除 /usr/local/sbin
			// 植入脚本被拦，模型退化为人工建议）。
			if strings.Contains(tok, "/usr/local/") {
				continue
			}
			if toolchainDirRe.MatchString(tok) {
				return &model.ImpactRisk{
					Category: impactToolchain,
					Reason:   fmt.Sprintf("%s 工具链目录 %s，破坏引擎诊断/执行依赖", bin, tok),
					Advice:   "保留系统工具链；如需清理请在人工会话中执行",
				}
			}
			if toolchainExecRe.MatchString(tok) {
				return &model.ImpactRisk{
					Category: impactToolchain,
					Reason:   fmt.Sprintf("%s 系统可执行文件 %s，破坏引擎诊断/执行依赖", bin, tok),
					Advice:   "保留系统工具链；如需清理请在人工会话中执行",
				}
			}
			// 库目录内：仅核心库删除破坏执行能力；非核心库（如植入的
			// 恶意 .so）属修复面，落入常规变更面。
			if toolchainLibRe.MatchString(tok) && coreLibRe.MatchString(tok) {
				return &model.ImpactRisk{
					Category: impactToolchain,
					Reason:   fmt.Sprintf("%s 核心库 %s，破坏引擎执行/通道依赖", bin, tok),
					Advice:   "保留核心运行库；如需清理请在人工会话中执行",
				}
			}
		}
	}
	// 卸载引擎依赖的核心软件包。
	if pkgRemoveRe.MatchString(cmd) {
		lower := strings.ToLower(cmd)
		for _, p := range coreToolPkgs {
			if strings.Contains(lower, p) {
				return &model.ImpactRisk{
					Category: impactToolchain,
					Reason:   fmt.Sprintf("卸载引擎依赖的软件包 %s，破坏诊断/执行能力", p),
					Advice:   "保留核心工具链；卸载请在人工会话中执行",
				}
			}
		}
	}
	return nil
}

// ── 小工具 ─────────────────────────────────────────────────────────

// containsPort 命令文本是否提及 ports 中的端口/服务（--dport 22、
// --dport=22、:22、22/tcp、port 22、--remove-port=22、裸参数 ufw deny 22
// 等形态）。
func containsPort(cmd string, ports map[string]bool) bool {
	for p := range ports {
		if strings.Contains(cmd, "--dport "+p) ||
			strings.Contains(cmd, "--dport="+p) ||
			strings.Contains(cmd, ":"+p) ||
			strings.Contains(cmd, p+"/tcp") ||
			strings.Contains(cmd, "port "+p) ||
			strings.Contains(cmd, "--remove-port="+p) ||
			strings.Contains(cmd, "--remove-port "+p) ||
			strings.Contains(cmd, "--remove-service="+p) ||
			strings.Contains(cmd, "--remove-service "+p) {
			return true
		}
	}
	// token 级：命令参数恰好等于端口或服务名（ufw deny 22 / ufw deny ssh）。
	for _, tok := range strings.Fields(cmd) {
		if ports[strings.Trim(tok, ",;")] {
			return true
		}
	}
	return false
}

// sortedPorts 端口集合的排序展示（22,22022）。
func sortedPorts(ports map[string]bool) string {
	list := make([]string, 0, len(ports))
	for p := range ports {
		list = append(list, p)
	}
	sort.Strings(list)
	return strings.Join(list, ",")
}
