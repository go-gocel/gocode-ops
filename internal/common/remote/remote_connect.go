package remote

// remote_connect.go — 连接建立：默认端口、错误脱敏、known_hosts 校验、认证回调。

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func addrPort(address string) string {
	if _, p, err := net.SplitHostPort(strings.TrimSpace(address)); err == nil && p != "" {
		return p
	}
	return "22"
}

func withDefaultPort(addr string) string {
	if addr == "" {
		return addr
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr // 已是 host:port 或 [v6]:port
	}
	if strings.Contains(addr, ":") {
		return "[" + addr + "]:22" // 裸 IPv6 字面量
	}
	return addr + ":22"
}

// dial 建立 SSH 连接。凭证只在本进程内使用，不外传。
func (e *sshExecutor) dial(h Host) (*ssh.Client, error) {
	addr := strings.TrimSpace(h.Address)
	if addr == "" {
		return nil, errors.New("主机缺少 address")
	}
	addr = withDefaultPort(addr)
	if strings.TrimSpace(h.User) == "" {
		return nil, errors.New("主机缺少 user")
	}

	var auths []ssh.AuthMethod
	if strings.TrimSpace(h.Password) != "" {
		auths = append(auths, ssh.Password(h.Password))
	}
	if strings.TrimSpace(h.KeyFile) != "" {
		keyPath := expandHome(h.KeyFile)
		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			// 私钥路径不进模型上下文（零泄露同源约定）：只报主机别名，
			// 细节留给操作员本机排查。
			return nil, fmt.Errorf("读取私钥失败（%s）", h.Name)
		}
		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("解析私钥失败（%s）", h.Name)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}
	if len(auths) == 0 {
		return nil, errors.New("主机缺少认证方式（password 或 key_file）")
	}

	callback, err := e.hostKeyCallback(h)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            h.User,
		Auth:            auths,
		HostKeyCallback: callback,
		Timeout:         10 * time.Second,
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		// 地址不进模型上下文：host key 校验错误给分类指引，其余剥掉
		// dial tcp ADDR: 前缀。
		return nil, wrapConnectErr(h.Name, err)
	}
	return client, nil
}

// dialTimeout 带超时参数建连（Probe 用：调用方 timeout 生效）。
func (e *sshExecutor) dialTimeout(h Host, timeout time.Duration) (*ssh.Client, error) {
	if timeout <= 0 {
		return e.dial(h)
	}
	addr := withDefaultPort(strings.TrimSpace(h.Address))
	var auths []ssh.AuthMethod
	if strings.TrimSpace(h.Password) != "" {
		auths = append(auths, ssh.Password(h.Password))
	}
	if strings.TrimSpace(h.KeyFile) != "" {
		keyData, err := os.ReadFile(expandHome(h.KeyFile))
		if err != nil {
			return nil, fmt.Errorf("读取私钥失败（%s）", h.Name)
		}
		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("解析私钥失败（%s）", h.Name)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}
	if len(auths) == 0 {
		return nil, errors.New("主机缺少认证方式（password 或 key_file）")
	}
	callback, err := e.hostKeyCallback(h)
	if err != nil {
		return nil, err
	}
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            h.User,
		Auth:            auths,
		HostKeyCallback: callback,
		Timeout:         timeout,
	})
	if err != nil {
		return nil, wrapConnectErr(h.Name, err)
	}
	return client, nil
}

// netAddrPrefixRe 匹配 net.OpError 中的地址前缀（dial tcp 10.0.0.11:22: …）。
var netAddrPrefixRe = regexp.MustCompile(`(?i)dial\s+tcp\s+[^:\s]+:\d+\s*:\s*`)

// redactNetErr 剥除网络错误中的地址（dial tcp ADDR: 前缀）：地址不进
// 模型上下文（凭证零泄露同源约定）；操作员需要时经主机页探测查看状态。
func redactNetErr(err error) string {
	return netAddrPrefixRe.ReplaceAllString(err.Error(), "")
}

// hostKeyHint 把 knownhosts 校验错误分类翻译成可操作的中文指引。
// KeyError.Want 为空 = 无该主机条目（key is unknown）；非空 = 有条目
// 但指纹/算法不符（key mismatch）。两类都要点明：指纹必须在 gocode-ops
// 同一运行环境（同一 HOME、同一网络路径）、以与清单 address 完全一致
// 的名字（hostname/IP/端口形式）录入；或对该主机设 host_key_check:
// false 跳过校验（需自行评估 MITM 风险）。
func hostKeyHint(err error) string {
	var ke *knownhosts.KeyError
	if !errors.As(err, &ke) {
		return redactNetErr(err)
	}
	if len(ke.Want) == 0 {
		return "host key 校验失败（key is unknown，known_hosts 无该主机条目）：从未录入、或录入用的名字/地址形式与清单 address 不一致（hostname vs IP、有无端口）、或条目已被清除。请在 gocode-ops 同一运行环境、以与清单 address 完全一致的名字 ssh 连接一次录入指纹；或对该主机设置 host_key_check: false（需自行评估 MITM 风险）"
	}
	return "host key 校验失败（key mismatch，指纹不匹配）：known_hosts 有该主机条目但服务器指纹不符——主机可能重装/重建、IP 被复用、或录入的 key 来自别的端点。请核对指纹后 ssh-keygen -R 清除旧条目重录；或对该主机设置 host_key_check: false（需自行评估 MITM 风险）"
}

// wrapConnectErr 包装建连错误：host key 校验错误给分类指引（指纹不是
// 凭证，可进模型上下文），其余剥掉网络地址前缀（地址不进模型上下文）。
func wrapConnectErr(name string, err error) error {
	var ke *knownhosts.KeyError
	if errors.As(err, &ke) {
		return fmt.Errorf("连接 %s 失败: %s", name, hostKeyHint(err))
	}
	return fmt.Errorf("连接 %s 失败: %s", name, redactNetErr(err))
}

// hostKeyCallback 按 host_key_check 决定 known_hosts 校验或跳过。
func (e *sshExecutor) hostKeyCallback(h Host) (ssh.HostKeyCallback, error) {
	check := true
	if h.HostKeyCheck != nil {
		check = *h.HostKeyCheck
	}
	if !check {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	kh := expandHome("~/.ssh/known_hosts")
	// 先读一次做条目存在性校验（给可操作的引导错误）；knownhosts.New
	// 内部再读一次用于回调（x/crypto 只提供路径版构造，两次读取窗口
	// 微秒级，可接受）。
	data, err := os.ReadFile(kh)
	if err != nil {
		return nil, fmt.Errorf("启用了 host_key_check 但找不到/无法读取 %s——请先 ssh 连接一次录入指纹，或在该主机条目设置 host_key_check: false（需自行评估 MITM 风险）", kh)
	}
	if !knownHostsHasEntries(data) {
		return nil, fmt.Errorf("启用了 host_key_check 但 %s 里没有任何主机条目（空文件或仅注释）——请先 ssh 连接一次录入指纹，或在该主机条目设置 host_key_check: false（需自行评估 MITM 风险）", kh)
	}
	cb, err := knownhosts.New(kh)
	if err != nil {
		return nil, fmt.Errorf("加载 known_hosts 失败: %w", err)
	}
	return cb, nil
}

// knownHostsHasEntries 判断 known_hosts 内容是否含至少一条主机条目
// （跳过空行、# 注释、@cert-authority/@revoked 标记行）。
func knownHostsHasEntries(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") ||
			strings.HasPrefix(line, "@cert-authority") || strings.HasPrefix(line, "@revoked") {
			continue
		}
		return true
	}
	return false
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			if p == "~" {
				return home
			}
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// ── remote_* 工具族 ───────────────────────────────────────────────────

// remote_terminal：单台主机执行命令（与本地 terminal 逻辑一致）。
