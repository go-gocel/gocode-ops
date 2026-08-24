package remote

// host key 校验相关纯函数测试：地址端口补全（含 IPv6）、连接缓存键的
// host_key_check 区分、known_hosts 条目探测、错误分类翻译。

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestWithDefaultPort(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"myhost", "myhost:22"},
		{"10.0.0.11", "10.0.0.11:22"},
		{"10.0.0.11:2222", "10.0.0.11:2222"},
		{"[2001:db8::1]:22", "[2001:db8::1]:22"},
		{"2001:db8::1", "[2001:db8::1]:22"},
		{"::1", "[::1]:22"},
	}
	for _, c := range cases {
		if got := withDefaultPort(c.in); got != c.want {
			t.Errorf("withDefaultPort(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestClientKeyHostKeyCheck(t *testing.T) {
	base := Host{Address: "10.0.0.1", User: "root", Password: "pw"}
	on := base
	on.HostKeyCheck = boolPtr(true)
	off := base
	off.HostKeyCheck = boolPtr(false)

	if clientKey(base) != clientKey(on) {
		t.Error("默认 host_key_check 应与显式 true 同缓存键")
	}
	if clientKey(on) == clientKey(off) {
		t.Error("host_key_check 开关切换后旧连接必须失效（缓存键应不同）")
	}
}

func TestKnownHostsHasEntries(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"\n\n", false},
		{"# only comment\n", false},
		{"@revoked foo ssh-ed25519 AAA\n", false},
		{"@cert-authority foo ssh-ed25519 AAA\n", false},
		{"10.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI\n", true},
		{"# c\n\n10.0.0.1 ssh-ed25519 AAAA\n", true},
	}
	for _, c := range cases {
		if got := knownHostsHasEntries([]byte(c.in)); got != c.want {
			t.Errorf("knownHostsHasEntries(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestHostKeyHintClassifies(t *testing.T) {
	priv, err := newTestHostKey()
	if err != nil {
		t.Fatalf("生成测试 key 失败: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("构造 signer 失败: %v", err)
	}

	// Want 为空 = key is unknown（无该主机条目）。
	unknown := &knownhosts.KeyError{}
	if h := hostKeyHint(unknown); !strings.Contains(h, "key is unknown") || !strings.Contains(h, "无该主机条目") {
		t.Errorf("unknown 分类错误: %s", h)
	}

	// Want 非空 = key mismatch（指纹不匹配）。
	mismatch := &knownhosts.KeyError{Want: []knownhosts.KnownKey{{Key: signer.PublicKey()}}}
	if h := hostKeyHint(mismatch); !strings.Contains(h, "key mismatch") || !strings.Contains(h, "指纹不匹配") {
		t.Errorf("mismatch 分类错误: %s", h)
	}

	// 非 host key 错误：走脱敏路径。
	plain := errors.New("dial tcp 10.0.0.11:22: connect: connection refused")
	if h := hostKeyHint(plain); strings.Contains(h, "10.0.0.11") || !strings.Contains(h, "connection refused") {
		t.Errorf("非 host key 错误处理错误: %s", h)
	}
}

// TestWrapConnectErrAsThroughSSHWrap 验证 errors.As 能穿透 x/crypto ssh
// 的 %w 包装（client.go: fmt.Errorf("ssh: handshake failed: %w", err)）
// 正确分类 KeyError。
func TestWrapConnectErrAsThroughSSHWrap(t *testing.T) {
	wrapped := fmt.Errorf("ssh: handshake failed: %w", &knownhosts.KeyError{})
	got := wrapConnectErr("t1", wrapped).Error()
	if !strings.Contains(got, "无该主机条目") {
		t.Errorf("穿透 %%w 包装后分类失败: %s", got)
	}
	if strings.Contains(got, "knownhosts:") {
		t.Errorf("原始库错误文本未替换为指引: %s", got)
	}
}

func boolPtr(b bool) *bool { return &b }
