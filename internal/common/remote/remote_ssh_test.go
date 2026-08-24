package remote

// 远程黑盒集成测试：真实 SSH server（x/crypto/ssh 服务端）模拟各种登录
// shell，验证 execOne 的探测 + stdin 传输语义——目标主机对引擎是黑盒，
// 登录 shell 不可假设为 sh：
//
//   - "sh" 模式：登录 shell 是标准 POSIX sh（现状环境的等价模拟）；
//   - "csh-like" 模式：登录 shell 对 $(...) 语法报错（模拟 csh 的
//     解析差异）——stdin 传输模式下命令内容不经登录 shell 解析，
//     仍能正确执行；
//   - "none" 模式：无任何可用 POSIX shell（如 Windows SSH 目标）——
//     探测失败回退裸命令，如实报错不 panic。
//
// 平台要求：测试机需有 sh（Git Bash/MSYS2/Linux 均提供）；无 sh 时跳过。

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// newTestHostKey 生成测试用的 ed25519 host key。
func newTestHostKey() (ed25519.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	return key, err
}

// testLoginShell 模拟登录 shell 的行为模式。
type testLoginShell string

const (
	loginShellSH      testLoginShell = "sh"       // 标准 POSIX sh
	loginShellCSH     testLoginShell = "csh-like" // 对 $(...) 报错（csh 语义差异）
	loginShellNoPOSIX testLoginShell = "none"     // 无可用 POSIX shell（Windows 目标）
)

// startTestSSHServer 起一个真实 ssh server：session exec 请求经"登录
// shell"执行（<shell> -c <payload>，与 sshd 行为一致）。返回地址与
// exec 请求计数（断言探测缓存用）。
func startTestSSHServer(t *testing.T, mode testLoginShell) (string, *atomic.Int32) {
	t.Helper()
	shPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available on this host")
	}

	key, err := newTestHostKey()
	if err != nil {
		t.Fatalf("生成 host key 失败: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("构造 signer 失败: %v", err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return nil, nil // 测试放行
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	var count atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sshConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					_ = conn.Close()
					return
				}
				go ssh.DiscardRequests(reqs)
				for newCh := range chans {
					if newCh.ChannelType() != "session" {
						_ = newCh.Reject(ssh.UnknownChannelType, "only session")
						continue
					}
					ch, requests, err := newCh.Accept()
					if err != nil {
						continue
					}
					go handleTestSession(ch, requests, mode, shPath, &count)
				}
				_ = sshConn.Close()
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), &count
}

// handleTestSession 处理一个 session channel 的 exec 请求。
func handleTestSession(ch ssh.Channel, requests <-chan *ssh.Request, mode testLoginShell, shPath string, count *atomic.Int32) {
	defer ch.Close()
	for req := range requests {
		switch req.Type {
		case "exec":
			cmd := string(req.Payload[4:]) // payload: uint32 长度 + 命令
			_ = req.Reply(true, nil)
			count.Add(1)
			runTestLoginShell(ch, cmd, mode, shPath)
			return
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// runTestLoginShell 模拟登录 shell 执行一条命令（sshd 语义：<shell> -c <cmd>）。
func runTestLoginShell(ch ssh.Channel, cmd string, mode testLoginShell, shPath string) {
	switch mode {
	case loginShellNoPOSIX:
		// 无 POSIX shell 的目标：任何 shell 命令都失败。
		_, _ = ch.Write([]byte("sh: command not found\n"))
		sendTestExitStatus(ch, 127)
		return
	case loginShellCSH:
		// csh 语义差异：$(...) 是非法变量语法，直接报错。
		if strings.Contains(cmd, "$(") {
			_, _ = ch.Write([]byte("Illegal variable name.\n"))
			sendTestExitStatus(ch, 1)
			return
		}
	}
	c := exec.Command(shPath, "-c", cmd)
	c.Stdin = ch // 登录 shell 的 stdin 即 session channel（stdin 传输依赖此）
	c.Stdout = ch
	c.Stderr = ch
	_ = c.Run()
	code := 0
	if c.ProcessState != nil {
		code = c.ProcessState.ExitCode()
		if code < 0 {
			code = 1
		}
	}
	sendTestExitStatus(ch, code)
}

// sendTestExitStatus 发送 exit-status request（uint32 退出码）。
func sendTestExitStatus(ch ssh.Channel, code int) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(code))
	_, _ = ch.SendRequest("exit-status", false, buf)
}

// newTestExecutor 用临时 inventory 构造连到测试 server 的真实执行器。
func newTestExecutor(t *testing.T, addr string) RemoteExecutor {
	t.Helper()
	dir := t.TempDir()
	inv := filepath.Join(dir, "hosts.yaml")
	data := fmt.Sprintf("hosts:\n  - name: t\n    address: %s\n    user: root\n    password: pw\n    host_key_check: false\n", addr)
	if err := os.WriteFile(inv, []byte(data), 0o600); err != nil {
		t.Fatalf("写 inventory 失败: %v", err)
	}
	return NewSSHExecutor(RemoteConfig{InventoryPath: inv, DefaultTimeout: 5 * time.Second})
}

// TestRemoteExec_StdInShellBypassesLoginShell 黑盒核心：登录 shell 是
// csh 类（$(...) 直接报错）时，stdin 传输模式仍能正确执行 POSIX 命令。
func TestRemoteExec_StdInShellBypassesLoginShell(t *testing.T) {
	addr, _ := startTestSSHServer(t, loginShellCSH)
	ex := newTestExecutor(t, addr)
	ctx := context.Background()

	// $(...) 在 csh 类登录 shell 下裸发必挂；stdin 传输模式由远端 sh
	// 解释，必须成功且输出正确展开结果。
	out, err := ex.Exec(ctx, []string{"t"}, "echo host-is-$(hostname)", 5*time.Second)
	if err != nil {
		t.Fatalf("stdin 模式执行 $(...) 命令失败（被登录 shell 解析？）: %v\n输出: %s", err, out)
	}
	if !strings.Contains(out, "host-is-") {
		t.Fatalf("输出未含展开结果: %q", out)
	}

	// 多行脚本 + 退出码：stdin 脚本语义与 sh -c 一致。
	out, err = ex.Exec(ctx, []string{"t"}, "echo line1; echo line2; exit 3", 5*time.Second)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if !strings.Contains(out, "line1") || !strings.Contains(out, "line2") {
		t.Fatalf("多行脚本输出不完整: %q", out)
	}
	if !strings.Contains(out, "[exit: 3]") {
		t.Fatalf("退出码未回传: %q", out)
	}
}

// TestRemoteExec_ShellProbeCached 探测只发生一次：首次 Exec 产生探测 +
// 执行两个 exec 请求，后续 Exec 只产生执行请求（连接内缓存）。
func TestRemoteExec_ShellProbeCached(t *testing.T) {
	addr, count := startTestSSHServer(t, loginShellSH)
	ex := newTestExecutor(t, addr)
	ctx := context.Background()

	if _, err := ex.Exec(ctx, []string{"t"}, "echo one", 5*time.Second); err != nil {
		t.Fatalf("首次 Exec: %v", err)
	}
	first := count.Load()
	if first < 2 {
		t.Fatalf("首次 Exec 应含探测+执行（≥2 个 exec 请求），实际 %d", first)
	}
	if _, err := ex.Exec(ctx, []string{"t"}, "echo two", 5*time.Second); err != nil {
		t.Fatalf("第二次 Exec: %v", err)
	}
	second := count.Load()
	if second != first+1 {
		t.Fatalf("探测未缓存：第二次 Exec 产生 %d 个请求（期望 1），累计 %d", second-first, second)
	}
}

// TestRemoteExec_NoPOSIXShellFallsBack 无可用 POSIX shell（Windows 目标
// 模拟）：探测失败回退裸命令，登录 shell 的报错如实回传（退出码语义
// 走输出文本，不 panic、不挂死）。
func TestRemoteExec_NoPOSIXShellFallsBack(t *testing.T) {
	addr, _ := startTestSSHServer(t, loginShellNoPOSIX)
	ex := newTestExecutor(t, addr)
	ctx := context.Background()

	out, err := ex.Exec(ctx, []string{"t"}, "echo fallback", 5*time.Second)
	if err != nil {
		t.Fatalf("回退裸命令路径不应返回 error（退出码走输出文本）: %v", err)
	}
	if !strings.Contains(out, "command not found") {
		t.Fatalf("登录 shell 的报错应如实回传: %q", out)
	}
	if !strings.Contains(out, "[exit: 127]") {
		t.Fatalf("退出码应回传: %q", out)
	}
}

// TestRemoteExec_TimeoutInStdInMode stdin 模式下超时兜底：远端不消费
// stdin（异常登录 shell）时，命令按超时返回而非永久挂起。
func TestRemoteExec_TimeoutInStdInMode(t *testing.T) {
	addr, _ := startTestSSHServer(t, loginShellSH)
	ex := newTestExecutor(t, addr)
	ctx := context.Background()

	start := time.Now()
	_, err := ex.Exec(ctx, []string{"t"}, "sleep 30", 2*time.Second)
	if err == nil {
		t.Fatal("长命令应超时")
	}
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Fatalf("超时未生效，耗时 %v", elapsed)
	}
}
