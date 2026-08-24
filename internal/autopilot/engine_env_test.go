package autopilot

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-gocel/gocode-ops/internal/common/env"
	"github.com/go-gocel/gocode-ops/internal/common/remote"
)

// stubRemote 只响应远程环境探测命令的最小 RemoteExecutor（演练 R5
// 机制层修复测试：远端系统面能力补齐）。
type stubRemote struct {
	out   string // Exec 返回的整段输出
	err   error
	cmd   string // 记录最近一次命令（断言探测命令形态）
	hosts []string
}

func (s *stubRemote) Exec(ctx context.Context, hosts []string, command string, timeout time.Duration) (string, error) {
	s.cmd = command
	s.hosts = hosts
	return "## " + hosts[0] + "\n" + s.out, s.err
}
func (s *stubRemote) Upload(ctx context.Context, hosts []string, localPath, remotePath string, mode os.FileMode) (string, error) {
	return "", nil
}
func (s *stubRemote) Download(ctx context.Context, hosts []string, remotePath, localDir string) (string, error) {
	return "", nil
}
func (s *stubRemote) FileInfo(ctx context.Context, host, remotePath string, list bool) (string, error) {
	return "", nil
}
func (s *stubRemote) ListHosts() (string, error) { return "", nil }
func (s *stubRemote) Probe(ctx context.Context, aliases []string, timeout time.Duration) map[string]string {
	return nil
}
func (s *stubRemote) Resolve(aliases []string) ([]string, error) { return aliases, nil }
func (s *stubRemote) Aliases() ([]string, error)                 { return nil, nil }

var _ remote.RemoteExecutor = (*stubRemote)(nil)

// TestDetectRemoteEnv_Systemd 远端 Linux 目标：systemd/docker/ss 能力
// 被确定性探测补齐。
func TestDetectRemoteEnv_Systemd(t *testing.T) {
	s := &stubRemote{out: "SYSTEMD=1\nDOCKER=1\nSS=1\n"}
	e := detectRemoteEnv(context.Background(), s, []string{"web-01"})
	if e == nil || !e.HasSystemd || !e.HasDocker || !e.HasSS {
		t.Fatalf("应补齐 systemd/docker/ss，got %+v", e)
	}
	if !strings.Contains(s.cmd, "/run/systemd/system") {
		t.Errorf("探测命令应含 systemd 运行目录检查: %s", s.cmd)
	}
	if len(s.hosts) != 1 || s.hosts[0] != "web-01" {
		t.Errorf("应在目标主机上探测: %v", s.hosts)
	}
}

// TestDetectRemoteEnv_NoCapability 无能力信号（精简容器）：视为探测
// 失败不补齐（调用方保持本机基线，不臆断远端能力）。
func TestDetectRemoteEnv_NoCapability(t *testing.T) {
	s := &stubRemote{out: "nothing here\n"}
	if e := detectRemoteEnv(context.Background(), s, []string{"web-01"}); e != nil {
		t.Fatalf("无能力信号应返回 nil，got %+v", e)
	}
}

// TestDetectRemoteEnv_Failure 执行失败：静默降级（返回 nil，不阻塞）。
func TestDetectRemoteEnv_Failure(t *testing.T) {
	s := &stubRemote{err: errors.New("ssh refused")}
	if e := detectRemoteEnv(context.Background(), s, []string{"web-01"}); e != nil {
		t.Fatalf("失败应返回 nil，got %+v", e)
	}
}

// TestMergeRemoteEnv 装配路径：远端能力与本地环境 OR 合并（本地无
// systemd、远端有 → HasSystemd=true；远端探测失败不降级本地）。
func TestMergeRemoteEnv(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EngineConfig.Hosts = []string{"web-01"}
	// 远端有 systemd：合并后 HasSystemd=true。
	e := &env.Env{HasSystemd: false, NProc: 4}
	mergeRemoteEnv(e, cfg, &stubRemote{out: "SYSTEMD=1\n"})
	if !e.HasSystemd {
		t.Fatal("远端 systemd 能力应合并到引擎环境")
	}
	// 远端探测失败：保持本地基线（HasSystemd=false 不虚报）。
	e2 := &env.Env{HasSystemd: false, NProc: 4}
	mergeRemoteEnv(e2, cfg, &stubRemote{err: errors.New("down")})
	if e2.HasSystemd {
		t.Fatal("远端失败不得虚报 systemd")
	}
	// 无远端（仅本机）：不探测不合并。
	e3 := &env.Env{HasSystemd: true}
	mergeRemoteEnv(e3, cfg, nil)
	if !e3.HasSystemd {
		t.Fatal("无远端应保持本机环境")
	}
}
