package collect

// testutil_test.go — 采集测试辅助（fake 执行器与健康/故障快检输出）。

import (
	"context"
	"os"
	"strings"
	"time"
)

// fakeL0Remote 实现 RemoteExecutor：按命令返回预设输出队列（按序消费），
// 无精确匹配时返回 defaultOut（注入整段 L0 快检输出）。
// restoreAfter 非空时：收到含该子串的命令（处置验证命令）后 defaultOut
// 切换为 healthyOut——模拟真实环境"处置成功 → L0 数据恢复干净"。
type fakeL0Remote struct {
	outputs      map[string][]string // 命令 → 输出队列
	defaultOut   string              // 兜底输出
	execErr      error               // 非 nil 时所有 Exec 返回该错误（模拟失联）
	restoreAfter string              // 处置成功信号：收到含该子串的命令后环境恢复
	calls        []string
}

func (f *fakeL0Remote) Exec(ctx context.Context, hosts []string, command string, timeout time.Duration) (string, error) {
	f.calls = append(f.calls, command)
	if f.execErr != nil {
		return "", f.execErr
	}
	out := f.defaultOut
	if q := f.outputs[command]; len(q) > 0 {
		out = q[0]
		f.outputs[command] = q[1:]
	}
	// 处置验证通过（收到验证命令）→ 环境恢复：后续 L0 不再检出故障。
	if f.restoreAfter != "" && f.defaultOut == svcFailedOut && strings.Contains(command, f.restoreAfter) {
		f.defaultOut = healthyOut
	}
	return "## " + hosts[0] + "\n" + out, nil
}
func (f *fakeL0Remote) Upload(ctx context.Context, hosts []string, localPath, remotePath string, mode os.FileMode) (string, error) {
	return "", nil
}
func (f *fakeL0Remote) Download(ctx context.Context, hosts []string, remotePath, localDir string) (string, error) {
	return "", nil
}
func (f *fakeL0Remote) FileInfo(ctx context.Context, host, remotePath string, list bool) (string, error) {
	return "", nil
}
func (f *fakeL0Remote) ListHosts() (string, error) { return "", nil }
func (f *fakeL0Remote) Probe(ctx context.Context, aliases []string, timeout time.Duration) map[string]string {
	return nil
}
func (f *fakeL0Remote) Resolve(aliases []string) ([]string, error) { return aliases, nil }

func (f *fakeL0Remote) Aliases() ([]string, error) { return nil, nil }

// 健康与故障的 L0 快检拼接输出（与 collector.buildCommand 的标记匹配）。

const (
	healthyOut = `__M_mem__
MemTotal:       8000000 kB
MemAvailable:   4000000 kB
__M_disk__
Filesystem     1024-blocks      Used Available Capacity Mounted on
/dev/sda1        104755200  83886080  20869120      40% /
__M_inode__
Filesystem      Inodes  IUsed IFree IUse% Mounted on
/dev/sda1        6553600  100000  6453600    2% /
__M_zombie__
PID  TTY  TIME CMD
  S
__M_cpu__
cpu  100 0 50 5000 100 0 0 0 0 0
__M_load__
0.05 0.10 0.15 1/234 12345
`
)

const (
	svcFailedOut = healthyOut + `__M_svc_failed__
nginx.service loaded failed failed nginx
`
)
