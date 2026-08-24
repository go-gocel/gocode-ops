package tools

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRemote 记录调用并返回固定输出，用于 remote_* 工具族的接线测试。
type fakeRemote struct {
	mu        sync.Mutex
	calls     []remoteCall
	uploads   []uploadCall
	downloads []downloadCall
	fileInfos []fileInfoCall
	outputs   map[string]string
	probe     map[string]string
}

type remoteCall struct {
	hosts   []string
	command string
}

type uploadCall struct {
	hosts      []string
	localPath  string
	remotePath string
	mode       os.FileMode
}

type downloadCall struct {
	hosts      []string
	remotePath string
	localDir   string
}

type fileInfoCall struct {
	host string
	path string
	list bool
}

func (f *fakeRemote) Exec(ctx context.Context, hosts []string, command string, timeout time.Duration) (string, error) {
	f.mu.Lock()
	f.calls = append(f.calls, remoteCall{hosts: append([]string{}, hosts...), command: command})
	f.mu.Unlock()
	// 模拟真实执行器：context 注入了进度 sink 时实时回传一个输出块。
	if s := RemoteProgressSink(ctx); s != nil && len(hosts) > 0 {
		s(RemoteProgress{Host: hosts[0], Phase: "output", Text: "stream chunk"})
	}
	var sb strings.Builder
	for _, h := range hosts {
		out := f.outputs[h]
		if out == "" {
			out = "ok"
		}
		sb.WriteString("## " + h + "\n$ " + command + "\n" + out + "\n")
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (f *fakeRemote) Upload(ctx context.Context, hosts []string, localPath, remotePath string, mode os.FileMode) (string, error) {
	f.mu.Lock()
	f.uploads = append(f.uploads, uploadCall{hosts: append([]string{}, hosts...), localPath: localPath, remotePath: remotePath, mode: mode})
	f.mu.Unlock()
	return "上传完成: " + localPath + " → " + remotePath + "（1 个文件，4.0 KB）", nil
}

func (f *fakeRemote) Download(ctx context.Context, hosts []string, remotePath, localDir string) (string, error) {
	f.mu.Lock()
	f.downloads = append(f.downloads, downloadCall{hosts: append([]string{}, hosts...), remotePath: remotePath, localDir: localDir})
	f.mu.Unlock()
	return "下载完成: " + remotePath + " → " + localDir + "（1 个文件，2.0 KB）", nil
}

func (f *fakeRemote) FileInfo(ctx context.Context, host, remotePath string, list bool) (string, error) {
	f.mu.Lock()
	f.fileInfos = append(f.fileInfos, fileInfoCall{host: host, path: remotePath, list: list})
	f.mu.Unlock()
	return "-rw-r--r-- 文件 /opt/app/nginx.conf 4.0 KB 2026-08-10 12:00", nil
}

func (f *fakeRemote) ListHosts() (string, error) {
	return "主机清单（2 台）：\n- web-01（密钥认证）\n- db-01（密码认证）", nil
}

func (f *fakeRemote) Aliases() ([]string, error) { return []string{"web-01", "db-01"}, nil }

func (f *fakeRemote) Probe(ctx context.Context, aliases []string, timeout time.Duration) map[string]string {
	return map[string]string{"web-01": "在线"}
}

// Resolve 展开 "all" 为已知主机名，其余原样返回。
func (f *fakeRemote) Resolve(aliases []string) ([]string, error) {
	var out []string
	for _, a := range aliases {
		if a == "all" {
			for name := range f.outputs {
				out = append(out, name)
			}
			continue
		}
		out = append(out, a)
	}
	return sortHosts(out), nil
}

func (f *fakeRemote) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeRemote) uploadCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.uploads)
}

func (f *fakeRemote) downloadCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.downloads)
}

// ── remote_terminal（单机） ───────────────────────────────────────────

func TestRemoteTerminalTool_SingleHostAndGuard(t *testing.T) {
	ex := &fakeRemote{outputs: map[string]string{"web-01": "CPU 12%"}}
	op := &fakeOperator{answers: []string{"y"}}
	guard := NewRiskyCommandGuard(op, PolicyAsk)
	tool := RemoteTerminalTool(ex, guard)

	// 单机只读命令：直接放行，不询问
	args, _ := json.Marshal(map[string]any{
		"host":    "web-01",
		"command": "uptime",
	})
	msg, err := tool.Run(context.Background(), string(args))
	if err != nil {
		t.Fatalf("只读命令应放行: %v", err)
	}
	if !strings.Contains(msg, "## web-01") || !strings.Contains(msg, "CPU 12%") {
		t.Errorf("单机输出应包含主机与输出: %s", msg)
	}
	if op.calls != 0 {
		t.Errorf("只读命令不应询问操作员，实际 %d 次", op.calls)
	}

	// 高危命令：操作员确认后放行（提示中应含真实主机名）
	args, _ = json.Marshal(map[string]any{
		"host":    "web-01",
		"command": "systemctl restart nginx",
	})
	if _, err := tool.Run(context.Background(), string(args)); err != nil {
		t.Fatalf("批准后应放行: %v", err)
	}
	if !strings.Contains(op.lastPrompt, "web-01") {
		t.Errorf("确认提示应包含目标主机，实际: %s", op.lastPrompt)
	}

	// 拒绝时高危命令不执行
	op2 := &fakeOperator{answers: []string{"n"}}
	guard2 := NewRiskyCommandGuard(op2, PolicyAsk)
	tool2 := RemoteTerminalTool(ex, guard2)
	args, _ = json.Marshal(map[string]any{
		"host":    "web-01",
		"command": "reboot",
	})
	if _, err := tool2.Run(context.Background(), string(args)); err == nil {
		t.Fatal("拒绝后应报错")
	}
	if ex.callCount() != 2 {
		t.Errorf("拒绝的高危命令不应执行，实际执行 %d 次", ex.callCount())
	}

	// 参数校验：host / command 必填
	for _, bad := range []string{
		`{"host":"","command":"uptime"}`,
		`{"host":"web-01","command":"  "}`,
	} {
		if _, err := tool.Run(context.Background(), bad); err == nil {
			t.Errorf("非法参数应报错: %s", bad)
		}
	}
}

// ── remote_batch（批量） ──────────────────────────────────────────────

func TestRemoteBatchTool_BatchAndGuarded(t *testing.T) {
	ex := &fakeRemote{outputs: map[string]string{"web-01": "CPU 12%", "db-01": "CPU 3%"}}
	op := &fakeOperator{answers: []string{"y"}}
	guard := NewRiskyCommandGuard(op, PolicyAsk)
	tool := RemoteBatchTool(ex, guard)

	// 批量只读命令：直接放行，输出按主机分段
	args, _ := json.Marshal(map[string]any{
		"hosts":   []string{"web-01", "db-01"},
		"command": "uptime",
	})
	msg, err := tool.Run(context.Background(), string(args))
	if err != nil {
		t.Fatalf("只读命令应放行: %v", err)
	}
	if !strings.Contains(msg, "## web-01") || !strings.Contains(msg, "## db-01") {
		t.Errorf("批量输出应包含两台主机: %s", msg)
	}
	if op.calls != 0 {
		t.Errorf("只读命令不应询问操作员，实际 %d 次", op.calls)
	}

	// 高危命令：操作员确认后放行（提示中应含目标主机）
	args, _ = json.Marshal(map[string]any{
		"hosts":   []string{"all"},
		"command": "systemctl restart nginx",
	})
	if _, err := tool.Run(context.Background(), string(args)); err != nil {
		t.Fatalf("批准后应放行: %v", err)
	}
	if !strings.Contains(op.lastPrompt, "web-01") || !strings.Contains(op.lastPrompt, "db-01") {
		t.Errorf("确认提示应包含目标主机，实际: %s", op.lastPrompt)
	}

	// 拒绝时高危命令不执行
	op2 := &fakeOperator{answers: []string{"n"}}
	guard2 := NewRiskyCommandGuard(op2, PolicyAsk)
	tool2 := RemoteBatchTool(ex, guard2)
	args, _ = json.Marshal(map[string]any{
		"hosts":   []string{"web-01"},
		"command": "reboot",
	})
	if _, err := tool2.Run(context.Background(), string(args)); err == nil {
		t.Fatal("拒绝后应报错")
	}
	if ex.callCount() != 2 {
		t.Errorf("拒绝的高危命令不应执行，实际执行 %d 次", ex.callCount())
	}

	// 硬性禁止命令：即使操作员同意也不执行
	op3 := &fakeOperator{answers: []string{"y"}}
	guard3 := NewRiskyCommandGuard(op3, PolicyAsk)
	tool3 := RemoteBatchTool(ex, guard3)
	args, _ = json.Marshal(map[string]any{
		"hosts":   []string{"all"},
		"command": "rm -rf /",
	})
	if _, err := tool3.Run(context.Background(), string(args)); err == nil {
		t.Fatal("rm -rf / 应被硬性禁止")
	}
	if ex.callCount() != 2 {
		t.Errorf("硬禁命令不应执行，实际执行 %d 次", ex.callCount())
	}
}

// ── remote_upload / remote_download ───────────────────────────────────

func TestRemoteUploadTool_GuardAndValidation(t *testing.T) {
	ex := &fakeRemote{outputs: map[string]string{"web-01": "ok"}}
	guard := NewRiskyCommandGuard(&fakeOperator{}, PolicyAsk)
	tool := RemoteUploadTool(ex, guard)

	// 凭证路径防护：上传到 ~/.ssh 被拦截
	for _, remotePath := range []string{"~/.ssh/authorized_keys", "/root/.ssh/id_rsa.pub"} {
		args, _ := json.Marshal(map[string]any{
			"hosts":       []string{"web-01"},
			"local_path":  "pubkey.pub",
			"remote_path": remotePath,
		})
		if _, err := tool.Run(context.Background(), string(args)); err == nil {
			t.Errorf("上传到凭证路径应被拦截: %s", remotePath)
		}
	}
	if ex.uploadCount() != 0 {
		t.Error("被拦截的上传不应到达执行器")
	}

	// 本地凭证路径防护：上传 hosts.yaml/私钥到远端再回读的通道同样拦截
	// （否则远端 cat /tmp/x 即可让密码进模型上下文）。
	for _, localPath := range []string{"/root/.ssh/id_ed25519", "deploy/.gocode/hosts.yaml", "/etc/shadow"} {
		args, _ := json.Marshal(map[string]any{
			"hosts":       []string{"web-01"},
			"local_path":  localPath,
			"remote_path": "/tmp/x",
		})
		if _, err := tool.Run(context.Background(), string(args)); err == nil {
			t.Errorf("上传本地凭证路径应被拦截: %s", localPath)
		}
	}
	if ex.uploadCount() != 0 {
		t.Error("本地凭证路径被拦截的上传不应到达执行器")
	}

	// 正常上传：到达执行器，mode 解析正确
	args, _ := json.Marshal(map[string]any{
		"hosts":       []string{"web-01"},
		"local_path":  "app.tar.gz",
		"remote_path": "/opt/app/app.tar.gz",
		"mode":        "0644",
	})
	msg, err := tool.Run(context.Background(), string(args))
	if err != nil {
		t.Fatalf("正常上传应放行: %v", err)
	}
	if !strings.Contains(msg, "上传完成") {
		t.Errorf("输出应含上传完成摘要: %s", msg)
	}
	if len(ex.uploads) != 1 || ex.uploads[0].localPath != "app.tar.gz" || ex.uploads[0].mode != 0o644 {
		t.Errorf("上传参数未正确传递: %+v", ex.uploads)
	}

	// 非法 mode 报错
	args, _ = json.Marshal(map[string]any{
		"hosts":       []string{"web-01"},
		"local_path":  "a.tar",
		"remote_path": "/opt/a.tar",
		"mode":        "not-a-mode",
	})
	if _, err := tool.Run(context.Background(), string(args)); err == nil {
		t.Error("非法 mode 应报错")
	}
}

func TestRemoteDownloadTool_GuardAndValidation(t *testing.T) {
	ex := &fakeRemote{outputs: map[string]string{"web-01": "ok"}}
	guard := NewRiskyCommandGuard(&fakeOperator{}, PolicyAsk)
	tool := RemoteDownloadTool(ex, guard)

	// 凭证路径防护：下载凭证被拦截
	for _, remotePath := range []string{"/root/.ssh/id_rsa", "/etc/shadow", "~/.gocode/hosts.yaml"} {
		args, _ := json.Marshal(map[string]any{
			"hosts":       []string{"web-01"},
			"remote_path": remotePath,
			"local_dir":   "./backup",
		})
		if _, err := tool.Run(context.Background(), string(args)); err == nil {
			t.Errorf("下载凭证路径应被拦截: %s", remotePath)
		}
	}
	if ex.downloadCount() != 0 {
		t.Error("被拦截的下载不应到达执行器")
	}

	// 正常下载：到达执行器
	args, _ := json.Marshal(map[string]any{
		"hosts":       []string{"web-01"},
		"remote_path": "/var/log/nginx/access.log",
		"local_dir":   "./logs",
	})
	msg, err := tool.Run(context.Background(), string(args))
	if err != nil {
		t.Fatalf("正常下载应放行: %v", err)
	}
	if !strings.Contains(msg, "下载完成") {
		t.Errorf("输出应含下载完成摘要: %s", msg)
	}
	if len(ex.downloads) != 1 || ex.downloads[0].localDir != "./logs" {
		t.Errorf("下载参数未正确传递: %+v", ex.downloads)
	}
}

// ── remote_list / remote_file ─────────────────────────────────────────

func TestRemoteListAndFileTools(t *testing.T) {
	ex := &fakeRemote{outputs: map[string]string{"web-01": "ok"}}
	guard := NewRiskyCommandGuard(&fakeOperator{}, PolicyAsk)

	// remote_list：无参，返回主机清单
	tool := RemoteListTool(ex, guard)
	msg, err := tool.Run(context.Background(), `{}`)
	if err != nil {
		t.Fatalf("remote_list: %v", err)
	}
	if !strings.Contains(msg, "主机清单") || !strings.Contains(msg, "web-01") {
		t.Errorf("remote_list 输出应含主机清单: %s", msg)
	}

	// remote_file：stat 与 list 两种形态
	ftool := RemoteFileTool(ex, guard)
	msg, err = ftool.Run(context.Background(), `{"host":"web-01","path":"/opt/app"}`)
	if err != nil {
		t.Fatalf("remote_file stat: %v", err)
	}
	if !strings.Contains(msg, "nginx.conf") {
		t.Errorf("remote_file 输出应含文件信息: %s", msg)
	}
	if _, err := ftool.Run(context.Background(), `{"host":"web-01","path":"/opt/app","list":true}`); err != nil {
		t.Fatalf("remote_file list: %v", err)
	}
	if len(ex.fileInfos) != 2 || !ex.fileInfos[1].list {
		t.Errorf("fileInfo 参数未正确传递: %+v", ex.fileInfos)
	}

	// 参数校验
	for _, bad := range []string{
		`{"host":"","path":"/opt"}`,
		`{"host":"web-01","path":"  "}`,
	} {
		if _, err := ftool.Run(context.Background(), bad); err == nil {
			t.Errorf("非法参数应报错: %s", bad)
		}
	}
}

// ── 进度回调注入 ──────────────────────────────────────────────────────

func TestRemoteProgressSinkInjectedToTool(t *testing.T) {
	// WithRemoteProgress 注入的 sink 应被工具透传进执行器（ctx 链）。
	ex := &fakeRemote{outputs: map[string]string{"web-01": "ok"}}
	tool := RemoteTerminalTool(ex, NewRiskyCommandGuard(&fakeOperator{}, PolicyAsk))

	var got []RemoteProgress
	ctx := WithRemoteProgress(context.Background(), func(p RemoteProgress) {
		got = append(got, p)
	})
	// fake 的 Exec 通过 remoteProgressSink 回传一个块，验证 ctx 链路完整。
	args, _ := json.Marshal(map[string]any{"host": "web-01", "command": "tail -f /var/log/x"})
	if _, err := tool.Run(ctx, string(args)); err != nil {
		t.Fatalf("tool.Run: %v", err)
	}
	if len(got) != 1 || got[0].Host != "web-01" || got[0].Phase != "output" {
		t.Errorf("进度回调未到达（ctx 链路断裂）: %+v", got)
	}
}

// ── SSH 执行器：清单与解析 ────────────────────────────────────────────

func TestRemoteCopyTool_GuardAndWiring(t *testing.T) {
	guard := NewRiskyCommandGuard(nil, PolicyDeny)
	// 凭证路径双向拦截。
	tool := RemoteCopyTool(&fakeCopier{fakeRemote: &fakeRemote{}}, guard)
	args, _ := json.Marshal(map[string]any{
		"source_host": "web-01", "source_path": "/root/.ssh/id_rsa",
		"target_hosts": []string{"web-02"}, "target_path": "/tmp/x",
	})
	if _, err := tool.Run(context.Background(), string(args)); err == nil {
		t.Error("复制凭证路径应被拦截")
	}
	// 正常路径 + fake 执行器 → 调用 Copy。
	args, _ = json.Marshal(map[string]any{
		"source_host": "web-01", "source_path": "/srv/app.tar",
		"target_hosts": []string{"web-02"}, "target_path": "/srv/app.tar",
	})
	got, err := tool.Run(context.Background(), string(args))
	if err != nil || got != "复制完成" {
		t.Fatalf("copy = %q, %v", got, err)
	}
	// 不支持 RemoteCopier 的执行器 → 引导双程。
	plain := RemoteCopyTool(&fakeRemote{}, guard)
	args, _ = json.Marshal(map[string]any{
		"source_host": "web-01", "source_path": "/srv/a",
		"target_hosts": []string{"web-02"}, "target_path": "/srv/a",
	})
	if _, err := plain.Run(context.Background(), string(args)); err == nil ||
		!strings.Contains(err.Error(), "remote_download") {
		t.Errorf("不支持时应引导双程: %v", err)
	}
}

// ── 观察项落地：断点续传 / 符号链接 / 探测缓存 ────────────────────────

// fakeCopier 实现 RemoteCopier 的 fake（接线测试用）。
type fakeCopier struct {
	*fakeRemote
	copied bool
}

func (f *fakeCopier) Copy(ctx context.Context, sourceHost, sourcePath string, targetHosts []string, targetPath string) (string, error) {
	f.copied = true
	return "复制完成", nil
}
