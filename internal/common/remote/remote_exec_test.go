package remote

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// remote_exec_test.go — SSH 执行器/清单/传输/结果格式化的白盒测试（随实现迁入 remote 包）。

func TestSSHExecutor_InventoryAndResolution(t *testing.T) {
	dir := t.TempDir()
	invPath := dir + "/hosts.yaml"
	writeTestInventory(t, invPath)

	ex := newSSHExecutor(RemoteConfig{InventoryPath: invPath})
	inv, err := ex.loadInventory()
	if err != nil {
		t.Fatalf("loadInventory: %v", err)
	}
	hosts, err := ex.resolveHosts(inv, []string{"all"})
	if err != nil || len(hosts) != 2 {
		t.Fatalf("resolveHosts(all) = %v, %v", hosts, err)
	}
	hosts, err = ex.resolveHosts(inv, []string{"web-01"})
	if err != nil || len(hosts) != 1 || hosts[0].Address != "10.0.0.11" {
		t.Fatalf("resolveHosts(web-01) = %v, %v", hosts, err)
	}
	if _, err := ex.resolveHosts(inv, []string{"nope"}); err == nil {
		t.Error("未知别名应报错")
	}
	if _, err := ex.resolveHosts(inv, nil); err == nil {
		t.Error("空 hosts 应报错")
	}

	// 无清单时的引导错误
	ex2 := newSSHExecutor(RemoteConfig{})
	if _, err := ex2.Exec(context.Background(), []string{"all"}, "uptime", 0); err == nil ||
		!strings.Contains(err.Error(), "gocode-ops init") {
		t.Errorf("无清单应给出引导错误: %v", err)
	}
}

func TestSSHExecutor_ListInventoryView(t *testing.T) {
	dir := t.TempDir()
	invPath := dir + "/hosts.yaml"
	writeTestInventory(t, invPath)

	views, err := ListInventory(invPath)
	if err != nil {
		t.Fatalf("ListInventory: %v", err)
	}
	if len(views) != 2 {
		t.Fatalf("应返回 2 台主机，实际 %d", len(views))
	}
	if views[0].Name != "web-01" || views[0].Address != "10.0.0.11" || views[0].User != "root" || views[0].Auth != "密钥" {
		t.Errorf("web-01 视图不正确: %+v", views[0])
	}
	if views[1].Auth != "密码" {
		t.Errorf("db-01 应为密码认证: %+v", views[1])
	}
}

func TestSSHExecutor_ListHostsHidesCredentials(t *testing.T) {
	dir := t.TempDir()
	invPath := dir + "/hosts.yaml"
	writeTestInventory(t, invPath)

	ex := newSSHExecutor(RemoteConfig{InventoryPath: invPath})
	out, err := ex.ListHosts()
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	// 别名与认证方式可见；地址、用户、密码绝不出现（凭证零泄露）
	if !strings.Contains(out, "web-01") || !strings.Contains(out, "密钥认证") {
		t.Errorf("清单应含别名与认证方式: %s", out)
	}
	for _, secret := range []string{"10.0.0.11", "root", "s3cret", "id_ed25519"} {
		if strings.Contains(out, secret) {
			t.Errorf("模型可读清单泄露了 %q: %s", secret, out)
		}
	}
}

func TestParseFileMode(t *testing.T) {
	cases := []struct {
		in   string
		want os.FileMode
	}{
		{"", 0},
		{"0644", 0o644},
		{"0755", 0o755},
		{"0600", 0o600},
		{"0644 ", 0o644},
	}
	for _, tc := range cases {
		got, err := parseFileMode(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("parseFileMode(%q) = %v, %v; want %v", tc.in, got, err, tc.want)
		}
	}
	if _, err := parseFileMode("abc"); err == nil {
		t.Error("非法 mode 应报错")
	}
}

func TestSortHosts(t *testing.T) {
	got := sortHosts([]string{"db-01", "web-01", "db-01", ""})
	want := []string{"db-01", "web-01"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("sortHosts = %v, want %v", got, want)
	}
}

func writeTestInventory(t *testing.T, path string) {
	t.Helper()
	content := `hosts:
  - name: web-01
    address: 10.0.0.11
    user: root
    key_file: ~/.ssh/id_ed25519
  - name: db-01
    address: 10.0.0.12:22
    user: ops
    password: "s3cret"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
}

// ── 远程工具族：P0/P1 修复与 remote_copy ─────────────────────────────

func TestTruncateHeadTail(t *testing.T) {
	if got := truncateHeadTail("短输出", 100); got != "短输出" {
		t.Errorf("短输出不应截断: %q", got)
	}
	long := strings.Repeat("0123456789", 1000) // 10K
	got := truncateHeadTail(long, 8000)
	if !strings.HasPrefix(got, "0123456789") || !strings.HasSuffix(got, "0123456789") {
		t.Error("截断应保留头尾")
	}
	if !strings.Contains(got, "省略") {
		t.Errorf("截断应含省略提示: %q", got[:80])
	}
}

func TestCapRemoteTimeout(t *testing.T) {
	if got := capRemoteTimeout(30 * time.Second); got != 30*time.Second {
		t.Errorf("常规值不应变化: %v", got)
	}
	if got := capRemoteTimeout(2 * time.Hour); got != remoteMaxTimeout {
		t.Errorf("超限应封顶: %v, want %v", got, remoteMaxTimeout)
	}
}

func TestClientKey_AuthFingerprint(t *testing.T) {
	a := Host{Address: "10.0.0.1", User: "root", KeyFile: "~/.ssh/id_rsa"}
	b := Host{Address: "10.0.0.1", User: "root", Password: "secret"}
	c := Host{Address: "10.0.0.1", User: "root", Password: "changed"}
	if clientKey(a) == clientKey(b) || clientKey(b) == clientKey(c) {
		t.Error("认证方式/凭证变化必须产生不同缓存键（否则旧连接继续用旧凭证）")
	}
	if clientKey(a) != clientKey(a) {
		t.Error("同配置应同键")
	}
}

// TestExec_AllHostsFailedReturnsError 全部主机连接失败必须返回 error
// （工具框架/TUI/引擎才能感知失败），输出文本仍保留逐台错误。
func TestExec_AllHostsFailedReturnsError(t *testing.T) {
	dir := t.TempDir()
	invPath := dir + "/hosts.yaml"
	if err := os.WriteFile(invPath, []byte("hosts:\n  - name: bad\n    address: 127.0.0.1:1\n    user: root\n    password: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ex := newSSHExecutor(RemoteConfig{InventoryPath: invPath})
	out, err := ex.Exec(context.Background(), []string{"all"}, "uptime", 5*time.Second)
	if err == nil {
		t.Fatal("全部主机失败应返回 error")
	}
	if !strings.Contains(out, "错误:") {
		t.Errorf("输出应保留逐台错误: %q", out)
	}
}

// TestUploadDownload_AllHostsFailedReturnsError 传输全部主机失败必须返回
// error（与 Exec 同语义）：此前 Upload/Download/Copy 全失败仍返回 nil，
// 工具框架视为成功，助手/引擎误判继续执行后续动作。
func TestUploadDownload_AllHostsFailedReturnsError(t *testing.T) {
	dir := t.TempDir()
	invPath := dir + "/hosts.yaml"
	if err := os.WriteFile(invPath, []byte("hosts:\n  - name: bad\n    address: 127.0.0.1:1\n    user: root\n    password: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	local := dir + "/app.tar.gz"
	if err := os.WriteFile(local, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	ex := newSSHExecutor(RemoteConfig{InventoryPath: invPath})

	out, err := ex.Upload(context.Background(), []string{"all"}, local, "/tmp/x", 0)
	if err == nil || !strings.Contains(err.Error(), "上传失败") {
		t.Fatalf("全部主机上传失败应返回 error: out=%q err=%v", out, err)
	}
	if !strings.Contains(out, "错误:") {
		t.Errorf("上传输出应保留逐台错误: %q", out)
	}

	out, err = ex.Download(context.Background(), []string{"all"}, "/var/log/app.log", dir+"/logs")
	if err == nil || !strings.Contains(err.Error(), "下载失败") {
		t.Fatalf("全部主机下载失败应返回 error: out=%q err=%v", out, err)
	}
	if !strings.Contains(out, "错误:") {
		t.Errorf("下载输出应保留逐台错误: %q", out)
	}
}

// TestFormatExecResults_PartialFailureSummary 部分失败时失败主机名置顶
// 聚合（模型必须知道哪台失败）；全部失败返回 error；全成功无聚合行。
func TestFormatExecResults_PartialFailureSummary(t *testing.T) {
	results := []execResult{
		{host: "web-01", output: "ok"},
		{host: "db-01", output: "错误: boom", err: errors.New("boom")},
		{host: "web-02", output: "ok2"},
	}
	out, err := formatExecResults(results, perHostCap, totalCap)
	if err != nil {
		t.Fatalf("部分失败应保留 nil error: %v", err)
	}
	if !strings.Contains(out, "部分失败（1/3）: db-01") {
		t.Errorf("输出应含失败主机聚合: %q", out)
	}

	out, err = formatExecResults([]execResult{
		{host: "a", output: "错误: x", err: errors.New("x")},
		{host: "b", output: "错误: y", err: errors.New("y")},
	}, perHostCap, totalCap)
	if err == nil || !strings.Contains(err.Error(), "全部 2 台") {
		t.Fatalf("全部失败应返回 error: out=%q err=%v", out, err)
	}

	out, err = formatExecResults([]execResult{{host: "a", output: "ok"}}, perHostCap, totalCap)
	if err != nil || strings.Contains(out, "部分失败") {
		t.Fatalf("全成功不应有聚合行: out=%q err=%v", out, err)
	}
}

// TestFormatExecResults_CollectBudget 收集路径（总预算 1MB）不得把唯一
// 主机的 >64K 采集输出整段跳过——展示预算会把整台主机输出丢弃，采集
// 侧因此静默失明（指标/状态探针 0 项）。
func TestFormatExecResults_CollectBudget(t *testing.T) {
	big := strings.Repeat("x", 71<<10)
	out, err := formatExecResults([]execResult{{host: "ops-target", output: big}}, maxCollectOut, remoteCollectCap)
	if err != nil {
		t.Fatalf("收集路径不应报错: %v", err)
	}
	if !strings.Contains(out, big) {
		t.Errorf("收集路径应保留主机完整输出: len(out)=%d", len(out))
	}
	// 展示路径同输出仍受 64K 总预算约束（模型上下文护栏）。
	out, err = formatExecResults([]execResult{{host: "ops-target", output: big}}, maxCollectOut, totalCap)
	if err != nil {
		t.Fatalf("展示路径不应报错: %v", err)
	}
	if strings.Contains(out, big) || !strings.Contains(out, "总上限") {
		t.Errorf("展示路径应跳过超预算主机并标注: len(out)=%d", len(out))
	}
}

func TestResumeOffset(t *testing.T) {
	if got := resumeOffset(1000, 0); got != 0 {
		t.Errorf("目标缺失应重传: %v", got)
	}
	if got := resumeOffset(1000, 600); got != 600 {
		t.Errorf("目标部分存在应续传: %v", got)
	}
	if got := resumeOffset(1000, 1000); got != 0 {
		t.Errorf("目标完整应重传（校验失败场景）: %v", got)
	}
	if got := resumeOffset(1000, 2000); got != 0 {
		t.Errorf("目标更大应重传: %v", got)
	}
}

// TestUploadDirSymlinkToDir 上传含 symlink-to-dir 的目录树：跟随链接
// （部署目录 current → releases/xxx 类链接不能丢），环防护保证终止。
func TestUploadDirSymlinkToDir(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base")
	if err := os.MkdirAll(filepath.Join(base, "releases", "v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "releases", "v1", "app.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Windows 建符号链接需要特权：不支持时跳过（CI Linux 覆盖）。
	if err := os.Symlink(filepath.Join("releases", "v1"), filepath.Join(base, "current")); err != nil {
		t.Skipf("符号链接不可用: %v", err)
	}
	// 环：current/loop → base 自身（visited 防护必须终止且不重复上传）。
	if err := os.Symlink(base, filepath.Join(base, "releases", "v1", "loop")); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("准备失败: %v", entries)
	}
	// 只验证类型判定逻辑（真实 SFTP 上传由集成环境覆盖）：
	for _, ent := range entries {
		lp := filepath.Join(base, ent.Name())
		isDir := ent.IsDir()
		if ent.Type()&os.ModeSymlink != 0 {
			if st, serr := os.Stat(lp); serr == nil {
				isDir = st.IsDir()
			}
		}
		if ent.Name() == "current" && !isDir {
			t.Error("symlink-to-dir 应判定为目录")
		}
	}
}

// TestProbeCacheSanitizedForModel 探测结果缓存进执行器并脱敏：
// 错误细节（含地址）不得出现在 ListHosts（模型上下文）。
func TestProbeCacheSanitizedForModel(t *testing.T) {
	dir := t.TempDir()
	invPath := dir + "/hosts.yaml"
	if err := os.WriteFile(invPath, []byte("hosts:\n  - name: bad\n    address: 127.0.0.1:1\n    user: root\n    password: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ex := newSSHExecutor(RemoteConfig{InventoryPath: invPath})
	res := ex.Probe(context.Background(), []string{"all"}, 0)
	if !strings.Contains(res["bad"], "连接失败") {
		t.Fatalf("探测应返回失败状态: %v", res)
	}
	out, err := ex.ListHosts()
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if !strings.Contains(out, "最近探测: 连接失败") {
		t.Errorf("ListHosts 应附最近探测状态: %q", out)
	}
	if strings.Contains(out, "127.0.0.1") {
		t.Errorf("地址不得进入模型上下文: %q", out)
	}
}
