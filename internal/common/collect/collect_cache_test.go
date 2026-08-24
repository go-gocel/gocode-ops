package collect

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestCollector_HeavyFactTTLCache 重探针（大文件/能力位/SUID/世界可写/临时
// 目录）TTL 内复用缓存：第二次显式采集的命令剔除这些片段（全盘 find 不再
// 每轮执行），缓存输出照常进 Raw 供归属规则与模型上下文消费；TTL 到期
// 后恢复实采。数值指标/漂移快照不受缓存影响（恒在命令中）。
// 例行集语义（design-v2.md §二）：全盘下钻探针（big_files）只经显式
// collect_probe 执行，例行全量命令绝不包含。
func TestCollector_HeavyFactTTLCache(t *testing.T) {
	env := &Env{HasSystemd: true, HasSS: true, NProc: 8}
	cfg := DefaultEngineConfig()
	cfg.Local = false
	cfg.Hosts = []string{"web-01"}
	cfg.FactRefreshInterval = time.Hour // 测试内不自然过期

	heavyOut := strings.Join([]string{
		"__M_big_files__",
		"/data/huge.bin",
		"__M_file_caps__",
		"/usr/bin/python3 cap_net_bind_service=ep",
		"__M_suid_files__",
		"/usr/bin/passwd",
		"__M_world_writable__",
		"/etc/example.conf",
		"__M_tmp_dirs__",
		"/tmp 3000",
	}, "\n")
	remote := &fakeL0Remote{defaultOut: healthyOut + heavyOut}
	c := NewCollector(cfg, env, remote)
	ms := Metrics(env)
	heavyIDs := []string{"big_files", "file_caps", "suid_files", "world_writable", "tmp_dirs"}

	// 第一轮：显式定向采集（含下钻探针 big_files）→ 实采 + 覆盖 full。
	snap1, err := c.CollectProbes(context.Background(), ms, heavyIDs)
	if err != nil {
		t.Fatalf("第一轮采集: %v", err)
	}
	if got := snap1.Hosts[0].Raw["big_files"]; !strings.Contains(got, "/data/huge.bin") {
		t.Fatalf("第一轮应实采 big_files: %q", got)
	}
	if cov := snap1.Hosts[0].FactCoverage["big_files"]; cov != "full" {
		t.Errorf("完整采集覆盖应为 full，实际 %q", cov)
	}
	full := remote.calls[0]
	for _, id := range heavyIDs {
		if !strings.Contains(full, fragmentMark(id)) {
			t.Fatalf("显式采集命令应包含 %s 片段", id)
		}
	}

	// 例行集排除下钻（独立采集器/空缓存）：全量命令不含 big_files——
	// 全盘枚举只经显式请求执行（2.3T/7000 万 inode 根分区上例行全盘
	// find 即事故源），定点探针在例行集中。
	r2 := &fakeL0Remote{defaultOut: healthyOut + heavyOut}
	c2 := NewCollector(cfg, env, r2)
	if _, err := c2.CollectMetrics(context.Background(), ms); err != nil {
		t.Fatalf("例行采集: %v", err)
	}
	routine := r2.calls[0]
	if strings.Contains(routine, fragmentMark("big_files")) {
		t.Error("例行集不得含下钻探针 big_files（全盘 find 无界）")
	}
	for _, id := range []string{"suid_files", "file_caps", "world_writable", "tmp_dirs"} {
		if !strings.Contains(routine, fragmentMark(id)) {
			t.Errorf("例行集应含定点探针 %s", id)
		}
	}
	if !strings.Contains(routine, fragmentMark("cpu")) || !strings.Contains(routine, fragmentMark("state_sshd")) {
		t.Error("数值指标与漂移快照应在例行命令中")
	}

	// 第二轮（显式）：重探针全部命中缓存，命令剔除五个片段。
	snap2, err := c.CollectProbes(context.Background(), ms, heavyIDs)
	if err != nil {
		t.Fatalf("第二轮采集: %v", err)
	}
	short := remote.calls[1]
	for _, id := range heavyIDs {
		if strings.Contains(short, fragmentMark(id)) {
			t.Errorf("第二轮命令不应再包含 %s 片段（缓存命中）", id)
		}
	}
	if !strings.Contains(short, fragmentMark("cpu")) {
		t.Error("cpu 片段恒附加，应在显式命令中")
	}
	if strings.Contains(short, fragmentMark("state_sshd")) {
		t.Error("显式定向采集不含状态快照（漂移由基线机制负责）")
	}
	// 缓存输出照常进 Raw（归属规则与模型上下文不感知缓存）。
	if got := snap2.Hosts[0].Raw["big_files"]; !strings.Contains(got, "/data/huge.bin") {
		t.Errorf("第二轮 big_files 应来自缓存: %q", got)
	}
	if age, ok := snap2.Hosts[0].FactAge["big_files"]; !ok || age == "" {
		t.Errorf("缓存命中应标注数据龄期（供模型上下文），实际 %q", age)
	}

	// 第三轮：TTL 到期后恢复实采（显式命令重新包含重探针）。
	c.cfg.FactRefreshInterval = time.Nanosecond
	time.Sleep(time.Millisecond)
	if _, err := c.CollectProbes(context.Background(), ms, heavyIDs); err != nil {
		t.Fatalf("第三轮采集: %v", err)
	}
	again := remote.calls[2]
	for _, id := range []string{"big_files", "file_caps", "suid_files", "world_writable", "tmp_dirs"} {
		if !strings.Contains(again, fragmentMark(id)) {
			t.Errorf("TTL 到期后命令应恢复 %s 片段", id)
		}
	}
}

// TestCollector_HeavyFactCacheEmptyResult 空结果也缓存：重探针扫描无
// 结果（标记段为空）同样是有效结果，TTL 内不重复全盘扫描。
func TestCollector_HeavyFactCacheEmptyResult(t *testing.T) {
	env := &Env{NProc: 8}
	cfg := DefaultEngineConfig()
	cfg.Local = false
	cfg.Hosts = []string{"web-01"}
	cfg.FactRefreshInterval = time.Hour

	out := healthyOut + "\n__M_big_files__\n\n__M_file_caps__\n\n__M_world_writable__\n\n__M_tmp_dirs__\n"
	remote := &fakeL0Remote{defaultOut: out}
	c := NewCollector(cfg, env, remote)
	ms := Metrics(env)
	ids := []string{"big_files", "file_caps", "world_writable", "tmp_dirs"}

	if _, err := c.CollectProbes(context.Background(), ms, ids); err != nil {
		t.Fatalf("第一轮采集: %v", err)
	}
	if _, err := c.CollectProbes(context.Background(), ms, ids); err != nil {
		t.Fatalf("第二轮采集: %v", err)
	}
	for _, id := range ids {
		if strings.Contains(remote.calls[1], fragmentMark(id)) {
			t.Errorf("空结果也应缓存：第二轮命令不应再包含 %s", id)
		}
	}
}

// TestCollector_CacheDisabledWhenIntervalZero FactRefreshInterval<=0
// 禁用缓存：每轮都执行完整命令（确定性最强，测试/特殊环境可关闭）。
func TestCollector_CacheDisabledWhenIntervalZero(t *testing.T) {
	env := &Env{NProc: 8}
	cfg := DefaultEngineConfig()
	cfg.Local = false
	cfg.Hosts = []string{"web-01"}
	cfg.FactRefreshInterval = 0

	out := healthyOut + "\n__M_big_files__\n/data/huge.bin\n"
	remote := &fakeL0Remote{defaultOut: out}
	c := NewCollector(cfg, env, remote)
	ms := Metrics(env)
	ids := []string{"big_files"}

	for i := 0; i < 2; i++ {
		if _, err := c.CollectProbes(context.Background(), ms, ids); err != nil {
			t.Fatalf("第 %d 轮采集: %v", i+1, err)
		}
		if !strings.Contains(remote.calls[i], fragmentMark("big_files")) {
			t.Errorf("缓存禁用时第 %d 轮命令应包含 big_files", i+1)
		}
	}
	if hits, _ := c.FactCacheStats(); hits != 0 {
		t.Errorf("缓存禁用时不应有命中，实际 %d", hits)
	}
}

// TestCollector_SentinelMarksPartial 探针完成哨兵：片段含
// __PROBE_INCOMPLETE__ → 覆盖 partial、结果不进缓存、哨兵行不污染 Raw。
func TestCollector_SentinelMarksPartial(t *testing.T) {
	env := &Env{NProc: 8}
	cfg := DefaultEngineConfig()
	cfg.Local = false
	cfg.Hosts = []string{"web-01"}
	cfg.FactRefreshInterval = time.Hour

	out := healthyOut + "\n__M_big_files__\n/data/huge.bin\n__PROBE_INCOMPLETE__\n"
	remote := &fakeL0Remote{defaultOut: out}
	c := NewCollector(cfg, env, remote)
	ms := Metrics(env)

	snap, err := c.CollectProbes(context.Background(), ms, []string{"big_files"})
	if err != nil {
		t.Fatalf("采集: %v", err)
	}
	hm := snap.Hosts[0]
	if cov := hm.FactCoverage["big_files"]; cov != "partial" {
		t.Errorf("哨兵触发后覆盖应为 partial，实际 %q", cov)
	}
	if strings.Contains(hm.Raw["big_files"], "__PROBE_INCOMPLETE__") {
		t.Error("哨兵行不得污染 Raw/上下文")
	}
	if !strings.Contains(hm.Raw["big_files"], "/data/huge.bin") {
		t.Error("部分完成的枚举结果仍应保留（作证据进上下文，但覆盖为 partial）")
	}
	// 不完整结果不进缓存：下一轮（TTL 内）仍实采。
	if _, err := c.CollectProbes(context.Background(), ms, []string{"big_files"}); err != nil {
		t.Fatalf("第二轮采集: %v", err)
	}
	if !strings.Contains(remote.calls[1], fragmentMark("big_files")) {
		t.Error("partial 结果不得进缓存：第二轮命令应重新实采 big_files")
	}
}

// TestCollector_CollectErrorMarksPartialAndNoCache 采集层失败（超时/
// 断连）：命令内事实覆盖 partial（结果不可作结论），且不写缓存。
func TestCollector_CollectErrorMarksPartialAndNoCache(t *testing.T) {
	env := &Env{NProc: 8}
	cfg := DefaultEngineConfig()
	cfg.Local = false
	cfg.Hosts = []string{"web-01"}
	cfg.FactRefreshInterval = time.Hour

	remote := &failL0Remote{out: healthyOut + "\n__M_big_files__\n/data/huge.bin\n"}
	c := NewCollector(cfg, env, remote)
	ms := Metrics(env)

	snap, err := c.CollectProbes(context.Background(), ms, []string{"big_files"})
	if err != nil {
		t.Fatalf("采集: %v", err)
	}
	hm := snap.Hosts[0]
	if cov := hm.FactCoverage["big_files"]; cov != "partial" {
		t.Errorf("采集失败后覆盖应为 partial，实际 %q", cov)
	}
	if _, ok := hm.Errors["collect"]; !ok {
		t.Error("采集失败应记录 collect 错误")
	}
	// 不写缓存：下一轮仍实采（命令再次发出）。
	if _, err := c.CollectProbes(context.Background(), ms, []string{"big_files"}); err != nil {
		t.Fatalf("第二轮采集: %v", err)
	}
	if len(remote.calls) != 2 {
		t.Fatalf("应执行 2 条命令（不完整结果不得进缓存复用），实际 %d", len(remote.calls))
	}
}

// failL0Remote 恒失败采集器（覆盖语义测试用）：复用 fakeL0Remote 的
// 其余 RemoteExecutor 方法，ExecCollect 恒返回错误（模拟超时/断连）。
type failL0Remote struct {
	fakeL0Remote
	out string
}

func (f *failL0Remote) ExecCollect(ctx context.Context, aliases []string, command string, timeout time.Duration) (string, error) {
	f.calls = append(f.calls, command)
	return f.out, errCollectFail
}

var errCollectFail = &collectFailErr{}

type collectFailErr struct{}

func (e *collectFailErr) Error() string { return "采集超时（模拟）" }
