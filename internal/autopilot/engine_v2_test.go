package autopilot

// 架构 v2 引擎测试：并行调度（批次级）、期望状态偏差集成、认知工具、
// 学习闭环、工作流状态机。

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-gocel/gocode-ops/internal/common/env"
	mdl "github.com/go-gocel/gocode-ops/internal/common/model"
	"github.com/go-gocel/gocode-ops/internal/common/probe"
)

// TestEngine_ParallelDeepDiveBatches 并行 DeepDive：多条线索分 2 批并行
// 执行（worker 池），两批都完成、线索被标记追查、无数据竞争（-race）。
func TestEngine_ParallelDeepDiveBatches(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: healthyOut}
	// 空 findings 回复：不产出新线索（避免干扰"全部追查"断言）。
	// 直接调 deepDive（不跑 survey）——回复序列从 deepdive 批开始。
	emptyReply := `{"phase":"deepdive","done":true,"covered":["svc"],"findings":[]}`
	e, _, model := testEngineProtocol(t,
		[]string{emptyReply, emptyReply},
		remote)
	e.cfg.Parallel.Workers = 2

	// 注入 25 条 pending 线索（> deepDiveBatchSize=1 → 25 批；Key 参与
	// 去重，必须互不相同）。
	var leads []*mdl.Finding
	for i := 0; i < 25; i++ {
		f := mdl.NewFinding("web-01", "svc", "svc_failed", fmtTestLead(i))
		f.Key = fmtTestLead(i)
		leads = append(leads, f)
	}
	if err := e.ws().AddFindings(leads); err != nil {
		t.Fatal(err)
	}

	e.deepDive(context.Background())

	// 两批都应成功：所有线索 Tried>=1。
	untried := 0
	for _, f := range e.ws().Pending() {
		if f.Tried == 0 {
			untried++
		}
	}
	if untried != 0 {
		t.Errorf("并行追查后仍有 %d 条未追查线索", untried)
	}
	// 两批并行 → 2 次追查模型调用（未跑 survey）。
	if model.call < 2 {
		t.Errorf("并行批次应产生 ≥2 次追查调用，实际 model.call=%d", model.call)
	}
}

func fmtTestLead(i int) string { return "test-lead-" + string(rune('a'+i%26)) }

// TestEngine_ParallelDeepDiveBatchesExceedWorkers 回归 P0：批次 > worker
// 时，旧实现按批下标取模选 app（batchApp），批 0 与批 2（差一个 worker 数）
// 会同时映射到同一 *phaseAgent（同一 Session），并发调用 Session.RunFresh
// 改写同一 s.history → 数据竞争（go test -race 下崩溃）。本测试 30 条线索
// → 6 批、parallel=2，断言所有线索均被追查且模型调用数 == 批数（每批独占
// 一个 worker app，无碰撞）。-race 下通过即证明竞争已消除。
func TestEngine_ParallelDeepDiveBatchesExceedWorkers(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: healthyOut}
	emptyReply := `{"phase":"deepdive","done":true,"covered":["svc"],"findings":[]}`
	e, _, model := testEngineProtocol(t, []string{emptyReply}, remote)
	e.cfg.Parallel.Workers = 2 // 默认配置即触发旧 bug

	// 30 条 pending 线索（> 30 × deepDiveBatchSize=1 → 30 批 > 2 worker）。
	// Key 必须互不相同（参与去重）。
	const n = 30
	var leads []*mdl.Finding
	for i := 0; i < n; i++ {
		f := mdl.NewFinding("web-01", "svc", "svc_failed", fmt.Sprintf("lead-%d", i))
		f.Key = fmt.Sprintf("lead-%d", i)
		leads = append(leads, f)
	}
	if err := e.ws().AddFindings(leads); err != nil {
		t.Fatal(err)
	}

	e.deepDive(context.Background())

	untried := 0
	for _, f := range e.ws().Pending() {
		if f.Tried == 0 {
			untried++
		}
	}
	if untried != 0 {
		t.Errorf("并行追查后仍有 %d 条未追查线索", untried)
	}
	// 每批独立一次调用 → 调用数 == 批数（30：30 条 / deepDiveBatchSize=1，
	// 单线索子代理粒度）。若旧代码的取模碰撞导致同一 Session 被并发
	// 调用，虽不直接影响调用计数，但本断言 + -race 共同锁死"批次经
	// 独占 worker 派发"的不变式。
	const batches = 30
	if model.call != batches {
		t.Errorf("模型调用数应为 %d（每批一次），实际 %d", batches, model.call)
	}
}

// TestEngine_ParallelRespondBatches 并行 Respond：6 个已确认故障分 3 批
// 并行生成方案并执行，全部被处置。
func TestEngine_ParallelRespondBatches(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	// 6 个故障的处置/验证命令各需 6 个响应（并行批次按序消费）。
	remote.outputs = map[string][]string{
		"systemctl restart nginx.service":   {"restarted", "restarted", "restarted", "restarted", "restarted", "restarted"},
		"systemctl is-active nginx.service": {"active", "active", "active", "active", "active", "active"},
	}
	// 6 个 confirmed（> respondBatchSize=2 → 3 批）；respondReply×2（每批
	// 一个方案回复，3 批共用 2 个回复 = 最后一批复用同款回复）。
	// 直接调 respond（不跑 survey）——回复序列从方案生成开始。
	replies := []string{respondReply, respondReply}
	e, _, model := testEngineProtocol(t, replies, remote)
	e.cfg.Parallel.Workers = 2

	base := mdl.NewFinding("web-01", "svc", "svc_failed", "nginx 服务 failed")
	base.Status = mdl.FindingConfirmed
	base.RootCause = "nginx 进程异常退出"
	var confs []*mdl.Finding
	for i := 0; i < 6; i++ {
		f := *base
		f.Key = fmtTestLead(i)
		confs = append(confs, &f)
	}
	if err := e.ws().AddFindings(confs); err != nil {
		t.Fatal(err)
	}

	e.respond(context.Background())

	remediated := 0
	for _, f := range e.ws().Confirmed() {
		if f.Remediated {
			remediated++
		}
	}
	// 每批回复含 1 个 plan（respondReply）→ 每批处置 1 个目标（顺序回退
	// 匹配）。核心断言：两批都执行（并行机制）且 plan 落地。
	if remediated < 2 {
		t.Errorf("并行批次各应处置至少 1 个目标，实际 %d/6", remediated)
	}
	if model.call < 2 {
		t.Errorf("并行 Respond 应产生 ≥2 次方案生成调用，实际 %d", model.call)
	}
}

// TestEngine_DeviationFindings 期望状态偏差集成：desired.json 声明 →
// L0 快检产出 deviation 线索。
func TestEngine_DeviationFindings(t *testing.T) {
	// 快检输出含 listen_ports 事实：80 在监听、4444 被后门监听。
	devOut := healthyOut + `__M_listen_ports__
LISTEN 0 128 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=1,fd=3))
LISTEN 0 128 0.0.0.0:4444 0.0.0.0:* users:(("python3",pid=2,fd=3))
`
	remote := &fakeL0Remote{defaultOut: devOut}
	cfg := DefaultConfig()
	cfg.Local = false
	cfg.Hosts = []string{"web-01"}
	cfg.WorkDir = t.TempDir()
	cfg.VerifyTimeout = 2 * time.Second
	cfg.Parallel.Workers = 1
	model := newFakeModel(surveyReply, deepDiveReply)
	e, err := newEngine(cfg, model, remote, &env.Env{HasSystemd: true, NProc: 8})
	if err != nil {
		t.Fatal(err)
	}
	// 期望状态：80 必须监听、4444 禁止监听。
	if err := probe.SaveDesired(cfg.WorkDir, &probe.DesiredState{
		Hosts: map[string]probe.HostDesire{
			"web-01": {Expect: probe.ExpectSpec{Ports: []int{80}, NoPorts: []int{4444}}},
		},
	}); err != nil {
		t.Fatal(err)
	}

	e.loopOnce(context.Background())

	var devFound bool
	for _, f := range e.ws().Findings() {
		if f.Signal == "deviation_unexpected_port" {
			devFound = true
			if !strings.Contains(f.Desc, "4444") {
				t.Errorf("偏差线索应含端口信息: %s", f.Desc)
			}
		}
	}
	if !devFound {
		t.Errorf("期望状态偏差未检出，findings: %+v", e.ws().Findings())
	}
}

// TestEngine_CognitionTools 认知工具 hooks：定向采集/经验检索/作战图写入。
func TestEngine_CognitionTools(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: healthyOut}
	remote.markerOutputs = map[string][]string{
		// 定向采集输出需带探针标记（splitFragments 按标记切分）。
		"listen_ports": {"__M_listen_ports__\nLISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:((\"python3\",pid=9,fd=3))"},
	}
	e, _, _ := testEngineProtocol(t, []string{surveyReply}, remote)
	e.cfg.Parallel.Workers = 1

	// 定向采集：collect_probe 走 CollectProbes（定向命令含 listen_ports 标记）。
	out, err := e.collectProbe(context.Background(), "web-01", "listen_ports")
	if err != nil {
		t.Fatalf("collectProbe: %v", err)
	}
	if !strings.Contains(out, "8080") {
		t.Errorf("定向采集输出不符: %s", out)
	}
	// 未知探针报错。
	if _, err := e.collectProbe(context.Background(), "web-01", "no_such_probe"); err == nil {
		t.Error("未知探针应报错")
	}

	// 经验检索：先沉淀再 recall。
	e.mem.Learn(&mdl.Finding{Host: "web-01", Signal: "unattributed_listen",
		Key: "0.0.0.0:8080", Status: mdl.FindingConfirmed, Remediated: true,
		Actions: []mdl.Action{{Name: "kill", Command: "kill 9", Auto: true, Verified: true}}})
	if r := e.recall("unattributed_listen", "web-01"); !strings.Contains(r, "kill 9") {
		t.Errorf("recall 不符: %s", r)
	}
	if r := e.recall("unknown_sig", ""); !strings.Contains(r, "无相关经验") {
		t.Errorf("无经验应返回提示: %s", r)
	}

	// 作战图：大脑写入假设 → Brief 可见 → 持久化。
	r := e.updateBench("hypothesis\n{\"claim\":\"8080 端口后门\",\"next_check\":\"查 cron\"}")
	if !strings.Contains(r, "假设已登记") {
		t.Errorf("假设登记失败: %s", r)
	}
	r = e.updateBench("problem\n{\"id\":\"f1\",\"host\":\"web-01\",\"signal\":\"unattributed_listen\",\"hypothesis\":\"后门\",\"status\":\"tracing\"}")
	if !strings.Contains(r, "作战图已更新") {
		t.Errorf("作战图更新失败: %s", r)
	}
	brief := e.workbenchSummary()
	if !strings.Contains(brief, "8080 端口后门") || !strings.Contains(brief, "进行中问题") {
		t.Errorf("作战图摘要不符: %s", brief)
	}
	// 非法 action 报错。
	if r := e.updateBench("bogus\n{}"); !strings.Contains(r, "未知 action") {
		t.Errorf("非法 action 应报错: %s", r)
	}
}

// TestEngine_LearnClosed 学习闭环：处置成功/排除的发现沉淀进记忆。
func TestEngine_LearnClosed(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: svcFailedOut, restoreAfter: "systemctl is-active nginx.service"}
	remote.outputs = map[string][]string{
		"systemctl restart nginx.service":   {"restarted"},
		"systemctl is-active nginx.service": {"active"},
	}
	e, _, _ := testEngineProtocol(t, []string{surveyReply, deepDiveReply, respondReply}, remote)
	e.cfg.Parallel.Workers = 1

	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.learnClosed()

	hits := e.mem.Recall("svc_failed", "web-01", 5)
	if len(hits) == 0 {
		t.Fatal("处置成功应沉淀经验")
	}
	if !strings.Contains(hits[0], "systemctl restart nginx.service") {
		t.Errorf("经验应含处置模板: %s", hits[0])
	}
	// 主机档案有恢复模式。
	if brief := e.mem.DossierBrief("web-01"); !strings.Contains(brief, "恢复模式") {
		t.Errorf("主机档案应记恢复模式: %s", brief)
	}
	// 再次沉淀应被 Learned 标记跳过（幂等）——host 与全局聚合两条均不再累加。
	e.learnClosed()
	for _, h := range e.mem.Recall("svc_failed", "web-01", 5) {
		if !strings.Contains(h, "1 次") {
			t.Errorf("重复沉淀不应累加: %v", h)
		}
	}
}

// TestEngine_WorkflowStage 工作流状态机映射。
func TestEngine_WorkflowStage(t *testing.T) {
	cases := []struct {
		f    *mdl.Finding
		want string
	}{
		{&mdl.Finding{Status: mdl.FindingPending}, "tracing"},
		{&mdl.Finding{Status: mdl.FindingPending, Tried: 1}, "tracing(evidence-insufficient)"},
		{&mdl.Finding{Status: mdl.FindingConfirmed}, "remediating"},
		{&mdl.Finding{Status: mdl.FindingConfirmed, Remediated: true}, "closed"},
		{&mdl.Finding{Status: mdl.FindingConfirmed, RespondTried: 3}, "blocked"},
		{&mdl.Finding{Status: mdl.FindingDismissed}, "closed"},
	}
	for _, c := range cases {
		if got := workflowStage(c.f); got != c.want {
			t.Errorf("workflowStage(%+v) = %q, want %q", c.f.Status, got, c.want)
		}
	}
}

// TestEngine_SyncWorkbench 作战图同步：引擎状态反映到工作台。
func TestEngine_SyncWorkbench(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	e, _, _ := testEngineProtocol(t, []string{surveyReply, deepDiveReply, respondReply}, remote)
	e.cfg.Parallel.Workers = 1

	f := mdl.NewFinding("web-01", "svc", "svc_failed", "nginx 挂了")
	f.Status = mdl.FindingConfirmed
	e.ws().AddFindings([]*mdl.Finding{f})
	e.syncWorkbench()

	problems := e.wb.SortedProblems()
	if len(problems) != 1 {
		t.Fatalf("作战图应有 1 个问题: %v", problems)
	}
	if !strings.Contains(e.wb.Brief(0), "remediating") {
		t.Errorf("作战图应标 remediating: %s", e.wb.Brief(0))
	}
	// 关闭后同步移除。
	f.Remediated = true
	e.ws().SaveFindings()
	e.syncWorkbench()
	if len(e.wb.SortedProblems()) != 0 {
		t.Errorf("已关闭问题应移出作战图")
	}
}

// TestEngine_WatchRound 复发检测：已处置 confirmed 被重检出 → 重置处置。
func TestEngine_WatchRound(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	e, _, _ := testEngineProtocol(t, []string{surveyReply}, remote)
	e.cfg.Parallel.Workers = 1

	f := mdl.NewFinding("web-01", "svc", "svc_failed", "nginx 挂了")
	f.Status = mdl.FindingConfirmed
	f.Remediated = true
	f.Redetect = 2 // L0 重检出（merge 递增）
	e.ws().AddFindings([]*mdl.Finding{f})

	// 仅验证复发重置（respond 处置尝试属于 watchRound 的后续行为）。
	relapsed := e.resetRelapsed()
	if relapsed != 1 {
		t.Fatalf("应检测到 1 项复发，实际 %d", relapsed)
	}
	got := e.ws().Confirmed()[0]
	if got.Remediated {
		t.Error("复发项应被重置为未处置")
	}
	if got.RespondTried != 0 {
		t.Errorf("复发项应重置尝试计数: %d", got.RespondTried)
	}
	if !strings.Contains(got.RemediationNote, "复发") {
		t.Errorf("复发应留痕: %s", got.RemediationNote)
	}
	// 非复发（Redetect=0）不受影响。
	f2 := mdl.NewFinding("web-01", "svc", "svc_failed", "正常项")
	f2.Key = "other"
	f2.Status = mdl.FindingConfirmed
	f2.Remediated = true
	e.ws().AddFindings([]*mdl.Finding{f2})
	if rel := e.resetRelapsed(); rel != 0 {
		t.Errorf("无重检出不复发: %d", rel)
	}
}
