package autopilot

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-gocel/gocode-ops/internal/common/env"
	"github.com/go-gocel/gocode-ops/internal/common/model"
	"github.com/go-gocel/gocode-ops/internal/common/remediate"
)

// 协议驱动的端到端测试：fake model 按阶段返回预设小结，
// fake remote 提供 L0 快检与处置命令输出。
// 覆盖：初始化阶段推进 → L0 线索 → DeepDive 确认 → Respond 三件套执行。

const (
	// surveyReply 初始化阶段（巡检三合一）的小结：环境画像 + 全域覆盖声明
	// + 一条 svc_failed 待查线索（后续 deepdive/respond 链路的输入）。
	surveyReply = `{"phase":"survey","done":true,"covered":["cpu","mem","disk","inode","zombie","svc","process","network","log","cron","security"],
"env":{"os":"Ubuntu 22.04","kernel":"5.15","hostname":"web-01","service_mgr":"systemd","container":false},
"findings":[{"host":"web-01","domain":"svc","signal":"svc_failed","desc":"nginx 服务 failed","status":"pending","evidence":["systemctl --failed"]}]}`
	deepDiveReply = `{"phase":"deepdive","done":true,"covered":["svc"],
"findings":[{"host":"web-01","domain":"svc","signal":"svc_failed","desc":"nginx 服务 failed",
"status":"confirmed","evidence":["systemctl status nginx.service 显示 failed"],
"root_cause":"nginx 进程异常退出","confidence":0.9}]}`
	// surveyEmptyReply survey 无 findings（测试用：只跑 L0 线索链路，
	// 避免 survey 产出额外线索改变 deepdive 批数——单线索子代理粒度下
	// 批数 = 线索数，回复序列必须精确对齐）。
	surveyEmptyReply = `{"phase":"survey","done":true,"covered":["cpu","mem","disk","inode","zombie","svc","process","network","log","cron","security"],
"env":{"os":"Ubuntu 22.04","kernel":"5.15","hostname":"web-01","service_mgr":"systemd","container":false},
"findings":[]}`
	respondReply = `{"plans":[{"finding_id":"svc_failed","actions":[{"name":"restart nginx","command":"systemctl restart nginx.service",
"rationale":"nginx 服务 failed，重启恢复","verify":"systemctl is-active nginx.service",
"check_up":"active","rollback":"systemctl restore nginx.service"}]}]}`
	// impactRespondReply 处置方案含自断通道动作（禁 root 密码登录）。
	impactRespondReply = `{"plans":[{"finding_id":"f","actions":[{"name":"harden sshd","command":"sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl reload sshd",
"rationale":"SSH 弱配置加固","verify":"grep PermitRootLogin /etc/ssh/sshd_config",
"check_up":"PermitRootLogin no","rollback":"sed -i 's/^PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config"}]}]}`
	// heldPendingReply DeepDive 裁决证据不足保持待查（重追查回路用）。
	heldPendingReply = `{"phase":"deepdive","done":true,"covered":["svc"],
"findings":[{"host":"web-01","domain":"svc","signal":"svc_failed","desc":"服务失败",
"status":"pending","evidence":["systemctl --failed 有输出，但未定位根因"]}]}`
)

func testEngineProtocol(t *testing.T, replies []string, remote *fakeL0Remote) (*Engine, Config, *fakeModel) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Local = false
	cfg.Hosts = []string{"web-01"}
	cfg.WorkDir = t.TempDir()
	cfg.VerifyTimeout = 2 * time.Second
	model := newFakeModel(replies...)
	// 注入确定性环境：systemd 可用（svc_failed 探针才进清单）；SS 可用
	// （ssh_root_login 等安全指标探针进清单——确定性复检计划依赖探针
	// 映射，缺环境开关会让模型确认的 ssh 类故障无判定层复检粒度）。
	e, err := newEngine(cfg, model, remote, &env.Env{HasSystemd: true, HasSS: true, NProc: 8})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	// 测试只验证重试逻辑，不等真实退避（1s–2s 抖动）。
	e.retryBackoff = func(int) time.Duration { return 0 }
	return e, cfg, model
}

func TestEngine_ProtocolFullFlow(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: svcFailedOut, restoreAfter: "systemctl is-active nginx.service"}
	remote.outputs = map[string][]string{
		"systemctl restart nginx.service":   {"restarted"},
		"systemctl is-active nginx.service": {"active"},
	}
	e, cfg, _ := testEngineProtocol(t,
		[]string{surveyReply, deepDiveReply, respondReply},
		remote)

	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	// 环境画像
	if e.ws().Env == nil || e.ws().Env.ServiceMgr != "systemd" {
		t.Fatalf("Explore 应产出环境画像: %+v", e.ws().Env)
	}
	// 阶段记录：survey 初始化阶段一次（巡检三合一）。
	if len(e.ws().Phases()) < 1 {
		t.Errorf("应有 survey 初始化阶段记录: %d", len(e.ws().Phases()))
	}
	if e.ws().Phases()[0].Phase != PhaseSurvey {
		t.Errorf("首个阶段应为 survey: %+v", e.ws().Phases())
	}
	// 确认故障 + 已处置
	confirmed := e.ws().Confirmed()
	if len(confirmed) != 1 {
		t.Fatalf("应有 1 个确认故障: %+v", e.ws().Findings())
	}
	f := confirmed[0]
	if f.Signal != "svc_failed" || f.RootCause != "nginx 进程异常退出" {
		t.Errorf("finding = %+v", f)
	}
	if !f.Remediated {
		t.Error("应已处置")
	}
	if len(f.Actions) != 1 || f.Actions[0].Command != "systemctl restart nginx.service" {
		t.Errorf("actions = %+v", f.Actions)
	}
	// 报告
	report, err := os.ReadFile(filepath.Join(cfg.WorkDir, "report.md"))
	if err != nil {
		t.Fatalf("report.md: %v", err)
	}
	for _, want := range []string{"确认故障", "nginx 进程异常退出", "已处置", "systemctl restart nginx.service"} {
		if !strings.Contains(string(report), want) {
			t.Errorf("报告缺少 %q", want)
		}
	}
}

func TestEngine_WorkspaceResume(t *testing.T) {
	// checkpoint：工作区逐文件落盘（env/findings/baseline/phases），
	// 重启引擎自动恢复——中断续跑不丢状态，这是"不设全局时限"的
	// 兜底之一：中断/崩溃后重启即可继续。
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.Local = false
	cfg.Hosts = []string{"web-01"}
	cfg.WorkDir = dir
	cfg.VerifyTimeout = 2 * time.Second

	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	e1, err := newEngine(cfg, newFakeModel(surveyReply), remote, &env.Env{HasSystemd: true, NProc: 8})
	if err != nil {
		t.Fatal(err)
	}
	if err := e1.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(e1.ws().Pending()) == 0 {
		t.Fatalf("第一轮应产生线索: %+v", e1.ws().Findings())
	}

	// 模拟中断后重启：同一工作目录新建引擎，状态应自动恢复。
	e2, err := NewEngine(cfg, nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	if len(e2.ws().Pending()) == 0 {
		t.Error("重启后应恢复已有发现（checkpoint）")
	}
	if e2.ws().Env == nil {
		t.Error("重启后应恢复环境画像")
	}
	if len(e2.ws().Phases()) == 0 {
		t.Error("重启后应恢复阶段记录")
	}
}

func TestEngine_ModelNil_L0Only(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Local = false
	cfg.Hosts = []string{"web-01"}
	cfg.WorkDir = t.TempDir()
	e, err := newEngine(cfg, nil, &fakeL0Remote{defaultOut: svcFailedOut}, &env.Env{HasSystemd: true, NProc: 8})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	// 无模型：L0 线索产生但无人裁决 → pending
	if len(e.ws().Pending()) == 0 {
		t.Errorf("L0 应产生 pending 线索: %+v", e.ws().Findings())
	}
	if len(e.ws().Confirmed()) != 0 {
		t.Error("无模型时不应有 confirmed")
	}
}

func TestEngine_DeepDiveDismisses(t *testing.T) {
	// DeepDive 裁决 dismissed → 报告"已排查"区，不视为故障。
	dismissReply := `{"phase":"deepdive","done":true,"covered":["svc"],
"findings":[{"host":"web-01","domain":"svc","signal":"svc_failed","desc":"服务失败",
"status":"dismissed","evidence":["复核后服务正常"]}]}`
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, dismissReply},
		remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(e.ws().Confirmed()) != 0 {
		t.Errorf("不应有确认故障: %+v", e.ws().Confirmed())
	}
	if len(e.ws().Dismissed()) != 1 {
		t.Errorf("应有 1 条已排除: %+v", e.ws().Findings())
	}
	report, _ := os.ReadFile(filepath.Join(e.cfg.WorkDir, "report.md"))
	if !strings.Contains(string(report), "已排查排除") {
		t.Error("报告应有已排查分区")
	}
}

func TestEngine_RespondContractRejected(t *testing.T) {
	// 三件套缺项（无 rollback）→ 不执行，finding 标记未处置原因。
	badRespond := `{"plans":[{"finding_id":"f","actions":[{"name":"restart","command":"systemctl restart nginx.service",
"rationale":"服务失败","verify":"systemctl is-active nginx.service","check_up":"active"}]}]}`
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, deepDiveReply, badRespond},
		remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := e.ws().Confirmed()[0]
	if f.Remediated {
		t.Error("契约不完整不应处置")
	}
	if !strings.Contains(f.RemediationNote, "三件套校验") {
		t.Errorf("应记录校验失败原因: %q", f.RemediationNote)
	}
}

func TestEngine_RespondRejectedStillReportsSuggestion(t *testing.T) {
	// 三件套缺项 → 不执行，但修复建议仍进报告：根因分析与修复
	// 建议不依赖处置是否成功，方案解析成功即记录。
	badRespond := `{"plans":[{"finding_id":"f","actions":[{"name":"restart","command":"systemctl restart nginx.service",
"rationale":"服务失败，重启恢复","verify":"systemctl is-active nginx.service","check_up":"active"}]}]}`
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, deepDiveReply, badRespond},
		remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := e.ws().Confirmed()[0]
	if len(f.SuggestedFix) == 0 {
		t.Fatal("方案解析成功应记录修复建议")
	}
	if !strings.Contains(f.SuggestedFix[0], "systemctl restart nginx.service") ||
		!strings.Contains(f.SuggestedFix[0], "重启恢复") {
		t.Errorf("建议应含命令与理由: %v", f.SuggestedFix)
	}
	report, _ := os.ReadFile(filepath.Join(e.cfg.WorkDir, "report.md"))
	for _, want := range []string{"修复建议", "systemctl restart nginx.service", "未处置"} {
		if !strings.Contains(string(report), want) {
			t.Errorf("报告缺少 %q:\n%s", want, report)
		}
	}
}

// TestEngine_RespondImpactAdvised 处置方案含自断通道动作（命令风险审查
// 自身影响面）→ 不执行、转人工建议、不标记已处置、报告如实呈现。
func TestEngine_RespondImpactAdvised(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	e, cfg, _ := testEngineProtocol(t,
		[]string{surveyReply, deepDiveReply, impactRespondReply},
		remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := e.ws().Confirmed()[0]
	if f.Remediated {
		t.Fatal("自断通道动作未执行，不得标记已处置")
	}
	if len(f.Actions) != 1 || !f.Actions[0].Advised {
		t.Fatalf("动作应标记为仅建议未执行: %+v", f.Actions)
	}
	if f.Actions[0].Result != "" || f.Actions[0].Error != "" {
		t.Errorf("被建议动作不应产生执行结果: %+v", f.Actions[0])
	}
	// 建议内容：含命令与替代方案提示。
	if f.Actions[0].AdvisedReason == "" {
		t.Error("应记录建议原因")
	}
	if !strings.Contains(f.Actions[0].AdvisedReason, "prohibit-password") {
		t.Errorf("建议原因应含安全替代方案: %q", f.Actions[0].AdvisedReason)
	}
	// 非 root 收紧面信号（svc_failed）：全部被拒也**不达限**——模型换
	// 方案可能成功（守住通道即可，不绝对化）。
	if f.RespondTried != 1 {
		t.Errorf("非收紧面信号被拒不应达限（RespondTried=%d, want 1）", f.RespondTried)
	}
	if f.Disposition != nil {
		t.Errorf("非收紧面信号被拒不应升级工单: %+v", f.Disposition)
	}
	report, err := os.ReadFile(filepath.Join(cfg.WorkDir, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"建议人工执行", "PermitRootLogin", "人工会话"} {
		if !strings.Contains(string(report), want) {
			t.Errorf("报告缺少 %q", want)
		}
	}
	if strings.Contains(string(report), "✅ 已处置") {
		t.Error("自断通道动作未执行，报告不得显示已处置")
	}
}

// TestEngine_RespondRootAuthTighteningImmediateWorkOrder 结构性必拒
// （真实场景）：ssh_root_login（root 连接下收紧 root 认证必被拒）→
// 全部动作被拒 → 立即达限转工单；后续 respond 不再生成方案。
func TestEngine_RespondRootAuthTighteningImmediateWorkOrder(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: healthyOut}
	e, _, m := testEngineProtocol(t, []string{impactRespondReply}, remote)
	f := model.NewFinding("web-01", "svc", "ssh_root_login", "root 密码直登")
	f.Status = model.FindingConfirmed
	f.Key = "PermitRootLogin_default_yes"
	if err := e.ws().AddFindings([]*model.Finding{f}); err != nil {
		t.Fatal(err)
	}

	e.respond(context.Background())

	got := e.ws().Confirmed()[0]
	if got.Remediated {
		t.Fatal("自断通道动作未执行，不得标记已处置")
	}
	if got.RespondTried != maxRespondTries {
		t.Errorf("root 收紧面全拒应立即达限（RespondTried=%d, want %d）", got.RespondTried, maxRespondTries)
	}
	if got.Disposition == nil || got.Disposition.Outcome != model.DispositionManualWorkOrder {
		t.Fatalf("root 收紧面全拒应升级人工工单: %+v", got.Disposition)
	}
	// 达限后不再重试：第二轮 respond 零方案生成调用。
	before := m.call
	e.respond(context.Background())
	if m.call != before {
		t.Errorf("达限后不应再生成处置方案（调用 %d → %d）", before, m.call)
	}
}

// TestEngine_RespondAdvisedDoesNotRollbackVerified 同批次含“被建议”动作时，
// 已验证成功的其它动作成果必须保留（R6 实测：被建议动作在前导致后续
// 成功修复被整体回滚、后门配置被回滚命令重建）。
func TestEngine_RespondAdvisedDoesNotRollbackVerified(t *testing.T) {
	mixedReply := `{"plans":[{"finding_id":"f","actions":[
		{"name":"rm core bin","command":"rm -f /usr/bin/systemctl",
		 "rationale":"删系统工具","verify":"test ! -f /usr/bin/systemctl && echo gone",
		 "check_up":"gone","rollback":"true"},
		{"name":"rm backdoor conf","command":"rm -f /etc/ssh/sshd_config.d/00-key-fetch.conf",
		 "rationale":"删除 sshd 后门钩子配置","verify":"test ! -f /etc/ssh/sshd_config.d/00-key-fetch.conf && echo removed",
		 "check_up":"removed","rollback":"printf AuthorizedKeysCommand > /etc/ssh/sshd_config.d/00-key-fetch.conf"}
	]}]}`
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	remote.outputs = map[string][]string{
		"test ! -f /etc/ssh/sshd_config.d/00-key-fetch.conf && echo removed": {"removed"},
	}
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, deepDiveReply, mixedReply},
		remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := e.ws().Confirmed()[0]
	if f.Remediated {
		t.Fatal("批次含被建议动作，整体不得标记已处置")
	}
	if len(f.Actions) != 2 {
		t.Fatalf("actions = %+v", f.Actions)
	}
	if !f.Actions[0].Advised {
		t.Errorf("系统工具删除应被守卫拒绝为建议: %+v", f.Actions[0])
	}
	if !f.Actions[1].Verified {
		t.Errorf("后续动作应正常验证: %+v", f.Actions[1])
	}
	if f.Actions[1].RolledBac {
		t.Error("已验证成功的动作不得被回滚")
	}
	if strings.Contains(f.Actions[1].Result, "已回滚") {
		t.Errorf("成功修复成果被回滚: %+v", f.Actions[1])
	}
	for _, call := range remote.calls {
		if strings.Contains(call, "printf AuthorizedKeysCommand") {
			t.Errorf("回滚命令不应执行（成功修复被误回滚）: %q", call)
		}
	}
}

// TestEngine_RespondVerifyFailedNotRemediated 处置动作执行成功但验证失败
// → 不得标记已处置（处置状态必须与验证结论一致），报告如实呈现。
func TestEngine_RespondVerifyFailedNotRemediated(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	// 执行成功（restarted），但验证命令输出不匹配 check_up（defaultOut
	// 不含 active 行）→ 验证失败 → 回滚。
	remote.outputs = map[string][]string{
		"systemctl restart nginx.service": {"restarted"},
	}
	e, cfg, _ := testEngineProtocol(t,
		[]string{surveyReply, deepDiveReply, respondReply},
		remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := e.ws().Confirmed()[0]
	if f.Remediated {
		t.Fatal("验证失败不得标记已处置")
	}
	if len(f.Actions) != 1 {
		t.Fatalf("actions = %+v", f.Actions)
	}
	if f.Actions[0].Verified {
		t.Error("验证未通过不得标记 Verified")
	}
	if !f.Actions[0].RolledBac {
		t.Error("验证失败应回滚（回滚成功）")
	}
	report, err := os.ReadFile(filepath.Join(cfg.WorkDir, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"未处置", "回滚"} {
		if !strings.Contains(string(report), want) {
			t.Errorf("报告缺少 %q", want)
		}
	}
	if strings.Contains(string(report), "✅ 已处置") {
		t.Error("验证失败，报告不得显示已处置")
	}
}

// TestEngine_RespondVerifyErrorLineNotEvidence 验证输出中的错误行不作
// 恢复证据：报错文本含 check_up 同名短语不得判定验证通过（run2 实测
// 失败命令的报错行含目标名可命中短语匹配）。
func TestEngine_RespondVerifyErrorLineNotEvidence(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	trapReply := `{"plans":[{"finding_id":"web-01/svc_failed","actions":[{"name":"cleanup","command":"echo cleaned",
"rationale":"清理 nginx 现场","verify":"getent passwd backdoor","check_up":"backdoor","rollback":"echo rollback"}]}]}`
	remote.outputs = map[string][]string{
		"echo cleaned":           {"cleaned"},
		"getent passwd backdoor": {"ERROR: user backdoor is currently used by process 1"},
	}
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, deepDiveReply, trapReply},
		remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := e.ws().Confirmed()[0]
	if f.Remediated {
		t.Fatal("错误行含同名短语不得判定验证通过")
	}
	if len(f.Actions) != 1 || !f.Actions[0].RolledBac {
		t.Errorf("验证失败应回滚: %+v", f.Actions)
	}
}

// TestEngine_RespondVerifyErrorNoiseTolerated 验证输出混入环境噪音
// （如 ld.so 报错行）但含正常恢复行时，验证照常通过——错误行过滤
// 不得误伤带噪音的正常环境。
func TestEngine_RespondVerifyErrorNoiseTolerated(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: svcFailedOut, restoreAfter: "systemctl is-active nginx.service"}
	remote.outputs = map[string][]string{
		"systemctl restart nginx.service":   {"restarted"},
		"systemctl is-active nginx.service": {"ERROR: ld.so: object '/usr/lib/libevilhook.so' cannot be preloaded: ignored.\nactive"},
	}
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, deepDiveReply, respondReply},
		remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := e.ws().Confirmed()[0]
	if !f.Remediated {
		t.Fatal("正常恢复行存在时验证应通过")
	}
}

// TestEngine_RespondFeedbackLoop 反馈闭环：首轮处置验证失败 → 下一轮
// 方案生成的 prompt 含上次执行摘要（失败原因回灌），模型据此修正。
// TestEngine_RespondBatchCoverage 批量契约覆盖检查：模型只给部分 plan
// 时，未获得方案的故障如实记录（不静默跳过）。
func TestEngine_RespondBatchCoverage(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: svcFailedOut, restoreAfter: "systemctl is-active nginx.service"}
	remote.outputs = map[string][]string{
		"systemctl is-active nginx.service": {"active"},
	}
	// 模型只给 1 个 plan（覆盖不全），且 finding_id 是模型侧写（无引擎 ID）。
	partialReply := `{"plans":[{"finding_id":"web-01/svc_failed","actions":[{"name":"restart",
"command":"systemctl restart nginx.service","rationale":"重启恢复","verify":"systemctl is-active nginx.service",
"check_up":"active","rollback":"systemctl restore nginx.service"}]}]}`
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, deepDiveReply, partialReply},
		remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := e.ws().Confirmed()[0]
	if !f.Remediated {
		t.Fatalf("唯一目标应经顺序回退被处置: %+v", f)
	}
	if f.RespondTried != 1 {
		t.Errorf("RespondTried = %d, want 1", f.RespondTried)
	}
}

// TestEngine_RespondBatchEmptyPlan 空 actions 的 plan（模型判定无法处置）
// → 处置机制三态契约：空方案是非法状态，升级为人工工单（manual_workorder），
// 不静默、不留"处置方案为空"。
func TestEngine_RespondBatchEmptyPlan(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	emptyReply := `{"plans":[{"finding_id":"f","actions":[]}]}`
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, deepDiveReply, emptyReply},
		remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := e.ws().Confirmed()[0]
	if f.Remediated {
		t.Error("空方案不应标记已处置")
	}
	if strings.Contains(f.RemediationNote, "处置方案为空") {
		t.Errorf("空方案必须升级为工单，不得残留非法状态文本: %q", f.RemediationNote)
	}
	if f.Disposition == nil {
		t.Fatal("空方案应有处置去向（三态契约）")
	}
	if f.Disposition.Outcome != model.DispositionManualWorkOrder {
		t.Errorf("空方案处置去向 = %s, want manual_workorder", f.Disposition.Outcome)
	}
	if f.Disposition.WorkOrder == nil || f.Disposition.WorkOrder.Summary == "" {
		t.Error("工单应含问题摘要（证据包）")
	}
	if v := f.Disposition.Validate(); len(v) > 0 {
		t.Errorf("工单去向应通过契约校验: %v", v)
	}
	if !strings.Contains(f.RemediationNote, "人工工单") {
		t.Errorf("应记录工单原因: %q", f.RemediationNote)
	}
}

// TestPlanTarget_Matching 处置方案目标匹配三层策略：精确 ID → signal
// （含模型自创的 "signal-特征" 写法，最长优先）→ 顺序回退。
// run1 实测模型自创 "signal-后缀" ID 且乱序输出，旧顺序回退把方案
// 错配到别的故障头上（kill 后门方案配到僵尸进程）。
func TestPlanTarget_Matching(t *testing.T) {
	mk := func(id, sig string) *Finding {
		f := model.NewFinding("node1", "proc", sig, "d")
		f.ID = id
		return f
	}
	fZ := mk("node1/zombie_procs/1", "zombie_procs")
	fM := mk("node1/mem_low/2", "mem_low")
	fO := mk("node1/oversized_file/3", "oversized_file")
	targets := []*Finding{fZ, fM, fO}
	byID := map[string]*Finding{fZ.ID: fZ, fM.ID: fM, fO.ID: fO}
	cases := []struct {
		name string
		id   string
		used map[string]bool
		want *Finding
	}{
		{"精确ID", "node1/mem_low/2", nil, fM},
		{"signal完全相等", "mem_low", nil, fM},
		{"signal-后缀自创ID", "zombie_procs-30", nil, fZ},
		{"signal-后缀自创ID2", "oversized_file-applog", nil, fO},
		{"三段式数字写错", "node1/mem_low/99999", nil, fM},
		{"目标已占用则跳过", "zombie_procs-30", map[string]bool{fZ.ID: true}, nil},
		{"多目标匹配不上不跨signal回退", "bogus", nil, nil},
		{"多目标signal不一致不硬塞", "bogus", map[string]bool{fZ.ID: true}, nil},
		{"单目标剩余允许回退", "bogus", map[string]bool{fZ.ID: true, fM.ID: true}, fO},
		{"全部占用返回nil", "bogus", map[string]bool{fZ.ID: true, fM.ID: true, fO.ID: true}, nil},
	}
	for _, c := range cases {
		used := c.used
		if used == nil {
			used = map[string]bool{}
		}
		if got := planTarget(&remediate.Plan{FindingID: c.id}, byID, targets, used); got != c.want {
			t.Errorf("%s: planTarget(%q) = %+v, want %+v", c.name, c.id, got, c.want)
		}
	}

	// 前缀歧义：更长 signal 优先（cpu_load 比 cpu 更具体）。
	fC := mk("node1/cpu/4", "cpu")
	fCL := mk("node1/cpu_load/5", "cpu_load")
	t2 := []*Finding{fC, fCL}
	by2 := map[string]*Finding{fC.ID: fC, fCL.ID: fCL}
	if got := planTarget(&remediate.Plan{FindingID: "cpu_load-90"}, by2, t2, map[string]bool{}); got != fCL {
		t.Errorf("前缀歧义应取更长 signal: %+v", got)
	}

	// signal:子键 精确匹配：同 signal 多个故障靠子键区分，不得错配。
	fd1 := mk("node1/config_drift/10", "config_drift")
	fd1.Key = "state_sshd"
	fd2 := mk("node1/config_drift/11", "config_drift")
	fd2.Key = "state_crontab"
	t3 := []*Finding{fd1, fd2}
	by3 := map[string]*Finding{fd1.ID: fd1, fd2.ID: fd2}
	if got := planTarget(&remediate.Plan{FindingID: "config_drift:state_crontab"}, by3, t3, map[string]bool{}); got != fd2 {
		t.Errorf("signal:子键 应定位到子键匹配的故障: %+v", got)
	}
}

// TestEngine_RespondScrambledIDs 模型自创 finding_id（signal-后缀）且
// 输出顺序与目标顺序不一致：方案必须按 signal 定位到正确故障，
// 不得顺序错配（run1 实测错配把处置方案挂到别的故障头上）。
func TestEngine_RespondScrambledIDs(t *testing.T) {
	multiDeepDive := `{"phase":"deepdive","done":true,"covered":["svc"],
"findings":[
{"host":"web-01","domain":"proc","signal":"zombie_procs","desc":"僵尸进程","status":"confirmed","evidence":["ps 显示 30 个僵尸，父进程 PID 126"]},
{"host":"web-01","domain":"mem","signal":"mem_low","desc":"内存泄漏","status":"confirmed","evidence":["free 显示泄漏进程 PID 125"]},
{"host":"web-01","domain":"disk","signal":"oversized_file","desc":"磁盘填充","status":"confirmed","evidence":["du 显示 /var/log/app.log 填充磁盘"]}]}`
	// 输出顺序故意与目标顺序相反，且 finding_id 是模型自创写法。
	// 注意：删除类动作的 verify 必须断言正面信号（如 test ! -f && echo），
	// 不能拿 "No such file" 这类错误文本当恢复证据（错误行不作证据）。
	scrambledRespond := `{"plans":[
{"finding_id":"oversized_file-applog","actions":[{"name":"rm app.log","command":"rm -f /var/log/app.log","rationale":"清理填充文件","verify":"test ! -f /var/log/app.log && echo absent","check_up":"absent","rollback":"true"}]},
{"finding_id":"mem_low-httpd","actions":[{"name":"kill leak","command":"kill 125","rationale":"终止泄漏进程","verify":"ps -p 125","check_up":"gone","rollback":"true"}]},
{"finding_id":"zombie_procs-30","actions":[{"name":"kill parent","command":"kill 126","rationale":"收割僵尸","verify":"ps -eo stat | grep -c Z","check_up":"0","rollback":"true"}]}]}`
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	remote.outputs = map[string][]string{
		"rm -f /var/log/app.log":                    {"removed"},
		"test ! -f /var/log/app.log && echo absent": {"absent"},
		"kill 125":                {"killed"},
		"ps -p 125":               {"gone"},
		"kill 126":                {"killed"},
		"ps -eo stat | grep -c Z": {"0"},
	}
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, multiDeepDive, scrambledRespond, scrambledRespond},
		remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	confirmed := e.ws().Confirmed()
	if len(confirmed) != 3 {
		t.Fatalf("应有 3 个确认故障: %+v", e.ws().Findings())
	}
	wantCmd := map[string]string{
		"zombie_procs":   "kill 126",
		"mem_low":        "kill 125",
		"oversized_file": "rm -f /var/log/app.log",
	}
	for _, f := range confirmed {
		if !f.Remediated {
			t.Errorf("%s 应已处置: %+v", f.Signal, f)
			continue
		}
		if len(f.Actions) != 1 || f.Actions[0].Command != wantCmd[f.Signal] {
			t.Errorf("%s 处置命令 = %+v, want %q（方案错配）", f.Signal, f.Actions, wantCmd[f.Signal])
		}
	}
}

// TestEngine_RespondRemoteNonZeroExitNotRemediated 远程命令退出码非零
// （输出尾部 "[exit: N]" 尾注）必须视为失败：不得标记已处置、不得走
// verify。run2 实测 userdel 被拒（exit 6）与 pkill 误杀自身会话
// （exit 143）均被误标为 ✓ 已处置。
func TestEngine_RespondRemoteNonZeroExitNotRemediated(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	remote.outputs = map[string][]string{
		"systemctl restart nginx.service": {"restarted\n[exit: 1]"},
	}
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, deepDiveReply, respondReply},
		remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := e.ws().Confirmed()[0]
	if f.Remediated {
		t.Fatal("退出码非零不得标记已处置")
	}
	if len(f.Actions) != 1 || !strings.Contains(f.Actions[0].Error, "退出码") {
		t.Errorf("动作应记录退出码失败: %+v", f.Actions)
	}
	if f.Actions[0].Verified {
		t.Error("失败动作不得走验证")
	}
}

func TestEngine_RespondFeedbackLoop(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: svcFailedOut, restoreAfter: "systemctl is-active nginx.service"}
	// 第一次验证输出为空（失败）；第二次同 verify 命令返回 active（修正后成功）。
	remote.outputs = map[string][]string{
		"systemctl restart nginx.service":   {"restarted", "restarted"},
		"systemctl is-active nginx.service": {"", "active"},
	}
	e, _, m := testEngineProtocol(t,
		[]string{surveyReply, deepDiveReply,
			respondReply, respondReply},
		remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := e.ws().Confirmed()[0]
	if f.Remediated {
		t.Fatal("首轮验证失败不应标记已处置")
	}
	if !f.Actions[0].RolledBac {
		t.Error("首轮验证失败应回滚")
	}
	// 第二轮 respond：prompt 必须携带上次执行结果（反馈闭环）。
	e.respond(context.Background())
	f = e.ws().Confirmed()[0]
	if !f.Remediated {
		t.Fatalf("反馈后修正方案应处置成功: %+v", f)
	}
	// 断言反馈回灌：第二次 respond 的 prompt 含执行摘要与失败原因。
	var secondRespond string
	for _, p := range m.prompts {
		if strings.Contains(p, "上次处置执行结果") {
			secondRespond = p
		}
	}
	if secondRespond == "" {
		t.Fatal("第二轮 respond 的 prompt 应包含反馈回灌段")
	}
	for _, want := range []string{"验证失败", "已回滚", "restart nginx"} {
		if !strings.Contains(secondRespond, want) {
			t.Errorf("反馈段缺少 %q: %s", want, secondRespond)
		}
	}
}

func TestEngine_RespondRetryOnGenerationFailure(t *testing.T) {
	// 首次输出不可解析（如全角引号/杂文）→ 重试一次 → 成功处置。
	// 与初始化阶段的重试策略对齐（runPhaseOnce 最多重试 1 次）。
	remote := &fakeL0Remote{defaultOut: svcFailedOut, restoreAfter: "systemctl is-active nginx.service"}
	remote.outputs = map[string][]string{
		"systemctl is-active nginx.service": {"active"},
	}
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, deepDiveReply, "garbage", respondReply},
		remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := e.ws().Confirmed()[0]
	if !f.Remediated {
		t.Errorf("重试后应成功处置: %+v", f)
	}
}

func TestEngine_RespondBothAttemptsFailNotesReason(t *testing.T) {
	// 两次生成均不可解析 → 不执行，finding 标记未处置原因（含原始输出可诊断性）。
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, deepDiveReply, "garbage", "garbage2"},
		remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := e.ws().Confirmed()[0]
	if f.Remediated {
		t.Error("两次失败不应处置")
	}
	// 两次输出均不可解析 → 解析路径失败，原因必须落盘到 finding。
	if !strings.Contains(f.RemediationNote, "处置方案解析失败") {
		t.Errorf("应记录未处置原因: %q", f.RemediationNote)
	}
}

func TestEngine_PhaseRetryThenFallback(t *testing.T) {
	// survey 契约校验失败（covered 缺 cpu）→ 重试仍失败 → 确定性兜底：
	// L0 探针判定直接产线索，DeepDive 有料可查（不降级跳过、不空转）。
	badSurvey := `{"phase":"survey","done":true,"covered":["mem"],"findings":[]}`
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	e, _, _ := testEngineProtocol(t,
		[]string{badSurvey, badSurvey, deepDiveReply},
		remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// 兜底应产出 L0 线索且被 DeepDive 确认——链路不空转。
	confirmed := e.ws().Confirmed()
	if len(confirmed) == 0 {
		t.Fatalf("survey 兜底线索应被 DeepDive 确认: %+v", e.ws().Findings())
	}
	if confirmed[0].Signal != "svc_failed" {
		t.Errorf("确认信号 = %s, want svc_failed（兜底探针产出）", confirmed[0].Signal)
	}
	// 兜底阶段记录：OK=false 且注明来源。
	found := false
	for _, p := range e.ws().Phases() {
		if p.Phase == PhaseSurvey && !p.OK && strings.Contains(p.Err, "兜底") {
			found = true
		}
	}
	if !found {
		t.Errorf("应记录 survey 兜底阶段: %+v", e.ws().Phases())
	}
}

func TestEngine_ExploreFallback(t *testing.T) {
	// survey 模型输出不可解析 → 确定性兜底：env 画像由探测生成 + L0/安全
	// 探针产线索，链路继续。
	remote := &fakeL0Remote{defaultOut: healthyOut}
	e, _, _ := testEngineProtocol(t,
		[]string{"garbage", "garbage"},
		remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.ws().Env == nil {
		t.Fatal("survey 兜底应生成 env 画像")
	}
	if e.ws().Env.ServiceMgr != "systemd" {
		t.Errorf("env 兜底 ServiceMgr = %q, want systemd（注入环境 HasSystemd=true）", e.ws().Env.ServiceMgr)
	}
	if !strings.Contains(e.ws().Env.Notes, "兜底") {
		t.Errorf("env 兜底应标注来源: %q", e.ws().Env.Notes)
	}
}

func TestEngine_SecurityFallback(t *testing.T) {
	// survey 模型输出两次不可解析 → 确定性兜底：env 探测 + L0 阈值线索 +
	// 安全探针（SUID/世界可写/SSH 弱配置）采集产线索，安全专项不空手。
	remote := &fakeL0Remote{defaultOut: securityOut}
	e, _, _ := testEngineProtocol(t,
		[]string{"garbage", "garbage", deepDiveReply},
		remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// 兜底应产出安全探针线索（suid_files 至少一条）。
	found := false
	for _, f := range e.ws().Findings() {
		if f.Signal == "suid_files" {
			found = true
		}
	}
	if !found {
		t.Fatalf("survey 兜底应产出 suid_files 线索: %+v", e.ws().Findings())
	}
	// 兜底阶段记录：OK=false 且注明来源。
	phaseFound := false
	for _, p := range e.ws().Phases() {
		if p.Phase == PhaseSurvey && !p.OK && strings.Contains(p.Err, "兜底") {
			phaseFound = true
		}
	}
	if !phaseFound {
		t.Errorf("应记录 survey 兜底阶段: %+v", e.ws().Phases())
	}
}
func TestEngine_UntilClean_Converges(t *testing.T) {
	// 收敛模式：检出 svc 故障 → 追查确认 → 处置 → 连续 2 轮无新线索 →
	// 退出 0，报告含收敛结论。
	remote := &fakeL0Remote{defaultOut: svcFailedOut, restoreAfter: "systemctl is-active nginx.service"}
	remote.outputs = map[string][]string{
		"systemctl is-active nginx.service": {"active"},
	}
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, deepDiveReply, respondReply},
		remote)
	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	confirmed := e.ws().Confirmed()
	if len(confirmed) != 1 || !confirmed[0].Remediated {
		t.Errorf("应处置全部确认故障: %+v", confirmed)
	}
	if !strings.Contains(e.core.Conclusion(), "收敛完成") {
		t.Errorf("应输出收敛结论: %q", e.core.Conclusion())
	}
	report, err := os.ReadFile(e.ReportPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(report), "运行结论") {
		t.Error("最终报告应含运行结论段")
	}
}

// TestEngine_PhaseContextIsolation 阶段任务上下文隔离（RunFresh）：每个
// 阶段的模型输入从干净上下文开始，不带上一阶段的工具调用历史——
// 上下文不再随阶段/轮次无界增长。
func TestEngine_PhaseContextIsolation(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: svcFailedOut, restoreAfter: "systemctl is-active nginx.service"}
	remote.outputs = map[string][]string{
		"systemctl is-active nginx.service": {"active"},
	}
	e, _, model := testEngineProtocol(t,
		[]string{surveyReply, deepDiveReply, respondReply},
		remote)
	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(model.msgCounts) == 0 {
		t.Fatal("应至少有一次模型调用")
	}
	base := model.msgCounts[0]
	for i, n := range model.msgCounts {
		if n != base {
			t.Fatalf("第 %d 次模型调用上下文 %d 条消息 ≠ 首阶段 %d 条（历史在跨阶段累积）", i, n, base)
		}
	}
}

func TestEngine_UntilClean_StallOnUnremediated(t *testing.T) {
	// 处置方案生成持续失败（3 次尝试达限）→ 引擎按处置机制升级人工
	// 工单（P0 语义：工单是闭环终态）→ 收敛退出 0，报告明示工单；
	// 不假装修好、不无限空转（旧语义"达限即停滞非零退出"已被工单
	// 终态取代——chaos-r1 实测正是该死锁）。
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	rescanReply := `{"phase":"rescan","done":true,"covered":["cpu","mem","disk","inode","zombie","svc","process","network","log","cron","security"],"findings":[]}`
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, deepDiveReply, "garbage", rescanReply},
		remote)
	err := e.Run(context.Background())
	if err != nil {
		t.Fatalf("方案生成失败达限转工单后应收敛退出 0: %v", err)
	}
	if !strings.Contains(e.core.Conclusion(), "收敛完成") {
		t.Errorf("报告结论应标注收敛: %q", e.core.Conclusion())
	}
	// 无法处置原因如实落盘到 finding（工单态）。
	f := e.ws().Confirmed()[0]
	if !workOrdered(f) {
		t.Errorf("达限应生成人工工单去向: %+v", f.Disposition)
	}
	if !strings.Contains(f.RemediationNote, "工单") {
		t.Errorf("应记录工单原因: %q", f.RemediationNote)
	}
}

func TestEngine_UntilClean_PendingEvidenceGap(t *testing.T) {
	// 证据不足的 pending（已追查 Tried>0）不阻塞收敛：DeepDive 裁决不了
	// 是验证回路的诚实行为，如实进报告"待查"区。
	heldReply := `{"phase":"deepdive","done":true,"covered":["svc"],
"findings":[{"host":"web-01","domain":"svc","signal":"svc_failed","desc":"服务失败",
"status":"pending","evidence":["systemctl --failed 有输出，但未定位根因"]}]}`
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, heldReply},
		remote)
	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("证据不足不应阻塞收敛: %v", err)
	}
	if !strings.Contains(e.core.Conclusion(), "收敛完成") {
		t.Errorf("应收敛: %q", e.core.Conclusion())
	}
	for _, f := range e.ws().Pending() {
		if f.Tried == 0 {
			t.Errorf("收敛后不应有未追查线索: %+v", f)
		}
	}
}

// TestEngine_WorkOrderTerminal_Converges 人工工单终态（P0 修复）：
// 模型判定无法自动处置（空方案）→ 引擎立即生成人工工单（manual_
// workorder）→ 工单是处置机制的合法闭环终态，不再阻塞收敛——
// chaos-r1 实测工单项每轮回灌处置、14 轮停滞退出的死锁由此消除。
// 引擎以收敛退出（退出 0），报告如实标注工单。
func TestEngine_WorkOrderTerminal_Converges(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	emptyPlan := `{"plans":[{"finding_id":"web-01/svc_failed","actions":[]}]}`
	rescanReply := `{"phase":"rescan","done":true,"covered":["cpu","mem","disk","inode","zombie","svc","process","network","log","cron","security"],"findings":[]}`
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, deepDiveReply, emptyPlan, rescanReply},
		remote)
	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("工单闭环应收敛退出 0: %v", err)
	}
	if !strings.Contains(e.core.Conclusion(), "收敛完成") {
		t.Errorf("结论应标注收敛: %q", e.core.Conclusion())
	}
	confs := e.ws().Confirmed()
	if len(confs) != 1 {
		t.Fatalf("应有 1 条确认项（工单态）: %+v", e.ws().Findings())
	}
	if !workOrdered(confs[0]) {
		t.Errorf("空方案应生成人工工单去向: %+v", confs[0].Disposition)
	}
	if !strings.Contains(confs[0].RemediationNote, "工单") {
		t.Errorf("应记录工单原因: %q", confs[0].RemediationNote)
	}
}

// TestEngine_VerifyFailAtLimit_WorkOrder 处置验证反复失败达限（P0 补全）：
// 动作执行但 verify/复检 3 轮失败 → 引擎按处置机制升级人工工单（闭环
// 终态）→ 收敛退出 0。旧语义"验证失败达限无工单 → 重裁决 → 停滞非零
// 退出"已被工单终态取代（chaos-r2 实测：passwd remember 项 3 轮验证
// 失败后无工单无出口，唯一阻塞项导致整场停滞）。
func TestEngine_VerifyFailAtLimit_WorkOrder(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	// 处置方案验证必败（fake remote 恒返回 failed，verify 判据 active
	// 永不满足）→ 3 轮达限 → 工单闭环。
	failingPlan := `{"plans":[{"finding_id":"web-01/svc_failed","actions":[{"name":"restart nginx","command":"systemctl restart nginx.service",
"rationale":"nginx 服务 failed，重启恢复","verify":"systemctl is-active nginx.service",
"check_up":"active","rollback":"systemctl start nginx.service"}]}]}`
	rescanReply := `{"phase":"rescan","done":true,"covered":["cpu","mem","disk","inode","zombie","svc","process","network","log","cron","security"],"findings":[]}`
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, deepDiveReply,
			failingPlan, failingPlan, failingPlan, rescanReply},
		remote)
	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("验证达限转工单后应收敛退出 0: %v", err)
	}
	if !strings.Contains(e.core.Conclusion(), "收敛完成") {
		t.Errorf("结论应标注收敛: %q", e.core.Conclusion())
	}
	confs := e.ws().Confirmed()
	if len(confs) != 1 {
		t.Fatalf("应有 1 条确认项（工单态）: %+v", e.ws().Findings())
	}
	if !workOrdered(confs[0]) {
		t.Errorf("验证达限应生成人工工单去向: %+v", confs[0].Disposition)
	}
}

// TestEngine_ReruleStuck_KeepsConfirmed 重裁决维持确认（P0 语义更新）：
// 空方案 → 引擎立即生成人工工单（闭环终态）→ 收敛退出 0，工单如实
// 进报告——"维持确认（无法自动处置）"不再制造死锁。本测试保留
// "模型反复空方案"的输入形态，断言新的终态语义。
func TestEngine_ReruleStuck_KeepsConfirmed(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	keepReply := `{"phase":"deepdive","done":true,"covered":["svc"],
"findings":[{"host":"web-01","domain":"svc","signal":"svc_failed","desc":"服务失败",
"status":"confirmed","evidence":["systemctl status 仍 failed"],"root_cause":"需人工介入"}]}`
	emptyPlan := `{"plans":[{"finding_id":"web-01/svc_failed","actions":[]}]}`
	rescanReply := `{"phase":"rescan","done":true,"covered":["cpu","mem","disk","inode","zombie","svc","process","network","log","cron","security"],"findings":[]}`
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, deepDiveReply,
			emptyPlan, rescanReply},
		remote)
	err := e.Run(context.Background())
	if err != nil {
		t.Fatalf("无法自动处置项转人工工单后应收敛退出 0: %v", err)
	}
	f := e.ws().Confirmed()[0]
	if !workOrdered(f) {
		t.Errorf("空方案应生成人工工单去向: %+v", f.Disposition)
	}
	if !strings.Contains(e.core.Conclusion(), "收敛完成") {
		t.Errorf("结论应标注收敛: %q", e.core.Conclusion())
	}
	_ = keepReply
}

// TestEngine_RechaseStalePending 重追查回路：模型首轮裁决"证据不足待查"
// 的线索被 L0 连续重检出后（Redetect≥阈值）再次追查——痕迹持续存在即
// 异常持续存在，首轮裁决不定不等于无限搁置（R5 实测确认面窄时剩余项
// 全部悬置即收敛）。
func TestEngine_RechaseStalePending(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: svcFailedOut, restoreAfter: "systemctl is-active nginx.service"}
	remote.outputs = map[string][]string{
		"systemctl restart nginx.service":   {"restarted"},
		"systemctl is-active nginx.service": {"active"},
	}
	// 回复序：explore/baseline/security → 首轮 deepdive 保持待查 →
	// 重追查确认 → respond 处置。
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, heldPendingReply, deepDiveReply, respondReply},
		remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := e.ws().Pending()[0]
	if f.Tried != 1 || f.Redetect != 0 {
		t.Fatalf("首轮裁决后 Tried=1 且计数清零: %+v", f)
	}
	// 两轮 L0 重检出 → Redetect 达到阈值 → 第三轮 deepdive 重追查。
	for i := 0; i < 2; i++ {
		if err := e.loopOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	f = e.ws().Confirmed()[0]
	if f.Tried != 2 || f.Rechased != 1 {
		t.Fatalf("重追查后 Tried=2 Rechased=1: %+v", f)
	}
	if !f.Remediated {
		t.Fatal("重追查确认后应完成处置")
	}
}

// TestEngine_RechaseCap 重追查上限：模型反复裁决待查时，单线索最多
// 重追查 maxRechase 次，之后不再烧模型调用（如实留在待查区）。
func TestEngine_RechaseCap(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	e, _, m := testEngineProtocol(t,
		[]string{surveyReply,
			heldPendingReply, heldPendingReply, heldPendingReply},
		remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// 首轮裁决后，两轮重检出 → 重追查1 → 再两轮 → 重追查2 → 达上限。
	for i := 0; i < 6; i++ {
		if err := e.loopOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	f := e.ws().Pending()[0]
	if f.Rechased != maxRechase {
		t.Fatalf("Rechased = %d, want %d", f.Rechased, maxRechase)
	}
	if f.Tried != 3 {
		t.Fatalf("Tried = %d, want 3（首轮+两次重追查）", f.Tried)
	}
	// 达上限后不再追查：再跑两轮，模型调用数不再增长。
	calls := m.call
	for i := 0; i < 2; i++ {
		if err := e.loopOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if m.call != calls {
		t.Errorf("达上限后不应再追查: calls %d -> %d", calls, m.call)
	}
}

func TestEngine_RespondGiveUpAfterLimit(t *testing.T) {
	// 处置方案尝试 3 次均失败 → 停止自动重试（不每轮无限烧调用），
	// 原因与上限如实进报告。
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, deepDiveReply,
			"garbage", "garbage", "garbage"},
		remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := e.ws().Confirmed()[0]
	if f.Remediated {
		t.Fatal("不应处置成功")
	}
	if f.RespondTried != 1 {
		t.Fatalf("首轮 RespondTried = %d, want 1", f.RespondTried)
	}
	// 再跑两轮：达上限 3。
	for i := 0; i < 2; i++ {
		if err := e.loopOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	f = e.ws().Confirmed()[0]
	if f.RespondTried != 3 {
		t.Fatalf("三轮后 RespondTried = %d, want 3", f.RespondTried)
	}
	// 第 4 轮：达限不再尝试。
	if err := e.loopOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	f = e.ws().Confirmed()[0]
	if f.RespondTried != 3 {
		t.Errorf("达限后不应再尝试: RespondTried = %d", f.RespondTried)
	}
	if !strings.Contains(f.RemediationNote, "尝试上限") {
		t.Errorf("报告应注明达上限: %q", f.RemediationNote)
	}
}

// TestEngine_RecheckBlocksFakeVerified 处置后确定性复检：L0 判定层能复核
// 的信号（对象键），模型 verify ✓ 但确定性层判定线索仍存在 → 不得标记
// 已处置（R20 假 ✓ 类缺口在确定性层收口）。
func TestEngine_RecheckBlocksFakeVerified(t *testing.T) {
	sudoOut := healthyOut + "\n__M_sudo_chain__\nALL ALL=(ALL) NOPASSWD: ALL\n"
	remote := &fakeL0Remote{defaultOut: sudoOut}
	sudoPlan := `{"plans":[{"finding_id":"web-01/sudo_chain_anomaly","actions":[{"name":"fix sudoers",
"command":"sed -i '/^ALL[[:space:]]ALL=(ALL)[[:space:]]NOPASSWD: ALL$/d' /etc/sudoers && visudo -c",
"rationale":"删除 sudo 万能免密行","verify":"grep -c 'NOPASSWD: ALL' /etc/sudoers",
"check_up":"0","rollback":"true"}]}]}`
	remote.outputs = map[string][]string{
		"sed -i '/^ALL[[:space:]]ALL=(ALL)[[:space:]]NOPASSWD: ALL$/d' /etc/sudoers && visudo -c": {"ok"},
		"grep -c 'NOPASSWD: ALL' /etc/sudoers":                                                    {"0"},
	}
	// deepdive 确认时携带对象键（key 是去重键，复述同一对象才能与 L0
	// 线索合并为同一条）。
	confirmSudo := `{"phase":"deepdive","done":true,"covered":["security"],
"findings":[{"host":"web-01","domain":"security","signal":"sudo_chain_anomaly","desc":"sudo 万能免密",
"status":"confirmed","evidence":["sudo_chain 输出含违规行"],"root_cause":"投毒","confidence":0.9,
"key":"ALL ALL=(ALL) NOPASSWD: ALL"}]}`
	e, _, _ := testEngineProtocol(t, []string{surveyEmptyReply, confirmSudo, sudoPlan}, remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := e.ws().Confirmed()[0]
	if f.Remediated {
		t.Fatal("复检未通过（线索仍存在）不得标记已处置")
	}
	if !strings.Contains(f.RemediationNote, "复检未通过") {
		t.Errorf("应记录复检未通过原因: %q", f.RemediationNote)
	}
}

// TestEngine_RecheckPassesWhenSignalGone 复检正向：处置真正消除对象后
// （L0 重采无该线索），标记已处置。
func TestEngine_RecheckPassesWhenSignalGone(t *testing.T) {
	sudoOut := healthyOut + "\n__M_sudo_chain__\nALL ALL=(ALL) NOPASSWD: ALL\n"
	remote := &fakeL0Remote{defaultOut: sudoOut}
	// 第一轮 L0（loopOnce 全量快检）与处置后复检（定向采集只含
	// sudo_chain 标记）都返回违规输出，第二次消费返回干净输出——
	// 按标记路由而非整条命令匹配（定向采集命令逐字不可预测）。
	remote.markerOutputs = map[string][]string{"sudo_chain": {sudoOut, healthyOut}}
	remote.outputs = map[string][]string{}
	sudoPlan := `{"plans":[{"finding_id":"web-01/sudo_chain_anomaly","actions":[{"name":"fix sudoers",
"command":"sed -i '/^ALL[[:space:]]ALL=(ALL)[[:space:]]NOPASSWD: ALL$/d' /etc/sudoers && visudo -c",
"rationale":"删除 sudo 万能免密行","verify":"grep -c 'NOPASSWD: ALL' /etc/sudoers",
"check_up":"0","rollback":"true"}]}]}`
	remote.outputs["sed -i '/^ALL[[:space:]]ALL=(ALL)[[:space:]]NOPASSWD: ALL$/d' /etc/sudoers && visudo -c"] = []string{"ok"}
	remote.outputs["grep -c 'NOPASSWD: ALL' /etc/sudoers"] = []string{"0"}
	confirmSudo := `{"phase":"deepdive","done":true,"covered":["security"],
"findings":[{"host":"web-01","domain":"security","signal":"sudo_chain_anomaly","desc":"sudo 万能免密",
"status":"confirmed","evidence":["sudo_chain 输出含违规行"],"root_cause":"投毒","confidence":0.9,
"key":"ALL ALL=(ALL) NOPASSWD: ALL"}]}`
	e, _, _ := testEngineProtocol(t, []string{surveyEmptyReply, confirmSudo, sudoPlan}, remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := e.ws().Confirmed()[0]
	if !f.Remediated {
		t.Fatalf("对象已消除应标记已处置: %+v", f)
	}
}

// TestEngine_FinalAdjudicate 收敛前终裁：剩余待查线索在退出前回灌一次
// 终裁（每条一次），新确认的返回 true 进入处置循环；无未终裁线索时不
// 再触发。
func TestEngine_FinalAdjudicate(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: healthyOut}
	finalReply := `{"phase":"deepdive","done":true,"covered":["svc"],
"findings":[{"host":"web-01","domain":"svc","signal":"svc_failed","desc":"服务失败",
"status":"confirmed","evidence":["实测 failed"],"root_cause":"r","confidence":0.9}]}`
	e, _, _ := testEngineProtocol(t, []string{finalReply, finalReply}, remote)
	p := model.NewFinding("web-01", "svc", "svc_failed", "待查线索")
	p.Tried = 1
	if err := e.ws().AddFindings([]*Finding{p}); err != nil {
		t.Fatal(err)
	}
	if changed, _ := e.finalAdjudicate(context.Background()); !changed {
		t.Fatal("终裁确认新故障应返回 true")
	}
	f := e.ws().Confirmed()[0]
	if !f.FinalRuled || f.Tried != 2 {
		t.Errorf("终裁后应标记 FinalRuled 且 Tried=2: %+v", f)
	}
	// 已终裁的不再重复终裁。
	if changed, _ := e.finalAdjudicate(context.Background()); changed {
		t.Error("无未终裁线索时不应再次终裁")
	}
}

// TestEngine_WarmupPreparesL0 预热一轮 L0：线索/基线在模型阶段前就绪。
func TestEngine_WarmupPreparesL0(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	e, _, _ := testEngineProtocol(t, []string{}, remote)
	if got := e.Warmup(context.Background()); len(got) == 0 {
		t.Fatal("预热应产 L0 线索")
	}
	if len(e.ws().Baseline()) != 1 {
		t.Errorf("预热应写入基线: %d", len(e.ws().Baseline()))
	}
	if len(e.ws().Pending()) == 0 {
		t.Error("预热线索应入库")
	}
}

// ── 日志可诊断性 ──────────────────────────────────────────────────────

// TestEngine_RespondActionErrorLineFails R15 回归：sed -i 对挂载文件
// 重命名失败输出 "sed: cannot rename..."，`; echo` 把整体退出码拉回 0——
// 错误行是唯一信号，必须判执行失败（执行与验证同源：错误行不作证据
// → 错误行即失败）。
func TestEngine_RespondActionErrorLineFails(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	errLineReply := `{"plans":[{"finding_id":"f","actions":[{"name":"fix hosts","command":"sed -i '/c2/d' /etc/hosts; echo hosts-c2-mapping-removed",
"rationale":"清除 nginx C2 劫持","verify":"echo hosts-c2-mapping-removed",
"check_up":"hosts-c2-mapping-removed","rollback":"true"}]}]}`
	remote.outputs = map[string][]string{
		"sed -i '/c2/d' /etc/hosts; echo hosts-c2-mapping-removed": {"sed: cannot rename /etc/sed7HYZA0: Device or resource busy\nhosts-c2-mapping-removed"},
	}
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, deepDiveReply, errLineReply},
		remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := e.ws().Confirmed()[0]
	if f.Remediated {
		t.Fatal("输出含错误行的动作不得标已处置")
	}
	if len(f.Actions) != 1 || !strings.Contains(f.Actions[0].Error, "错误行") {
		t.Errorf("应记录错误行失败: %+v", f.Actions)
	}
}

func TestEngine_DeepDiveFailureLogsRawOutput(t *testing.T) {
	// DeepDive 小结解析失败：原始输出留日志。svcFailedOut 产生 pending
	// 线索，DeepDive 才有追查目标。
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, "garbage"},
		remote)
	var buf bytes.Buffer
	e.core.SetLogOut(&buf)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "DeepDive 模型原始输出") || !strings.Contains(out, "garbage") {
		t.Errorf("日志应包含 DeepDive 原始输出:\n%s", out)
	}
}

func TestEngine_L0LogsPerHostErrors(t *testing.T) {
	// 远程主机采集失败（SSH 失联）：原因必须逐条进日志。
	remote := &fakeL0Remote{execErr: errors.New("ssh: connect refused")}
	cfg := DefaultConfig()
	cfg.Local = false
	cfg.Hosts = []string{"web-01"}
	cfg.WorkDir = t.TempDir()
	e, err := newEngine(cfg, nil, remote, &env.Env{HasSystemd: true, NProc: 8})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	e.core.SetLogOut(&buf)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "L0 web-01 采集 collect 失败") || !strings.Contains(out, "ssh: connect refused") {
		t.Errorf("日志应包含主机采集失败原因:\n%s", out)
	}
}

func TestEngine_DetailedLogs(t *testing.T) {
	// 运行日志纤毫毕露：L0 采集概况与线索明细、阶段开始/裁决明细、
	// Respond 目标与方案映射、处置动作与验证逐条留痕——发现问题
	// 不需要重新跑场景，日志即是断点。
	remote := &fakeL0Remote{defaultOut: svcFailedOut, restoreAfter: "systemctl is-active nginx.service"}
	remote.outputs = map[string][]string{
		"systemctl restart nginx.service":   {"restarted"},
		"systemctl is-active nginx.service": {"active"},
	}
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, deepDiveReply, respondReply},
		remote)
	var buf bytes.Buffer
	e.core.SetLogOut(&buf)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"L0 采集 web-01: 指标",                  // 每台主机采集概况
		"L0 线索 1 条",                         // 线索条数
		"- [web-01] svc_failed",             // 线索明细（主机+signal）
		"阶段 survey 开始",                      // 阶段目标可见
		"阶段 survey 完成",                      // 阶段耗时与产出
		"- [web-01] svc_failed",             // survey 产出明细
		"DeepDive 开始：追查 1 条未追查线索",           // 追查目标可见
		"DeepDive：裁决 1 条线索，明细",              // 裁决明细
		"- [web-01] svc_failed → confirmed", // 每条裁决结果
		"Respond 开始：1 个待处置故障",               // 处置目标可见
		"Respond 方案",                        // 方案→目标映射
		"处置动作 web-01[restart nginx]",        // 动作执行明细
		"→ 执行成功",                            // 执行结果
		"处置验证 web-01[restart nginx] → 通过",   // 验证明细
		"复检 web-01：通过 1，未通过 0",            // 确定性复检留痕（信号级）
	} {
		if !strings.Contains(out, want) {
			t.Errorf("日志应包含 %q:\n%s", want, out)
		}
	}
}

func TestEngine_RoundLogs_Converge(t *testing.T) {
	// 收敛循环逐轮留痕：轮次状态、复扫、收敛判定——比赛现场看日志
	// 即知引擎推进到哪一步。
	remote := &fakeL0Remote{defaultOut: svcFailedOut, restoreAfter: "systemctl is-active"}
	remote.outputs = map[string][]string{
		"systemctl restart nginx.service":   {"restarted"},
		"systemctl is-active nginx.service": {"active"},
	}
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, deepDiveReply, respondReply},
		remote)
	var buf bytes.Buffer
	e.core.SetLogOut(&buf)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := e.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"第 1 轮开始",
		"第 2 轮开始",
		"复扫开始",
		"收敛：",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("日志应包含 %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "停滞 ") {
		t.Errorf("收敛路径不应触发停滞检测:\n%s", out)
	}
}

func TestEngine_RoundLogs_Blockers(t *testing.T) {
	// 处置达限未修（P0 语义更新）：空方案 → 人工工单闭环 → 收敛退出 0，
	// 日志可见工单生成与收敛路径——阻塞项不再无限停滞（旧断言"停滞
	// 5/5 非零退出"对应已被工单终态取代的死锁）。
	emptyRespond := `{"plans":[{"finding_id":"f","actions":[]}]}`
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	rescanReply := `{"phase":"rescan","done":true,"covered":["cpu","mem","disk","inode","zombie","svc","process","network","log","cron","security"],"findings":[]}`
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, deepDiveReply, emptyRespond, rescanReply},
		remote)
	var buf bytes.Buffer
	e.core.SetLogOut(&buf)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	err := e.Run(ctx)
	if err != nil {
		t.Fatalf("空方案转工单应收敛退出 0: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"第 1 轮开始",
		"复扫开始",
		"收敛：",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("日志应包含 %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "停滞 ") {
		t.Errorf("工单闭环路径不应触发停滞检测:\n%s", out)
	}
}

func TestEngine_CancelReturnsErrorNotConverged(t *testing.T) {
	// 外部取消（SIGTERM/中断）：被中断的运行不得标记收敛——必须如实
	// 返回错误（R22 实测：评测超时 SIGTERM 截断仍标 converged=true
	// 导致评分失真；result.json 的 converged 以 Run 返回值为准）。
	remote := &fakeL0Remote{defaultOut: svcFailedOut}
	cfg := DefaultConfig()
	cfg.Local = false
	cfg.Hosts = []string{"web-01"}
	cfg.WorkDir = t.TempDir()
	cfg.VerifyTimeout = 2 * time.Second
	e, err := newEngine(cfg, newFakeModel(surveyReply), remote, &env.Env{HasSystemd: true, NProc: 8})
	if err != nil {
		t.Fatalf("newEngine: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 运行前已取消：模拟运行途中收到 SIGTERM
	if err := e.Run(ctx); err == nil {
		t.Fatal("被取消的运行必须返回错误，不得标记收敛")
	}
}

// ── 线索分批追查（截断漏检修复） ─────────────────────────────────────

// TestEngine_DeepDiveBatchesLargeLeadSets 单轮 >20 条未追查线索时分批
// 进模型：全部线索必须被追查（Tried>0）且每条都出现在某个批次 prompt
// 中——回归：此前一次调用 + 20 条截断会把第 21+ 条标记 Tried 却从未
// 进入任何模型上下文（静默漏检）。
func TestEngine_DeepDiveBatchesLargeLeadSets(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: healthyOut}
	e, _, m := testEngineProtocol(t, []string{deepDiveBatchReply, deepDiveBatchReply}, remote)
	const n = 25
	var leads []*Finding
	for i := 0; i < n; i++ {
		f := model.NewFinding("web-01", "svc", "svc_failed", fmt.Sprintf("线索 %d", i))
		f.Key = fmt.Sprintf("lead-%02d", i) // 不同子键：不合并为同一条
		leads = append(leads, f)
	}
	if err := e.ws().AddFindings(leads); err != nil {
		t.Fatal(err)
	}
	e.deepDive(context.Background())
	if m.call < 2 {
		t.Fatalf("应分多批调用模型: calls=%d", m.call)
	}
	for _, f := range e.ws().Pending() {
		if f.Tried == 0 {
			t.Errorf("线索 %s 未被追查（截断漏检）", f.Key)
		}
	}
	var all strings.Builder
	for _, p := range m.prompts {
		all.WriteString(p)
		// 回归（R23 实测）：批大小必须落在 DiagnoseTimeout 预算内——
		// 大批追查会话超时 → 整批失败 → 下轮重追同一批（死循环）。
		// 每批线索数不得超过 deepDiveBatchSize。
		if got := batchLeadCount(p); got > deepDiveBatchSize {
			t.Errorf("单批线索数 %d 超过上限 %d（超时预算不匹配会整批超时死循环）", got, deepDiveBatchSize)
		}
	}
	for i := 0; i < n; i++ {
		if !strings.Contains(all.String(), fmt.Sprintf("线索 %d", i)) {
			t.Errorf("线索 %d 未进入任何模型上下文", i)
		}
	}
}

// batchLeadCount 统计 prompt 的 goal 段（"## 已知状态"之前）中出现的
// 线索条目数——state 段是全工作区摘要（含其他批线索），不属于本批追查目标。
func batchLeadCount(p string) int {
	goal := p
	if i := strings.Index(goal, "## 已知状态"); i >= 0 {
		goal = goal[:i]
	}
	re := regexp.MustCompile(`线索 \d+`)
	seen := map[string]bool{}
	for _, m := range re.FindAllString(goal, -1) {
		seen[m] = true
	}
	return len(seen)
}

// deepDiveBatchReply 分批追查测试的空裁决回复（keep pending）。
const deepDiveBatchReply = `{"phase":"deepdive","done":true,"covered":["svc"],"findings":[]}`

// TestEngine_FinalAdjudicateBatchesLargeLeadSets 收敛前终裁 >5 条待查
// 线索时同样分批：全部标记 FinalRuled，且每条都进入某批 prompt——
// 回归：此前 20 条截断会让第 21+ 条带着 FinalRuled 标记退出却不曾被
// 终裁（带着"从未终裁"的线索收敛）。
func TestEngine_FinalAdjudicateBatchesLargeLeadSets(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: healthyOut}
	e, _, m := testEngineProtocol(t, []string{deepDiveBatchReply, deepDiveBatchReply}, remote)
	const n = 25
	var leads []*Finding
	for i := 0; i < n; i++ {
		f := model.NewFinding("web-01", "svc", "svc_failed", fmt.Sprintf("待裁线索 %d", i))
		f.Key = fmt.Sprintf("adj-%02d", i)
		f.Tried = 1 // 已追查、未终裁
		leads = append(leads, f)
	}
	if err := e.ws().AddFindings(leads); err != nil {
		t.Fatal(err)
	}
	if changed, _ := e.finalAdjudicate(context.Background()); changed {
		t.Error("空裁决不应新增确认")
	}
	if m.call < 2 {
		t.Fatalf("应分两批终裁: calls=%d", m.call)
	}
	for _, f := range e.ws().Pending() {
		if !f.FinalRuled {
			t.Errorf("线索 %s 未终裁（截断漏检）", f.Key)
		}
	}
	var all strings.Builder
	for _, p := range m.prompts {
		all.WriteString(p)
	}
	for i := 0; i < n; i++ {
		if !strings.Contains(all.String(), fmt.Sprintf("待裁线索 %d", i)) {
			t.Errorf("线索 %d 未进入任何终裁上下文", i)
		}
	}
}

// ── 处置幂等预检 ─────────────────────────────────────────────────────

// TestEngine_RespondPrecheckSkipsReexecution 重试轮（RespondTried≥2）：
// 前次处置已生效（verify 判据已满足）时预检短路——副作用命令不再
// 执行（防重复删除/回滚），仍进确定性复检闭环标记已处置。
func TestEngine_RespondPrecheckSkipsReexecution(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: svcFailedOut, restoreAfter: "systemctl is-active nginx.service"}
	// 首轮：执行成功但验证失败（无 active 行）→ 回滚；第二轮 verify
	// 返回 active（前次处置实际已生效）→ 预检短路跳过执行。
	remote.outputs = map[string][]string{
		"systemctl restart nginx.service":   {"restarted"},
		"systemctl is-active nginx.service": {"", "active"},
	}
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, deepDiveReply, respondReply, respondReply},
		remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f := e.ws().Confirmed()[0]; f.Remediated {
		t.Fatal("首轮验证失败不应标记已处置")
	}
	// 第二轮 respond：RespondTried=2 → 预检路径。
	e.respond(context.Background())
	f := e.ws().Confirmed()[0]
	if !f.Remediated {
		t.Fatalf("预检满足后应标记已处置: %+v", f)
	}
	if len(f.Actions) != 1 || !f.Actions[0].Prechecked || !f.Actions[0].Verified {
		t.Fatalf("动作应为预检通过: %+v", f.Actions)
	}
	// 副作用命令只执行过一次（首轮）——第二轮不得重复执行。
	execs := 0
	for _, c := range remote.calls {
		if strings.Contains(c, "systemctl restart nginx.service") {
			execs++
		}
	}
	if execs != 1 {
		t.Errorf("重启命令应只执行 1 次（第二轮被预检短路），实际 %d", execs)
	}
	if !strings.Contains(f.RemediationNote, "预检已满足") {
		t.Errorf("应记录预检说明: %q", f.RemediationNote)
	}
}

// TestEngine_RespondPkillAutoFixed 模型给出 pkill -f 自杀模式时引擎
// 机械改写执行（模式括号化/拆段）而非拒绝：已确认的处置不被守卫卡死
// （评测实测 9090/8088 后门因 pkill 拒绝 3 轮达限悬置）。
func TestEngine_RespondPkillAutoFixed(t *testing.T) {
	confirm := `{"phase":"deepdive","done":true,"covered":["network"],
"findings":[{"host":"web-01","domain":"network","signal":"unattributed_listen","desc":"9090 后门端口",
"status":"confirmed","evidence":["ss 显示 9090"],"root_cause":"后门","confidence":0.9,"key":"0.0.0.0:9090"}]}`
	plan := `{"plans":[{"finding_id":"web-01/unattributed_listen","actions":[{"name":"kill 9090",
"command":"pkill -f 'http.server 9090'","rationale":"终止后门进程","verify":"pgrep -f 'http[.]server 9090' >/dev/null || echo gone",
"check_up":"gone","rollback":"true"}]}]}`
	remote := &fakeL0Remote{defaultOut: healthyOut}
	// 执行段是改写后的命令（括号化），按改写后文本匹配输出。
	remote.outputs = map[string][]string{
		"pkill -f '[h]ttp.server 9090'":                         {"killed"},
		"pgrep -f 'http[.]server 9090' >/dev/null || echo gone": {"gone"},
	}
	e, _, _ := testEngineProtocol(t, []string{surveyReply, confirm, plan}, remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := e.ws().Confirmed()[0]
	if !f.Remediated {
		t.Fatalf("pkill 方案应被机械改写执行并处置成功: %+v", f)
	}
	if len(f.Actions) != 1 || f.Actions[0].Advised {
		t.Fatalf("动作应执行而非转建议: %+v", f.Actions)
	}
	// 原始未改写模式不得进入执行（自杀风险在执行层消除）。
	for _, c := range remote.calls {
		if c == "pkill -f 'http.server 9090'" {
			t.Errorf("未改写的自杀命令被执行: %q", c)
		}
	}
	executed := false
	for _, c := range remote.calls {
		if strings.Contains(c, "[h]ttp.server 9090") {
			executed = true
		}
	}
	if !executed {
		t.Error("改写后的命令应被执行")
	}
}

// ── 周期复扫（脏环境漏检窗口闭合） ─────────────────────────────────────

// TestEngine_PeriodicRescanTriggersInDirtyEnv 脏环境下追查静默且连续
// rescanEveryRounds 轮未复扫时触发周期复扫；有未追查线索（模型正在
// 追查）时不触发——复扫不与追查重复劳动。
func TestEngine_PeriodicRescanTriggersInDirtyEnv(t *testing.T) {
	// 复扫回复：发现一条新线索（covered 必须满足全域契约）。
	rescanReply := `{"phase":"rescan","done":true,"covered":["cpu","mem","disk","inode","zombie","svc","process","network","log","cron","security"],
"findings":[{"host":"web-01","domain":"proc","signal":"zombie_procs","desc":"复扫新发现僵尸进程","status":"pending"}]}`
	remote := &fakeL0Remote{defaultOut: healthyOut}
	e, _, _ := testEngineProtocol(t, []string{rescanReply}, remote)
	// 脏状态：一条已追查未裁决的待查线索（无未追查项），复扫计数到位。
	p := model.NewFinding("web-01", "svc", "svc_failed", "已追查未裁决")
	p.Tried = 1
	if err := e.ws().AddFindings([]*Finding{p}); err != nil {
		t.Fatal(err)
	}
	e.roundsSinceRescan = rescanEveryRounds
	if !e.maybePeriodicRescan(context.Background()) {
		t.Fatal("满足触发条件应执行周期复扫并发现新线索")
	}
	found := false
	for _, f := range e.ws().Findings() {
		if strings.Contains(f.Desc, "复扫新发现") {
			found = true
		}
	}
	if !found {
		t.Fatalf("复扫新线索应入库: %+v", e.ws().Findings())
	}
	// 有未追查线索时（模型正在追查）：不触发，也不消耗模型调用。
	e.roundsSinceRescan = rescanEveryRounds
	p2 := model.NewFinding("web-01", "svc", "svc_inactive", "未追查")
	if err := e.ws().AddFindings([]*Finding{p2}); err != nil {
		t.Fatal(err)
	}
	if e.maybePeriodicRescan(context.Background()) {
		t.Error("有未追查线索时不应触发周期复扫")
	}
}
