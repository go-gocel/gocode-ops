package autopilot

import (
	"context"
	"strings"
	"testing"

	"github.com/go-gocel/gocode-ops/internal/common/model"
)

// 自通道校验机制测试（design-v2.md §三.4）：认证/网络类处置后，引擎用
// 新连接验证管理通道——模型 verify 只验"配置生效"，验不了"通道还通不
// 通"；校验失败 = 锁死风险 → 强制回滚 + 去向降级人工工单，绝不标已处置。

// authRestrictReply 来源收窄类处置方案（守卫放行：不净禁用登录方式；
// 单 IP 白名单正是"锁死风险"场景——动态 IP/来源变更即断通道）。
const authRestrictReply = `{"plans":[{"finding_id":"f","actions":[{"name":"restrict root ssh source",
"command":"printf '\nAllowUsers root@192.168.1.9\n' >> /etc/ssh/sshd_config && sshd -t && systemctl reload sshd && echo SSH_RESTRICTED_OK",
"rationale":"SSH 弱配置加固：root 来源收窄到管理机（示例处置）",
"verify":"sshd -T | grep -i allowusers",
"check_up":"allowusers root@192.168.1.9",
"rollback":"sed -i '/AllowUsers/d' /etc/ssh/sshd_config && systemctl reload sshd"}]}]}`

// deepDiveSSHReply 深挖裁决：确认 ssh_root_login（ChangeAuth 类，触发
// 自通道校验）。
const deepDiveSSHReply = `{"phase":"deepdive","done":true,"covered":["security"],
"findings":[{"host":"web-01","domain":"security","signal":"ssh_root_login","desc":"SSH 允许 root 密码登录",
"status":"confirmed","evidence":["sshd -T 显示 permitrootlogin yes"],"root_cause":"CentOS 7 默认配置","confidence":0.9}]}`

// TestRespond_SelfChannelFailForceRollback 自通道校验失败（变更后新连接
// 不可达）：模型 verify 通过但引擎探测失败 → 强制回滚全部动作、去向
// 降为人工工单、不标记已处置。
func TestRespond_SelfChannelFailForceRollback(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: healthyOut, probeFail: true}
	remote.outputs = map[string][]string{
		"sshd -T | grep -i allowusers": {"allowusers root@192.168.1.9"},
	}
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, deepDiveSSHReply, authRestrictReply},
		remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := e.ws().Confirmed()[0]
	if f.Signal != "ssh_root_login" {
		t.Fatalf("测试前提：应确认 ssh_root_login，实际 %s", f.Signal)
	}
	if f.Remediated {
		t.Fatal("自通道校验失败不得标记已处置")
	}
	if f.Disposition == nil || f.Disposition.Outcome != model.DispositionManualWorkOrder {
		t.Fatalf("锁死风险应降级为人工工单（manual_workorder）: %+v", f.Disposition)
	}
	if !strings.Contains(f.RemediationNote, "自通道校验失败") {
		t.Errorf("应记录自通道校验失败原因: %q", f.RemediationNote)
	}
	// 强制回滚已执行（AllowUsers 行被删除 + reload）。
	found := false
	for _, c := range remote.calls {
		if strings.Contains(c, "sed -i '/AllowUsers/d'") {
			found = true
		}
	}
	if !found {
		t.Errorf("自通道校验失败后应执行强制回滚，实际调用: %v", remote.calls)
	}
}

// TestRespond_SelfChannelOKVerified 自通道校验通过（新连接可达）：正常
// 标记 verified_fixed + 验证证据，不触发回滚。
func TestRespond_SelfChannelOKVerified(t *testing.T) {
	remote := &fakeL0Remote{defaultOut: healthyOut} // probeFail=false → 在线
	remote.outputs = map[string][]string{
		"sshd -T | grep -i allowusers": {"allowusers root@192.168.1.9"},
	}
	e, _, _ := testEngineProtocol(t,
		[]string{surveyReply, deepDiveSSHReply, authRestrictReply},
		remote)
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := e.ws().Confirmed()[0]
	if f.Signal != "ssh_root_login" {
		t.Fatalf("测试前提：应确认 ssh_root_login，实际 %s", f.Signal)
	}
	if !f.Remediated {
		t.Fatal("自通道校验通过应正常标记已处置")
	}
	if f.Disposition == nil || f.Disposition.Outcome != model.DispositionVerifiedFixed {
		t.Fatalf("去向应为 verified_fixed: %+v", f.Disposition)
	}
	if len(f.Disposition.Evidence) == 0 {
		t.Error("verified_fixed 应绑定功能验证证据")
	}
	for _, c := range remote.calls {
		if strings.Contains(c, "sed -i '/AllowUsers/d'") {
			t.Error("校验通过不应执行回滚")
		}
	}
}
