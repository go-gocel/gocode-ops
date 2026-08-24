package autopilot

// respond_blocked_test.go — 通道约束预判（省重试轮，守住通道但不绝对）：
// 仅"处置必然收紧引擎自身认证通道"的故障（root 登录收紧面）在 root
// 连接下预判必拒；其余认证面信号由守卫实际裁决（可能不触碰通道）。

import (
	"testing"

	"github.com/go-gocel/gocode-ops/internal/common/model"
)

func TestAllAdvised(t *testing.T) {
	if allAdvised([]model.Action{{Advised: true}, {Advised: true}}) != true {
		t.Error("全建议应 true")
	}
	if allAdvised([]model.Action{{Advised: true}, {Advised: false}}) != false {
		t.Error("混入已执行应 false")
	}
	if allAdvised(nil) != false {
		t.Error("空列表应 false")
	}
}

func TestStructurallyBlocked(t *testing.T) {
	cases := []struct {
		name string
		acts []model.Action
		want bool
	}{
		{"通道保护拒绝（self-impact）", []model.Action{{Advised: true, AdvisedReason: "ops 安全守卫: 命令风险审查拒绝（self-impact/channel-auth）—— 修改 sshd/pam 认证配置并禁用了主机 web-01 当前的登录方式"}}, true},
		{"硬性禁止", []model.Action{{Advised: true, AdvisedReason: "ops 安全守卫: 硬性禁止 credential-read（credential/credential-read）—— 凭证文件/私钥——严禁进入模型上下文。该命令永远不允许执行。"}}, true},
		{"pkill 改写失败（可修正）", []model.Action{{Advised: true, AdvisedReason: "pkill/pgrep -f 模式无法机械改写为防自匹配形式"}}, false},
		{"混合拒绝（一个成功一个被拒）", []model.Action{{Advised: false, Command: "ok"}, {Advised: true, AdvisedReason: "命令风险审查拒绝（self-impact/channel-auth）"}}, false},
		{"拒绝原因缺失", []model.Action{{Advised: true}}, false},
	}
	for _, c := range cases {
		if got := structurallyBlocked(c.acts); got != c.want {
			t.Errorf("%s: structurallyBlocked = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAuthTighteningSignal(t *testing.T) {
	cases := []struct {
		signal string
		want   bool
	}{
		{"ssh_root_login", true},
		{"deviation_policy_root_ssh", true},
		{"root_login", true},
		{"ssh_root_login_extra", true}, // 前缀形态（模型自创 signal 变体）
		// 其余认证面信号：处置可能不触碰通道（MaxAuthTries 加固/faillock
		// deny 配置/锁定非当前账户/先配密钥再收紧）——不预判。
		{"ssh_chain", false},
		{"faillock_cfg", false},
		{"passwd_policy_weak", false},
		{"suspicious_account", false},
		{"svc_failed", false},
	}
	for _, c := range cases {
		if got := authTighteningSignal(c.signal); got != c.want {
			t.Errorf("authTighteningSignal(%q) = %v, want %v", c.signal, got, c.want)
		}
	}
}

func TestAuthBlockHint(t *testing.T) {
	remote := &fakeL0Remote{}
	e := &Engine{remote: remote}
	mk := func(signal string) *model.Finding {
		f := model.NewFinding("web-01", "svc", signal, "d")
		f.ID = "web-01/" + signal + "/1" // ID 入库时补全；此处模拟已入库对象
		f.Status = model.FindingConfirmed
		return f
	}
	targets := []*model.Finding{
		mk("ssh_root_login"),
		mk("ssh_chain"),
		mk("faillock_cfg"),
		mk("passwd_policy_weak"), // chage/login.defs：守卫不拦截，不标注
		mk("svc_failed"),
	}
	hints := authBlockHint(e, targets)
	if hints[targets[0].ID] == "" {
		t.Error("ssh_root_login（root 收紧面）在 root 连接下应标注通道约束")
	}
	// 其余认证面信号：处置可能不触碰通道（ssh 弱化项加固/faillock deny/
	// chage/服务）——守卫实际裁决，不预判（不能全拒绝）。
	for i, want := range map[int]string{1: "ssh_chain", 2: "faillock_cfg", 3: "passwd_policy_weak", 4: "svc_failed"} {
		if hints[targets[i].ID] != "" {
			t.Errorf("%s 不应标注（处置可能不触碰通道）", want)
		}
	}
	// 非 root 连接：不标注（PRL 收紧不影响非 root 引擎通道）。
	e2 := &Engine{remote: &nonRootRemote{}}
	targets2 := []*model.Finding{mk("ssh_root_login")}
	if hints2 := authBlockHint(e2, targets2); hints2[targets2[0].ID] != "" {
		t.Error("非 root 连接不应标注通道约束")
	}
}

// nonRootRemote 模拟 ops 用户连接（PRL 收紧不切断其通道）。
type nonRootRemote struct{ fakeL0Remote }

func (f *nonRootRemote) ConnFacts(aliases []string) map[string]model.ConnFact {
	res := map[string]model.ConnFact{}
	for _, a := range aliases {
		res[a] = model.ConnFact{Host: a, User: "ops", Auth: "password", Port: "22"}
	}
	return res
}
