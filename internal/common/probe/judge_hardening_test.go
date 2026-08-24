package probe

import "testing"

// 等保加固归属判定测试（数据驱动：无数据段即跳过）。

func TestJudgeHardeningFacts_LoginDefs(t *testing.T) {
	hm := &HostMetric{Host: "h", Raw: map[string]string{
		"login_defs": "PASS_MAX_DAYS 99999\nPASS_MIN_LEN 5\nPASS_WARN_AGE 3\n",
	}}
	out := JudgeHardeningFacts(hm)
	if len(out) != 3 {
		t.Fatalf("线索数 = %d, want 3: %+v", len(out), out)
	}
	for _, a := range out {
		if a.Metric != "login_defs" || a.Signal() != "passwd_policy_weak" {
			t.Errorf("信号/指标错误: %s/%s", a.Metric, a.Signal())
		}
	}
	// 合规配置：不产线。
	ok := JudgeHardeningFacts(&HostMetric{Host: "h", Raw: map[string]string{
		"login_defs": "PASS_MAX_DAYS 90\nPASS_MIN_LEN 8\nPASS_WARN_AGE 7\n",
	}})
	if len(ok) != 0 {
		t.Errorf("合规配置不应产线，got %v", ok)
	}
	// 无数据段：跳过。
	if got := JudgeHardeningFacts(&HostMetric{Host: "h"}); len(got) != 0 {
		t.Errorf("无数据不应产线，got %v", got)
	}
}

func TestJudgeHardeningFacts_PwqualityFaillock(t *testing.T) {
	out := JudgeHardeningFacts(&HostMetric{Host: "h", Raw: map[string]string{
		"pwquality":    "minlen = 6\n",
		"faillock_cfg": "deny = 10\nunlock_time = 600\n",
	}})
	// minlen 弱 + remember 缺失（pwquality 有数据但未配置重复限制）+ deny=10。
	if len(out) != 3 {
		t.Fatalf("线索数 = %d, want 3（minlen+remember 缺失+deny）: %+v", len(out), out)
	}
	// remember 合规（≥5）+ minlen 合规 → pwquality 不产线。
	out = JudgeHardeningFacts(&HostMetric{Host: "h", Raw: map[string]string{
		"pwquality":    "minlen = 8\nremember = 5\n",
		"faillock_cfg": "deny = 5\n",
	}})
	if len(out) != 0 {
		t.Errorf("合规 pwquality/faillock 不应产线，got %v", out)
	}
	// remember=3 弱。
	out = JudgeHardeningFacts(&HostMetric{Host: "h", Raw: map[string]string{
		"pwquality": "minlen = 8\nremember = 3\n",
	}})
	if len(out) != 1 || out[0].Key != "remember" {
		t.Errorf("remember=3 应产 1 条 remember 弱线，got %v", out)
	}
	// faillock deny=0（关闭）同样产线。
	out = JudgeHardeningFacts(&HostMetric{Host: "h", Raw: map[string]string{
		"faillock_cfg": "deny = 0\n",
	}})
	if len(out) != 1 {
		t.Errorf("deny=0 应产线，got %v", out)
	}
	// deny ≤5 合规。
	out = JudgeHardeningFacts(&HostMetric{Host: "h", Raw: map[string]string{
		"faillock_cfg": "deny = 5\n",
	}})
	if len(out) != 0 {
		t.Errorf("deny=5 不应产线，got %v", out)
	}
}

// TestJudgeHardeningFacts_FaillockMissing 有 PAM 密码认证但未配置
// faillock → 产线（等保要求失败锁定）；无 PAM 数据 → 跳过。
func TestJudgeHardeningFacts_FaillockMissing(t *testing.T) {
	out := JudgeHardeningFacts(&HostMetric{Host: "h", Raw: map[string]string{
		"auth_chain": "== /etc/pam.d/sshd\nauth include system-auth\n== /etc/pam.d/system-auth\nauth required pam_unix.so\n",
	}})
	if len(out) != 1 || out[0].Metric != "faillock_cfg" {
		t.Fatalf("PAM 密码认证无 faillock 应产线，got %v", out)
	}
	// 无 PAM 数据（容器/非密码认证面）→ 跳过。
	if got := JudgeHardeningFacts(&HostMetric{Host: "h"}); len(got) != 0 {
		t.Errorf("无 PAM 数据不应产线，got %v", got)
	}
}

// TestJudgeHardeningFacts_SessionTimeout 会话超时：无 TMOUT → 产线；
// TMOUT>0 → 合规；TMOUT=0 → 产线；NO_PROFILE/无数据 → 跳过。
func TestJudgeHardeningFacts_SessionTimeout(t *testing.T) {
	cases := []struct {
		raw  string
		want int
	}{
		{"PROFILE_PRESENT\n", 1},                              // profile 存在但无 TMOUT
		{"PROFILE_PRESENT\nTMOUT=600\n", 0},                   // 已配置
		{"PROFILE_PRESENT\nexport TMOUT=300\n", 0},            // export 形态
		{"PROFILE_PRESENT\nreadonly TMOUT=600\n", 0},          // readonly 形态
		{"PROFILE_PRESENT\nTMOUT=0\n", 1},                     // 0=关闭超时
		{"NO_PROFILE\n", 0},                                   // 无 profile 环境跳过
		{"", 0},                                               // 探针失败跳过
		{"PROFILE_PRESENT\nTMOUT=600\nreadonly TMOUT=0\n", 0}, // 任一有效配置即合规
	}
	for i, c := range cases {
		out := JudgeHardeningFacts(&HostMetric{Host: "h", Raw: map[string]string{"session_timeout": c.raw}})
		if len(out) != c.want {
			t.Errorf("case %d: 线索数 = %d, want %d (%v)", i, len(out), c.want, out)
		}
	}
	// 信号映射：no_session_timeout。
	if s := signalByMetric["session_timeout"]; s != "no_session_timeout" {
		t.Errorf("session_timeout 信号应为 no_session_timeout，got %q", s)
	}
}

func TestJudgeHardeningFacts_TimeSync(t *testing.T) {
	cases := []struct {
		raw  string
		want int
	}{
		{"NTPSynchronized=yes\nTimeUSec=...\n", 0},
		{"NTPSynchronized=no\nTimeUSec=...\n", 1},
		{"NTPSynchronized=no\nTimeUSec=...\nchronyc tracking\n  Reference ID : 1.2.3.4\n", 0}, // chronyc 成功覆盖
		{"", 0},
	}
	for i, c := range cases {
		out := JudgeHardeningFacts(&HostMetric{Host: "h", Raw: map[string]string{"time_sync": c.raw}})
		if len(out) != c.want {
			t.Errorf("case %d: 线索数 = %d, want %d (%v)", i, len(out), c.want, out)
		}
	}
}

func TestJudgeHardeningFacts_Umask(t *testing.T) {
	cases := []struct {
		raw  string
		want int
	}{
		{"umask 022\n", 0},
		{"umask 002\n", 1},
		{"UMASK 027\n", 0},
		{"umask 000\n", 1},
		{"umask 077\n", 0},
	}
	for i, c := range cases {
		out := JudgeHardeningFacts(&HostMetric{Host: "h", Raw: map[string]string{"umask_cfg": c.raw}})
		if len(out) != c.want {
			t.Errorf("case %d: 线索数 = %d, want %d (%v)", i, len(out), c.want, out)
		}
	}
}

func TestJudgeHardeningFacts_Services(t *testing.T) {
	// auditd inactive → 产线；auditctl enabled=0 → 产线。
	out := JudgeHardeningFacts(&HostMetric{Host: "h", Raw: map[string]string{
		"auditd_cfg": "inactive\n",
	}})
	if len(out) != 1 || out[0].Metric != "auditd_cfg" {
		t.Errorf("auditd inactive 应产线，got %v", out)
	}
	out = JudgeHardeningFacts(&HostMetric{Host: "h", Raw: map[string]string{
		"auditd_cfg": "active\nauditctl -s\nenabled 0\n",
	}})
	if len(out) != 1 {
		t.Errorf("auditctl enabled=0 应产线，got %v", out)
	}
	// auditd active + enabled 2 → 合规。
	out = JudgeHardeningFacts(&HostMetric{Host: "h", Raw: map[string]string{
		"auditd_cfg": "active\nenabled 2\n",
	}})
	if len(out) != 0 {
		t.Errorf("auditd 正常不应产线，got %v", out)
	}
	// rsyslog active → 合规；都 inactive → 产线。
	out = JudgeHardeningFacts(&HostMetric{Host: "h", Raw: map[string]string{"syslog_cfg": "active\n"}})
	if len(out) != 0 {
		t.Errorf("rsyslog active 不应产线，got %v", out)
	}
	out = JudgeHardeningFacts(&HostMetric{Host: "h", Raw: map[string]string{"syslog_cfg": "inactive\nunknown\n"}})
	if len(out) != 1 || out[0].Metric != "syslog_cfg" {
		t.Errorf("双日志服务停用应产线，got %v", out)
	}
}

func TestJudgeHardeningFacts_Firewall(t *testing.T) {
	out := JudgeHardeningFacts(&HostMetric{Host: "h", Raw: map[string]string{
		"firewall_policy": "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n",
	}})
	if len(out) != 2 {
		t.Fatalf("INPUT/FORWARD ACCEPT 应产 2 条，got %v", out)
	}
	out = JudgeHardeningFacts(&HostMetric{Host: "h", Raw: map[string]string{
		"firewall_policy": "-P INPUT DROP\n-P FORWARD DROP\n",
	}})
	if len(out) != 0 {
		t.Errorf("默认 DROP 不应产线，got %v", out)
	}
}

// TestHardeningSignalPlan 复检探针计划：passwd_policy_weak 信号应覆盖
// 全部三个数据源（login_defs/pwquality/faillock_cfg）。
func TestHardeningSignalPlan(t *testing.T) {
	env := &Env{}
	metricIDs, factIDs := SignalProbePlan(env, "passwd_policy_weak")
	if len(metricIDs) != 0 {
		t.Errorf("passwd_policy_weak 无数值指标源，got %v", metricIDs)
	}
	have := map[string]bool{}
	for _, id := range factIDs {
		have[id] = true
	}
	for _, want := range []string{"login_defs", "pwquality", "faillock_cfg"} {
		if !have[want] {
			t.Errorf("复检计划缺 %s（factIDs=%v）", want, factIDs)
		}
	}
	// k8s 信号复检源。
	_, k8sFacts := SignalProbePlan(env, "k8s_sensitive_obj")
	found := false
	for _, id := range k8sFacts {
		if id == "k8s_secrets" {
			found = true
		}
	}
	if !found {
		t.Errorf("k8s_sensitive_obj 复检计划缺 k8s_secrets（factIDs=%v）", k8sFacts)
	}
}
