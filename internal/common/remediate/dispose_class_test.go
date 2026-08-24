package remediate

import (
	"testing"

	"github.com/go-gocel/gocode-ops/internal/common/model"
)

// DisposeClassFor 变更分级：认证面（ChangeAuth）覆盖所有"决定引擎能否
// 再次登录"的处置——历史事故：passwd_policy_weak 未命中 "password"
// 子串落 ChangeConfig，chage 处置锁死引擎通道且未触发自通道校验。
func TestDisposeClassFor_ChangeAuthCoversAuthAffectingSignals(t *testing.T) {
	cases := []struct {
		signal string
		want   model.ChangeClass
	}{
		// 认证面：任何影响登录能力的信号必须 ChangeAuth（自通道校验兜底）。
		{"passwd_policy_weak", model.ChangeAuth},
		{"faillock_cfg", model.ChangeAuth},
		{"ssh_root_login", model.ChangeAuth},
		{"ssh_chain", model.ChangeAuth},
		{"auth_chain", model.ChangeAuth},
		{"pam_permit", model.ChangeAuth},
		{"empty_passwords", model.ChangeAuth},
		{"abnormal_uid0", model.ChangeAuth},
		{"suspicious_account", model.ChangeAuth},
		{"account_lock", model.ChangeAuth},
		{"password_expired", model.ChangeAuth},
		{"credential_leak", model.ChangeAuth},
		{"login_trail", model.ChangeAuth},
		// 网络面。
		{"unattributed_listen", model.ChangeNetwork},
		{"exposed_listen", model.ChangeNetwork},
		{"firewall_permissive", model.ChangeNetwork},
		{"port_scan", model.ChangeNetwork},
		// 服务面。
		{"svc_failed", model.ChangeService},
		{"nginx_crash", model.ChangeService},
		// 配置面（默认）。
		{"umask_weak", model.ChangeConfig},
		{"time_sync_off", model.ChangeConfig},
		{"auditd_off", model.ChangeConfig},
		{"syslog_off", model.ChangeConfig},
		{"lvm_lv_full", model.ChangeConfig},
		{"k8s_pod_abnormal", model.ChangeConfig},
		{"disk_high", model.ChangeConfig},
	}
	for _, c := range cases {
		f := &model.Finding{Signal: c.signal}
		if got := DisposeClassFor(f); got != c.want {
			t.Errorf("DisposeClassFor(%q) = %s, want %s", c.signal, got, c.want)
		}
	}
}
