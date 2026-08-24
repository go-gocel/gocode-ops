package remediate

// dispose.go — 处置去向构造：变更分级/工单/验证证据/达限升级。

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-gocel/gocode-ops/internal/common/collect"
	"github.com/go-gocel/gocode-ops/internal/common/model"
)

func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// ── 处置机制（docs/design-v2.md §三）：三态去向契约的执行侧实现 ──────

// DisposeClassFor 按 finding 信号给处置去向定变更分级（最小破坏序的
// 校验依据；未知信号默认配置级）。
//
// 认证面（ChangeAuth）覆盖所有"决定引擎能否再次登录"的处置：ssh 配置、
// PAM/认证链、密码/账户策略（passwd/chage/faillock/锁定）——这类处置
// 执行后引擎必须做自通道校验（新连接探测），失败强制回滚并转人工
// 工单。历史事故：passwd_policy_weak 未命中 "password"（passwd 与
// password 是不同子串）落 ChangeConfig，chage -M 90 对 lastchg=1969
// 的账户立即置密码过期，自通道校验未触发，引擎被自己的处置锁在门外
// 且标记"已处置"。
func DisposeClassFor(f *model.Finding) model.ChangeClass {
	s := strings.ToLower(f.Signal)
	switch {
	case strings.Contains(s, "ssh"), strings.Contains(s, "auth"), strings.Contains(s, "pam"),
		strings.Contains(s, "password"), strings.Contains(s, "passwd"), strings.Contains(s, "faillock"),
		strings.Contains(s, "credential"), strings.Contains(s, "login"), strings.Contains(s, "lock"),
		strings.Contains(s, "account"), strings.Contains(s, "uid0"):
		return model.ChangeAuth
	case strings.Contains(s, "listen"), strings.Contains(s, "exposure"), strings.Contains(s, "firewall"),
		strings.Contains(s, "network"), strings.Contains(s, "port"), strings.Contains(s, "identity"):
		return model.ChangeNetwork
	case strings.Contains(s, "svc"), strings.Contains(s, "service"), strings.Contains(s, "process"),
		strings.Contains(s, "minio"), strings.Contains(s, "zookeeper"), strings.Contains(s, "redis"),
		strings.Contains(s, "tomcat"), strings.Contains(s, "nginx"), strings.Contains(s, "oracle"):
		return model.ChangeService
	default:
		return model.ChangeConfig
	}
}

// WorkOrderFor 由 finding 构造人工工单（证据包：根因/置信度/影响面/
// 建议命令/步骤/验证/回滚——处置机制 manual_workorder 的产物）。
func WorkOrderFor(f *model.Finding, why string, cmds []string) *model.WorkOrder {
	wo := &model.WorkOrder{
		Summary:           why + "。" + f.Signal + "：" + collect.TruncateStr(f.Desc, 200),
		Impact:            fmt.Sprintf("%s（置信度 %.0f%%）", collect.TruncateStr(f.RootCause, 200), f.Confidence*100),
		SuggestedCommands: cmds,
		Steps: []string{
			"复核上方证据区的现场证据，确认问题是否仍存在（处置前先复检）",
			"评估影响面（业务依赖/唯一通道/数据面）后，执行建议命令或人工方案",
			"变更前备份原配置；按最小破坏序执行（配置修正 → 热生效 → 优雅重启 → 强制手段为最后手段）",
			"处置后按验证步骤验证生效，验证失败即回滚",
		},
		VerificationSteps: []string{
			"按业务协议验证处置生效（ssh 新会话实际认证 / 服务功能读写探针 / 新会话可达+业务端口探测）；pgrep+端口检查不算验证",
			"复检原线索是否消失（引擎确定性复检口径）",
		},
		Rollback: "变更前备份原配置；验证失败即回滚",
	}
	if len(f.SuggestedFix) > 0 {
		wo.SuggestedCommands = append(wo.SuggestedCommands, f.SuggestedFix...)
	}
	return wo
}

// VerifiedEvidence 由处置动作与方案构造功能验证证据（✓ 的绑定依据）：
// 每个验证通过的动作对应一条证据——verify 命令 + 恢复判据 + 实际输出。
func VerifiedEvidence(p *Plan, acts []model.Action) []model.VerificationEvidence {
	byName := make(map[string]*PlanAction, len(p.Actions))
	for i := range p.Actions {
		byName[p.Actions[i].Name] = &p.Actions[i]
	}
	var ev []model.VerificationEvidence
	for i := range acts {
		a := &acts[i]
		if a.Advised || a.Error != "" || !a.Verified {
			continue
		}
		pa := byName[a.Name]
		if pa == nil {
			continue
		}
		out := a.VerifyOut
		if a.Prechecked {
			out = "（执行前预检：恢复判据已满足，前次处置已生效）"
		}
		ev = append(ev, model.VerificationEvidence{
			VerifyCmd: pa.Verify,
			CheckUp:   pa.CheckUp,
			Output:    out,
			At:        a.At,
		})
	}
	return ev
}

// EnsureWorkOrderAtLimit 处置尝试达上限仍未处置时，保证 finding 有三态
// 去向（自动处置失败/无方案 → 升级人工工单，不静默、不降级）。已在途
// 有去向（工单/接受风险）或已修复则不覆盖。
func EnsureWorkOrderAtLimit(f *model.Finding, why string) {
	if f.Remediated || f.RespondTried < MaxTries || f.Disposition != nil {
		return
	}
	f.Disposition = model.NewWorkOrderDisposition(DisposeClassFor(f), WorkOrderFor(f, why, nil))
	f.RemediationNote += "；已按处置机制生成人工工单（处置去向: manual_workorder）"
}
