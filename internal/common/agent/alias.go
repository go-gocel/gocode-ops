package agent

// alias.go — 领域类型别名（agent 包适配层）：引用低层包的短名。
// 仅保留本包实际使用的符号（未使用别名已清理，避免虚假依赖边）。

import (
	au "github.com/go-gocel/gocode-ops/internal/common/audit"
	g "github.com/go-gocel/gocode-ops/internal/common/guard"
	m "github.com/go-gocel/gocode-ops/internal/common/model"
	r "github.com/go-gocel/gocode-ops/internal/common/remote"
)

type (
	// Operator is a package-level alias for model.Operator.
	// Operator 是 model.Operator 的适配层别名。
	Operator          = m.Operator
	// L0Snapshooter is a package-level alias for model.L0Snapshooter.
	// L0Snapshooter 是 model.L0Snapshooter 的适配层别名。
	L0Snapshooter     = m.L0Snapshooter
	// Policy is a package-level alias for guard.Policy.
	// Policy 是 guard.Policy 的适配层别名。
	Policy            = g.Policy
	// RiskyCommandGuard is a package-level alias for guard.RiskyCommandGuard.
	// RiskyCommandGuard 是 guard.RiskyCommandGuard 的适配层别名。
	RiskyCommandGuard = g.RiskyCommandGuard
	// AuditLog is a package-level alias for audit.AuditLog.
	// AuditLog 是 audit.AuditLog 的适配层别名。
	AuditLog          = au.AuditLog
	// RemoteExecutor is a package-level alias for remote.RemoteExecutor.
	// RemoteExecutor 是 remote.RemoteExecutor 的适配层别名。
	RemoteExecutor    = r.RemoteExecutor
	// Host is a package-level alias for remote.Host.
	// Host 是 remote.Host 的适配层别名。
	Host              = r.Host
	// ConnFact is a package-level alias for model.ConnFact.
	// ConnFact 是 model.ConnFact 的适配层别名。
	ConnFact          = m.ConnFact
)

const (
	// PolicyAuto is a package-level alias for guard.PolicyAuto.
	// PolicyAuto 是 guard.PolicyAuto 的适配层别名。
	PolicyAuto = g.PolicyAuto
)

var (
	// NewRiskyCommandGuard is a package-level alias for guard.NewRiskyCommandGuard.
	// NewRiskyCommandGuard 是 guard.NewRiskyCommandGuard 的适配层别名。
	NewRiskyCommandGuard = g.NewRiskyCommandGuard
	// NewAuditLog is a package-level alias for audit.NewAuditLog.
	// NewAuditLog 是 audit.NewAuditLog 的适配层别名。
	NewAuditLog          = au.NewAuditLog
	// ConfigDir is a package-level alias for model.ConfigDir.
	// ConfigDir 是 model.ConfigDir 的适配层别名。
	ConfigDir            = m.ConfigDir
	// RenderVars is a package-level alias for model.RenderVars.
	// RenderVars 是 model.RenderVars 的适配层别名。
	RenderVars           = m.RenderVars
	// HasEffectiveContent is a package-level alias for model.HasEffectiveContent.
	// HasEffectiveContent 是 model.HasEffectiveContent 的适配层别名。
	HasEffectiveContent  = m.HasEffectiveContent
	// IsInitialized is a package-level alias for model.IsInitialized.
	// IsInitialized 是 model.IsInitialized 的适配层别名。
	IsInitialized        = m.IsInitialized
)
