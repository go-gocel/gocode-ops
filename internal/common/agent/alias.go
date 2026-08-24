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
	Operator          = m.Operator
	L0Snapshooter     = m.L0Snapshooter
	Policy            = g.Policy
	RiskyCommandGuard = g.RiskyCommandGuard
	AuditLog          = au.AuditLog
	RemoteExecutor    = r.RemoteExecutor
	Host              = r.Host
	ConnFact          = m.ConnFact
)

const (
	PolicyAuto = g.PolicyAuto
)

var (
	NewRiskyCommandGuard = g.NewRiskyCommandGuard
	NewAuditLog          = au.NewAuditLog
	ConfigDir            = m.ConfigDir
	RenderVars           = m.RenderVars
	HasEffectiveContent  = m.HasEffectiveContent
	IsInitialized        = m.IsInitialized
)
