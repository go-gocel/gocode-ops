package probe

// alias.go — 领域类型别名（probe 包适配层）：引用 model/env 的短名。
// 仅保留本包实际使用的符号（未使用别名已清理）。

import (
	e "github.com/go-gocel/gocode-ops/internal/common/env"
	m "github.com/go-gocel/gocode-ops/internal/common/model"
)

type (
	// Env is an adapter alias for env.Env.
	// Env 是 env.Env 的适配层别名。
	Env        = e.Env
	// Thresholds is an adapter alias for model.Thresholds.
	// Thresholds 是 model.Thresholds 的适配层别名。
	Thresholds = m.Thresholds
	// Severity is an adapter alias for model.Severity.
	// Severity 是 model.Severity 的适配层别名。
	Severity   = m.Severity
	// Finding is an adapter alias for model.Finding.
	// Finding 是 model.Finding 的适配层别名。
	Finding    = m.Finding
)

const (
	// SevWarn is an adapter alias for model.SevWarn.
	// SevWarn 是 model.SevWarn 的适配层别名。
	SevWarn        = m.SevWarn
	// SevCrit is an adapter alias for model.SevCrit.
	// SevCrit 是 model.SevCrit 的适配层别名。
	SevCrit        = m.SevCrit
	// SourceL0 is an adapter alias for model.SourceL0.
	// SourceL0 是 model.SourceL0 的适配层别名。
	SourceL0       = m.SourceL0
	// FindingPending is an adapter alias for model.FindingPending.
	// FindingPending 是 model.FindingPending 的适配层别名。
	FindingPending = m.FindingPending
)

var (
	// NewFinding is an adapter alias for model.NewFinding.
	// NewFinding 是 model.NewFinding 的适配层别名。
	NewFinding        = m.NewFinding
	// DefaultThresholds is an adapter alias for model.DefaultThresholds.
	// DefaultThresholds 是 model.DefaultThresholds 的适配层别名。
	DefaultThresholds = m.DefaultThresholds
)
