package probe

// alias.go — 领域类型别名（probe 包适配层）：引用 model/env 的短名。
// 仅保留本包实际使用的符号（未使用别名已清理）。

import (
	e "github.com/go-gocel/gocode-ops/internal/common/env"
	m "github.com/go-gocel/gocode-ops/internal/common/model"
)

type (
	Env        = e.Env
	Thresholds = m.Thresholds
	Severity   = m.Severity
	Finding    = m.Finding
)

const (
	SevWarn        = m.SevWarn
	SevCrit        = m.SevCrit
	SourceL0       = m.SourceL0
	FindingPending = m.FindingPending
)

var (
	NewFinding        = m.NewFinding
	DefaultThresholds = m.DefaultThresholds
)
