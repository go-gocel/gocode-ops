package tools

// alias.go — 领域类型别名（tools 包适配层）：引用低层包的短名。
// 仅保留本包实际使用的符号（未使用别名已清理）。

import (
	e "github.com/go-gocel/gocode-ops/internal/common/env"
	g "github.com/go-gocel/gocode-ops/internal/common/guard"
	mm "github.com/go-gocel/gocode-ops/internal/common/memory"
	m "github.com/go-gocel/gocode-ops/internal/common/model"
	p "github.com/go-gocel/gocode-ops/internal/common/probe"
	r "github.com/go-gocel/gocode-ops/internal/common/remote"
)

type (
	Operator          = m.Operator
	L0Snapshooter     = m.L0Snapshooter
	RiskyCommandGuard = g.RiskyCommandGuard
	Memory            = mm.Memory
	DesiredState      = p.DesiredState
	HostDesire        = p.HostDesire
	RemoteExecutor    = r.RemoteExecutor
	RemoteProgress    = r.RemoteProgress
	RemoteCopier      = r.RemoteCopier
	Host              = r.Host
	Snapshot          = p.Snapshot
	HostMetric        = p.HostMetric
	Metric            = p.Metric
	Env               = e.Env
)

const (
	PolicyAsk  = g.PolicyAsk
	PolicyDeny = g.PolicyDeny
)

var (
	NewRiskyCommandGuard = g.NewRiskyCommandGuard
	LoadDossier          = mm.LoadDossier
	DetectEnv            = e.DetectEnv
	LocalShell           = e.LocalShell
	WithRemoteProgress   = r.WithRemoteProgress
	RemoteProgressSink   = r.RemoteProgressSink
	SecurityFacts        = p.SecurityFacts
	SecurityMetrics      = p.SecurityMetrics
	Metrics              = p.Metrics
	LoadDesired          = p.LoadDesired
	SaveDesired          = p.SaveDesired
)
