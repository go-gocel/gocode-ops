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
	// Operator is the adapter alias for model.Operator.
	// Operator 是 model.Operator 的适配层别名。
	Operator          = m.Operator
	// L0Snapshooter is the adapter alias for model.L0Snapshooter.
	// L0Snapshooter 是 model.L0Snapshooter 的适配层别名。
	L0Snapshooter     = m.L0Snapshooter
	// RiskyCommandGuard is the adapter alias for guard.RiskyCommandGuard.
	// RiskyCommandGuard 是 guard.RiskyCommandGuard 的适配层别名。
	RiskyCommandGuard = g.RiskyCommandGuard
	// Memory is the adapter alias for memory.Memory.
	// Memory 是 memory.Memory 的适配层别名。
	Memory            = mm.Memory
	// DesiredState is the adapter alias for probe.DesiredState.
	// DesiredState 是 probe.DesiredState 的适配层别名。
	DesiredState      = p.DesiredState
	// HostDesire is the adapter alias for probe.HostDesire.
	// HostDesire 是 probe.HostDesire 的适配层别名。
	HostDesire        = p.HostDesire
	// RemoteExecutor is the adapter alias for remote.RemoteExecutor.
	// RemoteExecutor 是 remote.RemoteExecutor 的适配层别名。
	RemoteExecutor    = r.RemoteExecutor
	// RemoteProgress is the adapter alias for remote.RemoteProgress.
	// RemoteProgress 是 remote.RemoteProgress 的适配层别名。
	RemoteProgress    = r.RemoteProgress
	// RemoteCopier is the adapter alias for remote.RemoteCopier.
	// RemoteCopier 是 remote.RemoteCopier 的适配层别名。
	RemoteCopier      = r.RemoteCopier
	// Host is the adapter alias for remote.Host.
	// Host 是 remote.Host 的适配层别名。
	Host              = r.Host
	// Snapshot is the adapter alias for probe.Snapshot.
	// Snapshot 是 probe.Snapshot 的适配层别名。
	Snapshot          = p.Snapshot
	// HostMetric is the adapter alias for probe.HostMetric.
	// HostMetric 是 probe.HostMetric 的适配层别名。
	HostMetric        = p.HostMetric
	// Metric is the adapter alias for probe.Metric.
	// Metric 是 probe.Metric 的适配层别名。
	Metric            = p.Metric
	// Env is the adapter alias for env.Env.
	// Env 是 env.Env 的适配层别名。
	Env               = e.Env
)

const (
	// PolicyAsk is the adapter alias for guard.PolicyAsk.
	// PolicyAsk 是 guard.PolicyAsk 的适配层别名。
	PolicyAsk  = g.PolicyAsk
	// PolicyDeny is the adapter alias for guard.PolicyDeny.
	// PolicyDeny 是 guard.PolicyDeny 的适配层别名。
	PolicyDeny = g.PolicyDeny
)

var (
	// NewRiskyCommandGuard is the adapter alias for guard.NewRiskyCommandGuard.
	// NewRiskyCommandGuard 是 guard.NewRiskyCommandGuard 的适配层别名。
	NewRiskyCommandGuard = g.NewRiskyCommandGuard
	// LoadDossier is the adapter alias for memory.LoadDossier.
	// LoadDossier 是 memory.LoadDossier 的适配层别名。
	LoadDossier          = mm.LoadDossier
	// DetectEnv is the adapter alias for env.DetectEnv.
	// DetectEnv 是 env.DetectEnv 的适配层别名。
	DetectEnv            = e.DetectEnv
	// LocalShell is the adapter alias for env.LocalShell.
	// LocalShell 是 env.LocalShell 的适配层别名。
	LocalShell           = e.LocalShell
	// WithRemoteProgress is the adapter alias for remote.WithRemoteProgress.
	// WithRemoteProgress 是 remote.WithRemoteProgress 的适配层别名。
	WithRemoteProgress   = r.WithRemoteProgress
	// RemoteProgressSink is the adapter alias for remote.RemoteProgressSink.
	// RemoteProgressSink 是 remote.RemoteProgressSink 的适配层别名。
	RemoteProgressSink   = r.RemoteProgressSink
	// SecurityFacts is the adapter alias for probe.SecurityFacts.
	// SecurityFacts 是 probe.SecurityFacts 的适配层别名。
	SecurityFacts        = p.SecurityFacts
	// SecurityMetrics is the adapter alias for probe.SecurityMetrics.
	// SecurityMetrics 是 probe.SecurityMetrics 的适配层别名。
	SecurityMetrics      = p.SecurityMetrics
	// Metrics is the adapter alias for probe.Metrics.
	// Metrics 是 probe.Metrics 的适配层别名。
	Metrics              = p.Metrics
	// LoadDesired is the adapter alias for probe.LoadDesired.
	// LoadDesired 是 probe.LoadDesired 的适配层别名。
	LoadDesired          = p.LoadDesired
	// SaveDesired is the adapter alias for probe.SaveDesired.
	// SaveDesired 是 probe.SaveDesired 的适配层别名。
	SaveDesired          = p.SaveDesired
)
