package collect

// alias.go — 领域类型别名（collect 包适配层）：引用低层包的短名。
// 仅保留本包实际使用的符号（未使用别名已清理）。

import (
	e "github.com/go-gocel/gocode-ops/internal/common/env"
	m "github.com/go-gocel/gocode-ops/internal/common/model"
	p "github.com/go-gocel/gocode-ops/internal/common/probe"
	r "github.com/go-gocel/gocode-ops/internal/common/remote"
)

type (
	// Snapshot is a package-level alias for probe.Snapshot.
	// Snapshot 是 probe.Snapshot 的适配层别名。
	Snapshot       = p.Snapshot
	// HostMetric is a package-level alias for probe.HostMetric.
	// HostMetric 是 probe.HostMetric 的适配层别名。
	HostMetric     = p.HostMetric
	// CPUInfo is a package-level alias for probe.CPUInfo.
	// CPUInfo 是 probe.CPUInfo 的适配层别名。
	CPUInfo        = p.CPUInfo
	// Metric is a package-level alias for probe.Metric.
	// Metric 是 probe.Metric 的适配层别名。
	Metric         = p.Metric
	// Env is a package-level alias for env.Env.
	// Env 是 env.Env 的适配层别名。
	Env            = e.Env
	// RemoteExecutor is a package-level alias for remote.RemoteExecutor.
	// RemoteExecutor 是 remote.RemoteExecutor 的适配层别名。
	RemoteExecutor = r.RemoteExecutor
	// EngineConfig is a package-level alias for model.EngineConfig.
	// EngineConfig 是 model.EngineConfig 的适配层别名。
	EngineConfig   = m.EngineConfig
)

const (
	// FactTargeted is a package-level alias for probe.FactTargeted.
	// FactTargeted 是 probe.FactTargeted 的适配层别名。
	FactTargeted = p.FactTargeted
)

var (
	// SecurityFacts is a package-level alias for probe.SecurityFacts.
	// SecurityFacts 是 probe.SecurityFacts 的适配层别名。
	SecurityFacts       = p.SecurityFacts
	// StateProbes is a package-level alias for probe.StateProbes.
	// StateProbes 是 probe.StateProbes 的适配层别名。
	StateProbes         = p.StateProbes
	// BoundedProbe is a package-level alias for probe.BoundedProbe.
	// BoundedProbe 是 probe.BoundedProbe 的适配层别名。
	BoundedProbe        = p.BoundedProbe
	// Metrics is a package-level alias for probe.Metrics.
	// Metrics 是 probe.Metrics 的适配层别名。
	Metrics             = p.Metrics
	// DefaultEngineConfig is a package-level alias for model.DefaultEngineConfig.
	// DefaultEngineConfig 是 model.DefaultEngineConfig 的适配层别名。
	DefaultEngineConfig = m.DefaultEngineConfig
)
