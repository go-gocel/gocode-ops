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
	Snapshot       = p.Snapshot
	HostMetric     = p.HostMetric
	CPUInfo        = p.CPUInfo
	Metric         = p.Metric
	Env            = e.Env
	RemoteExecutor = r.RemoteExecutor
	EngineConfig   = m.EngineConfig
)

const (
	FactTargeted = p.FactTargeted
)

var (
	SecurityFacts       = p.SecurityFacts
	StateProbes         = p.StateProbes
	BoundedProbe        = p.BoundedProbe
	Metrics             = p.Metrics
	DefaultEngineConfig = m.DefaultEngineConfig
)
