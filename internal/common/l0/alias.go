package l0

// alias.go — 领域类型别名（l0 包适配层）：引用低层包的短名。
// 仅保留本包实际使用的符号（未使用别名已清理）。

import (
	cl "github.com/go-gocel/gocode-ops/internal/common/collect"
	e "github.com/go-gocel/gocode-ops/internal/common/env"
	m "github.com/go-gocel/gocode-ops/internal/common/model"
	p "github.com/go-gocel/gocode-ops/internal/common/probe"
	r "github.com/go-gocel/gocode-ops/internal/common/remote"
	st "github.com/go-gocel/gocode-ops/internal/common/workspace"
)

type (
	Env            = e.Env
	EngineConfig   = m.EngineConfig
	Thresholds     = m.Thresholds
	Finding        = m.Finding
	Snapshot       = p.Snapshot
	HostMetric     = p.HostMetric
	Metric         = p.Metric
	Workspace      = st.Workspace
	BaselinePoint  = st.BaselinePoint
	RemoteExecutor = r.RemoteExecutor
)

const (
	SourceL0       = m.SourceL0
	SourceDeepDive = m.SourceDeepDive
)

var (
	NewFinding          = m.NewFinding
	DetectEnv           = e.DetectEnv
	Judge               = p.Judge
	StateProbeFragment  = p.StateProbeFragment
	Metrics             = p.Metrics
	NewWorkspace        = st.NewWorkspace
	RenderReport        = st.RenderReport
	RenderReportFinal   = st.RenderReportFinal
	ListInventory       = r.ListInventory
	AgentsMDPath        = m.AgentsMDPath
	DefaultEngineConfig = m.DefaultEngineConfig
	LoadDesired         = p.LoadDesired
	ComputeDeviations   = p.ComputeDeviations
	BuildMetricsCommand = cl.BuildMetricsCommand
)
