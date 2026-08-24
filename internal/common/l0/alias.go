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
	// Env is an alias for env.Env.
	// Env 是 env.Env 的适配层别名。
	Env            = e.Env
	// EngineConfig is an alias for model.EngineConfig.
	// EngineConfig 是 model.EngineConfig 的适配层别名。
	EngineConfig   = m.EngineConfig
	// Thresholds is an alias for model.Thresholds.
	// Thresholds 是 model.Thresholds 的适配层别名。
	Thresholds     = m.Thresholds
	// Finding is an alias for model.Finding.
	// Finding 是 model.Finding 的适配层别名。
	Finding        = m.Finding
	// Snapshot is an alias for probe.Snapshot.
	// Snapshot 是 probe.Snapshot 的适配层别名。
	Snapshot       = p.Snapshot
	// HostMetric is an alias for probe.HostMetric.
	// HostMetric 是 probe.HostMetric 的适配层别名。
	HostMetric     = p.HostMetric
	// Metric is an alias for probe.Metric.
	// Metric 是 probe.Metric 的适配层别名。
	Metric         = p.Metric
	// Workspace is an alias for workspace.Workspace.
	// Workspace 是 workspace.Workspace 的适配层别名。
	Workspace      = st.Workspace
	// BaselinePoint is an alias for workspace.BaselinePoint.
	// BaselinePoint 是 workspace.BaselinePoint 的适配层别名。
	BaselinePoint  = st.BaselinePoint
	// RemoteExecutor is an alias for remote.RemoteExecutor.
	// RemoteExecutor 是 remote.RemoteExecutor 的适配层别名。
	RemoteExecutor = r.RemoteExecutor
)

const (
	// SourceL0 is an alias for model.SourceL0.
	// SourceL0 是 model.SourceL0 的适配层别名。
	SourceL0       = m.SourceL0
	// SourceDeepDive is an alias for model.SourceDeepDive.
	// SourceDeepDive 是 model.SourceDeepDive 的适配层别名。
	SourceDeepDive = m.SourceDeepDive
)

var (
	// NewFinding is an alias for model.NewFinding.
	// NewFinding 是 model.NewFinding 的适配层别名。
	NewFinding          = m.NewFinding
	// DetectEnv is an alias for env.DetectEnv.
	// DetectEnv 是 env.DetectEnv 的适配层别名。
	DetectEnv           = e.DetectEnv
	// Judge is an alias for probe.Judge.
	// Judge 是 probe.Judge 的适配层别名。
	Judge               = p.Judge
	// StateProbeFragment is an alias for probe.StateProbeFragment.
	// StateProbeFragment 是 probe.StateProbeFragment 的适配层别名。
	StateProbeFragment  = p.StateProbeFragment
	// Metrics is an alias for probe.Metrics.
	// Metrics 是 probe.Metrics 的适配层别名。
	Metrics             = p.Metrics
	// NewWorkspace is an alias for workspace.NewWorkspace.
	// NewWorkspace 是 workspace.NewWorkspace 的适配层别名。
	NewWorkspace        = st.NewWorkspace
	// RenderReport is an alias for workspace.RenderReport.
	// RenderReport 是 workspace.RenderReport 的适配层别名。
	RenderReport        = st.RenderReport
	// RenderReportFinal is an alias for workspace.RenderReportFinal.
	// RenderReportFinal 是 workspace.RenderReportFinal 的适配层别名。
	RenderReportFinal   = st.RenderReportFinal
	// ListInventory is an alias for remote.ListInventory.
	// ListInventory 是 remote.ListInventory 的适配层别名。
	ListInventory       = r.ListInventory
	// AgentsMDPath is an alias for model.AgentsMDPath.
	// AgentsMDPath 是 model.AgentsMDPath 的适配层别名。
	AgentsMDPath        = m.AgentsMDPath
	// DefaultEngineConfig is an alias for model.DefaultEngineConfig.
	// DefaultEngineConfig 是 model.DefaultEngineConfig 的适配层别名。
	DefaultEngineConfig = m.DefaultEngineConfig
	// LoadDesired is an alias for probe.LoadDesired.
	// LoadDesired 是 probe.LoadDesired 的适配层别名。
	LoadDesired         = p.LoadDesired
	// ComputeDeviations is an alias for probe.ComputeDeviations.
	// ComputeDeviations 是 probe.ComputeDeviations 的适配层别名。
	ComputeDeviations   = p.ComputeDeviations
	// BuildMetricsCommand is an alias for collect.BuildMetricsCommand.
	// BuildMetricsCommand 是 collect.BuildMetricsCommand 的适配层别名。
	BuildMetricsCommand = cl.BuildMetricsCommand
)
