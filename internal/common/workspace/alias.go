package workspace

// alias.go — 领域模型别名（workspace 包适配层）。
//
// workspace 包（工作区/报告）引用的领域类型来自 common/model；
// 本文件为包内代码保留短名（Finding/EnvInfo/…）。仅保留本包实际
// 使用的符号（未使用别名已清理）。

import (
	m "github.com/go-gocel/gocode-ops/internal/common/model"
)

type (
	// Finding is an adapter alias for model.Finding.
	// Finding 是 model.Finding 的适配层别名。
	Finding              = m.Finding
	// EnvInfo is an adapter alias for model.EnvInfo.
	// EnvInfo 是 model.EnvInfo 的适配层别名。
	EnvInfo              = m.EnvInfo
	// Phase is an adapter alias for model.Phase.
	// Phase 是 model.Phase 的适配层别名。
	Phase                = m.Phase
	// Action is an adapter alias for model.Action.
	// Action 是 model.Action 的适配层别名。
	Action               = m.Action
	// Disposition is an adapter alias for model.Disposition.
	// Disposition 是 model.Disposition 的适配层别名。
	Disposition          = m.Disposition
	// WorkOrder is an adapter alias for model.WorkOrder.
	// WorkOrder 是 model.WorkOrder 的适配层别名。
	WorkOrder            = m.WorkOrder
	// VerificationEvidence is an adapter alias for model.VerificationEvidence.
	// VerificationEvidence 是 model.VerificationEvidence 的适配层别名。
	VerificationEvidence = m.VerificationEvidence
)

const (
	// FindingPending is an adapter alias for model.FindingPending.
	// FindingPending 是 model.FindingPending 的适配层别名。
	FindingPending   = m.FindingPending
	// FindingConfirmed is an adapter alias for model.FindingConfirmed.
	// FindingConfirmed 是 model.FindingConfirmed 的适配层别名。
	FindingConfirmed = m.FindingConfirmed
	// FindingDismissed is an adapter alias for model.FindingDismissed.
	// FindingDismissed 是 model.FindingDismissed 的适配层别名。
	FindingDismissed = m.FindingDismissed
	// PhaseRescan is an adapter alias for model.PhaseRescan.
	// PhaseRescan 是 model.PhaseRescan 的适配层别名。
	PhaseRescan      = m.PhaseRescan
	// SourceL0 is an adapter alias for model.SourceL0.
	// SourceL0 是 model.SourceL0 的适配层别名。
	SourceL0         = m.SourceL0

	// DispositionVerifiedFixed is an adapter alias for model.DispositionVerifiedFixed.
	// DispositionVerifiedFixed 是 model.DispositionVerifiedFixed 的适配层别名。
	DispositionVerifiedFixed   = m.DispositionVerifiedFixed
	// DispositionManualWorkOrder is an adapter alias for model.DispositionManualWorkOrder.
	// DispositionManualWorkOrder 是 model.DispositionManualWorkOrder 的适配层别名。
	DispositionManualWorkOrder = m.DispositionManualWorkOrder
	// DispositionAcceptedRisk is an adapter alias for model.DispositionAcceptedRisk.
	// DispositionAcceptedRisk 是 model.DispositionAcceptedRisk 的适配层别名。
	DispositionAcceptedRisk    = m.DispositionAcceptedRisk
	// ChangeAuth is an adapter alias for model.ChangeAuth.
	// ChangeAuth 是 model.ChangeAuth 的适配层别名。
	ChangeAuth                 = m.ChangeAuth
)

var (
	// NewFinding is an adapter alias for model.NewFinding.
	// NewFinding 是 model.NewFinding 的适配层别名。
	NewFinding                 = m.NewFinding
	// DispositionInvariants is an adapter alias for model.DispositionInvariants.
	// DispositionInvariants 是 model.DispositionInvariants 的适配层别名。
	DispositionInvariants      = m.DispositionInvariants
	// NewVerifiedDisposition is an adapter alias for model.NewVerifiedDisposition.
	// NewVerifiedDisposition 是 model.NewVerifiedDisposition 的适配层别名。
	NewVerifiedDisposition     = m.NewVerifiedDisposition
	// NewWorkOrderDisposition is an adapter alias for model.NewWorkOrderDisposition.
	// NewWorkOrderDisposition 是 model.NewWorkOrderDisposition 的适配层别名。
	NewWorkOrderDisposition    = m.NewWorkOrderDisposition
	// NewAcceptedRiskDisposition is an adapter alias for model.NewAcceptedRiskDisposition.
	// NewAcceptedRiskDisposition 是 model.NewAcceptedRiskDisposition 的适配层别名。
	NewAcceptedRiskDisposition = m.NewAcceptedRiskDisposition
)
