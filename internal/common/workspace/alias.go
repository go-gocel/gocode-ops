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
	Finding              = m.Finding
	EnvInfo              = m.EnvInfo
	Phase                = m.Phase
	Action               = m.Action
	Disposition          = m.Disposition
	WorkOrder            = m.WorkOrder
	VerificationEvidence = m.VerificationEvidence
)

const (
	FindingPending   = m.FindingPending
	FindingConfirmed = m.FindingConfirmed
	FindingDismissed = m.FindingDismissed
	PhaseRescan      = m.PhaseRescan
	SourceL0         = m.SourceL0

	DispositionVerifiedFixed   = m.DispositionVerifiedFixed
	DispositionManualWorkOrder = m.DispositionManualWorkOrder
	DispositionAcceptedRisk    = m.DispositionAcceptedRisk
	ChangeAuth                 = m.ChangeAuth
)

var (
	NewFinding                 = m.NewFinding
	DispositionInvariants      = m.DispositionInvariants
	NewVerifiedDisposition     = m.NewVerifiedDisposition
	NewWorkOrderDisposition    = m.NewWorkOrderDisposition
	NewAcceptedRiskDisposition = m.NewAcceptedRiskDisposition
)
