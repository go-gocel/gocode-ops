package autopilot

// engine_respond.go — 处置阶段：respond/respondBatchApp（目标匹配→契约校验→执行）。

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-gocel/gocode-ops/internal/common/collect"
	"github.com/go-gocel/gocode-ops/internal/common/model"
	"github.com/go-gocel/gocode-ops/internal/common/remediate"
	"github.com/go-gocel/gocode-ops/internal/common/workspace"
)

// businessPorts 采集指定主机的业务端口清单（business_ports 探针：
// 监听中且非管理面进程的端口）。失败/无数据返回 nil（调用方按
// "无数据不误判"处理）。
func (e *Engine) businessPorts(ctx context.Context, host string) map[string]string {
	snap, err := e.core.CollectProbes(ctx, nil, []string{"business_ports"})
	if err != nil {
		return nil
	}
	for i := range snap.Hosts {
		if snap.Hosts[i].Host == host {
			return remediate.ParseBusinessPorts(snap.Hosts[i].Raw["business_ports"])
		}
	}
	return nil
}

// batchNeedsBusinessGuard 批内是否存在网络/服务类处置（业务面校验
// 的适用范围：等保收窄/服务处置才可能锁死业务；认证/配置类不涉及）。
func batchNeedsBusinessGuard(targets []*Finding) bool {
	for _, f := range targets {
		cls := remediate.DisposeClassFor(f)
		if cls == model.ChangeNetwork || cls == model.ChangeService {
			return true
		}
	}
	return false
}

// authTighteningSignal 该 signal 的处置是否**必然**要求收紧引擎的认证
// 通道（root 登录面）：ssh_root_login（root 密码直登）的修复必然收紧
// root 认证——引擎以 root 连接时任何收紧都会被守卫通道保护拒绝
// （结构必拒）。其余认证面信号（ssh 弱化项/faillock/账户锁定/PAM）
// 的处置**可能不触碰通道**（MaxAuthTries 加固、faillock deny 配置、
// 锁定非当前账户、先配密钥再收紧等均放行）——是否被拒由守卫实际
// 裁决，不预判（守住通道即可，不能全拒绝、也不能绝对）。
func authTighteningSignal(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.Contains(s, "root_ssh") || strings.Contains(s, "root_login")
}

// authBlockHint 认证面故障的通道约束预判（respond 提示层，省重试轮）：
// 仅对"处置必然收紧引擎自身认证通道"的故障（authTighteningSignal）且
// 引擎以 root 连接时标注——root 连接下收紧 root 认证必被守卫通道保护
// 拒绝，提示模型第一次就输出人工建议（actions 留空 → 工单）或仅保留
// 当前通道的加固。返回 findingID → 提示文本；无约束返回空。
func authBlockHint(e *Engine, targets []*Finding) map[string]string {
	hints := map[string]string{}
	if e.remote == nil {
		return hints
	}
	cf, ok := e.remote.(interface {
		ConnFacts([]string) map[string]model.ConnFact
	})
	if !ok {
		return hints
	}
	aliases := make([]string, 0, len(targets))
	for _, f := range targets {
		aliases = append(aliases, f.Host)
	}
	facts := cf.ConnFacts(aliases)
	for _, f := range targets {
		fact, ok := facts[f.Host]
		if !ok || fact.User != "root" {
			continue
		}
		if !authTighteningSignal(f.Signal) {
			continue
		}
		hints[f.ID] = "引擎以 root 连接本主机，本故障的处置必然收紧 root 认证（PermitRootLogin/禁密码/锁定 root），会被安全守卫的通道保护机械拒绝（自断通道）——请输出人工建议（actions 留空，引擎将生成工单），或仅提出不收紧 root 认证通道的加固（如 MaxAuthTries/登录告警等非认证收紧项）。"
	}
	return hints
}

// allAdvised 全部动作均为"被守卫拒绝转建议"（未执行）。空列表返回
// false（无动作被拒，不触发"全部被拒"升级）。
func allAdvised(acts []model.Action) bool {
	if len(acts) == 0 {
		return false
	}
	for _, a := range acts {
		if !a.Advised {
			return false
		}
	}
	return true
}

// structurallyBlocked 拒绝是否结构性必拒：AdviseReason 为守卫的通道
// 保护/硬性禁止文案（self-impact 面与 hard-block）——换方案也必拒。
// pkill 机械改写失败类拒绝（可修正为 [p]attern 形式）不在此列。
func structurallyBlocked(acts []model.Action) bool {
	for _, a := range acts {
		if a.AdvisedReason == "" {
			return false
		}
		r := a.AdvisedReason
		if !strings.Contains(r, "命令风险审查拒绝") &&
			!strings.Contains(r, "硬性禁止") &&
			!strings.Contains(r, "永远不允许执行") {
			return false
		}
	}
	return true
}

// respond 对已确认且未处置的故障分批生成处置方案并执行。
// 分批而非一次全量：批量上下文过长时模型会把故障与方案搞混
// （run13 实测 oversized_file 的处置被写成删 crontab）——
// 每批 4 个故障，聚焦度与调用次数平衡。
func (e *Engine) respond(ctx context.Context) {
	if e.app == nil {
		return
	}
	var targets []*Finding
	for _, f := range e.ws().Confirmed() {
		// 已转人工工单的项是闭环终态（P0 修复）：不再回灌处置——
		// chaos-r1 实测工单项每轮被重新处置/重新生成工单（respTried 60），
		// 纯浪费且无状态变化。
		if f.Remediated || workOrdered(f) || f.RespondTried >= maxRespondTries {
			continue
		}
		targets = append(targets, f)
	}
	if len(targets) == 0 {
		return
	}
	ids := make([]string, 0, len(targets))
	for _, f := range targets {
		ids = append(ids, f.ID)
	}
	e.logf("Respond 开始：%d 个待处置故障：%s", len(targets), strings.Join(ids, ", "))
	started := time.Now()
	// 批次并行（worker 池）：各批处置不同故障（批次间零依赖）。
	// respondBatch 内部容错（失败记录 RemediationNote），批恒"完成"。
	batchList := make([][]*Finding, 0, (len(targets)+respondBatchSize-1)/respondBatchSize)
	for start := 0; start < len(targets); start += respondBatchSize {
		end := start + respondBatchSize
		if end > len(targets) {
			end = len(targets)
		}
		batchList = append(batchList, targets[start:end])
	}
	// 认知状态预构建：并行批内不再调用 cogState（全量序列化会读其他批
	// 正在修改的 finding 字段——数据竞争）。
	state := e.cogState()
	e.runBatches(ctx, "Respond", len(batchList), func(i int, app *phaseAgent) bool {
		e.respondBatchApp(ctx, app, batchList[i], state)
		return true
	})
	// Respond 阶段耗时留痕（phases.json 此前缺处置阶段——复盘阶段耗时
	// 分布只能靠日志反推）。
	e.ws().AddPhaseLog(workspace.PhaseLog{Phase: PhaseRespond, At: started, Duration: time.Since(started), OK: true})
	// 统一入库 + 统一失效重探针缓存（批次完成后执行——批内失效会与
	// 其他批的定向采集并发写事实缓存）。
	var all []*Finding
	for _, b := range batchList {
		all = append(all, b...)
	}
	e.ws().AddFindings(all)
	for _, f := range all {
		for _, a := range f.Actions {
			if a.Auto {
				e.core.InvalidateFactCache(f.Host)
				break
			}
		}
	}
}

// respondBatchSize 单批处置的故障数（并行粒度与上下文聚焦度的平衡点）：
// 单批耗时 ≈ 批内故障数 × 每个方案的生成时间（批内模型串行出方案），
// 批越小 worker 越多 → 波内并行更细（与 deepDiveBatchSize 同理，实测
// 7 目标：4/批×3 worker → 2 波；2/批×5 worker → 1 波，省 ~1.5m）。
// 2 个/批 × 60s/个预算 = 2m < 6m 阶段超时，余量充足；批内聚焦度更高，
// 契约预检失败率同步下降。
const respondBatchSize = 2

// respondBatchApp 批量处置（app 为执行该批的独立阶段 agent）：一次模型
// 调用为全部待处置故障生成方案（plans 契约）→ 逐 plan 契约校验 → 守卫
// 执行 → 标记。批内 plan 执行保持串行（同批故障可能共享环境，动作交错
// 有风险）；不同批（不同故障）由调度器并行。
//
// 生成/解析失败退避重试 1 次（重试带拒绝原因反馈，self-correction），
// 仍失败则全部目标标记未处置原因；每目标计一次 RespondTried，
// 达 maxRespondTries 停止。反馈闭环：每个目标的上次执行结果拼入提示，
// 模型据此修正方案而非盲目重试同样的失败。
func (e *Engine) respondBatchApp(ctx context.Context, app *phaseAgent, targets []*Finding, state string) {
	e.setPhase(PhaseRespond)
	// 业务面基线（等保合规 × 业务连续性）：批含网络/服务类处置时，
	// 记录处置前业务端口清单；处置后校验非处置目标的业务端口未消失
	// ——等保收窄锁死业务流量的静默事故（自通道校验只验管理面，
	// 验不了业务面，由本校验闭环兜底）。
	bizBase := map[string]map[string]string{} // host -> 端口|进程
	if batchNeedsBusinessGuard(targets) {
		for _, f := range targets {
			if _, ok := bizBase[f.Host]; !ok {
				bizBase[f.Host] = e.businessPorts(ctx, f.Host)
			}
		}
	}
	var g strings.Builder
	g.WriteString("为以下已确认故障逐个生成处置方案（每个故障一个 plan）。方案必须满足三件套契约：每个动作需同时提供 command（执行命令）、rationale（处置理由）、verify（处置后验证命令）、check_up（验证输出中表示恢复的完整行文本）、rollback（验证失败回滚命令）。只对确认的根因处置；证据不足则 actions 留空。")
	// 环境能力事实（P0 修复）：容器/受限环境的可行性预判进处置上下文——
	// 避免尝试性安装/启用在环境里不可能成功的服务（chaos-r1 实测：
	// 容器内安装 audit 后 auditd failed，由"未装"恶化为"failed"）。
	// 环境性不可修复项的正确出口是 actions 置空转人工工单。
	if env := e.core.Env(); env != nil && env.IsContainer {
		g.WriteString("\n\n## 环境能力事实（引擎确定性探测）\n目标为容器（container=true）：安装类动作（dnf/apt install）、系统服务启用可能受容器能力限制（如 auditd 需内核审计接口、内核参数受宿主托管）。处置前先验证可行性（包是否存在、服务能否在本容器运行）；不可行时该故障的 actions 置空 []（引擎将生成人工工单），不要做尝试性安装/启用。")
	}
	// 通道约束预判标注（省重试）：认证面故障（ssh/账户锁定类）在引擎
	// 以 root 连接时，收紧认证（PRL/禁密码/禁 root/锁定 root）的方案
	// 会被守卫的通道保护机械拒绝（自断通道）——提示模型第一次就输出
	// 人工建议（actions 留空 → 工单）或非认证面加固，避免生成必拒方案
	// 后整轮浪费（历史实测：ssh_root_login 被拒 3 轮达限）。
	authHints := authBlockHint(e, targets)
	for _, f := range targets {
		f.RespondTried++
		fmt.Fprintf(&g, "\n\n### %s\n%s", f.ID, findingDetail(f))
		if hint := authHints[f.ID]; hint != "" {
			fmt.Fprintf(&g, "\n⚠️ 通道约束：%s", hint)
		}
		if fb := respondFeedback(f); fb != "" {
			fmt.Fprintf(&g, "\n上次处置执行结果：\n%s\n请据此修正方案（修正失败原因，不要重复同样的动作）。", fb)
		}
	}
	if fb := e.toolErrFeedback(); fb != "" {
		fmt.Fprintf(&g, "\n\n%s", fb)
	}
	prompt := respondTaskPrompt(g.String(), state)
	var plans *ResponsePlans
	var lastPlans *ResponsePlans // 末次解析成功的方案（契约被拒时仍记录建议）
	note := ""
	for attempt := 0; attempt < 2; attempt++ {
		task := prompt
		if attempt > 0 && note != "" {
			// 把拒绝原因喂回模型：修正方案而非重试同样的失败。
			task += fmt.Sprintf("\n\n## 上次方案被拒绝\n%s\n请修正后重新输出完整 JSON 处置方案。", note)
		}
		pctx, cancel := context.WithTimeout(ctx, e.cfg.DiagnoseTimeout)
		res, err := app.sess.RunFresh(pctx, task)
		cancel()
		if err != nil {
			e.stats.batchFails.Add(1)
			e.logf("Respond 阶段第 %d 次失败: %v", attempt+1, err)
			note = "处置方案生成失败: " + err.Error()
			if attempt+1 < 2 {
				time.Sleep(e.retryBackoff(attempt))
			}
			continue
		}
		content := strings.TrimSpace(res.Content)
		ps, perr := parseResponsePlans(content)
		if perr != nil {
			e.logf("Respond 处置方案解析第 %d 次失败: %v", attempt+1, perr)
			e.logf("Respond 处置方案原始输出: %s", collect.TruncateStr(content, 2000))
			note = "处置方案解析失败: " + perr.Error()
			continue
		}
		lastPlans = ps
		// 契约预检（三件套/证据对应/验证对象）：机械拒绝时同阶段即时
		// 重试——精确拒绝原因回灌大脑，不再机械等下一轮（速度 + 模型
		// 权限：精确信息下的即时修正比下一轮重来快一个完整循环）。
		if rej := planContractRejections(targets, ps); len(rej) > 0 {
			e.logf("Respond 契约预检拒绝 %d 项，即时重试: %s", len(rej), collect.TruncateStr(strings.Join(rej, "; "), 300))
			note = "以下方案被机械校验拒绝：\n" + strings.Join(rej, "\n")
			continue
		}
		plans = ps
		break
	}
	if plans == nil {
		// 末次解析成功但契约被拒：仍走执行路径记录修复建议与拒绝原因
		// （根因分析与修复建议不依赖处置是否成功），只是不执行。
		plans = lastPlans
	}
	byID := make(map[string]*Finding, len(targets))
	for _, f := range targets {
		byID[f.ID] = f
	}
	if plans == nil {
		for _, f := range targets {
			f.RemediationNote = note
			if f.RespondTried >= maxRespondTries {
				f.RemediationNote += fmt.Sprintf("；已达处置尝试上限 %d 次，不再自动重试", maxRespondTries)
			}
			// 处置机制：达限仍未处置 → 升级人工工单（空方案/生成失败
			// 是非法状态，无自动方案即产工单，不静默）。
			remediate.EnsureWorkOrderAtLimit(f, "处置方案生成失败/未生成")
		}
		return // 字段已改，由调度器统一入库
	}
	// 三层匹配（精确 ID → signal → 顺序回退）：模型会改写/自创
	// finding_id（常见写法 "signal-特征"），精确匹配失败时按 signal
	// 定位而不是盲按顺序分配——顺序分配在模型重排输出时会把方案
	// 错配到别的故障（run1 实测：kill 后门方案配到僵尸进程头上）。
	used := make(map[string]bool, len(targets))
	planByID := make(map[string]*remediate.Plan, len(plans.Plans)) // 业务面校验回滚用
	var verified []*Finding                                        // 执行+验证通过，待引擎确定性复检后定论
	for i := range plans.Plans {
		p := &plans.Plans[i]
		f := planTarget(p, byID, targets, used)
		if f == nil {
			e.logf("Respond 方案找不到可用目标 %q，跳过", p.FindingID)
			continue
		}
		used[f.ID] = true
		planByID[f.ID] = p
		e.logf("Respond 方案 %q → 目标 %s（%s）", p.FindingID, f.ID, f.Signal)
		// 空 actions：模型判定无法处置/已恢复——处置机制三态契约：
		// 空方案是非法状态，无自动方案即升级为人工工单（附证据包），
		// 不静默、不留"处置方案为空"。
		if len(p.Actions) == 0 {
			f.Disposition = model.NewWorkOrderDisposition(remediate.DisposeClassFor(f), remediate.WorkOrderFor(f, "模型判定无法自动处置（证据不足或已恢复）", nil))
			f.RemediationNote = "人工工单：模型判定无法自动处置（证据不足或已恢复）——按处置机制生成工单（manual_workorder），人工执行或改判接受风险"
			if f.RespondTried >= maxRespondTries {
				f.RemediationNote += fmt.Sprintf("；已达处置尝试上限 %d 次，不再自动重试", maxRespondTries)
			}
			continue
		}
		// 修复建议：方案解析成功即记录（即使校验/执行失败，建议仍进报告——
		// 根因分析与修复建议不依赖处置是否成功）。
		f.SuggestedFix = p.Suggestions()
		// 三件套契约校验：缺项不执行（处置权不交给不可信输出）。
		if bad := p.Validate(); len(bad) > 0 {
			f.RemediationNote = fmt.Sprintf("处置方案未通过三件套校验（缺: %s）", strings.Join(bad, ", "))
			if f.RespondTried >= maxRespondTries {
				f.RemediationNote += fmt.Sprintf("；已达处置尝试上限 %d 次，不再自动重试", maxRespondTries)
			}
			// 处置机制：达限仍未处置 → 升级人工工单（建议命令保留）。
			remediate.EnsureWorkOrderAtLimit(f, "处置方案未通过三件套校验（缺: "+strings.Join(bad, ", ")+"）")
			continue
		}
		// 幂等预检（仅重试轮 RespondTried≥2）：前次处置可能已生效（验证
		// 环节在途失败/被噪声干扰），执行副作用命令前先跑验证——全部
		// 动作判据已满足则跳过执行，防重复处置（重启类动作可容忍，
		// 删除/回滚类动作重复执行有害）。预检通过的仍进确定性复检闭环。
		if f.RespondTried >= 2 {
			if ok, acts := remediate.PrecheckSatisfied(ctx, e.remediateCfg(), e.remote, f.Host, p, f.Key); ok {
				e.logf("处置 %s：幂等预检通过（前次处置已生效），跳过重复执行", f.ID)
				f.Actions = acts
				f.RemediationNote = remediate.SummarizeActions(f.Actions) + "；预检已满足（前次处置已生效，跳过重复执行）"
				// 处置机制：✓ 绑定功能验证证据（预检判据即证据）。
				f.Disposition = model.NewVerifiedDisposition(remediate.DisposeClassFor(f), remediate.VerifiedEvidence(p, f.Actions))
				verified = append(verified, f)
				continue
			}
		}
		var allVerified bool
		f.Actions, allVerified = e.executor().Execute(ctx, f.Host, p, f.ID)
		// 结构性必拒预判（机械层兜底）：全部动作被守卫拒绝且拒绝原因是
		// 通道保护/硬性禁止（self-impact/hard-block），且该故障的处置
		// **必然**要求收紧 root 认证（authTighteningSignal）——当前连接
		// 配置下换方案也必拒，继续重试只烧模型调用（历史实测：
		// ssh_root_login 被拒 3 轮达限）。立即达限转人工工单（建议命令
		// 保留在工单包），不再进入后续轮次。
		// 其余信号（ssh 弱化项/账户锁定/faillock 等）即使本轮全被拒也
		// 不达限：模型换方案（加固项/锁定非当前账户/保留通道的收紧）
		// 可能成功——守住通道即可，不能绝对化。
		if len(f.Actions) > 0 && authTighteningSignal(f.Signal) &&
			allAdvised(f.Actions) && structurallyBlocked(f.Actions) {
			f.RespondTried = maxRespondTries
			remediate.EnsureWorkOrderAtLimit(f, "处置动作全部被守卫拒绝（通道保护/硬性禁止），当前连接配置下不可自动执行")
			e.logf("处置 %s：全部动作被守卫拒绝（结构性必拒），立即达限转人工工单——不再重试", f.ID)
			continue
		}
		if allVerified {
			cls := remediate.DisposeClassFor(f)
			// 自通道校验（认证/网络类变更，design-v2.md §三.4）：模型
			// verify 只验"配置生效"，验不了"管理通道还通不通"——引擎
			// 用新连接探测（Probe 直连、不走连接池：sshd reload 后既有
			// 会话仍存活，池内连接会假通过）。校验失败 = 锁死风险 →
			// 强制回滚全部动作，去向降为人工工单，绝不标已处置。
			if cls == model.ChangeAuth || cls == model.ChangeNetwork {
				if !remediate.SelfChannelOK(ctx, e.remediateCfg(), e.remote, f.Host) {
					e.logf("处置 %s：自通道校验失败（变更后新连接不可达）——强制回滚（锁死风险）", f.ID)
					ex := e.executor()
					f.Actions = ex.ForceRollback(ctx, f.Host, p, f.Actions)
					f.Remediated = false
					f.Disposition = model.NewWorkOrderDisposition(cls, remediate.WorkOrderFor(f, "自通道校验失败（变更后引擎新连接不可达），已强制回滚", nil))
					f.RemediationNote = remediate.SummarizeActions(f.Actions) + "；自通道校验失败，已强制回滚（锁死风险）——需人工复核"
					e.logf("处置 %s：%s", f.ID, f.RemediationNote)
					continue
				}
				e.logf("处置 %s：自通道校验通过（新连接可达）", f.ID)
			}
			// 模型 verify ✓ 只是初判：待引擎确定性复检（recheckVerified）
			// 确认线索确实消失后才标记已处置。
			// 处置机制：去向 verified_fixed + 功能验证证据（verify 命令/
			// 判据/实际输出）。
			f.Disposition = model.NewVerifiedDisposition(cls, remediate.VerifiedEvidence(p, f.Actions))
			f.RemediationNote = remediate.SummarizeActions(f.Actions)
			verified = append(verified, f)
		} else {
			f.Remediated = false
			f.Disposition = nil // 未通过验证：无去向，下轮继续处置
			f.RemediationNote = remediate.SummarizeActions(f.Actions)
			// 达限兜底（P0 补全）：验证失败达限同样升级人工工单——此前
			// 只有"空方案/方案无效/未生成"路径达限产工单，验证反复失败
			// 达限的项永远悬置（chaos-r2 实测 passwd remember 项 3 轮
			// 验证失败后无工单、无重裁决出口，唯一阻塞项导致停滞退出）。
			remediate.EnsureWorkOrderAtLimit(f, "处置动作执行但验证/复检反复失败（达尝试上限）")
		}
		e.logf("处置 %s：%s", f.ID, f.RemediationNote)
		// 有动作真实执行过（非纯建议）→ 下一轮 L0 对状态快照静默重基线：
		// 引擎自身处置引起的状态变化（杀进程改端口摘要、删文件改配置
		// 摘要）不是攻击痕迹，不应产漂移线索（R13 实测 state_ports）。
		// 全部自身动作命令同步记录：重基线轮对文件内容类探针做行级归属——
		// 解释不了的变化（攻击者交错注入）仍产线索（R14 实测）。
		var selfCmds []string
		for _, a := range f.Actions {
			if a.Auto {
				selfCmds = append(selfCmds, a.Command)
			}
		}
		if len(selfCmds) > 0 {
			e.core.RebaselineNext(selfCmds)
			// 重探针缓存失效统一由调度器在批次后执行（批内失效会与
			// 其他批的定向采集并发写事实缓存——数据竞争）。
		}
	}
	// 处置后确定性复检（按主机批量采集一次）：verify ✓ 不算数，引擎重新
	// 判定线索是否仍存在——假 ✓ 在确定性层收口（见 recheckVerified）。
	// 复检前状态沉降（P0 修复）：动作"瞬时生效"不等于"稳定生效"
	// （auditd enable --now 瞬时 active 后 failed），等待 Settle 窗口
	// 让慢发故障暴露后再复检，杜绝瞬时绿假通过。
	if len(verified) > 0 && e.cfg.Settle > 0 {
		e.logf("处置后沉降 %v（%d 项待确定性复检）", e.cfg.Settle, len(verified))
		time.Sleep(e.cfg.Settle)
	}
	e.rechecker().Recheck(ctx, verified)
	// 业务面校验（等保合规 × 业务连续性硬闭环）：处置后对比业务端口
	// 清单——非处置目标的业务端口消失 = 业务中断事故（等保收窄锁死
	// 业务流量的静默事故：引擎自己的通道仍通，自通道校验不感知）。
	// 事故处理：强制回滚本批已执行动作 + 工单（恢复业务优先）。
	if len(bizBase) > 0 {
		var cmds []string
		for _, p := range planByID {
			for _, a := range p.Actions {
				cmds = append(cmds, a.Command)
			}
		}
		for host, before := range bizBase {
			after := e.businessPorts(ctx, host)
			if len(after) == 0 && len(before) > 0 {
				// 处置后采集失败/无数据：不能把"无数据"当"业务全消失"
				// 误回滚——留待下轮复检如实判定。
				e.logf("业务面校验 %s：处置后采集无数据（待复检），不误判", host)
				continue
			}
			lost := remediate.BusinessDiff(before, after, cmds)
			if len(lost) == 0 {
				continue
			}
			e.logf("业务面校验 %s：非处置目标业务端口消失 %v——业务中断事故（等保收窄锁死业务），强制回滚本批动作", host, lost)
			for _, f := range targets {
				if f.Host != host || len(f.Actions) == 0 {
					continue
				}
				p := planByID[f.ID]
				if p == nil {
					continue
				}
				ex := e.executor()
				f.Actions = ex.ForceRollback(ctx, f.Host, p, f.Actions)
				f.Remediated = false
				f.Disposition = model.NewWorkOrderDisposition(remediate.DisposeClassFor(f),
					remediate.WorkOrderFor(f, "业务面校验失败（非处置目标业务端口消失，等保收窄锁死业务流量），已强制回滚", nil))
				f.RemediationNote = remediate.SummarizeActions(f.Actions) + "；业务面校验失败，已强制回滚——需人工复核业务恢复"
				e.logf("处置 %s：%s", f.ID, f.RemediationNote)
			}
		}
	}
	// 覆盖检查：未获得 plan 的目标如实记录（模型输出不全时原因可见，
	// 达限后报告不丢信息）。
	for _, f := range targets {
		if used[f.ID] {
			continue
		}
		f.RemediationNote = "本轮未生成处置方案（模型输出缺失）"
		if f.RespondTried >= maxRespondTries {
			f.RemediationNote += fmt.Sprintf("；已达处置尝试上限 %d 次，不再自动重试", maxRespondTries)
		}
		// 处置机制：达限仍未处置 → 升级人工工单（不静默）。
		remediate.EnsureWorkOrderAtLimit(f, "本轮未生成处置方案（模型输出缺失）")
		e.logf("处置 %s：%s", f.ID, f.RemediationNote)
	}
	// 字段已改（Actions/RemediationNote/Remediated），由调度器统一入库——
	// 并行批内 AddFindings 会全量序列化，读其他批正在修改的字段。
}
