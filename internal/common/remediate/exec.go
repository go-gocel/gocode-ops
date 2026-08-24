package remediate

// exec.go — 处置执行器：三件套契约执行/验证/回滚/幂等预检/自通道校验。

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-gocel/gocode-ops/internal/common/audit"
	"github.com/go-gocel/gocode-ops/internal/common/collect"
	"github.com/go-gocel/gocode-ops/internal/common/guard"
	"github.com/go-gocel/gocode-ops/internal/common/model"
	"github.com/go-gocel/gocode-ops/internal/common/remote"
)

// Executor 处置执行器（幂等由 finding 状态保证：confirmed 只处置一次）。
type Executor struct {
	cfg    Config
	guard  *guard.RiskyCommandGuard
	remote remote.RemoteExecutor
	logf   func(format string, args ...any) // 动作执行明细日志（nil=不记录）
	// rollbacks 回滚计数（运行统计；nil=不计数）。
	rollbacks *atomic.Int64
	// findingID 当前处置目标（审计追溯键：respond 审计事件关联到故障）。
	findingID string
}

// NewExecutor 创建处置执行器。guard 必须为 PolicyAuto 守卫（处置通道
// 登记白名单仅经本包 AllowAuto 调用，模型发起的命令永远无法进入）。
func NewExecutor(cfg Config, g *guard.RiskyCommandGuard, rmt remote.RemoteExecutor, logf func(format string, args ...any), rollbacks *atomic.Int64) *Executor {
	if cfg.Guard == nil {
		cfg.Guard = g
	}
	return &Executor{cfg: cfg, guard: g, remote: rmt, logf: logf, rollbacks: rollbacks}
}

// log 明细日志薄封装（nil 安全）。
func (ex *Executor) log(format string, args ...any) {
	if ex.logf != nil {
		ex.logf(format, args...)
	}
}

// Execute 执行处置方案：
// 契约校验 → 守卫预检（硬禁/自影响拒绝）→ 逐动作执行 → 验证 → 失败回滚。
// 返回每个动作的执行记录与是否全部验证通过（allVerified 为 false 时
// 调用方不得标记已处置——处置状态必须与验证结论一致）。
func (ex *Executor) Execute(ctx context.Context, host string, plan *Plan, findingID string) ([]model.Action, bool) {
	ex.findingID = findingID
	var acts []model.Action
	for i := range plan.Actions {
		acts = append(acts, ex.runAction(ctx, host, &plan.Actions[i]))
	}
	allVerified := ex.verifyAll(ctx, host, plan, &acts)
	if !allVerified && len(acts) > 0 {
		ex.rollback(ctx, host, plan, &acts)
	}
	return acts, allVerified
}

// auditRespond 处置动作审计留痕：引擎直连 exec 通道此前无审计——
// 无人值守下最危险的命令恰恰是唯一不落盘的部分。命令经 SanitizeArgs
// 脱敏后入库（与守卫审计同一脱敏函数）；携带 finding 关联（处置审计
// 追溯键：这条命令处置了哪个故障的哪个动作）。
func (ex *Executor) auditRespond(host, actionName, cmd, decision, result string) {
	if ex.guard.Audit == nil {
		return
	}
	ev := audit.AuditEvent{
		Kind:       "respond",
		Tool:       "engine",
		Args:       audit.SanitizeArgs(cmd),
		Decision:   decision,
		Result:     collect.TruncateStr(result, 300),
		FindingID:  ex.findingID,
		ActionName: actionName,
	}
	if host != "" {
		ev.Hosts = []string{host}
	}
	if err := ex.guard.Audit.Write(ev); err != nil {
		fmt.Fprintf(os.Stderr, "ops audit: %v\n", err)
	}
}

func (ex *Executor) runAction(ctx context.Context, host string, a *PlanAction) model.Action {
	act := model.Action{Name: a.Name, Host: host, Command: a.Command, At: time.Now().UTC()}
	start := time.Now()
	defer func() { act.DurationS = time.Since(start).Seconds() }()

	// 守卫预检：硬性禁止与自影响风险（断自身通道/工具链）在发起前拒绝，
	// 命中自影响只给建议不执行（fail-closed，见 guard_impact.go）。
	if err := ex.guard.CheckAuto(a.Command, ex.targetHosts(host)); err != nil {
		act.Advised = true
		act.AdvisedReason = err.Error()
		ex.auditRespond(host, a.Name, a.Command, "advised", err.Error())
		ex.log("处置动作 %s[%s] → 被守卫拒绝（自影响风险），转建议: %s", host, act.Name, err.Error())
		return act
	}
	// 契约已由调用方校验（三件套齐全）；登记白名单并执行。
	// 硬性禁止命令由守卫 decide 兜底拒绝（即使登记也不放行）。
	ex.guard.AllowAuto(a.Command, a.Rollback)
	// pkill/pgrep -f 自杀防护（机械改写执行，非拒绝）：模型常见
	// pkill -f '模式' 未防自匹配——直接执行会命中执行 shell 自身
	// （退出码 143，R22 实测）。但引擎已确认问题存在，拒绝只会把
	// 已确认的处置卡死（评测实测 9090/8088 后门 3 轮达限悬置）。
	// 守卫改为执行器的一部分：模式首字符括号化 + 必要时按顶层分隔符
	// 拆段独立 exec——处置自由度与执行安全兼得；改写不了才转建议
	// （fail-closed 兜底，例如模式无字面字符可括号化）。
	segs, fixable := PkillAutoFix(a.Command)
	if !fixable {
		act.Advised = true
		act.AdvisedReason = "pkill/pgrep -f 模式无法机械改写为防自匹配形式（请改用 'pa[t]tern' 形式或显式 PID）"
		ex.auditRespond(host, a.Name, a.Command, "advised", act.AdvisedReason)
		ex.log("处置动作 %s[%s] → 被拒绝（pkill 自杀风险且无法机械改写），转建议", host, act.Name)
		return act
	}
	if len(segs) > 1 {
		ex.log("处置动作 %s[%s] 拆分为 %d 段独立执行（pkill -f 防自匹配）：%s", host, act.Name, len(segs), collect.TruncateStr(strings.Join(segs, " ⏎ "), 200))
	} else {
		ex.log("处置动作 %s[%s] 执行: %s", host, act.Name, collect.TruncateStr(a.Command, 200))
	}
	act.Auto = true
	var outs []string
	for _, seg := range segs {
		out, err := ex.exec(ctx, host, seg, ex.cfg.ActTimeout)
		if err != nil {
			act.Error = fmt.Sprintf("%v（输出: %s）", err, collect.TruncateStr(out, 300))
			ex.auditRespond(host, a.Name, seg, "failed", act.Error)
			ex.log("处置动作 %s[%s] 段 %q → 执行失败: %s", host, act.Name, collect.TruncateStr(seg, 120), collect.TruncateStr(act.Error, 300))
			return act
		}
		// 输出错误行即执行失败：`cmd; echo OK` 把非零退出码掩蔽成 0 时，
		// 错误文本是唯一信号（R15 实测：sed -i 对 docker 挂载的 /etc/hosts
		// 重命名失败输出 "sed: cannot rename..."，整体退出码被尾随 echo 拉
		// 回 0，误标已处置）。执行与验证同源：错误行不作证据 → 错误行即失败。
		if el := firstErrorLine(out); el != "" {
			act.Error = fmt.Sprintf("命令输出含错误行: %s", collect.TruncateStr(el, 200))
			act.Result = collect.TruncateStr(out, 300)
			ex.auditRespond(host, a.Name, seg, "failed", act.Error)
			ex.log("处置动作 %s[%s] 段 %q → 输出含错误行，判失败: %s", host, act.Name, collect.TruncateStr(seg, 120), collect.TruncateStr(el, 200))
			return act
		}
		outs = append(outs, out)
		ex.auditRespond(host, a.Name, seg, "executed", collect.TruncateStr(out, 300))
	}
	act.Result = collect.TruncateStr(strings.Join(outs, "\n"), 300)
	ex.log("处置动作 %s[%s] → 执行成功（%d 段，输出 %d 字符）", host, act.Name, len(segs), len(strings.Join(outs, "\n")))
	return act
}

// verifyReadOnly 校验 verify 命令的只读性：verify 由模型生成、直接执行，
// 此前无任何守卫（模型填入破坏性命令即绕过全部硬性禁止——P0 级通道
// 缺口）。只读通道只允许"天然只读"命令：命令风险审查（硬性禁止/自
// 影响）先行，命中任何高危规则即拒绝执行该 verify（处置动作应走
// command，验证只做只读检查）。guard 为 nil（测试注入路径）时跳过。
func (ex *Executor) verifyReadOnly(host, cmd string) error {
	g := ex.cfg.Guard
	if g == nil {
		g = ex.guard
	}
	if g == nil {
		return nil
	}
	return g.CheckReadOnly(cmd, ex.targetHosts(host))
}

// verifyAll 执行全部已执行动作的验证命令：输出中完整匹配 CheckUp 的行
// 才算恢复。被建议（未执行）/执行失败的动作跳过验证（没有可验证的状态），
// 但继续验证其余动作——早退会导致后续已验证动作的成果被误回滚（R6 实测：
// 同批次"被建议"动作在前，成功修复在后的 rm 成果被整体回滚）。全部验证
// 通过且无失败/建议动作才返回 true。
// 验证前短暂等待（minDur(VerifyTimeout/2, 3s)）：kill/truncate 类动作
// 立即生效，3 秒足够；配置类（服务重启）的生效由 verify 命令自身等待。
func (ex *Executor) verifyAll(ctx context.Context, host string, plan *Plan, acts *[]model.Action) bool {
	time.Sleep(1 * time.Second)
	allOK := true
	for i := range *acts {
		act := &(*acts)[i]
		if act.Advised || act.Error != "" {
			allOK = false // 有动作未执行/失败 → 整体未全部处置
			continue
		}
		var a *PlanAction
		for j := range plan.Actions {
			if plan.Actions[j].Name == act.Name {
				a = &plan.Actions[j]
				break
			}
		}
		if a == nil {
			allOK = false
			continue
		}
		// 只读校验：verify 命中高危规则（非只读）不执行——硬性禁止与
		// 自影响任何策略一致拒绝，常规规则命中同样拒绝（verify 必须只读）。
		if err := ex.verifyReadOnly(host, a.Verify); err != nil {
			act.VerifyNote = "verify 命令非只读（" + err.Error() + "），不执行"
			ex.log("处置验证 %s[%s] → 拒绝（verify 非只读）: %v", host, act.Name, err)
			allOK = false
			continue
		}
		// 恒真验证检测：check_up 命中文本与 verify 命令中的无条件 echo/
		// printf 输出相同（不带 &&/|| 状态门控）——状态检查失败也照常
		// 输出标记，恒真验证在结构上不算恢复证据（R15 同类：处置失败
		// 后 verify 的标记 echo 仍命中 check_up 放行）。
		if tautologicalVerify(a.Verify, a.CheckUp) {
			act.VerifyNote = fmt.Sprintf("check_up %q 与 verify 中的无条件输出相同（恒真验证，不算恢复证据）", a.CheckUp)
			ex.log("处置验证 %s[%s] → 恒真验证（check_up %q 是无条件输出），不算恢复证据", host, act.Name, a.CheckUp)
			allOK = false
			continue
		}
		out, err := ex.exec(ctx, host, a.Verify, ex.cfg.VerifyTimeout)
		if err != nil || !checkUpMatches(out, a.CheckUp) {
			// 验证失败详情留痕（反馈闭环）：期望 vs 实际输出摘要，
			// 模型下轮据此修正验证契约而非重复同样的失败。
			sum := strings.TrimSpace(collect.TruncateStr(out, 200))
			if sum == "" {
				sum = "（无输出）"
			}
			act.VerifyNote = fmt.Sprintf("期望输出含 %q，实际输出：%s", a.CheckUp, sum)
			ex.log("处置验证 %s[%s] → 失败：期望含 %q，实际输出: %s", host, act.Name, a.CheckUp, sum)
			allOK = false
			continue
		}
		act.Verified = true
		// 验证输出落盘（功能验证证据：处置机制 verified_fixed 的
		// evidence 来源，报告"验证证据"区展示——✓ 必须绑定实际输出）。
		act.VerifyOut = collect.TruncateStr(out, 300)
		ex.log("处置验证 %s[%s] → 通过（期望 %q 命中）", host, act.Name, a.CheckUp)
	}
	return allOK
}

// rollbackExec 执行回滚命令并判定成功：退出码 0 且输出无错误行才算
// 成功——与执行侧 R15 语义同源（`restore.sh; echo OK` 把非零退出码
// 掩蔽成 0 时，错误文本是唯一信号；此前回滚路径只查退出码，回滚
// 实际失败会谎报已回滚）。
func (ex *Executor) rollbackExec(ctx context.Context, host, cmd string, timeout time.Duration) (string, error) {
	out, err := ex.exec(ctx, host, cmd, timeout)
	if err != nil {
		return out, err
	}
	if el := firstErrorLine(out); el != "" {
		return out, fmt.Errorf("回滚命令输出含错误行: %s", collect.TruncateStr(el, 200))
	}
	return out, nil
}

// rollback 验证失败后执行回滚（回滚命令在登记白名单时已同步登记）。
// 已验证成功的动作不回滚（真实修复成果保留，避免"修好了又回滚"）；
// 被建议（未执行）的动作跳过；回滚命令本身也过守卫（自影响风险
// 同样拒绝），失败如实记录而非谎报已回滚。
func (ex *Executor) rollback(ctx context.Context, host string, plan *Plan, acts *[]model.Action) {
	for i := range *acts {
		act := &(*acts)[i]
		if act.Error != "" || act.Advised || act.Verified {
			continue
		}
		for _, a := range plan.Actions {
			if a.Name == act.Name && a.Rollback != "" {
				if err := ex.guard.CheckAuto(a.Rollback, ex.targetHosts(host)); err != nil {
					act.Error = act.Error + "；回滚被守卫拒绝: " + err.Error()
					continue
				}
				out, err := ex.rollbackExec(ctx, host, a.Rollback, ex.cfg.ActTimeout)
				act.RolledBac = err == nil // 回滚执行失败不谎报已回滚
				if ex.rollbacks != nil {
					ex.rollbacks.Add(1)
				}
				if err != nil {
					act.Error = act.Error + "；回滚失败: " + err.Error()
					ex.auditRespond(host, a.Name, a.Rollback, "rollback_failed", err.Error())
					ex.log("处置回滚 %s[%s] → 失败: %v", host, act.Name, err)
				} else {
					act.Result = act.Result + "；已回滚: " + collect.TruncateStr(out, 200)
					ex.auditRespond(host, a.Name, a.Rollback, "rolled_back", collect.TruncateStr(out, 300))
					ex.log("处置回滚 %s[%s] → 完成", host, act.Name)
				}
			}
		}
	}
}

// targetHosts 处置目标的主机别名（本地执行为空，通道面按本地语义跳过）。
func (ex *Executor) targetHosts(host string) []string {
	if host == "" || (ex.cfg.Local && host == ex.cfg.LocalHost) {
		return nil
	}
	return []string{host}
}

// exec 在 host（""=本机）执行命令。远程命令要求零退出码：
// sshExecutor.Exec 把非零退出码作为 "[exit: N]" 文本尾注返回（模型侧
// 展示约定），处置路径必须把它当作失败——否则失败动作（userdel 拒绝、
// pkill 误杀自身会话 exit 143）会被 verify 误判为已处置（run2 实测）。
func (ex *Executor) exec(ctx context.Context, host, cmd string, timeout time.Duration) (string, error) {
	if host == "" || host == ex.cfg.LocalHost && ex.cfg.Local {
		return collect.ExecLocal(ctx, cmd, timeout)
	}
	if ex.remote == nil {
		return "", fmt.Errorf("ops: 未配置远程执行器，无法处置 %s", host)
	}
	out, err := ex.remote.Exec(ctx, []string{host}, cmd, timeout)
	if err != nil {
		return "", err
	}
	out = collect.StripSectionHeader(out)
	if code, ok := parseExitCode(out); ok && code != 0 {
		return out, fmt.Errorf("命令退出码 %d", code)
	}
	return out, nil
}

// ForceRollback 锁死风险强制回滚：全部已执行动作逐一执行回滚命令
// （覆盖 Execute"已验证不回滚"的语义——通道级变更即使模型 verify 通过
// 也可能切断管理通道，必须整体回退）。回滚命令经守卫预检；失败如实
// 记录（通道若已全断，回滚由人工控制台执行）。
func (ex *Executor) ForceRollback(ctx context.Context, host string, plan *Plan, acts []model.Action) []model.Action {
	for i := range acts {
		act := &acts[i]
		if act.Advised || act.Error != "" {
			continue
		}
		for _, a := range plan.Actions {
			if a.Name != act.Name || a.Rollback == "" {
				continue
			}
			if err := ex.guard.CheckAuto(a.Rollback, ex.targetHosts(host)); err != nil {
				act.Error = act.Error + "；强制回滚被守卫拒绝: " + err.Error()
				continue
			}
			out, err := ex.rollbackExec(ctx, host, a.Rollback, ex.cfg.ActTimeout)
			act.RolledBac = err == nil
			if ex.rollbacks != nil {
				ex.rollbacks.Add(1)
			}
			if err != nil {
				act.Error = act.Error + "；强制回滚失败: " + err.Error()
				ex.auditRespond(host, a.Name, a.Rollback, "rollback_failed", err.Error())
				ex.log("处置回滚 %s[%s] → 强制回滚失败: %v", host, act.Name, err)
			} else {
				act.Result = act.Result + "；强制回滚: " + collect.TruncateStr(out, 200)
				ex.auditRespond(host, a.Name, a.Rollback, "rolled_back", collect.TruncateStr(out, 300))
				ex.log("处置回滚 %s[%s] → 强制回滚完成", host, act.Name)
			}
		}
	}
	return acts
}

// PrecheckSatisfied 处置前幂等预检：逐动作运行 verify 并比对 check_up，
// 全部满足（且无恒真验证、判据引用处置对象）说明前次处置已生效，返回
// true 与预检动作记录（跳过副作用命令）。任一动作不满足即返回 false
// （调用方走正常执行路径）——预检是短路优化，不改变处置语义。
// 判据脱靶防护：verify 命令必须引用 finding Key 的对象关键词（R24 实测
// "sshd -t && echo AKF_RESTORED" 语法检查与处置对象无关，预检假通过
// 导致已确认的后门配置行永久残留并收敛）——不引用对象即不预检，走真实
// 执行让处置副作用真正发生。
// verify 只读校验（CheckReadOnly）：verify 是模型生成的只读检查，执行侧
// 已过契约校验与只读强制——非只读 verify 不预检不执行（与 verifyAll
// 同口径）。
func PrecheckSatisfied(ctx context.Context, cfg Config, rmt remote.RemoteExecutor, host string, plan *Plan, findingKey string) (bool, []model.Action) {
	ex := &Executor{cfg: cfg, remote: rmt}
	token := precheckObjectToken(findingKey)
	var acts []model.Action
	for i := range plan.Actions {
		a := &plan.Actions[i]
		if tautologicalVerify(a.Verify, a.CheckUp) {
			return false, nil // 恒真验证：不能作为已恢复证据
		}
		if err := ex.verifyReadOnly(host, a.Verify); err != nil {
			// 非只读 verify：不预检（走真实执行路径会让 verify 被
			// verifyAll 拒绝并如实记录）。
			return false, nil
		}
		if token != "" && !strings.Contains(strings.ToLower(a.Verify), token) {
			// 判据脱靶：verify 未引用处置对象（如只验语法/只查无关项），
			// 通过与否都与对象状态无关——不预检，走真实执行。
			return false, nil
		}
		out, err := ex.exec(ctx, host, a.Verify, cfg.VerifyTimeout)
		if err != nil || !checkUpMatches(out, a.CheckUp) {
			return false, nil
		}
		acts = append(acts, model.Action{
			Name: a.Name, Host: host, Command: a.Command,
			Auto: true, Verified: true, Prechecked: true,
			VerifyNote: "执行前预检：验证判据已满足（前次处置已生效）",
			At:         time.Now().UTC(),
		})
	}
	return len(acts) == len(plan.Actions) && len(acts) > 0, acts
}

// SelfChannelOK 自通道校验：以新连接探测管理通道（Probe 直连、不走
// 连接池——sshd reload/防火墙变更后既有会话仍存活，池内连接会假
// 通过；Probe 每次 dial 新连接，是锁死风险的可靠探测）。
func SelfChannelOK(ctx context.Context, cfg Config, rmt remote.RemoteExecutor, host string) bool {
	if host == "" || (cfg.Local && host == cfg.LocalHost) {
		return true // 本地执行无通道风险
	}
	if rmt == nil {
		return true // 无远程执行器（异常态，保守放行）
	}
	st := rmt.Probe(ctx, []string{host}, 15*time.Second)
	return st[host] == "在线"
}

// SummarizeActions 处置结果摘要（报告与日志用）。
// 状态优先级：建议（未执行）> 失败 > 回滚 > 成功。
func SummarizeActions(acts []model.Action) string {
	var parts []string
	for _, a := range acts {
		switch {
		case a.Advised:
			parts = append(parts, a.Name+"📋建议人工执行")
		case a.Error != "":
			parts = append(parts, a.Name+"✗("+collect.TruncateStr(a.Error, 60)+")")
		case a.RolledBac:
			parts = append(parts, a.Name+"↩回滚")
		default:
			parts = append(parts, a.Name+"✓")
		}
	}
	if len(parts) == 0 {
		return "无动作"
	}
	return strings.Join(parts, "，")
}
