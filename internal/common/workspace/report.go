package workspace

import (
	"fmt"
	"github.com/go-gocel/gocode-ops/internal/common/fsutil"
	"sort"
	"strings"
	"time"
)

// RenderReport renders the real-time inspection report in markdown.
// RenderReport 渲染实时报告（markdown）。报告由工作区（环境画像/三态发现/
// 基线/阶段记录）渲染，任何时刻调用都得到完整结果——事件发生时调用即
// 实时更新。分区设计对应报告关注点：确认故障 / 已排查（防误报）/ 待查 /
// 覆盖声明 / 耗时。
//
// 处置机制（design-v2.md §四）：报告构建期断言处置不变量（运行中=结构
// 违规断言；终态=追加去向闭合断言），违规在报告头部显著横幅标注——
// 本报告为中途快照/未闭合状态，不可作为最终处置结论。
func RenderReport(ws *Workspace, startedAt time.Time) string {
	return renderReport(ws, startedAt, false)
}

// RenderReportFinal renders the final report with terminal disposition assertions and a run conclusion.
// RenderReportFinal 终态报告：与 RenderReport 相同，但按终态断言处置
// 不变量（confirmed 去向闭合——运行被取消/超时/未收敛时必然触发横幅，
// 如实呈现"未完成"），并追加运行结论段。收敛完成的运行无违规、无横幅。
func RenderReportFinal(ws *Workspace, startedAt time.Time, conclusion string) string {
	r := renderReport(ws, startedAt, true)
	if conclusion != "" {
		r += "\n## 六、运行结论\n\n" + conclusion + "\n"
	}
	return r
}

func renderReport(ws *Workspace, startedAt time.Time, final bool) string {
	var b strings.Builder
	now := time.Now()
	b.WriteString("# 运维智能体巡检报告（gocode-ops）\n\n")
	// 处置机制不变量横幅：违规即显著标注（报告结构上不能撒谎——已处置∧
	// 待查互斥、✓ 绑定证据、三态去向闭合、空方案非法）。
	if violations := DispositionInvariants(ws.Findings(), final); len(violations) > 0 {
		b.WriteString("> ⚠️ **报告不变量违规（" + fmt.Sprint(len(violations)) + " 项）——本报告为中途快照/未闭合状态，不可作为最终处置结论**\n>\n")
		for _, v := range violations {
			fmt.Fprintf(&b, "> - %s\n", v)
		}
		b.WriteString(">\n")
	}
	fmt.Fprintf(&b, "- **生成时间**: %s\n", now.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "- **运行时长**: %s\n", now.Sub(startedAt).Round(time.Second))
	if ws.Env != nil {
		fmt.Fprintf(&b, "- **环境**: %s / %s（容器=%v，服务管理=%s）\n",
			ws.Env.OS, ws.Env.Kernel, ws.Env.Container, ws.Env.ServiceMgr)
	}
	writeSummary(&b, ws)
	writeConfirmed(&b, ws)
	writeDismissed(&b, ws)
	writePending(&b, ws)
	writeCoverage(&b, ws)
	return b.String()
}

// writeSummary 顶部汇总。
func writeSummary(b *strings.Builder, ws *Workspace) {
	confirmed := ws.Confirmed()
	pending := ws.Pending()
	dismissed := 0
	for _, f := range ws.Findings() {
		if f.Status == FindingDismissed {
			dismissed++
		}
	}
	fmt.Fprintf(b, "\n## 一、汇总\n\n")
	fmt.Fprintf(b, "- **确认故障**: %d\n", len(confirmed))
	fmt.Fprintf(b, "- 可疑待查: %d\n", len(pending))
	fmt.Fprintf(b, "- 已排查排除: %d（误报控制）\n", dismissed)
	writeBaselineTrend(b, ws)
	b.WriteString("\n")
}

// writeBaselineTrend 最新基线趋势（痕迹机制的证据：变化对比）。
func writeBaselineTrend(b *strings.Builder, ws *Workspace) {
	bl := ws.Baseline()
	if len(bl) < 2 {
		return
	}
	last := bl[len(bl)-1]
	prev := bl[len(bl)-2]
	b.WriteString("\n**L0 基线趋势**（对比上一轮）:\n\n| 主机 | 指标 | 上轮 | 本轮 | 变化 |\n|------|------|------|------|------|\n")
	for host, metrics := range last.Hosts {
		for k, v := range metrics {
			if pv, ok := prev.Hosts[host][k]; ok {
				delta := v - pv
				mark := "—"
				if delta > 5 {
					mark = "▲"
				} else if delta < -5 {
					mark = "▼"
				}
				fmt.Fprintf(b, "| %s | %s | %.1f | %.1f | %s%.1f |\n", host, k, pv, v, mark, delta)
			}
		}
	}
}

// writeConfirmed 确认故障区（含根因/证据/处置/验证）。
func writeConfirmed(b *strings.Builder, ws *Workspace) {
	list := ws.Confirmed()
	b.WriteString("\n## 二、确认故障\n\n")
	if len(list) == 0 {
		b.WriteString("（无）\n")
		return
	}
	for i, f := range list {
		fmt.Fprintf(b, "### %d. [%s] %s — %s\n\n", i+1, f.Host, f.Signal, f.Desc)
		if !f.At.IsZero() {
			fmt.Fprintf(b, "- **检出时间**: %s\n", f.At.Local().Format("2006-01-02 15:04:05"))
		}
		if f.RootCause != "" {
			fmt.Fprintf(b, "- **根因**: %s（置信度 %.0f%%）\n", f.RootCause, f.Confidence*100)
		}
		if len(f.Evidence) > 0 {
			b.WriteString("- **证据**:\n")
			for _, ev := range f.Evidence {
				fmt.Fprintf(b, "  - `%s`\n", fsutil.TruncateStr(ev, 160))
			}
		}
		if f.Disposition != nil {
			// 处置机制三态去向渲染（verified_fixed/manual_workorder/
			// accepted_risk——confirmed 必有去向，去向即报告的处置结论）。
			writeDisposition(b, f)
		} else if f.Remediated {
			b.WriteString("- **处置**: ✅ 已处置 — " + f.RemediationNote + "\n")
			if len(f.Actions) > 0 {
				for _, a := range f.Actions {
					note := ""
					if a.Advised {
						note = "（未执行：" + fsutil.TruncateStr(a.AdvisedReason, 600) + "）"
					} else if a.Error != "" {
						note = "（失败: " + fsutil.TruncateStr(a.Error, 100) + "）"
					} else if a.RolledBac {
						note = "（验证失败已回滚）"
					}
					fmt.Fprintf(b, "  - `%s`%s\n", a.Command, note)
				}
			}
		} else {
			// 未处置：区分"建议人工执行"与"失败未处置"，如实标注。
			hasAdvised := false
			hasFailed := false
			for _, a := range f.Actions {
				if a.Advised {
					hasAdvised = true
				}
				if a.Error != "" {
					hasFailed = true
				}
			}
			mark := "❌ 未处置"
			if hasAdvised && !hasFailed {
				mark = "📋 建议人工执行"
			}
			b.WriteString("- **处置**: " + mark + " — " + f.RemediationNote + "\n")
			if len(f.Actions) > 0 {
				for _, a := range f.Actions {
					switch {
					case a.Advised:
						b.WriteString("  - 📋 `" + fsutil.TruncateStr(a.Command, 200) + "`（未执行：" + fsutil.TruncateStr(a.AdvisedReason, 600) + "）\n")
					case a.Error != "":
						b.WriteString("  - ❌ `" + fsutil.TruncateStr(a.Command, 200) + "`（失败: " + fsutil.TruncateStr(a.Error, 100) + "）\n")
					default:
						b.WriteString("  - `" + fsutil.TruncateStr(a.Command, 200) + "`\n")
					}
				}
			}
			// 修复建议：方案已生成但未执行/执行失败时，建议本身仍是根因分析
			// 与修复建议的有效输出。
			if len(f.SuggestedFix) > 0 {
				b.WriteString("- **修复建议**:\n")
				for _, s := range f.SuggestedFix {
					fmt.Fprintf(b, "  - `%s`\n", fsutil.TruncateStr(s, 200))
				}
			}
		}
		b.WriteString("\n")
	}
}

// writeDisposition 渲染处置机制三态去向（verified_fixed / manual_workorder /
// accepted_risk）：
//   - verified_fixed：✅ + 功能验证证据（verify 命令/恢复判据/实际输出）；
//   - manual_workorder：📋 工单（影响面/建议命令/人工步骤/验证步骤/回滚）；
//   - accepted_risk：⚠️ 理由。
//
// 去向渲染取代旧的"✅/❌/📋"推断——处置结论以机制契约为准，不靠动作
// 列表反推。
func writeDisposition(b *strings.Builder, f *Finding) {
	d := f.Disposition
	switch d.Outcome {
	case DispositionVerifiedFixed:
		b.WriteString("- **处置**: ✅ 已处置（verified_fixed）— " + f.RemediationNote + "\n")
		if len(d.Evidence) > 0 {
			b.WriteString("- **验证证据**（功能验证，业务协议）:\n")
			for _, ev := range d.Evidence {
				out := strings.TrimSpace(ev.Output)
				if out == "" {
					out = "（无输出）"
				}
				fmt.Fprintf(b, "  - `%s` → 期望含 `%s`；实际输出: `%s`\n",
					fsutil.TruncateStr(ev.VerifyCmd, 160), fsutil.TruncateStr(ev.CheckUp, 80), fsutil.TruncateStr(out, 160))
			}
		}
	case DispositionManualWorkOrder:
		b.WriteString("- **处置**: 📋 人工工单（manual_workorder）— " + f.RemediationNote + "\n")
		if wo := d.WorkOrder; wo != nil {
			if wo.Summary != "" {
				fmt.Fprintf(b, "- **工单摘要**: %s\n", fsutil.TruncateStr(wo.Summary, 200))
			}
			if wo.Impact != "" {
				fmt.Fprintf(b, "- **影响面**: %s\n", fsutil.TruncateStr(wo.Impact, 200))
			}
			if len(wo.SuggestedCommands) > 0 {
				b.WriteString("- **建议命令**:\n")
				for _, s := range wo.SuggestedCommands {
					fmt.Fprintf(b, "  - `%s`\n", fsutil.TruncateStr(s, 200))
				}
			}
			if len(wo.Steps) > 0 {
				b.WriteString("- **人工步骤**:\n")
				for _, s := range wo.Steps {
					fmt.Fprintf(b, "  - %s\n", fsutil.TruncateStr(s, 300))
				}
			}
			if len(wo.VerificationSteps) > 0 {
				b.WriteString("- **验证步骤**:\n")
				for _, s := range wo.VerificationSteps {
					fmt.Fprintf(b, "  - %s\n", fsutil.TruncateStr(s, 300))
				}
			}
			if wo.Rollback != "" {
				fmt.Fprintf(b, "- **回滚预案**: %s\n", fsutil.TruncateStr(wo.Rollback, 200))
			}
		}
	case DispositionAcceptedRisk:
		b.WriteString("- **处置**: ⚠️ 接受风险（accepted_risk）— " + fsutil.TruncateStr(d.RiskRationale, 300) + "\n")
	}
	if len(f.Actions) > 0 {
		b.WriteString("- **动作记录**:\n")
		for _, a := range f.Actions {
			switch {
			case a.Advised:
				b.WriteString("  - 📋 `" + fsutil.TruncateStr(a.Command, 200) + "`（未执行：" + fsutil.TruncateStr(a.AdvisedReason, 600) + "）\n")
			case a.Error != "":
				b.WriteString("  - ❌ `" + fsutil.TruncateStr(a.Command, 200) + "`（失败: " + fsutil.TruncateStr(a.Error, 100) + "）\n")
			default:
				b.WriteString("  - `" + fsutil.TruncateStr(a.Command, 200) + "`\n")
			}
		}
	}
}

// writeDismissed 已排查区（防误报的可见证据：不是故障，但查过）。
func writeDismissed(b *strings.Builder, ws *Workspace) {
	var list []*Finding
	for _, f := range ws.Findings() {
		if f.Status == FindingDismissed {
			list = append(list, f)
		}
	}
	b.WriteString("\n## 三、已排查排除（非故障）\n\n")
	if len(list) == 0 {
		b.WriteString("（无）\n")
		return
	}
	for _, f := range list {
		fmt.Fprintf(b, "- [%s] %s — %s\n", f.Host, f.Signal, f.Desc)
	}
}

// writePending 待查区（证据不足，不算故障——不参与误报扣分）。
func writePending(b *strings.Builder, ws *Workspace) {
	list := ws.Pending()
	b.WriteString("\n## 四、可疑待查\n\n")
	if len(list) == 0 {
		b.WriteString("（无）\n")
		return
	}
	for _, f := range list {
		fmt.Fprintf(b, "- [%s] %s — %s%s\n", f.Host, f.Signal, f.Desc,
			map[bool]string{true: fmt.Sprintf("（已追查 %d 次，证据不足）", f.Tried)}[f.Tried > 0])
	}
}

// writeCoverage 检查覆盖声明与阶段耗时（完整性自评）。
// 周期复扫（rescan）记录合并显示：只列最近一次，避免 30min 一条的
// 重复行刷屏；次数以 ×N 标注。
func writeCoverage(b *strings.Builder, ws *Workspace) {
	b.WriteString("\n## 五、检查覆盖与阶段耗时\n\n")
	b.WriteString("| 阶段 | 结果 | 耗时 | 覆盖域 |\n")
	b.WriteString("|------|------|------|--------|\n")
	phases := ws.Phases()
	rescanCount := 0
	var lastRescan *PhaseLog
	for i := range phases {
		p := &phases[i]
		if p.Phase == PhaseRescan {
			rescanCount++
			lastRescan = p
			continue
		}
		writePhaseRow(b, p)
	}
	if rescanCount > 0 && lastRescan != nil {
		last := *lastRescan
		last.Phase = Phase("rescan×" + fmt.Sprint(rescanCount))
		writePhaseRow(b, &last)
	}
	// L0 事实覆盖声明：确定性采集的事实面人读可见——模型上下文之外，
	// 报告同样声明覆盖了哪些事实（全绿/漏采可查）。
	if facts := ws.L0FactsSnapshot(); len(facts) > 0 {
		b.WriteString("\n**L0 事实覆盖**（确定性采集，最新一轮）:\n\n")
		cov := ws.L0CoverageSnapshot()
		for host, f := range facts {
			fmt.Fprintf(b, "- %s: %s\n", host, fsutil.TruncateStr(f, 400))
			// 覆盖语义（design-v2.md §二）：覆盖度是事实的一部分——
			// 不完整（partial）/未扫（skipped）如实标注，审计面不得把
			// 不完整枚举当"全绿"。
			if marks := coverageMarks(cov[host]); marks != "" {
				fmt.Fprintf(b, "  - **覆盖**: %s\n", marks)
			}
		}
	}
	// S2 上板基线状态：全盘枚举探针（suid_files_full/big_files）的上板/
	// 刷新/未上板如实可见——大文件系统上全盘扫描超时（partial）即
	// "未上板"等待重试，不伪装覆盖（事故根因的审计面）。
	if inv := ws.InventorySnapshot(); len(inv) > 0 {
		b.WriteString("\n**S2 上板基线**（全盘枚举探针，例行轮不重扫）:\n\n")
		hosts := make([]string, 0, len(inv))
		for host := range inv {
			hosts = append(hosts, host)
		}
		sort.Strings(hosts)
		for _, host := range hosts {
			probes := inv[host]
			ids := make([]string, 0, len(probes))
			for id := range probes {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			for _, id := range ids {
				iv := probes[id]
				switch {
				case iv.Partial:
					fmt.Fprintf(b, "- %s %s: ⚠️ 未上板（覆盖不完整，%s 后重试）\n", host, id, InventoryRetry.Round(time.Hour))
				default:
					fmt.Fprintf(b, "- %s %s: ✅ 上板（%s，%d 条目）\n", host, id, iv.At.Local().Format("01-02 15:04"), len(iv.Entries))
				}
			}
		}
	}
	b.WriteString("\n---\n")
	b.WriteString("*报告由 ops 协议引擎实时生成；处置动作均经安全守卫审计，未经验证结论不计为故障。*\n")
}

// coverageMarks 覆盖标注（只标非 full 项，避免健康轮刷屏）：
// partial=⚠️ 不完整（枚举结果不可作结论）；skipped=未扫（下钻探针
// 例行未含，属设计决策）。
func coverageMarks(cov map[string]string) string {
	if len(cov) == 0 {
		return ""
	}
	ids := make([]string, 0, len(cov))
	for id := range cov {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var parts []string
	for _, id := range ids {
		switch cov[id] {
		case "partial":
			parts = append(parts, fmt.Sprintf("⚠️ %s=不完整（需定向下钻复采）", id))
		case "skipped":
			parts = append(parts, fmt.Sprintf("%s=未扫（下钻项，例行不采）", id))
		}
	}
	return strings.Join(parts, "；")
}

// writePhaseRow 单行阶段记录（含 skipped 标注）。
func writePhaseRow(b *strings.Builder, p *PhaseLog) {
	mark := "✅"
	if !p.OK {
		mark = "⚠️"
	}
	line := fmt.Sprintf("| %s | %s | %s | %s |", p.Phase, mark, p.Duration.Round(time.Second), strings.Join(p.Covered, ", "))
	if len(p.Skipped) > 0 {
		line += " <br>skipped: " + strings.Join(p.Skipped, ", ")
	}
	fmt.Fprintln(b, line)
}
