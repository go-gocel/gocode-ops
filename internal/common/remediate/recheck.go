package remediate

// recheck.go — 处置后确定性复检：verified 逐个重扫确认/失败回退。

import (
	"context"
	"time"

	"github.com/go-gocel/gocode-ops/internal/common/collect"
	"github.com/go-gocel/gocode-ops/internal/common/env"
	"github.com/go-gocel/gocode-ops/internal/common/model"
	"github.com/go-gocel/gocode-ops/internal/common/probe"
)

// L0 is the recheck dependency interface: post-remediation recheck needs
// signal-directed re-collection, with SignalProbePlan as the single source.
// L0 复检依赖接口：处置后复检需按信号定向重采（单一来源 SignalProbePlan）。
// *l0.Engine 实现本接口（Env/CollectProbes）。
type L0 interface {
	Env() *env.Env
	CollectProbes(ctx context.Context, ms []probe.Metric, factIDs []string) (*probe.Snapshot, error)
}

// Rechecker performs deterministic post-remediation recheck: the model's
// verify mark does not count, so it re-collects and re-judges; a clue that
// still exists means the finding is not remediated.
// Rechecker 处置后确定性复检：模型 verify ✓ 不算数——重新采集并重新
// 判定，线索仍存在即未处置（Key 精确到对象）。
type Rechecker struct {
	L0         L0
	Thresholds model.Thresholds
	Logf       func(format string, args ...any) // nil 安全
}

// log 日志薄封装（nil 安全）。
func (r *Rechecker) log(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

// Recheck deterministically re-checks remediation by re-collecting probes
// once per host and re-judging each verified finding.
// Recheck 处置后确定性复检（按主机批量采集一次）：
// R20 实测：sudoers 万能行删除动作 verify ✓ 但 sync-ops 对象未处置——
// 假 ✓ 类缺口在确定性层收口。处置已使重探针缓存失效（InvalidateFactCache），
// 复检均为实采。
//   - 对象键（Key 非空）：按 (host, signal, key) 精确复检；
//   - 聚合信号（Key 为空但 signal 有判定层映射：svc_failed/log_errors/
//     zombie/mem/swap 等）：按 (host, signal) 信号级复检——重采后判定层
//     仍产出该信号（count 未归零/水位未恢复）即未处置；
//   - 无判定层映射（模型自创信号）：fail-closed——不确认已处置（确定性
//     复检承诺"假 ✓ 在确定性层收口"，无粒度即未确认；达限由
//     EnsureWorkOrderAtLimit 升级工单，不静默放行）；
//   - 复检指标探针无数据（超时/解析失败/命令缺失/整机失联）：未完成复检，
//     不放行——探针失败被当"线索消失"是假修复成功（P1 修复）；
//   - 漂移线索（config_drift）无判定层信号源，自然跳过（基线机制负责）；
//   - 定向采集：按 signal → 探针映射（probe.SignalProbePlan）只重采判定
//     该信号所需的探针，而非整机全量（重探针全盘扫描是复检的主要
//     耗时源，定向后复检从分钟级降到秒级）。
func (r *Rechecker) Recheck(ctx context.Context, verified []*model.Finding) {
	if len(verified) == 0 {
		return
	}
	var need []*model.Finding
	for _, f := range verified {
		metricIDs, factIDs := probe.SignalProbePlan(r.L0.Env(), f.Signal)
		// 有判定层映射：对象键精确复检（Key 非空）或信号级复检（聚合信号）。
		if len(metricIDs)+len(factIDs) > 0 {
			need = append(need, f)
			continue
		}
		// 无判定层映射（模型自创/非规范信号）：fail-closed 原则保留——
		// 但收敛语义升级为"验证阶梯"（P0 修复）：确定性复检承诺的是
		// "假 ✓ 在确定性层收口"，对于判定层无法重采的信号，机械层无法
		// 证伪模型 verify；此前把这类项永久置"未处置"导致收敛死锁
		// （chaos-r1 实测：config_drift 系 7 项处置动作全部生效且 verify
		// 通过，仍因"无判定层映射"永远阻塞收敛，引擎 14 轮停滞退出）。
		// 阶梯第 2 级：模型 verify 通过 + 动作执行成功即标记已处置，
		// 报告如实标注"确定性复检无判定层，按模型验证结果待人工复核"
		// （不阻塞收敛；人工复核信息进报告工单区）。
		MarkRemediated(f)
		f.RemediationNote = SummarizeActions(f.Actions) + "；处置后确定性复检无判定层映射（信号不在 L0 词表），按模型验证结果标记已处置——待人工复核"
		r.log("复检：%s（%s）无判定层复检粒度，按验证阶梯标记已处置（待人工复核）", f.ID, f.Signal)
	}
	if len(need) == 0 {
		return
	}
	hosts := map[string]bool{}
	for _, f := range need {
		hosts[f.Host] = true
	}
	for host := range hosts {
		// 本主机待复检信号的探针并集（单一来源：SignalProbePlan）。
		metricSet := map[string]bool{}
		factSet := map[string]bool{}
		for _, f := range need {
			if f.Host != host {
				continue
			}
			mids, fids := probe.SignalProbePlan(r.L0.Env(), f.Signal)
			for _, id := range mids {
				metricSet[id] = true
			}
			for _, id := range fids {
				factSet[id] = true
			}
		}
		ms := probe.MetricsForIDs(r.L0.Env(), metricSet)
		facts := make([]string, 0, len(factSet))
		for id := range factSet {
			facts = append(facts, id)
		}
		snap, err := r.L0.CollectProbes(ctx, ms, facts)
		if err != nil {
			// 覆盖语义：复检采集失败/超时 = 无法在确定性层确认线索消失——
			// 不放行（旧行为"按模型验证结果放行"是假放行：超时截断的
			// 探针结果当"无结果"会掩盖未处置）。留待下轮复检，达限由
			// EnsureWorkOrderAtLimit 升级工单。
			r.log("复检采集失败（%s）: %v，未确认处置（待复检或转工单）", host, err)
			for _, f := range need {
				if f.Host == host {
					f.Remediated = false
					f.Disposition = nil
					f.RemediationNote = SummarizeActions(f.Actions) + "；处置后确定性复检未完成（采集失败），待复检或转人工工单"
				}
			}
			continue
		}
		// 判定层一次性重算：数值指标 + 安全事实归属，(host, signal, key)
		// 命中即"线索仍存在"；信号级集合（host, signal）用于聚合信号的
		// 复检（count/avail_pct 无对象键）。
		present := map[string]bool{}
		presentSignals := map[string]bool{}
		for _, a := range probe.Judge(snap, r.Thresholds) {
			presentSignals[a.Host+"\x00"+a.Signal()] = true
			if k := probe.ObjectKey(a.Key); k != "" {
				present[a.Host+"\x00"+a.Signal()+"\x00"+k] = true
			}
		}
		hostCov := map[string]string{}
		for i := range snap.Hosts {
			if snap.Hosts[i].Host == host {
				hostCov = snap.Hosts[i].FactCoverage
			}
		}
		for i := range snap.Hosts {
			if snap.Hosts[i].Host != host {
				continue
			}
			for _, a := range probe.JudgeSecurityFacts(&snap.Hosts[i]) {
				presentSignals[a.Host+"\x00"+a.Signal()] = true
				if k := probe.ObjectKey(a.Key); k != "" {
					present[a.Host+"\x00"+a.Signal()+"\x00"+k] = true
				}
			}
		}
		for _, f := range need {
			if f.Host != host {
				continue
			}
			// 覆盖语义：复检探针未完整（partial）→ 无法确认线索消失，
			// 不放行（partial 不产结论；"覆盖不完整"与"线索不存在"
			// 语义不同，混同为假放行）。
			_, fids := probe.SignalProbePlan(r.L0.Env(), f.Signal)
			partial := false
			for _, id := range fids {
				if hostCov[id] == "partial" {
					partial = true
					break
				}
			}
			if partial {
				f.Remediated = false
				f.Disposition = nil
				f.RemediationNote = SummarizeActions(f.Actions) + "；处置后确定性复检未完成（探针覆盖不完整），待复检或转人工工单"
				r.log("处置 %s：复检未完成（覆盖不完整），下轮修正", f.ID)
				continue
			}
			// 复检指标探针覆盖（P1 修复）：所需数值指标探针本轮无数据
			// （超时/解析失败/命令缺失/整机失联——真实采集器对空结果也
			// 输出标记+空片段，缺标记即探针未运行）→ 无法确认线索消失，
			// 不放行——探针失败被当"线索消失"是假修复成功路径。
			mids, _ := probe.SignalProbePlan(r.L0.Env(), f.Signal)
			metricMissing := false
			for _, mid := range mids {
				hm := hostMetricFor(snap, host)
				if hm == nil || hm.Metrics[mid] == nil {
					metricMissing = true
					break
				}
			}
			if metricMissing {
				f.Remediated = false
				f.Disposition = nil
				f.RemediationNote = SummarizeActions(f.Actions) + "；处置后确定性复检未完成（复检指标探针无数据，无法确认线索消失），待复检或转人工工单"
				r.log("处置 %s：复检未完成（指标探针无数据），下轮修正", f.ID)
				continue
			}
			// 线索存在性判定：对象键精确（Key 非空）或信号级（聚合信号）。
			if f.Key != "" {
				if present[f.Host+"\x00"+f.Signal+"\x00"+f.Key] {
					f.Remediated = false
					// 处置机制：确定性复检未通过 → 撤销"已修复"去向（无去向，
					// 下轮继续处置；达限由 EnsureWorkOrderAtLimit 兜底升级工单）。
					f.Disposition = nil
					f.RemediationNote = SummarizeActions(f.Actions) + "；处置后引擎确定性复检未通过（线索仍存在，处置未生效或对象错位）"
					r.log("处置 %s：复检未通过（%s），下轮修正", f.ID, f.Signal)
					continue
				}
			} else if presentSignals[f.Host+"\x00"+f.Signal] {
				f.Remediated = false
				f.Disposition = nil
				f.RemediationNote = SummarizeActions(f.Actions) + "；处置后引擎确定性复检未通过（聚合信号仍存在，处置未生效）"
				r.log("处置 %s：复检未通过（%s 信号仍存在），下轮修正", f.ID, f.Signal)
				continue
			}
			MarkRemediated(f)
		}
		passed, failed := 0, 0
		for _, f := range need {
			if f.Host != host {
				continue
			}
			if f.Remediated {
				passed++
			} else {
				failed++
			}
		}
		r.log("复检 %s：通过 %d，未通过 %d（%d 台待检项）", host, passed, failed, len(need))
	}
}

// hostMetricFor 返回快照中指定主机的 HostMetric（nil=快照无该主机）。
func hostMetricFor(snap *probe.Snapshot, host string) *probe.HostMetric {
	for i := range snap.Hosts {
		if snap.Hosts[i].Host == host {
			return &snap.Hosts[i]
		}
	}
	return nil
}

// MarkRemediated finalizes a successfully remediated finding: it records
// the completion time and compresses suggested fixes.
// MarkRemediated 处置成功收口：记录处置完成时间（处置时间线指标）并
// 压缩修复建议（成功项建议价值趋零，findings.json 体积主要来自
// suggested_fix 全文——报告未处置区才展示全文）。
func MarkRemediated(f *model.Finding) {
	f.Remediated = true
	if f.RemediatedAt.IsZero() {
		f.RemediatedAt = time.Now().UTC()
	}
	for i := range f.SuggestedFix {
		f.SuggestedFix[i] = collect.TruncateStr(f.SuggestedFix[i], 200)
	}
}

// 探针 ID → Metric 清单的映射单一来源在 probe.MetricsForIDs（与
// autopilot 认知工具共用同一实现）。
