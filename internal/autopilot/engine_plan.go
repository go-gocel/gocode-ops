package autopilot

// engine_plan.go — 处置计划匹配：finding ID→目标解析/信号归一/契约拒绝分析。

import (
	"fmt"
	"strings"

	"github.com/go-gocel/gocode-ops/internal/common/probe"
	"github.com/go-gocel/gocode-ops/internal/common/remediate"
)

// planTarget 把处置方案匹配到目标故障（模型常改写 finding_id，
// 单靠精确 ID 会大面积错配）：
//  1. 精确 ID 匹配（模型复述了完整 ID）；
//  2. signal:子键 精确匹配（同 signal 多个故障靠子键区分，模型按
//     prompt 引导用该格式）；
//  3. signal 匹配：从 finding_id 提取 signal 候选（见 signalCandidates），
//     候选等于 signal 或形如 "signal-特征"——多 signal 前缀命中时取最长者
//     （更具体）；
//  4. 顺序回退（有约束兜底）：剩余目标**唯一**时无歧义允许回退（单目标
//     批内模型 plan ID 乱写的兜底）；多目标时仅接受 signal 与任一候选
//     一致的剩余目标——**跨 signal 硬塞是错配根源**（历史实测：模型按
//     对象拆分方案（telnet/db/app-agent 各一个 plan）而引擎按 signal
//     合并 finding 时，无约束的顺序回退把 db 方案挂到 ssh_root_login
//     名下：真实修复记错账、正确故障无处置去向）。
//
// used 记录已分配的故障；每层匹配都要求目标未被占用（同一目标不被
// 多个 plan 重复处置）。匹配不上返回 nil（方案不执行、如实记录）。
func planTarget(p *remediate.Plan, byID map[string]*Finding, targets []*Finding, used map[string]bool) *Finding {
	if f, ok := byID[p.FindingID]; ok && !used[f.ID] {
		return f
	}
	// signal:子键 形式：同 signal 多故障的唯一确定性定位依据。
	if sig, key, ok := splitSignalKey(p.FindingID); ok {
		for _, t := range targets {
			if used[t.ID] {
				continue
			}
			if normSignal(t.Signal) == sig && normSignal(t.Key) == key {
				return t
			}
		}
	}
	cands := signalCandidates(p.FindingID)
	for _, cand := range cands {
		want := strings.ToLower(cand)
		var best *Finding
		for _, t := range targets {
			if used[t.ID] {
				continue
			}
			sig := strings.ToLower(strings.TrimSpace(t.Signal))
			if want == sig {
				return t // 完全相等，无歧义
			}
			if strings.HasPrefix(want, sig+"-") {
				if best == nil || len(sig) > len(best.Signal) {
					best = t
				}
			}
		}
		if best != nil {
			return best
		}
	}
	// 顺序回退（有约束兜底）：
	//   - 多目标：只接受 signal 与候选一致的剩余目标——跨 signal 硬塞
	//     是错配根源（历史实测：模型按对象拆分方案而引擎按 signal
	//     合并 finding 时，无约束回退把 db 方案挂到 ssh_root_login
	//     名下：真实修复记错账、正确故障无处置去向）；
	//   - 单目标：候选含已知信号但与目标不符 → 拒绝（模型明确指向
	//     别的故障，回退=错配执行，比不执行更糟）；候选不含已知信号
	//     （模型乱写 ID、无信号信息）→ 允许无歧义兜底。
	var remaining []*Finding
	for _, t := range targets {
		if !used[t.ID] {
			remaining = append(remaining, t)
		}
	}
	for _, t := range remaining {
		if signalMatches(t.Signal, cands) {
			return t
		}
	}
	if len(remaining) == 1 && !candsMentionKnownSignal(cands, remaining[0].Signal) {
		return remaining[0]
	}
	return nil
}

// candsMentionKnownSignal 候选集合是否提到"与 target 不同的已知信号"：
// 候选提取出的信号段在已知词表中且不等于目标信号 → true（模型明确
// 指向别的故障，禁止单目标兜底错配）；候选是乱写（不在词表）→ false
// （允许无信号信息时的单目标兜底）。
func candsMentionKnownSignal(cands []string, targetSignal string) bool {
	target := normSignal(targetSignal)
	if target == "" {
		return false
	}
	for _, c := range cands {
		sig := candSignal(c)
		if sig == "" || sig == target {
			continue
		}
		if knownSignal(sig) {
			return true
		}
	}
	return false
}

// candSignal 从候选 finding_id 提取信号段：去 host/ 前缀、:子键、
// -特征 后缀后剩余部分。
func candSignal(cand string) string {
	c := strings.TrimSpace(cand)
	if i := strings.IndexByte(c, '/'); i >= 0 {
		c = c[i+1:]
	}
	if i := strings.IndexByte(c, ':'); i >= 0 {
		c = c[:i]
	}
	if i := strings.IndexByte(c, '-'); i >= 0 {
		c = c[:i]
	}
	return strings.TrimSpace(c)
}

// knownSignal 信号词表成员判定（归一化比较；词表单一来源：probe）。
var knownSignalSet = func() map[string]bool {
	set := make(map[string]bool)
	for _, s := range probe.KnownSignals() {
		set[strings.ToLower(strings.TrimSpace(s))] = true
	}
	return set
}()

func knownSignal(sig string) bool {
	return knownSignalSet[strings.ToLower(strings.TrimSpace(sig))]
}

// signalMatches 目标 signal 是否与任一候选一致（归一化比较）。
func signalMatches(sig string, cands []string) bool {
	want := strings.ToLower(strings.TrimSpace(sig))
	for _, c := range cands {
		if strings.ToLower(strings.TrimSpace(c)) == want {
			return true
		}
	}
	return false
}

// splitSignalKey 解析 "signal:子键" 形式的 finding_id。signal 名用下划线、
// 不含冒号，故首个冒号即分隔符；子键允许任意内容（漂移源如 state_sshd）。
func splitSignalKey(id string) (sig, key string, ok bool) {
	id = strings.TrimSpace(id)
	if i := strings.IndexByte(id, ':'); i > 0 {
		return normSignal(id[:i]), normSignal(id[i+1:]), true
	}
	return "", "", false
}

// normSignal 归一化 signal/key 比较（小写 + 折叠空白）。
func normSignal(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(s))), " ")
}

// signalCandidates 从模型复述的 finding_id 提取 signal 候选（按优先级）。
//
// finding_id 的三段式 host/signal/数字 里，数字是入库时的时间戳随机数，
// 模型跨阶段复述极易写错——按 signal 定位而非精确 ID 是机制级容错（任何
// 含随机数字的 ID 都有此问题，非针对具体场景）。候选按匹配成功率排序。
func signalCandidates(id string) []string {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	var out []string
	// host/signal/数字：倒数第二段最可能是 signal。
	if parts := strings.Split(id, "/"); len(parts) >= 2 {
		out = append(out, parts[len(parts)-2])
	}
	// signal-特征（signal 名用下划线，横杠是特征分隔符）：取横杠前段。
	if i := strings.IndexByte(id, '-'); i > 0 {
		out = append(out, id[:i])
	}
	// 完整串兜底（纯 signal）。
	out = append(out, id)
	return out
}

// planContractRejections 处置方案契约预检（不执行）：三件套/证据对应/
// 验证对象。返回非空拒绝原因列表（空=全部通过）——respondBatch 据此
// 同阶段即时重试（精确原因回灌）。
// pkill/pgrep -f 自杀模式不在此拦截：执行层机械改写（模式括号化/拆段
// 独立 exec，见 pkillAutoFix）——引擎已确认问题存在，契约预检拒绝只会
// 让模型在重试循环里反复撞墙（评测实测 9090/8088 后门 3 轮达限悬置）。
func planContractRejections(targets []*Finding, plans *ResponsePlans) []string {
	byID := make(map[string]*Finding, len(targets))
	for _, f := range targets {
		byID[f.ID] = f
	}
	used := make(map[string]bool, len(targets))
	var rej []string
	matched := 0
	for i := range plans.Plans {
		p := &plans.Plans[i]
		f := planTarget(p, byID, targets, used)
		if f == nil {
			// 越批输出：模型常为本批之外/已处置的故障也生成方案
			// （同批 target 列表之外的内容也在其视野内）——匹配
			// 不到本批目标属合法输出形态，跳过即可；若把它当契约
			// 违例整批拒绝重试，会因越批 plan 反复空转烧模型调用
			// （实测：firewall_permissive 越批 plan 导致 3 轮重试
			// 全废，目标实际未处置）。
			continue
		}
		matched++
		used[f.ID] = true
		if len(p.Actions) == 0 {
			continue // 空方案合法（模型判定无法处置）
		}
		if bad := p.Validate(); len(bad) > 0 {
			rej = append(rej, fmt.Sprintf("plan %q 未通过三件套校验（缺: %s）", p.FindingID, strings.Join(bad, ", ")))
			continue
		}
	}
	// 本批目标完全无方案匹配才拒绝重试（提示模型输出本批方案）。
	if matched == 0 {
		rej = append(rej, fmt.Sprintf("本批 %d 个故障均无匹配的处置方案（模型输出 %d 个 plan 均无法对应本批目标，请只为本批列出的故障输出方案）",
			len(targets), len(plans.Plans)))
	}
	return rej
}
