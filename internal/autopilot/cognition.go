package autopilot

// 认知层（架构支柱二：会干活）——LLM 大脑的工具与引擎侧集成：
//   - collect_probe：大脑缺证据 → 请求引擎定向确定性采集（走探针白名单，
//     安全边界不变）；"all"=全量安全事实；
//   - recall：经验检索（记忆资产查询，跨轮次学习）；
//   - update_workbench：大脑回写作战图/假设/待验证（认知状态持久化）。
//
// 认知护栏：采集走探针白名单（守卫不拦只读采集）、工具调用受 agent
// MaxSteps 与可选 per-finding 预算约束、全部动作经事件流留痕。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/go-gocel/gocel-core/core/kernel"
	"github.com/go-gocel/gocel-core/core/tool"

	"github.com/go-gocel/gocode-ops/internal/common/collect"
	"github.com/go-gocel/gocode-ops/internal/common/probe"
	"github.com/go-gocel/gocode-ops/internal/common/remediate"
	"github.com/go-gocel/gocode-ops/internal/common/workbench"
)

// cognitionHooks 认知工具回调集（引擎注入阶段 agent；nil 字段=工具不可用）。
type cognitionHooks struct {
	collectProbe func(ctx context.Context, host, probes string) (string, error)
	recall       func(signal, host string) string
	updateBench  func(payload string) string
}

// ── collect_probe ────────────────────────────────────────────────────

// collectProbeTool 定向采集工具：大脑判断缺什么证据 → 引擎确定性采集
// 指定探针（探针 ID 见 ops 事实清单，如 listen_ports/suid_files/…），
// 返回结构化原始输出。采集只读、白名单、带超时——认知的"手"，安全
// 边界与 L0 一致。
func collectProbeTool(h *cognitionHooks) kernel.Tool {
	return tool.MustToolFromFunc(
		func(ctx context.Context, args struct {
			Host   string `json:"host" description:"目标主机别名（与 remote_terminal 一致）"`
			Probes string `json:"probes" description:"探针 ID 列表（逗号分隔）；all=全部安全事实探针。可用：listen_ports,listen_udp,uid0_users,svc_units,suid_files,suid_files_full,world_writable,world_writable_full,big_files,mounts,cron_chain,user_crons,ssh_chain,auth_chain,sysctl_keys,shell_init_hooks,rc_local,env_global,ld_so_conf,ld_preload,file_caps,estab_conns,arp_neighbors,net_identity,empty_passwords,journald_cfg,tmp_dirs,resolv_conf,kernel_modules,promisc_ifaces,udev_rules,at_jobs,systemd_custom,selinux_status,immutable_files,login_trail（*_full 为全盘下钻变体，代价高，仅定向复采时使用）"`
		}) (string, error) {
			if h == nil || h.collectProbe == nil {
				return "", errors.New("collect_probe 不可用（引擎未注入采集通道）")
			}
			return h.collectProbe(ctx, args.Host, args.Probes)
		},
		tool.WithToolName("collect_probe"),
		tool.WithToolDescription("定向确定性采集指定探针（与 L0 快检同源，只读、白名单）。大脑在追查中需要补充证据时使用：给出目标主机与探针 ID，返回该探针的原始采集输出——比自行拼 terminal 命令可靠且不污染守卫审计面。"),
	)
}

// collectProbe 引擎侧实现：解析探针 ID → 定向采集 → 格式化输出。
func (e *Engine) collectProbe(ctx context.Context, host, probes string) (string, error) {
	env := e.core.Env()
	probes = strings.TrimSpace(probes)
	if probes == "" {
		return "", errors.New("collect_probe: probes 必填（逗号分隔探针 ID 或 all）")
	}
	var factSet, metricSet map[string]bool
	if probes == "all" {
		factSet = map[string]bool{}
		for _, f := range probe.SecurityFacts(env) {
			factSet[f.ID] = true
		}
		metricSet = nil
	} else {
		factSet = map[string]bool{}
		metricSet = map[string]bool{}
		for _, name := range strings.Split(probes, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			found := false
			for _, f := range probe.SecurityFacts(env) {
				if f.ID == name {
					factSet[name] = true
					found = true
				}
			}
			for _, m := range append(probe.Metrics(env), probe.SecurityMetrics(env)...) {
				if m.ID == name {
					metricSet[name] = true
					found = true
				}
			}
			if !found {
				return "", fmt.Errorf("collect_probe: 未知探针 %q（可用: all 或安全事实/指标探针 ID）", name)
			}
		}
	}
	ms := probe.MetricsForIDs(env, metricSet)
	facts := make([]string, 0, len(factSet))
	for id := range factSet {
		facts = append(facts, id)
	}
	snap, err := e.core.CollectProbes(ctx, ms, facts)
	if err != nil {
		return "", fmt.Errorf("collect_probe: 采集失败: %w", err)
	}
	var b strings.Builder
	for i := range snap.Hosts {
		hm := &snap.Hosts[i]
		if host != "" && hm.Host != host {
			continue
		}
		if len(hm.Errors) > 0 {
			for id, msg := range hm.Errors {
				fmt.Fprintf(&b, "## %s 探针 %s 采集失败: %s\n", hm.Host, id, msg)
			}
		}
		for id := range factSet {
			if raw := hm.Raw[id]; raw != "" {
				fmt.Fprintf(&b, "## %s %s\n%s\n", hm.Host, id, raw)
			}
		}
		for id := range metricSet {
			if raw := hm.Raw[id]; raw != "" {
				fmt.Fprintf(&b, "## %s %s\n%s\n", hm.Host, id, raw)
			}
		}
	}
	if b.Len() == 0 {
		return "(采集完成：指定探针无输出——该探针无命中或主机无数据)", nil
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

// ── recall ───────────────────────────────────────────────────────────

// recallTool 经验检索工具：大脑决策前查历史经验（本信号在本机/全局的
// 处置模板与误报统计）。
func recallTool(h *cognitionHooks) kernel.Tool {
	return tool.MustToolFromFunc(
		func(ctx context.Context, args struct {
			Signal string `json:"signal" description:"信号名（如 unattributed_listen、suid_files、deviation_unexpected_port）"`
			Host   string `json:"host,omitempty" description:"可选：限定主机（省略=全局经验）"`
		}) (string, error) {
			if h == nil || h.recall == nil {
				return "（记忆不可用：本引擎未启用经验库）", nil
			}
			return h.recall(args.Signal, args.Host), nil
		},
		tool.WithToolName("recall"),
		tool.WithToolDescription("检索历史经验：该信号在本机/全局的既往处置模板、命中次数、误报率。裁决/出方案前先查——同类问题直接复用经验，避免从零追查。无经验时返回空。"),
	)
}

// recall 引擎侧实现。
func (e *Engine) recall(signal, host string) string {
	if e.mem == nil {
		return "（记忆不可用）"
	}
	hits := e.mem.Recall(signal, host, 5)
	if len(hits) == 0 {
		return "（无相关经验）"
	}
	return strings.Join(hits, "\n")
}

// ── update_workbench ─────────────────────────────────────────────────

// updateBenchTool 作战图回写工具：大脑把认知状态（根因假设/证据/待验证/
// 下一步）持久化到工作台——跨轮次记忆的写入通道。
func updateBenchTool(h *cognitionHooks) kernel.Tool {
	return tool.MustToolFromFunc(
		func(ctx context.Context, args struct {
			Action  string          `json:"action" description:"problem=更新作战图问题；hypothesis=新建假设；hypothesis_evidence=追加假设证据；pending=登记待验证；action=记录已做动作（防重复）"`
			Payload json.RawMessage `json:"payload" description:"JSON 载荷（对象或 JSON 字符串均可）：problem:{\"id\",\"host\",\"signal\",\"hypothesis\",\"status\",\"next_step\"}；hypothesis:{\"claim\",\"next_check\"}；hypothesis_evidence:{\"id\",\"evidence\",\"support\"(bool),\"next_check\"}；pending:{\"finding_id\",\"need\",\"probe\"}；action:{\"key\"}"`
		}) (string, error) {
			if h == nil || h.updateBench == nil {
				return "（工作台不可用）", nil
			}
			return h.updateBench(args.Action + "\n" + payloadText(args.Payload)), nil
		},
		tool.WithToolName("update_workbench"),
		tool.WithToolDescription("把认知状态写入持久化工作台（作战图/假设/待验证）。大脑在追查中得出的假设、证据、下一步计划写进来——跨轮次不丢失；引擎每轮把工作台状态注入上下文。"),
	)
}

// payloadText 宽松解组 payload（P0 修复）：工具契约与模型自然输出对齐
// ——模型习惯直接给 JSON 对象（{"id":...}），schema 却要求字符串，
// chaos-r1 实测 7+ 次 "cannot unmarshal object into Go struct field
// .payload of type string" 契约报错。两者都接受：对象原样、字符串
// 去引号。
func payloadText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	s := strings.TrimSpace(string(raw))
	if strings.HasPrefix(s, `"`) {
		var str string
		if err := json.Unmarshal(raw, &str); err == nil {
			return str
		}
	}
	return s
}

// updateBench 引擎侧实现：解析 action+payload JSON → 工作台写入。
func (e *Engine) updateBench(raw string) string {
	if e.wb == nil {
		return "（工作台不可用）"
	}
	action, payload, _ := strings.Cut(raw, "\n")
	action = strings.TrimSpace(action)
	switch action {
	case "problem":
		var p workbench.WorkbenchProblem
		if err := json.Unmarshal([]byte(payload), &p); err != nil {
			return "update_workbench: payload 解析失败: " + err.Error()
		}
		if p.ID == "" || p.Host == "" || p.Signal == "" {
			return "update_workbench: problem 需要 id/host/signal"
		}
		e.wb.UpsertProblem(p)
		return "作战图已更新: " + p.ID
	case "hypothesis":
		var h struct {
			Claim     string `json:"claim"`
			NextCheck string `json:"next_check"`
		}
		if err := json.Unmarshal([]byte(payload), &h); err != nil {
			return "update_workbench: payload 解析失败: " + err.Error()
		}
		if h.Claim == "" {
			return "update_workbench: hypothesis 需要 claim"
		}
		id := e.wb.AddHypothesis(h.Claim, h.NextCheck)
		return "假设已登记: " + id
	case "hypothesis_evidence":
		var h struct {
			ID        string `json:"id"`
			Evidence  string `json:"evidence"`
			Support   bool   `json:"support"`
			NextCheck string `json:"next_check"`
		}
		if err := json.Unmarshal([]byte(payload), &h); err != nil {
			return "update_workbench: payload 解析失败: " + err.Error()
		}
		if !e.wb.UpdateHypothesis(h.ID, h.Evidence, h.Support, h.NextCheck) {
			return "update_workbench: 假设不存在: " + h.ID
		}
		return "假设已更新: " + h.ID
	case "pending":
		var p workbench.PendingCheck
		if err := json.Unmarshal([]byte(payload), &p); err != nil {
			return "update_workbench: payload 解析失败: " + err.Error()
		}
		if p.FindingID == "" || p.Need == "" {
			return "update_workbench: pending 需要 finding_id/need"
		}
		e.wb.AddPendingCheck(p.FindingID, p.Need, p.Probe)
		return "待验证已登记: " + p.FindingID
	case "action":
		var a struct {
			Key string `json:"key"`
		}
		if err := json.Unmarshal([]byte(payload), &a); err != nil {
			return "update_workbench: payload 解析失败: " + err.Error()
		}
		if a.Key == "" {
			return "update_workbench: action 需要 key"
		}
		if e.wb.RecordAction(a.Key) {
			return "动作已记录（新）: " + a.Key
		}
		return "动作已记录过（跳过重复）: " + a.Key
	}
	return "update_workbench: 未知 action " + action + "（problem/hypothesis/hypothesis_evidence/pending/action）"
}

// cogState 注入大脑的上下文：工作区状态 + 认知状态（作战图/假设/待验证/
// 经验库）——大脑看到的是"当前作战形势"而非全量事实转储。
func (e *Engine) cogState() string {
	state := e.ws().StateSummary()
	if extra := e.workbenchSummary(); extra != "" {
		if state != "" {
			state += "\n\n" + extra
		} else {
			state = extra
		}
	}
	return state
}

// ── 学习闭环（记忆沉淀） ─────────────────────────────────────────────

// learnClosed 把已关闭（处置成功/排除）的发现沉淀进记忆（经验库 + 主机
// 档案），Learned 标记防重复。respond 后调用。
func (e *Engine) learnClosed() {
	if e.mem == nil {
		return
	}
	changed := false
	for _, f := range e.ws().Findings() {
		closed := (f.Status == FindingConfirmed && f.Remediated) || f.Status == FindingDismissed
		if !closed || f.Learned {
			continue
		}
		e.mem.Learn(f)
		if f.Status == FindingConfirmed && f.Remediated {
			e.mem.RecordHostEvent(f.Host, "history", fmt.Sprintf("%s 已处置（%s）", f.Signal, collect.TruncateStr(f.RemediationNote, 80)))
			e.mem.RecordHostEvent(f.Host, "recovery", collect.TruncateStr(remediate.SummarizeActions(f.Actions), 120))
		} else {
			e.mem.RecordHostEvent(f.Host, "quirk", fmt.Sprintf("%s 误报/排除（%s）", f.Signal, collect.TruncateStr(f.Desc, 60)))
		}
		f.Learned = true
		changed = true
	}
	if changed {
		e.ws().SaveFindings()
		e.logf("学习沉淀：已关闭发现写入记忆（经验库+主机档案）")
	}
}

// activateHypotheses 证据变化时激活待验证假设（L0 后调用），返回激活
// 摘要（进日志；大脑在下轮上下文看到待续查的假设）。
func (e *Engine) activateHypotheses() {
	if e.wb == nil {
		return
	}
	if activated := e.wb.ActivateHypotheses(); len(activated) > 0 {
		for _, a := range activated {
			e.logf("假设激活（新证据）：%s", a)
		}
	}
}

// resolvePendingChecks 解析待验证：证据已到位（本轮 L0 有数据）的待验证
// 项返回摘要，引擎安排定向采集后重裁（下轮 deepdive 上下文携带）。
func (e *Engine) resolvePendingChecks() []workbench.PendingCheck {
	if e.wb == nil {
		return nil
	}
	return e.wb.ResolvePendingChecks()
}
