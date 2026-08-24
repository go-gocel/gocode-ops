package autopilot

// engine_phase.go — 阶段推进：runPhaseOnce/fallback/securityScan/探针→指标映射。

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/go-gocel/gocode-ops/internal/common/collect"
	"github.com/go-gocel/gocode-ops/internal/common/env"
	"github.com/go-gocel/gocode-ops/internal/common/l0"
	"github.com/go-gocel/gocode-ops/internal/common/probe"
)

// RunOnce 执行一轮（初始化阶段 + 一次 L0 循环），调试用。
func (e *Engine) RunOnce(ctx context.Context) error {
	e.core.MarkStarted()
	e.runInitPhases(ctx)
	return e.loopOnce(ctx)
}

// surveyMaxSteps survey 会话 ReAct 步数上限：巡检三合一的机械预算——
// "每域 1-2 条命令浅扫、疑点进 pending 不深挖"是阶段职责，但模型常
// 在 survey 内无界深挖（实测 13+ 次工具调用把深挖做进巡检阶段）。
// 限步后模型在预算内优先覆盖全域并收尾输出小结（深挖留给 deepdive
// 批次——职责边界 + 总耗时双赢：survey 实测 2m33s → 预算内 ~1m）。
const surveyMaxSteps = 16

// runInitPhases 初始化阶段：巡检三合一（survey）一次模型会话完成
// 环境认知/全域基线/安全隐患专项，引擎只校验一次 11 域覆盖契约。
func (e *Engine) runInitPhases(ctx context.Context) {
	if e.app == nil {
		e.logf("无模型：跳过模型阶段（仅 L0 确定性层）")
		return
	}
	// 目标主机别名是任务定义（连接配置），不是环境信息：模型据此使用
	// remote_terminal 的 host 参数，避免猜测别名导致失败/在本机翻找
	// 清单文件（explore 曾因猜错别名 web-01 失败浪费 ~90s）。
	targets := strings.Join(e.core.Targets(), ",")
	e.runPhaseOnce(ctx, PhaseSurvey,
		fmt.Sprintf("巡检三合一（一次完成）：1. 认知目标环境：操作系统/内核/服务管理器/容器/网络拓扑/关键服务与日志位置/工具链，产出 env 画像；2. 全域健康基线：系统/资源/进程/服务/网络/日志/计划任务逐域检查；3. 安全隐患专项：开放端口与暴露面、弱配置（权限/口令策略）、可疑进程与启动项、异常计划任务、后门痕迹、日志异常模式。\n如目标环境是 Kubernetes 集群（kubectl 可用），增加 k8s 域检查：pod/deployment/node 状态与副本就绪、资源配额、敏感配置对象（Secret/ConfigMap 名称级、明文 env），并声明 covered（l0_facts 已含 k8s 对象级事实，直接作为依据，无需重复采集）。\n通道优先：如已知状态显示目标主机采集零可见性/采集失败（target_no_data/collect_anomaly 线索），先判定并追查通道根因（口令过期/账户锁定/连接拒绝），进 findings 后按查不了处理（skipped 声明原因）——不要反复重试基础命令，通道不通时重试不会改变结果。\n产出 env 画像、findings（status=pending 的线索）与 covered/skipped 清单（覆盖声明必须完整）。\n目标主机别名：%s（remote_terminal 的 host 用该别名；先 remote_list 确认）。", targets), fullCoverageDomains, surveyMaxSteps)
}

// defaultRetryBackoff 重试退避：指数基数 1s + 1x–2x 抖动。
// LLM/API 瞬时错误（限流/超时）重试的行业标准做法（OpenAI SDK、
// AWS/GCP 重试指南同款）——失败立即重试会加剧限流，退避让服务恢复；
// 抖动避免多阶段同时重试形成波峰。
func defaultRetryBackoff(attempt int) time.Duration {
	d := time.Second << min(attempt, 2) // 1s, 2s, 4s
	return d + time.Duration(rand.Int63n(int64(d)))
}

// runPhaseOnce 执行一个模型阶段：失败退避重试 1 次（重试把拒绝原因
// 反馈给模型修正——self-correction 实践，比盲目重试成功率高），仍失败
// 由 fallbackPhase 用确定性数据完成阶段职责。绝不降级跳过：env 与基线
// 线索是排障链路的输入，跳过即空转。maxSteps>0 时限制本次会话步数
// （survey 限步：机械执行"浅扫不深挖"的阶段职责）。
func (e *Engine) runPhaseOnce(ctx context.Context, phase Phase, goal string, mustCover []string, maxSteps int) {
	if e.app == nil {
		return
	}
	e.setPhase(phase)
	e.logf("阶段 %s 开始：%s", phase, collect.TruncateStr(goal, 300))
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		start := time.Now()
		task := taskPromptWithHints(phase, goal, e.cogState(), maxSteps, e.toolErrFeedback())
		if attempt > 0 && lastErr != nil {
			// 把拒绝原因喂回模型：让它看到自己的错误并修正，而非重试同样的失败。
			task += fmt.Sprintf("\n\n## 上次输出被拒绝\n%v\n请修正后重新输出完整 JSON 小结。", lastErr)
		}
		sum, content, err := runPhase(ctx, e.app, phase, task, e.cfg.DiagnoseTimeout, maxSteps)
		log := PhaseLog{Phase: phase, At: time.Now(), Duration: time.Since(start)}
		if err != nil {
			log.Err = err.Error()
			e.ws().AddPhaseLog(log)
			e.logf("阶段 %s 第 %d 次失败（%s）: %v", phase, attempt+1, time.Since(start).Round(time.Millisecond), err)
			// 小结解析失败时保留模型原始输出——没有它测试阶段无法定位问题。
			if content != "" {
				e.logf("阶段 %s 模型原始输出: %s", phase, collect.TruncateStr(content, 2000))
			}
			lastErr = err
			if attempt+1 < 2 {
				time.Sleep(e.retryBackoff(attempt))
			}
			continue
		}
		if verr := sum.validate(phase, mustCover); verr != nil {
			log.Err = verr.Error()
			e.ws().AddPhaseLog(log)
			e.logf("阶段 %s 契约校验失败: %v", phase, verr)
			lastErr = verr
			continue
		}
		log.OK = true
		log.Covered = sum.Covered
		log.Skipped = sum.Skipped
		e.ws().AddPhaseLog(log)
		if sum.Env != nil {
			e.ws().SetEnv(sum.Env)
		}
		e.ws().AddFindings(sum.Findings)
		// 通道约束兜底（机制 2）：自由文本里的疑点实例化——模型把疑点
		// 写进 notes/desc 而非 findings 时，发现不因通道错位而丢失。
		if leads := extractDoubtLeads(sum, e.core.Targets()); len(leads) > 0 {
			e.ws().AddFindings(leads)
			e.logf("阶段 %s 疑点提取：%d 条自由文本疑点实例化", phase, len(leads))
		}
		e.logf("阶段 %s 完成（%s）：covered=%v findings=%d，产出明细：", phase, time.Since(start).Round(time.Millisecond), sum.Covered, len(sum.Findings))
		for _, f := range sum.Findings {
			e.logf("  - [%s] %s%s→%s: %s", f.Host, f.Signal, l0.KeyNote(f.Key), f.Status, collect.TruncateStr(f.Desc, 120))
		}
		return
	}
	e.logf("阶段 %s 重试后仍失败（%v），确定性兜底", phase, lastErr)
	e.fallbackPhase(ctx, phase, lastErr)
}

// fallbackPhase 模型阶段失败的确定性兜底：用 L0 探针数据完成阶段职责，
// 不做"降级跳过"——env 与基线线索是排障链路的输入，跳过即空转；
// 兜底保证 DeepDive 有料可查、报告如实标注来源。
func (e *Engine) fallbackPhase(ctx context.Context, phase Phase, reason error) {
	log := PhaseLog{Phase: phase, At: time.Now(), OK: false, Err: fmt.Sprintf("模型阶段失败（%v），确定性兜底", reason)}
	switch phase {
	case PhaseSurvey:
		// 确定性兜底三合一：env 探测 + L0 阈值线索 + 安全探针（一次补齐
		// 巡检三职责，不空手、不假装完成；过线线索由 DeepDive 验证回路裁决）。
		if err := e.ws().SetEnv(env.DetectEnvInfo(e.core.Env())); err != nil {
			e.logf("Survey 兜底 env 落盘失败: %v", err)
		}
		leads := append(e.core.L0Round(ctx), e.securityScan(ctx)...)
		if len(leads) > 0 {
			if err := e.ws().AddFindings(leads); err != nil {
				e.logf("Survey 兜底线索落盘失败: %v", err)
			}
		}
		log.Covered = append(probeCovered(e.core.Env()), "security")
		e.logf("Survey 兜底：env 由确定性探测生成，L0+安全探针线索 %d，covered=%v", len(leads), log.Covered)
	}
	e.ws().AddPhaseLog(log)
}

// securityScan Security 兜底：按安全探针清单采集全部目标并做阈值判定，
// 返回线索（与 l0Scan 同构，不写基线——安全探针无趋势意义）。
func (e *Engine) securityScan(ctx context.Context) []*Finding {
	ms := probe.SecurityMetrics(e.core.Env())
	snap, err := e.core.CollectMetrics(ctx, ms)
	if err != nil {
		e.logf("Security 兜底采集失败: %v", err)
		return nil
	}
	for i := range snap.Hosts {
		hm := &snap.Hosts[i]
		for id, msg := range hm.Errors {
			e.logf("Security %s 采集 %s 失败: %s", hm.Host, id, msg)
		}
	}
	var out []*Finding
	for _, a := range probe.Judge(snap, e.cfg.Thresholds) {
		out = append(out, a.ToFinding())
	}
	return out
}

// probeCovered L0 探针按环境覆盖的域（Baseline 兜底的 covered 声明）。
func probeCovered(env *Env) []string {
	c := []string{"cpu", "mem", "disk", "inode", "zombie"}
	if env.HasSystemd {
		c = append(c, "svc")
	}
	if env.HasDocker {
		c = append(c, "container")
	}
	return c
}
