package guard

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/go-gocel/gocel-core/core/kernel"
	"github.com/go-gocel/gocode-ops/internal/common/audit"
	"github.com/go-gocel/gocode-ops/internal/common/model"
)

// Policy 决定高危命令的处置方式。
type Policy string

const (
	// PolicyAsk 每次高危命令执行前都向操作员确认（默认，最安全）。
	PolicyAsk Policy = "ask"
	// PolicyAllow 自动放行高危命令（操作员显式选择；硬性禁止命令仍拦截）。
	PolicyAllow Policy = "allow"
	// PolicyDeny 一律拒绝高危命令（只读巡检不受影响）。
	PolicyDeny Policy = "deny"
	// PolicyAuto 无人值守自动策略：只读命令天然放行；高危命令自动审查
	// （自影响审查通过即放行并留痕审计，硬性禁止照旧）。供全自动运维引擎
	// 使用——全自动即自动判断风险，不再依赖人工确认。
	PolicyAuto Policy = "auto"
)

// riskyRule 描述一类高危命令。
type RiskyCommandGuard struct {
	Operator model.Operator
	Policy   Policy
	// Audit 非 nil 时记录每次决策（批准/拒绝/硬禁）。
	Audit *audit.AuditLog
	// ResolveHosts 可选：把主机别名（含 "all"）解析为真实主机名，
	// 用于确认提示展示目标。未设置时直接显示别名。
	ResolveHosts func(aliases []string) ([]string, error)
	// mu 保护 approved/allowAll/autoAllow（并发工具调用/并行 worker）。
	mu sync.Mutex
	// approved 缓存本次会话内已获批准的命令（按「命令原文 + 目标主机」区分，
	// 改一个字符或换一批主机都需重新确认）。
	approved map[string]bool
	// allowAll 会话级放行：操作员在某次确认中选择“本会话全部放行”后，
	// PolicyAsk 下的常规高危变更命令不再逐条确认（硬性禁止与风险审查
	// 不受影响，照旧拦截）。
	allowAll bool
	// autoAllow 是 PolicyAuto 下的白名单：命令原文精确匹配才自动放行。
	// 由全自动运维引擎在发起处置前登记（处置来源标记，审计留痕用）；自影响
	// 审查通过后非硬性禁止命令即放行，白名单不再是放行的唯一依据。
	autoAllow map[string]bool
	// pendingAsk 并发去重：同一 (cmd,hosts) 的高危确认仅向操作员弹一次，
	// 并发触发的其它 goroutine 复用同一结论（避免并发高危命令双弹确认）。
	pendingAsk map[string]*askWaiter
	// ConnFacts 可选：把主机别名解析为连接事实（自影响审查用）；
	// nil 时通道面审查按保守模式（无法确认保留通道即拒绝）。
	ConnFacts func(aliases []string) map[string]model.ConnFact
	// OnApproved 可选：操作员确认放行（approved/approved_all/session_allow）
	// 后的回调——"人在环背书"信号。交互式运维助手用它把操作员批准的
	// 命令沉淀进主机档案（越用越懂这台机器）；PolicyAuto 下不触发
	// （无人确认）。回调在守卫调用 goroutine 内执行，须线程安全。
	OnApproved func(cmd string, hosts []string)
}

// askWaiter 同一 (cmd,hosts) 并发确认去重：首个 goroutine 向操作员提问并
// 广播结论，其余 goroutine 接收同一结论（不再重复弹确认、不重复写审计）。
type askWaiter struct {
	done    chan struct{}
	allowed bool
	err     error
}

// NewRiskyCommandGuard 创建守卫。operator 为 nil 时 ask 策略退化为 deny。
func NewRiskyCommandGuard(operator model.Operator, policy Policy) *RiskyCommandGuard {
	if policy == "" {
		policy = PolicyAsk
	}
	return &RiskyCommandGuard{
		Operator:   operator,
		Policy:     policy,
		approved:   map[string]bool{},
		autoAllow:  map[string]bool{},
		pendingAsk: map[string]*askWaiter{},
	}
}

// AllowAllSession 会话级放行：后续高危常规变更命令不再逐条确认
// （操作员在某次确认中选择 a 时由 decide 置位；硬性禁止命令不受影响）。
func (g *RiskyCommandGuard) AllowAllSession() {
	g.mu.Lock()
	g.allowAll = true
	g.mu.Unlock()
}

// AllowAuto 在 PolicyAuto 下把命令原文登记为自动放行（精确匹配）。
// 只应由引擎处置通道调用——处置命令经三件套契约校验后登记、参数受限；
// 模型发起的命令永远无法进入白名单（工具调用不经过本方法）。
func (g *RiskyCommandGuard) AllowAuto(cmds ...string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, c := range cmds {
		g.autoAllow[strings.TrimSpace(c)] = true
	}
}

// CheckAuto 预检一条命令在 PolicyAuto 下是否会被放行：
// 返回 nil 表示可执行。供处置通道在执行前校验处置命令
// （命令风险审查与策略拒绝立即暴露，不等到执行时才发现）。
// hosts 为目标主机别名：非空表示远程执行（通道面按连接事实/保守模式
// 判定），空表示本地执行（通道面跳过、工具链面生效）。
func (g *RiskyCommandGuard) CheckAuto(cmd string, hosts []string) error {
	// 命令风险审查：自身影响/目标危害/凭证/混淆，命中即拒绝（任何策略一致）。
	if v := g.reviewRisk(cmd, hosts); v != nil {
		return verdictError(v)
	}
	// 常规变更面按策略：auto/allow 放行（全自动自判合规），其余拒绝。
	switch g.Policy {
	case PolicyAuto, PolicyAllow:
		return nil
	}
	if matchRiskyRule(cmd) == nil {
		return nil // 只读命令，天然放行
	}
	return fmt.Errorf("ops 安全守卫: 当前策略拒绝—— %s：%s", matchRiskyRule(cmd).name, cmd)
}

// Register 挂接 BeforeToolCall 钩子。
func (g *RiskyCommandGuard) Register(rt kernel.HookRegistrar) {
	rt.OnToolCall(g.onToolCall)
}

func (g *RiskyCommandGuard) onToolCall(ctx context.Context, info *kernel.ToolCallInfo) (context.Context, *kernel.ToolCallInfo, error) {
	switch info.Name {
	case "terminal", "task_run":
		return g.checkTerminal(ctx, info)
	case "remote_terminal", "remote_batch":
		return g.checkRemoteTerminal(ctx, info)
	case "remote_upload", "remote_download":
		return g.checkRemoteTransfer(ctx, info)
	case "read", "grep":
		return g.checkCredentialTool(ctx, info)
	case "write", "trash", "rename", "multi_edit":
		// 文件工具路径同样过凭证守卫：凭证守卫只覆盖命令与 read/grep 时，
		// 模型可经 write/trash 直接改写 .gocode/ 凭证清单/审计日志/提示词
		// （凭证路径对文件工具与命令同口径拦截）。
		return g.checkFileTool(ctx, info)
	}
	return ctx, info, nil
}

func (g *RiskyCommandGuard) checkTerminal(ctx context.Context, info *kernel.ToolCallInfo) (context.Context, *kernel.ToolCallInfo, error) {
	var args struct {
		Command string `json:"command"`
	}
	if err := unmarshalArgs(info.Args, &args); err != nil {
		info.Error = err
		return ctx, info, err
	}
	cmd := strings.TrimSpace(args.Command)
	if cmd == "" {
		return ctx, info, nil
	}
	// 命令风险审查无条件先行（不命中高危规则的命令同样受自影响/工具链
	// 审查约束——网络/工具链/认证栈类破坏命令不再因"无规则命中"放行）。
	if err := g.decideCommand(ctx, cmd, nil, info.Name); err != nil {
		info.Error = err
		return ctx, info, err
	}
	return ctx, info, nil
}

func (g *RiskyCommandGuard) checkRemoteTerminal(ctx context.Context, info *kernel.ToolCallInfo) (context.Context, *kernel.ToolCallInfo, error) {
	var args struct {
		Hosts   []string `json:"hosts"`
		Host    string   `json:"host"`
		Command string   `json:"command"`
	}
	if err := unmarshalArgs(info.Args, &args); err != nil {
		info.Error = err
		return ctx, info, err
	}
	cmd := strings.TrimSpace(args.Command)
	if cmd == "" {
		return ctx, info, nil
	}
	// 兼容两种参数形态：remote_terminal 单机（host）、remote_batch 批量（hosts）。
	hosts := args.Hosts
	if len(hosts) == 0 && strings.TrimSpace(args.Host) != "" {
		hosts = []string{args.Host}
	}
	// 命令风险审查无条件先行（与本地路径同口径，见 checkTerminal）。
	if err := g.decideCommand(ctx, cmd, g.resolveHosts(hosts), info.Name); err != nil {
		info.Error = err
		return ctx, info, err
	}
	return ctx, info, nil
}

// checkRemoteTransfer 拦截上传/下载到凭证路径（防模型借文件传输绕过
// 凭证守卫：把后门写进 ~/.ssh 或把私钥/清单拉回本地）。下载侧本地
// 落盘目录（local_dir）同样校验——否则模型可把远端文件下载覆盖本机
// 凭证路径（~/.ssh/authorized_keys、.gocode/hosts.yaml）。
func (g *RiskyCommandGuard) checkRemoteTransfer(ctx context.Context, info *kernel.ToolCallInfo) (context.Context, *kernel.ToolCallInfo, error) {
	var args struct {
		RemotePath string `json:"remote_path"`
		LocalDir   string `json:"local_dir"`
	}
	if err := unmarshalArgs(info.Args, &args); err != nil {
		info.Error = err
		return ctx, info, err
	}
	if err := g.CheckTransferPath(args.RemotePath, ""); err != nil {
		info.Error = err
		return ctx, info, err
	}
	if err := g.CheckTransferPath(args.LocalDir, "下载"); err != nil {
		info.Error = err
		return ctx, info, err
	}
	return ctx, info, nil
}

// checkFileTool 拦截文件工具（write/trash/rename/multi_edit）对凭证
// 路径的写操作：凭证清单（hosts.yaml）/审计日志/提示词/密钥等只允许
// 操作员本机直接维护，模型不得经任何通道触碰——与命令/read/grep/
// 传输守卫同一 credentialPathRe 口径。
func (g *RiskyCommandGuard) checkFileTool(ctx context.Context, info *kernel.ToolCallInfo) (context.Context, *kernel.ToolCallInfo, error) {
	var args struct {
		Path    string `json:"path"`
		OldPath string `json:"old_path"`
		NewPath string `json:"new_path"`
		Edits   []struct {
			Path string `json:"path"`
		} `json:"edits"`
	}
	if err := unmarshalArgs(info.Args, &args); err != nil {
		info.Error = err
		return ctx, info, err
	}
	paths := []string{args.Path, args.OldPath, args.NewPath}
	for _, e := range args.Edits {
		paths = append(paths, e.Path)
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		if credentialPathRe.MatchString(p) {
			err := fmt.Errorf("ops 安全守卫: 文件工具目标触碰凭证路径，已拦截（凭证清单/审计/密钥仅操作员本机可维护）—— %s", p)
			info.Error = err
			return ctx, info, err
		}
	}
	return ctx, info, nil
}

// checkTransferPath 校验传输目标路径不触碰凭证材料。
func (g *RiskyCommandGuard) CheckTransferPath(remotePath, verb string) error {
	if remotePath == "" {
		return nil
	}
	if credentialPathRe.MatchString(remotePath) {
		label := verb
		if label == "" {
			label = "文件传输"
		}
		return fmt.Errorf("ops 安全守卫: %s目标触碰凭证路径，已拦截—— %s", label, remotePath)
	}
	return nil
}

// checkCredentialTool 拦截 read/grep 对凭证路径的访问。
func (g *RiskyCommandGuard) checkCredentialTool(ctx context.Context, info *kernel.ToolCallInfo) (context.Context, *kernel.ToolCallInfo, error) {
	var args struct {
		Path string `json:"path"`
	}
	if err := unmarshalArgs(info.Args, &args); err != nil {
		info.Error = err
		return ctx, info, err
	}
	if args.Path == "" {
		return ctx, info, nil
	}
	if credentialPathRe.MatchString(args.Path) {
		err := fmt.Errorf("ops 安全守卫: 凭证文件不可读取（防泄露给外部大模型）—— %s", args.Path)
		info.Error = err
		return ctx, info, err
	}
	return ctx, info, nil
}

// resolveHosts 把别名解析为真实主机名用于确认提示；解析失败时回退为
// 去重排序后的原始别名（提示不能因解析失败而消失）。
func (g *RiskyCommandGuard) resolveHosts(aliases []string) []string {
	if g.ResolveHosts != nil {
		if resolved, err := g.ResolveHosts(aliases); err == nil && len(resolved) > 0 {
			return resolved
		}
	}
	return sortHosts(aliases)
}

// RiskVerdict 命令风险审查结论（统一出口）。命中任何风险面即拒绝
// （hard），策略不可调节——只给建议，不执行。
type RiskVerdict struct {
	// Face 风险面：self-impact（自身影响）/ target-harm（目标危害）/
	// credential（凭证泄露）/ obfuscation（混淆绕过）。
	Face string
	// Category 细分类别（如 channel-auth / root-delete）。
	Category string
	// Reason 面向操作员/报告的解释。
	Reason string
	// Advice 安全替代建议（可为空：部分风险面无建议）。
	Advice string
}

// 风险面标识。
const (
	riskFaceSelfImpact  = "self-impact"
	riskFaceTargetHarm  = "target-harm"
	riskFaceCredential  = "credential"
	riskFaceObfuscation = "obfuscation"
)

// reviewCommandRisk 命令风险审查（统一入口，所有风险面一次判定）：
//
//	自身影响面  —— 断自身通道/毁工具链（自影响审查，子集，见 selfimpact.go）
//	目标危害面  —— 宕机/不可恢复（rm -rf /、mkfs、dd 设备、fork-bomb、reboot）
//	凭证泄露面  —— shadow/私钥/明文密码
//	混淆绕过面  —— 解码管道/解释器危险代码
//
// 命中任何风险面 → 拒绝执行。常规变更面（kill/userdel/service 等）不在
// 本审查内，由策略层（ask/allow/deny/auto）调节。facts 是目标主机的
// 连接事实（自身影响面判定用；本地命令传 nil，通道面按保守跳过、
// 工具链面生效）。返回 nil 表示无风险。
func reviewCommandRisk(cmd string, facts map[string]model.ConnFact) *RiskVerdict {
	// 面 1：自身影响（断自身通道/毁工具链）——命令风险审查的子集。
	if risk := assessSelfImpact(cmd, facts); risk != nil {
		return &RiskVerdict{
			Face: riskFaceSelfImpact, Category: risk.Category,
			Reason: risk.Reason, Advice: risk.Advice,
		}
	}
	// 面 2-4：目标危害/凭证泄露/混淆绕过（riskyRules 中 hard 规则）。
	if rule := matchRiskyRule(cmd); rule != nil && rule.hard {
		face := riskFaceTargetHarm
		switch rule.name {
		case "credential-read", "ssh-self-connect", "plaintext-password":
			face = riskFaceCredential
		case "decode-pipe-shell", "interp-c-dangerous":
			face = riskFaceObfuscation
		}
		return &RiskVerdict{Face: face, Category: rule.name, Reason: rule.explain}
	}
	return nil
}

// verdictError 把审查结论转为拒绝错误（文案带风险面与建议）。
func verdictError(v *RiskVerdict) error {
	if v.Advice != "" {
		return fmt.Errorf("ops 安全守卫: 命令风险审查拒绝（%s/%s）—— %s。%s", v.Face, v.Category, v.Reason, v.Advice)
	}
	return fmt.Errorf("ops 安全守卫: 硬性禁止 %s（%s/%s）—— %s。该命令永远不允许执行。", v.Category, v.Face, v.Category, v.Reason)
}

// decideCommand 命令统一裁决入口：命令风险审查无条件先行（任何策略
// 一致），再按规则命中走策略裁决。未命中规则的只读命令在风险审查通过
// 后天然放行。本地（hosts=nil）与远端（hosts 非空）共用本入口——
// 自影响审查对"不命中规则的命令"同样生效（网络/工具链/认证栈类破坏
// 命令不再因规则库未覆盖而静默放行）。
func (g *RiskyCommandGuard) decideCommand(ctx context.Context, cmd string, hosts []string, tool string) error {
	if v := g.reviewRisk(cmd, hosts); v != nil {
		g.record(tool, hosts, v.Category, cmd, "hard_blocked", nil)
		return verdictError(v)
	}
	rule := matchRiskyRule(cmd)
	return g.decideAfterRisk(ctx, cmd, rule, hosts, tool)
}

// decide 按规则与策略处置一条高危命令（hosts 非 nil 时面向远端执行，
// 确认提示包含目标主机；tool 为真实工具名，审计留痕用）。
// 返回 nil 表示放行。
func (g *RiskyCommandGuard) decide(ctx context.Context, cmd string, rule *riskyRule, hosts []string, tool string) error {
	// 命令风险审查先行（任何策略一致）：自身影响/目标危害/凭证/混淆
	// 任一风险面命中即拒绝、只给建议——交互式运维助手同样拒绝（避免把操作员
	// 也断在远端），策略（ask/allow/deny/auto）只调节常规变更面。
	if v := g.reviewRisk(cmd, hosts); v != nil {
		g.record(tool, hosts, v.Category, cmd, "hard_blocked", nil)
		return verdictError(v)
	}
	return g.decideAfterRisk(ctx, cmd, rule, hosts, tool)
}

// decideAfterRisk 假定命令风险审查已完成（硬性禁止/自影响已拦截），
// 只按规则命中与策略处置常规变更面。
func (g *RiskyCommandGuard) decideAfterRisk(ctx context.Context, cmd string, rule *riskyRule, hosts []string, tool string) error {
	if rule == nil {
		return nil // 只读命令，天然放行
	}
	switch g.Policy {
	case PolicyDeny:
		g.record(tool, hosts, rule.name, cmd, "policy_deny", nil)
		return fmt.Errorf("ops 安全守卫: 高危命令被拒绝（当前策略 deny）—— %s：%s。请只做只读诊断，并给操作员人工执行建议。", rule.name, cmd)
	case PolicyAuto:
		// 无人值守：命令风险审查已过，常规变更面自动放行（全自动即自动
		// 审查风险、自行判断合规）；登记白名单仅作处置来源留痕。
		g.mu.Lock()
		_, inAllow := g.autoAllow[cmd]
		g.mu.Unlock()
		if inAllow {
			g.record(tool, hosts, rule.name, cmd, "auto_allow", nil)
		} else {
			g.record(tool, hosts, rule.name, cmd, "auto_allowed", nil)
		}
		return nil
	case PolicyAllow:
		g.record(tool, hosts, rule.name, cmd, "policy_allow", nil)
		return nil
	}
	// PolicyAsk
	if g.Operator == nil {
		g.record(tool, hosts, rule.name, cmd, "policy_deny", nil)
		return fmt.Errorf("ops 安全守卫: 非交互环境，高危命令被阻止—— %s：%s", rule.name, cmd)
	}
	// 会话级放行：操作员已选择“本会话全部放行”，常规变更面不再逐条打断
	// （硬性禁止与风险审查在前面已拦截，此处只余常规变更面）。
	g.mu.Lock()
	if g.allowAll {
		g.mu.Unlock()
		g.record(tool, hosts, rule.name, cmd, "session_allow", nil)
		g.fireApproved(cmd, hosts)
		return nil
	}
	// 批准缓存按「命令 + 目标主机」区分：同一命令对另一批主机执行必须
	// 重新确认（本地执行与远端批量是不同目标）。
	key := cmd
	if len(hosts) > 0 {
		key = cmd + "\x00" + strings.Join(hosts, ",")
	}
	if g.approved[key] {
		g.mu.Unlock()
		return nil // 本会话已批准同一命令（同一目标）
	}
	// 并发去重：同一 key 仅向操作员弹一次确认。已有 goroutine 在询问时，
	// 本 goroutine 复用其结论（不再弹确认，也不重复写审计）。
	if w, ok := g.pendingAsk[key]; ok {
		g.mu.Unlock()
		<-w.done
		if w.err != nil {
			return w.err
		}
		if w.allowed {
			return nil
		}
		return fmt.Errorf("ops 安全守卫: 操作员拒绝执行—— %s", cmd)
	}
	// 本 goroutine 负责询问：登记 waiter（确认在锁外进行，避免持锁阻塞）。
	w := &askWaiter{done: make(chan struct{})}
	g.pendingAsk[key] = w
	g.mu.Unlock()

	prompt := fmt.Sprintf("高危命令: %s\n原因: %s\n", cmd, rule.explain)
	if len(hosts) > 0 {
		prompt += fmt.Sprintf("目标主机: %s\n", strings.Join(hosts, ", "))
	}
	prompt += "允许执行吗? [y/N/a=本会话全部放行] "
	ans, err := g.Operator.Ask(prompt, []string{"y", "n", "a"})

	// 计算结论并广播给等待的并发 goroutine（仅询问方写一次审计）。
	g.mu.Lock()
	if err != nil {
		w.err = fmt.Errorf("ops 安全守卫: 等待操作员确认失败: %w", err)
		delete(g.pendingAsk, key)
		g.mu.Unlock()
		close(w.done)
		return w.err
	}
	if strings.EqualFold(strings.TrimSpace(ans), "a") {
		g.allowAll = true
		g.approved[key] = true
		w.allowed = true
		g.record(tool, hosts, rule.name, cmd, "approved_all", &ans)
		g.fireApproved(cmd, hosts)
	} else if isAffirmative(ans) {
		g.approved[key] = true
		w.allowed = true
		g.record(tool, hosts, rule.name, cmd, "approved", &ans)
		g.fireApproved(cmd, hosts)
	} else {
		g.record(tool, hosts, rule.name, cmd, "rejected", &ans)
	}
	delete(g.pendingAsk, key)
	g.mu.Unlock()
	close(w.done)

	if w.allowed {
		return nil
	}
	return fmt.Errorf("ops 安全守卫: 操作员拒绝执行—— %s", cmd)
}

// CheckCommand 检查并裁决一条命令是否可执行（统一入口：命令风险审查
// 无条件先行，再按规则命中走策略裁决；未命中规则的只读命令放行）。
// remote_* 工具族与外部装配层的统一入口。
func (g *RiskyCommandGuard) CheckCommand(ctx context.Context, cmd string, hosts []string, tool string) error {
	return g.decideCommand(ctx, cmd, hosts, tool)
}

// CheckReadOnly 只读通道校验（verify 等只读执行通道用）：命令不得命中
// 任何高危规则——只读通道只允许"天然只读"的命令。命令风险审查先行
// （硬性禁止/自影响任何策略一致拒绝）；命中常规规则即拒绝（verify
// 应只读检查，含副作用命令的 verify 不执行）。kill -0 为进程存在性
// 检查（只读信号），放行。
func (g *RiskyCommandGuard) CheckReadOnly(cmd string, hosts []string) error {
	if v := g.reviewRisk(cmd, hosts); v != nil {
		return verdictError(v)
	}
	if rule := matchRiskyRule(cmd); rule != nil {
		if rule.name == "kill" && isKillZero(cmd) {
			return nil
		}
		return fmt.Errorf("ops 安全守卫: 命令命中高危规则 %s——只读通道拒绝（verify 必须为只读检查）: %s", rule.name, cmd)
	}
	return nil
}

// isKillZero 判断是否为 kill -0 <pid>（信号 0：进程存在性检查，只读）。
func isKillZero(cmd string) bool {
	tokens := strings.Fields(cmd)
	return len(tokens) >= 2 && baseName(tokens[0]) == "kill" && tokens[1] == "-0"
}

// fireApproved 触发操作员确认回调（approved/approved_all/session_allow）。
func (g *RiskyCommandGuard) fireApproved(cmd string, hosts []string) {
	if g.OnApproved != nil {
		g.OnApproved(cmd, hosts)
	}
}

// reviewRisk 命令风险审查（守卫实例版）：把 hosts 解析为连接事实后审查。
// hosts 为空（本地执行）→ 通道面跳过、工具链面生效；hosts 非空但
// ConnFacts 不可用 → 保守模式（按最脆弱通道 root+密码+22 判定，
// 无法确认保留通道即拒绝）。
func (g *RiskyCommandGuard) reviewRisk(cmd string, hosts []string) *RiskVerdict {
	if len(hosts) == 0 {
		return reviewCommandRisk(cmd, nil)
	}
	if g.ConnFacts == nil {
		return reviewCommandRisk(cmd, remoteConservativeFacts())
	}
	return reviewCommandRisk(cmd, g.ConnFacts(hosts))
}

// remoteConservativeFacts 远程目标但无法获知连接事实时的保守事实：
// 按最脆弱通道（root + 密码 + 22 端口）判定——无法确认保留通道即拒绝。
func remoteConservativeFacts() map[string]model.ConnFact {
	return map[string]model.ConnFact{"": {Host: "远程主机", User: "root", Auth: "password", Port: "22"}}
}

func (g *RiskyCommandGuard) record(tool string, hosts []string, rule, cmd, decision string, ans *string) {
	if g.Audit == nil {
		return
	}
	if tool == "" {
		tool = "terminal"
	}
	ev := audit.AuditEvent{
		Kind:     "guard",
		Tool:     tool,
		Args:     audit.SanitizeArgs(cmd),
		Hosts:    hosts,
		Decision: decision,
	}
	if ans != nil {
		ev.Result = *ans
	}
	if err := g.Audit.Write(ev); err != nil {
		fmt.Fprintf(os.Stderr, "ops audit: %v\n", err)
	}
}

// matchRiskyRule 返回第一条命中的规则；未命中返回 nil。
//
// 匹配顺序：先对原始命令串做动态规则检查（内容无法静态还原，如解码管道），
// 再拆分命令段（&&/||/; 分隔的每条命令都要审计）、逐段解包包装层后按常规
// 规则匹配。这样 `bash -c 'rm -rf /'`、`df -h; rm -rf /` 等包装/拼接形式
// 都无法绕过守卫，本地 terminal 与远端 remote_terminal 共用本函数，同步生效。

// sortHosts 排序去重（守卫提示用；与 remote 包实现独立）。
func sortHosts(hosts []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}
