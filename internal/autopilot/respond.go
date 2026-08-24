package autopilot

// respond.go — 处置方案的模型侧契约：生成提示与解析（执行在
// common/remediate——三件套契约执行/验证/回滚/复检是两种形态共用的
// 处置能力，本文件只负责"让模型产出方案"的协议编排）。

import (
	"fmt"
	"strings"

	"github.com/go-gocel/gocode-ops/internal/common/prompt"
	"github.com/go-gocel/gocode-ops/internal/common/remediate"
)

// ResponsePlans holds batch remediation plans generated in one model call for
// multiple confirmed findings.
// ResponsePlans 批量处置方案（一次模型调用为多个已确认故障生成方案，
// 减少 LLM 调用次数——逐故障调用在故障多时耗时线性增长）。
type ResponsePlans struct {
	Plans []remediate.Plan `json:"plans"`
}

// parseResponsePlans 解析模型输出的批量处置方案（经 parseModelJSON 语法容错）。
// 模型偶尔把"plans 为数组"误写成顶层裸数组（[...] 而非 {"plans":[...]}）——
// 这是契约层的输出形态适配，不是语法修复（语法修复统一在 jsonx），数组
// 元素即 plans。
func parseResponsePlans(content string) (*ResponsePlans, error) {
	var ps ResponsePlans
	objErr := parseModelJSON(content, &ps)
	if objErr == nil && len(ps.Plans) > 0 {
		return &ps, nil
	}

	// 裸数组形态：元素即 plans。
	var arr []remediate.Plan
	if arrErr := parseModelJSON(content, &arr); arrErr == nil {
		if len(arr) == 0 {
			return nil, fmt.Errorf("处置方案为空（plans 为空）")
		}
		return &ResponsePlans{Plans: arr}, nil
	}

	if objErr == nil {
		return nil, fmt.Errorf("处置方案为空（plans 为空）")
	}
	return nil, fmt.Errorf("处置方案解析失败: %w", objErr)
}

// respondTaskPrompt 构造 respond 阶段任务提示。输出契约只含处置方案
// （remediate.Plan）——与阶段小结（PhaseSummary）分离，模型只需满足
// 一个 schema，不再被两套不兼容的契约夹击。
func respondTaskPrompt(goal, state string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## 当前阶段：%s\n\n%s\n\n", PhaseRespond, goal)
	if state != "" {
		fmt.Fprintf(&b, "## 已知状态（工作区）\n%s\n\n", state)
	}
	b.WriteString(fmt.Sprintf(`## 输出契约
只输出一个 JSON 对象（不要输出 JSON 以外的内容）：
{
  "plans": [为上面列出的每个故障各输出一个 plan：
    {"finding_id":"<故障 ID>","actions":[可选，每个动作必须同时提供全部六个字段：
      {"name":"<动作名>","command":"<执行命令>","rationale":"<处置理由>",
       "verify":"<处置后验证命令>","check_up":"<验证输出中表示恢复的完整行文本>",
       "rollback":"<验证失败回滚命令>"}]}]
}
规则：
1. 为上面列出的每个故障各输出一个 plan（全覆盖）；无法处置的（证据
   不足/已恢复）也要输出该 plan 且 actions 置空数组 []——引擎会把
   空方案按处置机制升级为人工工单（自动装配证据包，见报告工单区），
   不会当作"无需处理"静默跳过；
2. 每个 plan 必须带正确的 finding_id。首选直接复制上面 ### 标题中的
   ID（确定性 ID：主机/信号/对象哈希，同一故障恒同 ID、无随机数字）；
   若无法精确复制，用"信号名:子键"格式（如 exposed_listen:telnet.socket:23，
   直接照抄上面"子键"字段），多个同信号故障必须以此区分；无子键的
   用纯信号名（引擎按信号/子键定位）。跨信号/找不到目标的方案不会
   被误配执行——宁可不执行也不张冠李戴；
3. 命令由引擎经安全守卫执行，直接给出可执行命令即可；
4. command 必须是**改变状态**的处置（删除/恢复/修改/终止/重启等）；
   不得用只读检查命令（echo/cat/grep/ss 等无重定向输出）充当处置——
   终态确认属于 verify 字段，状态变更才属于 command（R8 教训：纯验证
   命令被标已处置，配置残留实际未恢复）；
5. verify 必须断言正面恢复信号——错误/失败文本不作验证证据。删除类
   动作用 test ! -f <路径> && echo 已删除 这类形式（不要用 ls 的报错
   当成功判据）；verify 命令本身必须退出码为 0（末尾用 ; echo ...
   或 || echo ... 收敛退出码）；check_up 写你期望出现的正面输出行/短语。
6. 每个 plan 的 action 必须只处置该 finding 自己的证据对象（文件路径/
   进程 PID/配置行）——同域名/同批次的多个 finding 分别处置时不得
   张冠李戴（R9/R10 实测：A finding 的动作删了 B 的证据对象）；
   rationale 写明目标对象，verify 断言该对象的状态变化。
7. 执行后引擎会用确定性探针复检：verify 通过但线索仍存在会被判定
   未处置并回灌修正——请确保 command 真正消除该 finding 的证据对象
   （不要只做表面动作或改无关对象）。
8. 来源收窄类处置（AllowUsers/防火墙来源/IP 白名单）必须**先枚举全部
   合法来源**（近期成功登录源 + 当前连接源 + 运维主机清单），不得用
   单次观测到的单个 IP 收窄——动态 IP/DHCP 环境下单 IP 白名单=锁死
   风险；首选密钥认证通道（与 IP 无关），或子网级 Match/防火墙来源
   区。认证/网络类变更执行后引擎会用**新连接**做自通道校验，校验
   失败自动回滚——请为每个动作提供可自动执行的 rollback（如配置
   备份恢复 + reload）。
9. 密码策略类处置（login.defs/chage/passwd）是认证面变更：执行后引擎
   立即用新连接自检，任何"导致引擎当前登录方式不可用"的方案都会被
   回滚——chage -M <天数> 仅设最大有效期会基于密码**最后修改日**
   计算过期：对 lastchg 为 1969（永不过期）的存量账户必须同时重置
   起始日（chage -d $(date +%%F) -M 90 <user>），否则立即过期、SSH
   密码登录被 PAM 拒绝（无 TTY 无法改密）——引擎与操作员同时锁死。
   改密码类动作同理：不得对当前登录账户执行 passwd -e/-d 类立即过期
   操作；rollback 必须能撤销该动作的**状态变更**（如 chage 类动作的
   rollback 要恢复原 lastchg/MaxDays，配置备份恢复无效）。
10. 只输出上面"###"列出的故障的方案：其他故障（不在本批列表中的）
   即使你已掌握其情况也不要输出——越批方案会被引擎丢弃，且可能
   触发整批重试空转。本批每个故障恰好一个 plan，不重不漏。
11. 本地控制台会话（ttyN/本地终端登录，非 SSH 网络会话）：操作者
   身份无法远程确认时**禁止自动终止**——可能是真实管理员在控制台
   工作；终止不可逆且无法回滚。此类会话转人工工单（actions 置空
   []），由人工核实后决定，除非有确凿的攻击证据（如已知后门账户
   的登录）才可处置。
12. 账户类处置（userdel/usermod/passwd -l 等）只针对**有明确创建
   证据**的账户：secure/messages 日志中存在 useradd 事件（如
   "useradd[pid]: new user name=X"）或账户文件 mtime 与入侵窗口
   一致的运行期新建账户。**系统供应期预设账户**（无任何 useradd
   日志记录、uid 非 0、kickstart/镜像/首次部署自带）一律转人工
   工单（actions 置空），不得自动删除——误删合法账户不可逆，且
   供应期账户可能承载运维通道（历史实测：无 useradd 记录的预设
   账户被当后门删除，实际是部署脚本创建）。
13. kill/终止类动作必须先核验目标身份再执行：用 pgrep/ps/ss 拿到
   目标 PID 与命令行，确认与 finding 证据对象一致（PID、启动时间、
   完整命令行匹配）后才 kill——**不得凭服务名/端口宽匹配**（
   pkill -f 'nginx' 会把同名业务进程全杀；kill 错对象 = 正常服务
   不可逆下线）。核验与 kill 拆成两个动作（先 pgrep 输出证据，
   verify 阶段用 PID 精确断言），rollback 说明如何恢复该服务。
14. 防火墙/网络处置的等保"默认拒绝"语义：**只针对管理面**——管理
   端口（22 等）限制为管理来源（运维网段/密钥认证）；**业务端口
   必须按业务需要保持放行**。工作区中的 business_ports 事实是
   确定性业务端口清单（监听中且非管理面进程：web 80/443、db
   3306 等）——防火墙/网络处置方案必须显式放行清单中每个端口。
   禁止"整机默认拒绝 + 只放行引擎来源"的收窄——它会锁死全部
   业务流量（业务中断），而引擎自己的通道仍通（自通道校验不
   感知；引擎会在处置后做业务面校验，非处置目标端口消失将强制
   回滚）。无法确认业务端口清单时转人工工单。
15. 命令纪律（P0 修复）：每条 command/verify 必须服务于处置、验证或
   证据采集——禁止无效果命令（echo 文案、true、无输出无副作用的
   空转命令）充当动作；执行前先想清楚它改变或断言了什么。

%s`, prompt.ChannelSafetyRules))
	return b.String()
}
