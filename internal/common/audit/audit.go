package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-gocel/gocel-core/core/kernel"
	"github.com/go-gocel/gocode-ops/internal/common/model"
)

// AuditFileName 是运维操作审计文件（JSON lines）。
const AuditFileName = "ops-audit.log"

// AuditEvent 是一条审计记录。
type AuditEvent struct {
	Time   time.Time `json:"time"`
	Tool   string    `json:"tool"`
	Args   string    `json:"args,omitempty"`
	Result string    `json:"result,omitempty"`
	Error  string    `json:"error,omitempty"`
	// Hosts 目标主机别名（守卫决策/远程工具调用；本地执行为空）。
	Hosts []string `json:"hosts,omitempty"`
	// Kind 标注审计来源：tool=工具调用，guard=高危命令守卫决策。
	Kind string `json:"kind,omitempty"`
	// Decision 是守卫决策：approved / approved_all / session_allow /
	// rejected / hard_blocked / policy_allow / policy_deny / auto_allow /
	// auto_allowed。
	Decision string `json:"decision,omitempty"`
	// FindingID 处置审计关联的故障（respond 来源；guard/tool 来源为空）。
	// 复盘"这条命令处置了哪个故障的哪个动作"的追溯键——此前 respond
	// 审计只有命令文本，无法回溯。
	FindingID  string `json:"finding_id,omitempty"`
	ActionName string `json:"action_name,omitempty"`
}

// AuditLog 把审计事件追加写入 JSON lines 文件，并发安全。
type AuditLog struct {
	mu   sync.Mutex
	path string
}

// NewAuditLog 在 <workDir>/.gocode/ops-audit.log 创建审计日志（与状态
// json、配置清单同目录）。
func NewAuditLog(workDir string) (*AuditLog, error) {
	dir := model.ConfigDir(workDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("audit: 创建审计目录失败: %w", err)
	}
	path, err := filepath.Abs(filepath.Join(dir, AuditFileName))
	if err != nil {
		return nil, fmt.Errorf("audit: 解析路径失败: %w", err)
	}
	return &AuditLog{path: path}, nil
}

// Path 返回审计文件路径。
func (a *AuditLog) Path() string { return a.path }

// auditRotateSize 审计日志轮转阈值：超过即把当前文件改名为 .1 并新建
// （长驻进程/引擎长跑不无限增长，P3 修复）。10MB ≈ 数万条审计记录。
const auditRotateSize = 10 << 20

// Write 追加一条审计记录。审计失败只影响留痕，不阻断 agent。
func (a *AuditLog) Write(ev AuditEvent) error {
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	ev.Time = ev.Time.UTC()
	line, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("audit: 序列化失败: %w", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// 0600：审计含命令原文与参数，仅属主可读（世界可读会把凭证/业务
	// 细节暴露给同机其他用户）。
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit: 打开失败: %w", err)
	}
	defer f.Close()
	// 大小轮转：追加前检查（stat 比 O_APPEND 写便宜；轮转只在超阈值时
	// 发生一次，重命名后继续追加到新文件）。
	if fi, serr := f.Stat(); serr == nil && fi.Size() > auditRotateSize {
		f.Close()
		if rerr := os.Rename(a.path, a.path+".1"); rerr == nil {
			f, err = os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
			if err != nil {
				return fmt.Errorf("audit: 轮转后打开失败: %w", err)
			}
			defer f.Close()
		} else {
			// 轮转失败（权限/占用）：继续写原文件（留痕优先于轮转）。
			f, err = os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
			if err != nil {
				return fmt.Errorf("audit: 重开失败: %w", err)
			}
			defer f.Close()
		}
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("audit: 写入失败: %w", err)
	}
	return nil
}

// AuditModule 记录每一次工具调用到审计日志。
//
// 截断上限取日志留痕与防刷屏的平衡：args 2000 / result 4000 / error
// 2000 字符，测试阶段足以从审计还原问题现场（旧值 300~400 太小，
// 命令输出几乎都被截断）。
type AuditModule struct {
	Log *AuditLog
}

// Register 挂接 AfterToolCall 钩子。
func (m *AuditModule) Register(rt kernel.HookRegistrar) {
	rt.OnToolResult(m.onToolResult)
}

func (m *AuditModule) onToolResult(ctx context.Context, info *kernel.ToolCallInfo) (context.Context, *kernel.ToolCallInfo, error) {
	ev := AuditEvent{
		Kind:   "tool",
		Tool:   info.Name,
		Args:   truncate(SanitizeArgs(info.Args), 2000),
		Result: truncate(info.Result, 4000),
	}
	if info.Error != nil {
		ev.Error = truncate(info.Error.Error(), 2000)
	}
	// 审计失败只打 stderr，不能中断 agent 循环。
	if err := m.Log.Write(ev); err != nil {
		fmt.Fprintf(os.Stderr, "ops audit: %v\n", err)
	}
	return ctx, info, nil
}

// IsToolError 判断工具结果内容是否为失败负载。gocel 约定工具执行失败
// （守卫拦截/执行报错/结果拒绝）时结果以 {"error": ...} 开头；事件流
// 不携带 error 字段，界面与日志用内容前缀区分成败。
func IsToolError(content string) bool {
	return strings.HasPrefix(strings.TrimSpace(content), `{"error":`)
}

// truncate 保留前 n 个 rune，超长加省略号。
func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "…"
}

// ── 审计参数脱敏 ────────────────────────────────────────────────────────

var (
	// auditURLPassRe URL 内嵌明文凭证（scheme://user:pass@host）。
	auditURLPassRe = regexp.MustCompile(`://[^/@\s]+:[^/@\s]+@`)
	// auditSecretRe 常见密码/令牌/用户参数（--password/-p/-w/-u/--api-key/
	// --token/--secret 后值，含 -psecret 粘连写法）。
	auditSecretRe = regexp.MustCompile(`(?i)(?:--password|--passwd|--api-key|--token|--secret|-p|-w|-u)(?:=|\s+)\S+|(?i)(?:-p|-w)\S+`)
	// auditAuthHdrRe 认证/会话头（Authorization/Cookie/API Key 后整段值；
	// 审计中过度脱敏可接受，漏掩不可接受）。
	auditAuthHdrRe = regexp.MustCompile(`(?i)(Authorization|Cookie|X-Api-Key|X-Auth-Token|Api-Key|Access-Token|Private-Token)\s*[:=].*`)
	// auditEnvSecretRe env 赋值形态的凭证（PGPASSWORD=secret 等——参数类
	// 规则不覆盖 NAME=value 前缀；值整体掩掉，变量名保留便于排查）。
	auditEnvSecretRe = regexp.MustCompile(`(?i)\b(PGPASSWORD|MYSQL_PWD|MYSQL_ROOT_PASSWORD|REDIS_PASSWORD|MONGODB_URI|DATABASE_URL|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|GITLAB_TOKEN|NPM_TOKEN|DOCKER_PASSWORD|KUBECONFIG|KUBERNETES_SERVICE_ACCOUNT_TOKEN)\s*=\s*\S+`)
)

// SanitizeArgs 脱敏审计参数中的明文凭证：URL 内嵌 user:pass、密码/令牌
// 参数与认证头后值替换为 ***——审计文件仅属主可读是纵深，命令原文本身
// 不该带凭证（R14 教训：echo 注释里的 /root/.ssh 都会进审计）。
// 引擎处置审计（respond 通道）同样复用。
func SanitizeArgs(s string) string {
	s = auditURLPassRe.ReplaceAllString(s, "://***@")
	s = auditAuthHdrRe.ReplaceAllString(s, "$1 ***")
	s = auditEnvSecretRe.ReplaceAllString(s, "$1=***")
	return auditSecretRe.ReplaceAllStringFunc(s, func(m string) string {
		trimmed := strings.TrimSpace(m)
		if i := strings.IndexAny(trimmed, "= \t"); i > 0 {
			return trimmed[:i] + " ***" // --password=xxx / -p xxx 形态
		}
		return trimmed[:2] + " ***" // -psecret 粘连形态
	})
}
