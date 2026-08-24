package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/go-gocel/gocel-core/core/kernel"
	"github.com/go-gocel/gocel/llm"

	"github.com/go-gocel/gocode-ops/internal/assistant"
	"github.com/go-gocel/gocode-ops/internal/autopilot"
	"github.com/go-gocel/gocode-ops/internal/common/guard"
)

// ── 模型构建 ─────────────────────────────────────────────────────────

// defaultModelName 固定模型名（CLI 不暴露模型参数）。
const defaultModelName = "deepseek-v4-flash"

// defaultProvider 固定提供商：当前版本仅支持 deepseek。多供应商支持
// 后续经 .gocode 配置文件提供（UI 切换 → 内部实现 → 配置文件整链开发），
// 现阶段 CLI 只保留 -p 参数做入参校验。
const defaultProvider = "deepseek"

// buildModel 构建模型。API Key 一律从环境变量 DEEPSEEK_API_KEY 读取
// （空 Key 由 SDK 侧在调用时报错，保持启动不阻塞）。
func buildModel(provider, modelName, apiKey string) (kernel.Model, error) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "deepseek":
		key := strings.TrimSpace(apiKey)
		if key == "" {
			key = os.Getenv("DEEPSEEK_API_KEY")
		}
		return llm.NewDeepSeekModel(modelName, key, nil), nil
	default:
		return nil, fmt.Errorf("未知提供商 %q（当前版本仅支持 deepseek；多供应商支持后续经 .gocode 配置文件提供）", provider)
	}
}

func parsePolicy(s string) (guard.Policy, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "ask":
		return guard.PolicyAsk, nil
	case "allow":
		return guard.PolicyAllow, nil
	case "deny":
		return guard.PolicyDeny, nil
	}
	return "", fmt.Errorf("无效的 --risky 值 %q（可选: ask/allow/deny）", s)
}

// ── 工作目录模板 ─────────────────────────────────────────────────────

// inventoryTemplate 远程主机清单模板（凭证所在，0600，模型不可见）。
const inventoryTemplate = `# gocode-ops 远程主机清单
# 位于工作目录 .gocode/hosts.yaml（init 生成）。凭证（用户/密码/私钥）
# 仅存本机，模型永远不可见；请勿把本文件提交到 git。
# 字段说明:
#   name         主机别名（模型只能看到这个名字）
#   address      地址，可带端口（默认 22）
#   user         登录用户
#   key_file     私钥路径（推荐）；password 二选一
#   password     明文密码（不推荐，建议用 key_file）
#   host_key_check 是否校验 known_hosts（默认 true；校验失败提示会区分
#                  “无该主机条目/指纹不匹配”，按提示在 gocode-ops 同环境
#                  以与 address 一致的名字录入指纹；无法可靠录入时可设
#                  false，需自评 MITM 风险）
#
# 配置后即可使用全部远程能力（界面「远程主机」页可查看清单与连通性）：
#   remote_terminal  单台执行命令（输出实时回传）
#   remote_batch     多台批量执行
#   remote_upload    上传文件/目录（进度实时可见）
#   remote_download  下载文件/目录（进度实时可见）
#   remote_file      远端文件信息/目录列举
#   remote_list      模型侧主机清单（别名+认证方式）
#   remote_copy      远端↔远端复制（本机 SFTP 双程中转）
hosts:
  - name: web-01
    address: 10.0.0.11
    user: root
    key_file: ~/.ssh/id_ed25519
  - name: db-01
    address: 10.0.0.12:22
    user: ops
    key_file: ~/.ssh/id_rsa
`

// assistantPromptBody 交互式运维助手系统提示词正文（.gocode/prompt.assistant.md）：
// init 释放的内置交互提示产品专属面（{{host}}/{{workdir}} 占位，加载时
// 渲染；交互与安全规则由程序按当前策略追加），由 assistant 包单一来源提供。
func assistantPromptBody() string { return assistant.PromptBody() }

// enginePromptBody 全自动运维引擎系统提示词正文（.gocode/prompt.engine.md）：
// init 释放的引擎专属面（阶段任务提示与输出契约由引擎另行附加），
// 由 autopilot 包单一来源提供。
func autopilotPromptBody() string { return autopilot.PromptBody() }
