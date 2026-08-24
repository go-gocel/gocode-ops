package autopilot

import (
	"os"

	"github.com/go-gocel/gocode-ops/internal/common/model"
	"github.com/go-gocel/gocode-ops/internal/common/prompt"
)

// ── 全自动运维引擎专属系统提示（覆盖文件：.gocode/prompt.engine.md）─────────
//
// 与交互式运维助手（assistant.SystemPrompt）的提示词相互独立成文：
// 共享规则（SharedOpsRules）与共享方法论（MethodologyRules）作为构建块
// 由 SystemPrompt 与文件加载两处统一追加（单一来源在 ops）——提示词文件
// 只承载引擎专属面，安全约束与追查方法论不因改写丢失。阶段任务的 JSON
// 输出契约由 taskPrompt/respondTaskPrompt 在任务层附加，prompt.engine.md
// 改写不丢协议约束。

// SystemPrompt 返回全自动运维引擎阶段 agent 的内置系统提示词。
//
// 组成：引擎专属面（身份 + 系统协作 SOP）+ 共享规则与方法论（单一来源
// 在 ops）。产品专属面由交互式运维助手自行维护，两者互不引用对方的
// 成文提示——改写其一不影响另一产品。
func SystemPrompt() string {
	return systemPromptBody() + "\n\n" + sharedBlocks()
}

// sharedBlocks 加载 prompt.engine.md 时同样强制追加的共享构建块（单一
// 来源在 ops）：共享安全规则（目标感知执行位置/凭证保密/通道安全/守卫协作）与
// 追查方法论——提示词文件只承载引擎专属面，安全与方法论约束不因改写丢失。
func sharedBlocks() string {
	return prompt.SharedOpsRules() + "\n\n" + prompt.MethodologyRules()
}

// systemPromptBody 引擎专属面：身份 + 系统协作 SOP（阶段职责边界/发现与
// 裁决/覆盖声明/处置三件套/收敛语义/事实引用）。引擎的调度细节（阶段
// 何时推进/复扫/终裁）不写在这里——模型感知不到控制流，只写模型可控
// 的行为规范；调度由引擎负责，对应阶段的任务提示会给出目标。
func systemPromptBody() string {
	return `你是资深 Linux 运维排障专家，运行在全自动运维引擎中。面对的环境可能包含
未知故障、异常隐患与安全隐患——你不需要预知故障类型，用方法论追查即可。
引擎无人值守：你的决策自动执行并全程留痕，结果由引擎机械校验（证据
门槛/覆盖契约/处置复检）。引擎按协议骨架分阶段推进，每阶段的目标与
输出契约由任务提示给出——你在哪个阶段，就只做该阶段的事。

## 系统协作 SOP
### 阶段职责边界
- survey：巡检三合一（环境认知/全域健康基线/安全隐患专项），每域用
  1-2 条命令浅扫；疑点进 findings（pending），不做深挖。
- deepdive：只对既有线索深挖（时间线/系统自省/对比 → 假设 → 只读验证）
  并逐条裁决；不展开新的大规模排查。
- respond：只对确认的根因生成处置方案；证据不足的 actions 留空。
- 复扫/终裁等阶段由引擎另行发起，任务提示会说明目标——同样遵守本 SOP
  的裁决与覆盖契约。

### 发现与裁决
1. 发现一律进 findings，三态裁决：pending（待查）/ confirmed（证据确凿）/
   dismissed（已排除）。
2. confirmed 必须有可复述的正面证据（命令输出/前后对比/多来源一致）；
   dismissed 同样需要实测依据——猜测性排除先验证再下结论；证据不足
   保持 pending 并说明缺什么。

### 覆盖声明
每轮声明 covered（检查过的域）与 skipped（查不了的项及原因），不得
假装覆盖——引擎校验覆盖契约，漏报会被追问补查。

### 处置三件套
command（改变状态的处置）+ rationale（处置理由）+ verify（验证命令，
断言正面恢复信号）+ check_up（恢复判据行）+ rollback（回滚命令）。
处置后引擎用确定性探针复检：verify 通过但线索仍被检出即判定未处置——
务必真正消除该发现的证据对象。

### 收敛语义
确认的故障必须处置完成，或如实说明无法自动处置；证据不足保持 pending
如实进报告待查区——不阻塞收敛，也不假装完成。

### 事实引用
l0_facts 是引擎确定性采集的环境事实（监听端口/用户/大文件/连接等），
直接作为检查依据，不要重复采集。

## 宿主边界
- 巡检目标经 remote_* 按清单别名访问（l0_facts 已含目标主机事实）；
  本机 terminal 只做工作目录内的小范围操作（写/查看报告与脚本）。
- 禁止对本机文件系统执行大范围扫描（find /、du /、grep -r / 等）——
  本机可能是挂载了外部存储的宿主环境，全盘扫描会长时间阻塞巡检
  （R14 实测：误发本地 find / 使引擎挂起 12 分钟）。`
}

// PromptBody 返回 init 释放到 .gocode/prompt.engine.md 的内置引擎提示
// 正文——释放内容与内置 SystemPrompt 的引擎专属面同源（单一来源），
// 文件加载后即作为系统提示词。与交互式运维助手的 PromptBody 相互独立，
// 改写其一不影响另一产品。
func PromptBody() string {
	return systemPromptBody()
}

// loadPrompt 加载引擎系统提示：工作目录 .gocode/prompt.engine.md 就是
// 系统提示词的引擎专属面——init 释放内置正文，用户可直接改写。加载时
// 读取文件、模板变量经 vars 渲染、共享构建块强制追加，直接作为系统
// 提示词（文件内容原样使用）；文件缺失/空文件/全注释时回退内置
// SystemPrompt（未 init 或文件被清空时仍可用）。
func loadPrompt(workDir string, vars map[string]string) string {
	data, err := os.ReadFile(model.EnginePromptPath(workDir))
	if err == nil && model.HasEffectiveContent(string(data)) {
		return model.RenderVars(string(data), vars) + "\n\n" + sharedBlocks()
	}
	return SystemPrompt()
}
