package main

// tui_strings.go — TUI 界面文案集中地。
//
// 所有跨文件复用的用户可见文案（状态、提示、帮助、命令、欢迎语）在此
// 定义；业务域文本（工具结果摘要、错误原文等）保留在各处理点。为后续
// i18n 铺路：需要翻译的文案全部以常量/函数形式收敛，避免散落字面量。
//
// 文案风格约定：面向运维操作员，口语化、一致、有引导性——
//   1. 同一概念用同一词汇（任务/会话/主机/清单不混用）；
//   2. 状态词简洁（两到四字），提示语说明"能做什么"而非技术细节；
//   3. 带操作路径的提示给出具体按键或命令。

import (
	"strconv"
	"strings"

	"github.com/go-gocel/termagent/pkg/keymap"
)

// ── 状态标签（status bar 状态灯/主文本） ─────────────────────────────

const (
	statusStateReady   = "READY"
	statusStateRunning = "RUNNING"

	statusReadyWait   = "就绪，等待任务"
	statusReadyNew    = "已开启新会话"
	statusRunning     = "执行中"
	statusDone        = "任务完成"
	statusFailed      = "本轮失败"
	statusInterrupted = "已中断"
)

// runningStatusText 运行中状态主文本：当前任务 + 耗时（耗时由 tick 刷新）。
func runningStatusText(task string, dur string) string {
	return statusRunning + ": " + truncate(task, 28) + " · " + dur
}

// ── 快捷键提示行（输入框上方） ───────────────────────────────────────

const (
	// hintDefault 对话页提示：紧凑列出最高频操作。滚动需 Tab 聚焦后
	// 才生效（输入框聚焦时 ↑↓ 是光标移动），故标注 "Tab+"。
	hintDefault = " Enter 发送 · Ctrl+↑/↓ 历史 · Tab+↑↓/PgUp/PgDn 滚动 · Alt+1/2/3 切页 · Ctrl+P 命令 · ? 帮助"
	hintHosts   = " r 刷新清单 · p 探测连通性 · s 排序 · Enter 详情 · ←/→ 切页(Tab 聚焦) · ? 帮助"
	hintHelp    = " ?/Esc 返回 · PgUp/PgDn/↑↓/Home/End 滚动 · Ctrl+C 中断/退出"
)

// ── 输入框 ───────────────────────────────────────────────────────────

// inputPlaceholder 输入框占位：只留"做什么 + 怎么发"；历史/命令/帮助等
// 键位已在输入框上方的提示行展示，不重复占位。
const (
	inputPlaceholder = "输入运维/实施任务，Enter 发送…"
)

// welcomeText 欢迎语（未 init 时追加引导提示）。
func welcomeText(meta tuiMeta) string {
	text := "# gocode-ops\n\n在下方输入框直接下达运维任务：巡检、诊断、日志分析、服务处置、远程运维、部署实施。\n\n" +
		"- 高危命令执行前会先征求您的确认\n" +
		"- 远程命令输出与文件传输进度实时可见\n" +
		"- 需要全局体检时直接说（如「全面体检」），我会按需调用快检工具\n"
	if !meta.initialized {
		text += "\n> ⚠ 工作目录尚未初始化（缺少 .gocode/ 配置）：运行 `gocode-ops init -d " + meta.workDir + "` 可生成主机清单、环境约定、提示词模板与使用手册。\n"
	}
	return text
}

// ── 标签页标题 ───────────────────────────────────────────────────────

const (
	tabTitleChat  = "💬 对话"
	tabTitleTools = "⚙ 工具调用"
	tabTitleHosts = "🌐 远程主机"
	hostsTabIndex = 2 // 与 tabs 顺序一致（对话/工具/主机）
	chatTabIndex  = 0
	toolsTabIndex = 1
)

// tabTitleToolsWithCount 工具页标题（带调用计数）。
func tabTitleToolsWithCount(n int) string {
	return tabTitleTools + " (" + strconv.Itoa(n) + ")"
}

// tabTitleHostsWithOnline 主机页标题（带在线统计；未探测时不带）。
func tabTitleHostsWithOnline(online, total int, probed bool) string {
	if !probed {
		return tabTitleHosts
	}
	return tabTitleHosts + " (" + strconv.Itoa(online) + "/" + strconv.Itoa(total) + " 在线)"
}

// ── 表格 ─────────────────────────────────────────────────────────────

const (
	toolTableEmptyText = "还没有工具调用记录，任务执行后会显示在这里"
	hostTableEmptyText = "主机清单为空：运行 gocode-ops init 生成 hosts.yaml"
	colTitleTool       = "工具"
	colTitleTarget     = "目标"
	colTitleArgs       = "参数"
	colTitleStatus     = "状态"
	colTitleDur        = "耗时"
	colTitleHost       = "主机"
	colTitleAddress    = "地址"
	colTitleUser       = "用户"
	colTitleAuth       = "认证"
)

// 工具行状态文本（保持精确匹配：测试与导出都依赖这些字面量）。
const (
	toolStatusRunning   = "运行中"
	toolStatusDone      = "完成"
	toolStatusFailed    = "失败"
	toolStatusInterrupt = "已中断"
)

// ── 提示通知（toast） ────────────────────────────────────────────────

const (
	toastLiveDropped    = "部分实时输出未匹配到运行中的工具，未展示"
	toastLiveOver       = "输出过长，后续内容省略"
	toastQueueBusy      = "当前有任务在执行，请稍后再试"
	toastUnknownCmd     = "未知命令，/help 查看可用命令"
	toastHostsRefreshed = "主机清单已刷新"
	toastProbeDone      = "连通性探测完成：%d/%d 台在线"
	toastSortByName     = "已按主机名排序"
	toastSortByAddress  = "已按地址排序"
	toastSortOff        = "已取消排序"
	toastCopied         = "已复制 %s 的结果"
	toastCopyNothing    = "还没有可复制的内容"
	toastCopyFailed     = "复制失败：%s"
	toastExported       = "会话已导出：%s"
	toastExportFailed   = "会话导出失败：%s"
	toastTransferDone   = "%s [%s] %s 完成（%s）"
	toastBufferOverflow = "事件更新过快，部分过程输出被丢弃"
)

// ── 操作员提问弹窗 ───────────────────────────────────────────────────

const (
	askTitle           = " ⚠ 操作员确认 "
	askCustomLabel     = " ✏️ 补充说明："
	askCustomHint      = "  [Enter] 提交 · [Esc] 返回选项列表"
	askOtherEntry      = " ✏️ 其他（自行输入回答）"
	askHintSelect      = "  [↑/↓] 选择 · [Enter] 确认 · [Esc] 取消"
	askHintSelectYN    = "  [↑/↓] 选择 · [y] 是 · [n] 否 · [Enter] 确认 · [Esc] 取消"
	askTruncatedSuffix = "\n  …问题过长，已折叠展示（完整内容见对话区）"
	askMaxLines        = 20
)

// ── 内置命令 ─────────────────────────────────────────────────────────

const (
	cmdLineHelp   = "/help"
	cmdLineNew    = "/new"
	cmdLineHosts  = "/hosts"
	cmdLineTokens = "/tokens"
	cmdLineExport = "/export"
	cmdLineExit   = "/exit"
)

// ── 帮助页（markdown 源，渲染进帮助面板） ────────────────────────────

// helpMarkdown 生成帮助页 markdown 内容（键位/命令/配置/示例）。
func helpMarkdown(km *keymap.Keymap) string {
	var b strings.Builder
	b.WriteString("## gocode-ops 帮助\n\n")
	b.WriteString("在下方输入框用自然语言描述运维任务，Enter 发送。按 `?` 或 `Esc` 关闭本页。\n\n")
	b.WriteString("### 键位\n\n")
	for _, kb := range km.Help() {
		b.WriteString("- `" + kb.Key + "` — " + kb.Help + "\n")
	}
	b.WriteString("- `r` — 刷新主机清单（远程主机页）\n")
	b.WriteString("- `p` — 探测主机连通性（远程主机页）\n")
	b.WriteString("- `s` — 切换主机排序（名称/地址/取消）\n")
	b.WriteString("- `c` — 复制最近一次工具调用的结果\n")
	b.WriteString("- `Alt+1/2/3` — 直接切换对话/工具/主机页\n\n")
	b.WriteString("### 内置命令\n\n")
	for _, c := range helpCommands() {
		b.WriteString("- `" + c.line + "` — " + c.desc + "\n")
	}
	b.WriteString("\n### 配置文件（.gocode/，gocode-ops init 生成）\n\n")
	for _, c := range helpConfigFiles() {
		b.WriteString("- `" + c.line + "` — " + c.desc + "\n")
	}
	b.WriteString("\n### 本地运维示例\n\n")
	for _, s := range helpExamplesLocal() {
		b.WriteString("- " + s + "\n")
	}
	b.WriteString("\n### 远程运维示例\n\n")
	for _, s := range helpExamplesRemote() {
		b.WriteString("- " + s + "\n")
	}
	b.WriteString("\n### 部署实施示例\n\n")
	for _, s := range helpExamplesDeploy() {
		b.WriteString("- " + s + "\n")
	}
	b.WriteString("\n按 `?` 或 `Esc` 返回\n")
	return b.String()
}

type helpCommand struct {
	line string
	desc string
}

func helpCommands() []helpCommand {
	return []helpCommand{
		{cmdLineHelp, "打开帮助"},
		{cmdLineNew, "清空上下文，开始新会话"},
		{cmdLineHosts, "切换到远程主机页"},
		{cmdLineTokens, "显示累计 token 用量"},
		{cmdLineExport, "导出会话记录到 .gocode/sessions/"},
		{cmdLineExit, "退出程序"},
	}
}

func helpConfigFiles() []helpCommand {
	return []helpCommand{
		{"hosts.yaml", "远程主机清单（凭证所在，模型不可见）"},
		{"AGENTS.md", "环境信息约定（自动注入）"},
		{"prompt.assistant.md", "交互式运维助手提示词覆盖（可改写）"},
		{"prompt.engine.md", "全自动运维引擎提示词覆盖（可改写）"},
		{"theme.json", "TUI 主题调色板（可选）"},
		{"helper.md", "完整使用手册"},
	}
}

func helpExamplesLocal() []string {
	return []string{
		`"巡检系统健康"`,
		`"磁盘快满了，定位大文件并给出清理方案"`,
		`"nginx 最近报 502，帮我查日志找根因"`,
		`"检查 mysql 服务状态，异常则按预案重启"`,
	}
}

func helpExamplesRemote() []string {
	return []string{
		`"列出远程主机，并对 web-01 执行健康巡检"`,
		`"对 all 主机批量执行磁盘巡检"`,
		`"把 ./build/app.tar.gz 上传到 web-01 的 /opt/app/"`,
		`"把 db-01 的 /var/log/mysql/error.log 下载到本地 logs/"`,
	}
}

func helpExamplesDeploy() []string {
	return []string{
		`"把本地 dist 目录部署到 web-01 的 /srv/www，先备份旧版本，部署后验证服务"`,
		`"在 all 主机安装 nginx 并启动，验证 80 端口监听"`,
	}
}
