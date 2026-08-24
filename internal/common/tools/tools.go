package tools

import (
	"time"

	"github.com/go-gocel/gocel-core/core/kernel"
	"github.com/go-gocel/gocel/tools/git"
	"github.com/go-gocel/gocel/tools/glob"
	"github.com/go-gocel/gocel/tools/grep"
	"github.com/go-gocel/gocel/tools/multiedit"
	"github.com/go-gocel/gocel/tools/read"
	"github.com/go-gocel/gocel/tools/shell"
	"github.com/go-gocel/gocel/tools/trash"
	"github.com/go-gocel/gocel/tools/write"
)

// terminal 超时策略（注入 gocel shell 工具）：运维命令普遍比编码场景重
// （安装/编译/迁移/大包解压），默认 60s；单次上限 10m，小时级任务走
// task_run 后台工具族。
const (
	TerminalDefaultTimeout = 60 * time.Second
	TerminalMaxTimeout     = 10 * time.Minute
)

// AllTools 返回 Linux 运维领域的工具集。
//
// 设计原则：命令优先，工具最小化。巡检、诊断、日志、服务状态等全部
// 通过 terminal 直接执行 Linux 命令完成——模型对命令的掌握远好于任何
// 薄封装，且输出不受固定解析器裁剪。领域专属工具只保留 shell 没有
// 替代品的能力，远程能力按粒度拆分为工具族（单机/批量/上传/下载/
// 文件信息/清单）：
//
//   - terminal：本机 shell（gocel shell 工具，超时参数化：默认 60s/上限
//     10m，经 shell.WithDefaultTimeout/WithMaxTimeout 注入）；
//   - git_*：本机 git 全套操作（status/diff/log/blame/show/commit/checkout/
//     branch/pull/push，gocel git 工具族原生实现，不依赖 git 二进制——
//     未安装 git 的环境同样可用）；
//   - task_run / task_status / task_stop：后台长任务（gocel shell 工具族，
//     小时级任务，日志落工作目录 tasks/）；
//   - remote_terminal：单台远端执行命令（与本地 terminal 逻辑一致）；
//   - remote_batch：多台批量执行；
//   - remote_upload / remote_download：SFTP 文件传输（带进度）；
//   - remote_file：远端文件信息/目录列举；
//   - remote_list：模型可读的主机清单；
//   - remote_copy：远端↔远端复制（本机 SFTP 双程中转，集群同步/配置分发）；
//   - ask_operator：执行中向操作员提问（信息补充/方案选择/处置确认），
//     shell 没有等价物；
//   - 安全与留痕不依赖工具而是守卫模块：RiskyCommandGuard 拦截高危
//     terminal/task_run 命令并要求操作员确认，AuditModule 记录全部调用。
func AllTools(operator Operator, remote RemoteExecutor, guard *RiskyCommandGuard) []kernel.Tool {
	var tools []kernel.Tool
	tools = append(tools, read.AllTools()...)
	tools = append(tools, write.AllTools()...)
	tools = append(tools, multiedit.AllTools()...)
	tools = append(tools, trash.AllTools()...)
	tools = append(tools, grep.AllTools()...)
	tools = append(tools, glob.AllTools()...)
	tools = append(tools, shell.AllTools(shell.WithDefaultTimeout(TerminalDefaultTimeout), shell.WithMaxTimeout(TerminalMaxTimeout))...)
	tools = append(tools, git.AllTools()...)
	tools = append(tools, RemoteTerminalTool(remote, guard))
	tools = append(tools, RemoteBatchTool(remote, guard))
	tools = append(tools, RemoteUploadTool(remote, guard))
	tools = append(tools, RemoteDownloadTool(remote, guard))
	tools = append(tools, RemoteFileTool(remote, guard))
	tools = append(tools, RemoteListTool(remote, guard))
	tools = append(tools, RemoteCopyTool(remote, guard))
	tr := shell.NewTaskRunner("tasks")
	// 后台任务的执行 ctx 不继承调用方注入（jobs 注册表以 Background 为根，
	// 见 gocel tools/shell/task.go TaskRunner 注释）——shell 探测结果必须
	// 在 runner 级注入，否则无 sh 环境（bash-only 容器/无 Git Bash 的
	// Windows）的 task_run 整片失败。
	ls := LocalShell()
	tr.ShellName = ls.Name
	tr.ShellArgs = ls.Args
	tools = append(tools, shell.TaskRunTool(tr), shell.TaskStatusTool(tr), shell.TaskStopTool(tr))
	tools = append(tools, AskOperatorTool(operator))
	return tools
}
