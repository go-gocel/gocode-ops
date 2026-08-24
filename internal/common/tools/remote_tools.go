package tools

// remote_tools.go — remote_* 工具族（terminal/batch/upload/download/copy/list/file），经守卫审查后放行。

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-gocel/gocel-core/core/kernel"
	"github.com/go-gocel/gocel-core/core/tool"
)

type remoteTerminalParams struct {
	// Host 目标主机别名（来自本机清单，模型不可见凭证）。
	Host string `json:"host" description:"目标主机别名（清单中的 name）"`
	// Command 在远端执行的 shell 命令。
	Command string `json:"command" description:"要执行的 shell 命令"`
	// TimeoutS 单台主机超时秒数，默认 30，上限 600。
	TimeoutS int `json:"timeout_s,omitempty" description:"超时秒数（默认 30，上限 600）"`
}

// aliasLister 清单别名读取（单主机回填用；*remote.sshExecutor 实现）。
type aliasLister interface {
	Aliases() ([]string, error)
}

// RemoteTerminalTool returns the remote_terminal tool that runs a command
// on a single remote host.
// RemoteTerminalTool 返回 remote_terminal 工具：在**单台**远端主机执行
// 命令，与本地 terminal 逻辑一致（差异只在目标与显示）。凭证由本机清单
// 安全保管，模型不可见；命令仍受高危守卫管控。
func RemoteTerminalTool(ex RemoteExecutor, guard *RiskyCommandGuard) kernel.Tool {
	return tool.MustToolFromFunc(
		func(ctx context.Context, p remoteTerminalParams) (string, error) {
			host := strings.TrimSpace(p.Host)
			if host == "" {
				// 单主机清单回填（P0 修复）：chaos-r1 实测模型连续 29 次
				// 漏传 host 参数被拒——清单只有一台时回填唯一别名，
				// 契约错误从根上消除；多主机清单保持必填（防张冠李戴）。
				if l, ok := ex.(aliasLister); ok {
					if als, err := l.Aliases(); err == nil && len(als) == 1 {
						host = als[0]
					}
				}
			}
			if host == "" {
				return "", errors.New("remote_terminal: host 必填（清单别名；多主机清单无法自动回填）")
			}
			command := strings.TrimSpace(p.Command)
			if command == "" {
				return "", errors.New("remote_terminal: command 必填")
			}
			if err := guard.CheckCommand(ctx, command, guardResolveHosts(guard, ex, []string{host}), "remote_terminal"); err != nil {
				return "", err
			}
			return ex.Exec(ctx, []string{host}, command, time.Duration(p.TimeoutS)*time.Second)
		},
		tool.WithToolName("remote_terminal"),
		tool.WithToolDescription("在单台远端主机执行 shell 命令（与本地 terminal 一致）。凭证由本机清单保管，模型不可见；高危命令需操作员确认。"),
		tool.WithToolSource("gocode"),
	)
}

// remote_batch：多台主机批量执行。
type remoteBatchParams struct {
	// Hosts 主机别名列表；["all"] 为全部主机。
	Hosts []string `json:"hosts" description:"主机别名列表；[\"all\"] 为全部主机"`
	// Command 在远端执行的 shell 命令。
	Command string `json:"command" description:"要执行的 shell 命令"`
	// TimeoutS 单台主机超时秒数，默认 30，上限 600。
	TimeoutS int `json:"timeout_s,omitempty" description:"单台超时秒数（默认 30，上限 600）"`
}

// RemoteBatchTool returns the remote_batch tool that runs a command on
// multiple remote hosts.
// RemoteBatchTool 返回 remote_batch 工具：在**多台**远端主机批量执行
// 命令（并发上限 8，输出按主机分段）。高危命令确认提示列出真实主机名。
func RemoteBatchTool(ex RemoteExecutor, guard *RiskyCommandGuard) kernel.Tool {
	return tool.MustToolFromFunc(
		func(ctx context.Context, p remoteBatchParams) (string, error) {
			command := strings.TrimSpace(p.Command)
			if command == "" {
				return "", errors.New("remote_batch: command 必填")
			}
			if err := guard.CheckCommand(ctx, command, guardResolveHosts(guard, ex, p.Hosts), "remote_batch"); err != nil {
				return "", err
			}
			return ex.Exec(ctx, p.Hosts, command, time.Duration(p.TimeoutS)*time.Second)
		},
		tool.WithToolName("remote_batch"),
		tool.WithToolDescription("在多台远端主机批量执行同一命令（输出按主机分段）。高危命令需操作员确认。"),
		tool.WithToolSource("gocode"),
	)
}

// remote_upload：上传文件/目录（带进度）。
type remoteUploadParams struct {
	// Hosts 目标主机别名列表；["all"] 为全部主机（逐台串行上传）。
	Hosts []string `json:"hosts" description:"目标主机别名列表；[\"all\"] 为全部主机"`
	// LocalPath 本地文件或目录路径（相对工作目录或绝对路径）。
	LocalPath string `json:"local_path" description:"本地文件或目录路径"`
	// RemotePath 远端目标路径：上传文件时为文件路径（父目录自动创建）；
	// 上传目录时为目标目录。
	RemotePath string `json:"remote_path" description:"远端目标路径（文件→文件路径，目录→目录路径）"`
	// Mode 目标文件权限（八进制），默认 0644。
	Mode string `json:"mode,omitempty" description:"目标文件权限（八进制），默认 0644"`
}

// RemoteUploadTool returns the remote_upload tool that uploads a local file
// or directory to remote hosts.
// RemoteUploadTool 返回 remote_upload 工具：把本地文件/目录上传到远端
// （SFTP，逐台串行，进度实时回传）。部署、传包、分发配置的通道。
func RemoteUploadTool(ex RemoteExecutor, guard *RiskyCommandGuard) kernel.Tool {
	return tool.MustToolFromFunc(
		func(ctx context.Context, p remoteUploadParams) (string, error) {
			mode, err := parseFileMode(p.Mode)
			if err != nil {
				return "", err
			}
			// 本地路径同样过凭证守卫：上传通道不得把本机凭证材料
			// （hosts.yaml/私钥等）推到远端再回读（否则密码进模型上下文）。
			if err := guard.CheckTransferPath(p.LocalPath, "上传"); err != nil {
				return "", err
			}
			if err := guard.CheckTransferPath(p.RemotePath, "上传"); err != nil {
				return "", err
			}
			return ex.Upload(ctx, p.Hosts, p.LocalPath, p.RemotePath, mode)
		},
		tool.WithToolName("remote_upload"),
		tool.WithToolDescription("把本地文件或目录上传到远端主机（SFTP，断点续传）。部署包、配置、脚本分发的通道；父目录自动创建。"),
		tool.WithToolSource("gocode"),
	)
}

// remote_download：从远端下载文件/目录（带进度）。
type remoteDownloadParams struct {
	// Hosts 目标主机别名列表（下载单文件时通常一台）。
	Hosts []string `json:"hosts" description:"目标主机别名列表；[\"all\"] 为全部主机"`
	// RemotePath 远端文件或目录路径。
	RemotePath string `json:"remote_path" description:"远端文件或目录路径"`
	// LocalDir 本地保存目录（默认工作目录）。
	LocalDir string `json:"local_dir,omitempty" description:"本地保存目录（默认工作目录）"`
}

// RemoteDownloadTool returns the remote_download tool that downloads a
// remote file or directory to the local machine.
// RemoteDownloadTool 返回 remote_download 工具：把远端文件/目录下载到
// 本地（SFTP，进度实时回传）。日志、报告、配置备份的通道。
func RemoteDownloadTool(ex RemoteExecutor, guard *RiskyCommandGuard) kernel.Tool {
	return tool.MustToolFromFunc(
		func(ctx context.Context, p remoteDownloadParams) (string, error) {
			if err := guard.CheckTransferPath(p.RemotePath, "下载"); err != nil {
				return "", err
			}
			// 本地落盘目录同样过凭证守卫：下载到 ~/.ssh、.gocode/ 等
			// 凭证路径可覆盖本机 authorized_keys/hosts.yaml（与上传侧
			// local_path 同口径，防非对称缺口）。
			if err := guard.CheckTransferPath(p.LocalDir, "下载"); err != nil {
				return "", err
			}
			return ex.Download(ctx, p.Hosts, p.RemotePath, p.LocalDir)
		},
		tool.WithToolName("remote_download"),
		tool.WithToolDescription("把远端文件或目录下载到本地（SFTP，断点续传）。日志、报告、配置备份的通道；多台主机按主机名分目录保存。"),
		tool.WithToolSource("gocode"),
	)
}

// remote_copy：远端→远端复制（本机 SFTP 双程中转）。
type remoteCopyParams struct {
	// SourceHost 源主机别名。
	SourceHost string `json:"source_host" description:"源主机别名（清单中的 name）"`
	// SourcePath 源主机上的文件或目录路径。
	SourcePath string `json:"source_path" description:"源主机上的文件或目录路径"`
	// TargetHosts 目标主机别名列表；["all"] 为全部主机。
	TargetHosts []string `json:"target_hosts" description:"目标主机别名列表；[\"all\"] 为全部主机"`
	// TargetPath 目标主机上的目标路径（文件→文件路径，目录→目录路径）。
	TargetPath string `json:"target_path" description:"目标路径（文件→文件路径，目录→目录路径）"`
}

// RemoteCopyTool returns the remote_copy tool that copies files or
// directories between remote hosts.
// RemoteCopyTool 返回 remote_copy 工具：远端主机间复制文件/目录（集群间
// 同步、配置分发的通道）。scp/rsync 被守卫硬拦截（凭证零泄露），本工具
// 内部 SFTP 双程中转，凭证不出本机。
func RemoteCopyTool(ex RemoteExecutor, guard *RiskyCommandGuard) kernel.Tool {
	return tool.MustToolFromFunc(
		func(ctx context.Context, p remoteCopyParams) (string, error) {
			srcHost := strings.TrimSpace(p.SourceHost)
			if srcHost == "" {
				return "", errors.New("remote_copy: source_host 必填（清单别名）")
			}
			srcPath := strings.TrimSpace(p.SourcePath)
			if srcPath == "" {
				return "", errors.New("remote_copy: source_path 必填")
			}
			if len(p.TargetHosts) == 0 {
				return "", errors.New("remote_copy: target_hosts 必填（别名列表或 [\"all\"]）")
			}
			tgtPath := strings.TrimSpace(p.TargetPath)
			if tgtPath == "" {
				return "", errors.New("remote_copy: target_path 必填")
			}
			// 与上传/下载同一凭证路径守卫：复制通道同样不能触碰凭证材料。
			if err := guard.CheckTransferPath(srcPath, "复制"); err != nil {
				return "", err
			}
			if err := guard.CheckTransferPath(tgtPath, "复制"); err != nil {
				return "", err
			}
			c, ok := ex.(RemoteCopier)
			if !ok {
				return "", errors.New("当前远程执行器不支持 remote_copy（请改用 remote_download + remote_upload 双程）")
			}
			return c.Copy(ctx, srcHost, srcPath, p.TargetHosts, tgtPath)
		},
		tool.WithToolName("remote_copy"),
		tool.WithToolDescription("在远端主机之间复制文件/目录（经本机 SFTP 中转，凭证不出本机）。scp/rsync 被守卫禁止，用本工具。"),
		tool.WithToolSource("gocode"),
	)
}

// remote_list：列出清单主机（模型可读视图）。
type remoteListParams struct{}

// RemoteListTool returns the remote_list tool that lists the remote host
// inventory.
// RemoteListTool 返回 remote_list 工具：列出远程主机清单（别名 + 认证
// 方式；地址/用户/凭证不在模型上下文出现）。
func RemoteListTool(ex RemoteExecutor, guard *RiskyCommandGuard) kernel.Tool {
	return tool.MustToolFromFunc(
		func(ctx context.Context, _ remoteListParams) (string, error) {
			return ex.ListHosts()
		},
		tool.WithToolName("remote_list"),
		tool.WithToolDescription("列出远程主机清单（别名 + 认证方式 + 最近探测状态）。远程任务前先调用它确认可用主机。"),
		tool.WithToolSource("gocode"),
	)
}

// remote_file：远端文件信息。
type remoteFileParams struct {
	// Host 目标主机别名。
	Host string `json:"host" description:"目标主机别名（清单中的 name）"`
	// Path 远端文件或目录路径。
	Path string `json:"path" description:"远端文件或目录路径"`
	// List true=列出目录内容（类 ls -l）；false=查看单个路径信息（默认）。
	List bool `json:"list,omitempty" description:"true=列出目录内容；false=查看单个路径信息（默认）"`
}

// RemoteFileTool returns the remote_file tool that inspects remote file
// info or directory contents.
// RemoteFileTool 返回 remote_file 工具：查看远端文件信息或目录内容
// （部署前检查路径、确认产物、核对版本等）。
func RemoteFileTool(ex RemoteExecutor, guard *RiskyCommandGuard) kernel.Tool {
	return tool.MustToolFromFunc(
		func(ctx context.Context, p remoteFileParams) (string, error) {
			host := strings.TrimSpace(p.Host)
			if host == "" {
				return "", errors.New("remote_file: host 必填（清单别名）")
			}
			remotePath := strings.TrimSpace(p.Path)
			if remotePath == "" {
				return "", errors.New("remote_file: path 必填")
			}
			return ex.FileInfo(ctx, host, remotePath, p.List)
		},
		tool.WithToolName("remote_file"),
		tool.WithToolDescription("查看远端文件信息或目录内容（类 ls -l）：部署前检查路径、确认产物、核对版本。"),
		tool.WithToolSource("gocode"),
	)
}

// guardResolveHosts 供工具内确认提示使用：优先解析真实主机名，失败回退别名。
func guardResolveHosts(guard *RiskyCommandGuard, ex RemoteExecutor, aliases []string) []string {
	if guard != nil && guard.ResolveHosts != nil {
		if resolved, err := guard.ResolveHosts(aliases); err == nil && len(resolved) > 0 {
			return resolved
		}
	}
	if ex != nil {
		if resolved, err := ex.Resolve(aliases); err == nil && len(resolved) > 0 {
			return resolved
		}
	}
	return sortHosts(aliases)
}

// parseFileMode 解析八进制权限字符串（"0644" → 0o644）。
// setuid/setgid 特殊位（0o6000）拒绝：模型可控的上传不得携带提权位
// （远端文件权限被模型控制 = 提权落地载体，P3 修复）；sticky 位
// （0o1000，目录常规形态）允许。
func parseFileMode(s string) (os.FileMode, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("mode 必须是八进制字符串（如 \"0644\"），收到 %q", s)
	}
	if v&0o6000 != 0 {
		return 0, fmt.Errorf("mode 含 setuid/setgid 特殊位（%#o），上传目标权限不允许提权位——请使用常规权限（如 0644/0755）", v)
	}
	return os.FileMode(v), nil
}

// sortHosts 排序去重（供守卫提示与测试使用）。
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
