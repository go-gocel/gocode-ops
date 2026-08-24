package remote

// 远程执行：凭证零泄露设计 + 细粒度工具族 + 实时进度。
//
// 凭证（用户/密码/私钥）只存在于本机清单文件 <工作目录>/.gocode/hosts.yaml
// （0600）。SSH/SFTP 连接由本包内部建立（x/crypto/ssh + pkg/sftp），模型
// 经 remote_* 工具只能看到「主机别名 + 命令/路径」——用户、地址、私钥、
// 密码永不进入模型上下文，从根本上杜绝凭证泄露给外部大模型。守卫模块
// 同时硬性禁止模型自建 ssh/scp 连接或读取任何凭证文件。
//
// 实时性：WithRemoteProgress 向 context 注入进度回调后，命令输出按
// ~50ms 节流实时回传（不必等命令结束），上传/下载回传字节进度；无回调
// 时行为不变（整段返回）。

import (
	"context"
	"os"
	"time"
)

// Host 是清单中的一台远程主机。
type Host struct {
	Name         string `yaml:"name"`
	Address      string `yaml:"address"`
	User         string `yaml:"user"`
	Password     string `yaml:"password,omitempty"`
	KeyFile      string `yaml:"key_file,omitempty"`
	HostKeyCheck *bool  `yaml:"host_key_check,omitempty"`
}

// Inventory 是主机清单。
type Inventory struct {
	Hosts []Host `yaml:"hosts"`
}

// RemoteConfig 是远程执行的运行配置。
type RemoteConfig struct {
	// InventoryPath 清单文件路径（凭证所在，模型不可读）。
	InventoryPath string
	// DefaultTimeout 单台主机命令超时，默认 30s。
	DefaultTimeout time.Duration
	// OnProgress 实时进度回调：命令输出块（Phase=output）、上传/下载
	// 字节进度（Phase=upload/download）。多台并发执行时可能从多个
	// goroutine 触发，调用方需自行保证线程安全。
	OnProgress func(RemoteProgress)
}

// RemoteProgress 是一次远程执行进度事件（命令输出块或传输进度）。
type RemoteProgress struct {
	// Host 产生事件的主机别名。
	Host string `json:"host"`
	// Phase 事件阶段：output=命令输出块，upload=上传进度，download=下载进度。
	Phase string `json:"phase"`
	// Text output 阶段的输出块（可能切在行中间，UI 原样渲染）。
	Text string `json:"text,omitempty"`
	// Path 传输中的远端路径。
	Path string `json:"path,omitempty"`
	// Done 已传输字节。
	Done int64 `json:"done,omitempty"`
	// Total 总字节（0 表示未知）。
	Total int64 `json:"total,omitempty"`
}

// progressChunkCap 限制单个 output 进度块大小（界面事件上限，
// 模型侧输出另有 8K 截断）。
const progressChunkCap = 8000

// remoteProgressKey 是 context 中进度回调的键。
type remoteProgressKey struct{}

// WithRemoteProgress 向 context 注入远程进度回调。注入后 remote_* 工具
// 执行期间会把命令输出块、传输进度实时回传（节流 ~50ms）；不注入则行为
// 不变（整段返回）。回调可能从多个 goroutine 触发，须线程安全。
func WithRemoteProgress(ctx context.Context, sink func(RemoteProgress)) context.Context {
	if sink == nil {
		return ctx
	}
	return context.WithValue(ctx, remoteProgressKey{}, sink)
}

func RemoteProgressSink(ctx context.Context) func(RemoteProgress) {
	if fn, ok := ctx.Value(remoteProgressKey{}).(func(RemoteProgress)); ok && fn != nil {
		return fn
	}
	return nil
}

// RemoteExecutor 抽象远程执行（测试与界面可替换实现）。
//
// 工具粒度说明：远程能力按职责拆为单机执行、批量执行、上传、下载、
// 文件信息、清单列举与连通性探测，各自独立成方法，供 remote_* 工具
// 一一对应调用。
type RemoteExecutor interface {
	// Exec 在 hosts（已解析的别名）上并行执行 command，按主机顺序返回
	// 分段输出。注入进度回调时输出实时回传。
	Exec(ctx context.Context, hosts []string, command string, timeout time.Duration) (string, error)
	// Upload 把本地文件/目录上传到 hosts（逐台串行，进度实时回传），
	// 返回按主机分段的执行结果。
	Upload(ctx context.Context, hosts []string, localPath, remotePath string, mode os.FileMode) (string, error)
	// Download 把远端文件/目录下载到本地目录（逐台串行，进度实时回传）。
	// 多台主机时按 <localDir>/<host>/<name> 保存，避免同名覆盖。
	Download(ctx context.Context, hosts []string, remotePath, localDir string) (string, error)
	// FileInfo 返回远端单个文件的信息或目录内容列表（类 ls -l）。
	FileInfo(ctx context.Context, host, remotePath string, list bool) (string, error)
	// ListHosts 返回模型可读的主机清单（别名 + 认证方式，不含地址/用户/凭证）。
	ListHosts() (string, error)
	// Aliases 返回清单别名列表（P0 修复：单主机清单下 remote_terminal
	// 允许省略 host 参数，引擎回填唯一别名——chaos-r1 实测模型连续
	// 漏传 host 报错 29 次；多主机清单仍要求显式 host，防张冠李戴）。
	Aliases() ([]string, error)
	// Probe 并发探测主机连通性，返回 别名 → 状态描述。
	Probe(ctx context.Context, aliases []string, timeout time.Duration) map[string]string
	// Resolve 把别名（含 "all"）解析为真实主机名，供确认提示展示。
	Resolve(aliases []string) ([]string, error)
}
