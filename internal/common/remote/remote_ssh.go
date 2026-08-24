package remote

// remote_ssh.go — SSH 执行器实现：连接缓存/复用/空闲回收、清单加载与主机解析、远程复制、连接事实。

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-gocel/gocode-ops/internal/common/model"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

type sshExecutor struct {
	cfg RemoteConfig
	// 连接复用：处置/巡检连续执行大量命令时避免每次新建 SSH 连接
	// （dial+认证 ~1s/次，25 个处置动作即 ~25s 纯连接开销）。
	// 空闲超时惰性清理；命令失败不关连接（exit code 非零是命令语义），
	// 会话级错误（NewSession 失败）剔除后重建。
	// inUse 在借计数：运行中的长命令（>30s）不得被并发 checkout 当
	// 闲置关闭——ssh.Client 支持多会话复用，并发共享同一连接安全。
	mu      sync.Mutex
	clients map[string]*ssh.Client
	lastUse map[string]time.Time
	inUse   map[string]int
	// shells 缓存每连接的远端 POSIX shell 探测结果（clientKey → shell 名；
	// 空串 = 已探测但无可用 shell，回退裸命令）。探测一次，连接生命周期
	// 内复用——目标主机对引擎是黑盒，登录 shell 可能是 csh/fish/无 sh，
	// 探测结果决定命令走 stdin 传输（绕开登录 shell 解析）还是裸命令。
	shells map[string]string

	// probe 最近一次连通性探测结果（别名 → 脱敏状态）。只存状态不含
	// 错误细节——错误文本里有地址，绝不能进模型上下文（凭证零泄露）。
	probeMu sync.Mutex
	probe   map[string]string

	// invMu 保护清单缓存（与连接池 mu 分离，避免文件 IO 持锁）。
	invMu      sync.Mutex
	invCache   *Inventory // 上一次解析的清单（只读共享，调用方不得原地修改）
	invPath    string     // 缓存对应的清单路径
	invModTime time.Time  // 缓存时清单文件的 mtime（用于失效判定）
}

// connIdleTimeout 复用连接的空闲超时：超过即关闭（下次使用时重建）。
const connIdleTimeout = 30 * time.Second

// probeConcurrency 连通性探测并发上限（数百台清单不风暴 dial）。
const probeConcurrency = 8

// clientKey 连接缓存键（地址+用户+认证指纹+host_key_check 状态）：清单
// 热更新换密码/换 key/切换 host_key_check 后必须让旧连接失效（否则缓存
// 连接仍用旧凭证/旧校验策略继续跑）。
func clientKey(h Host) string {
	auth := "none"
	switch {
	case strings.TrimSpace(h.KeyFile) != "":
		auth = "key:" + h.KeyFile
	case h.Password != "":
		sum := sha256.Sum256([]byte(h.Password))
		auth = fmt.Sprintf("pw:%x", sum[:4])
	}
	hc := "hc:1"
	if h.HostKeyCheck != nil && !*h.HostKeyCheck {
		hc = "hc:0"
	}
	return h.Address + "|" + h.User + "|" + auth + "|" + hc
}

// getClient 返回复用连接（缓存命中且未空闲超时/仍被占用）；否则新建并缓存。
// 调用方使用完毕必须调用 releaseClient——在借计数保护运行中的连接不被
// 空闲回收关闭；空闲计时从真正释放起算。
func (e *sshExecutor) getClient(h Host) (*ssh.Client, error) {
	key := clientKey(h)
	e.mu.Lock()
	if c, ok := e.clients[key]; ok {
		if e.inUse[key] > 0 || time.Since(e.lastUse[key]) < connIdleTimeout {
			e.inUse[key]++
			e.mu.Unlock()
			return c, nil
		}
		_ = c.Close()
		delete(e.clients, key)
		delete(e.lastUse, key)
		delete(e.inUse, key)
		// shell 探测结果随连接作废：空闲回收后重建的连接探测新主机
		// （IP 复用/容器重建场景不残留旧主机探测结果）。
		delete(e.shells, key)
	}
	e.mu.Unlock()
	c, err := e.dial(h)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	if e.clients == nil {
		e.clients = map[string]*ssh.Client{}
		e.lastUse = map[string]time.Time{}
		e.inUse = map[string]int{}
		e.shells = map[string]string{}
	}
	if existing, ok := e.clients[key]; ok {
		// 并发首连：另一位已抢先建连——丢弃自己新建的连接，复用已有。
		e.inUse[key]++
		e.mu.Unlock()
		_ = c.Close()
		return existing, nil
	}
	e.clients[key] = c
	e.inUse[key] = 1
	e.lastUse[key] = time.Now()
	e.mu.Unlock()
	return c, nil
}

// releaseClient 归还连接（与 getClient 配对）：在借计数归零时刷新
// lastUse——空闲超时从真正释放算起，运行中的长命令不被误判闲置关闭。
func (e *sshExecutor) releaseClient(h Host) {
	key := clientKey(h)
	e.mu.Lock()
	if e.inUse[key] > 0 {
		e.inUse[key]--
		if e.inUse[key] == 0 {
			e.lastUse[key] = time.Now()
		}
	}
	e.mu.Unlock()
}

// dropClient 剔除失效连接（NewSession 失败等连接级错误后调用）。
func (e *sshExecutor) dropClient(h Host) {
	key := clientKey(h)
	e.mu.Lock()
	if c, ok := e.clients[key]; ok {
		_ = c.Close()
		delete(e.clients, key)
		delete(e.lastUse, key)
		delete(e.inUse, key)
		delete(e.shells, key)
	}
	e.mu.Unlock()
}

// CloseAll 关闭全部复用连接（引擎结束调用）。
func (e *sshExecutor) CloseAll() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for k, c := range e.clients {
		_ = c.Close()
		delete(e.clients, k)
		delete(e.lastUse, k)
		delete(e.inUse, k)
		delete(e.shells, k)
	}
}

// newSSHExecutor 创建真实执行器；InventoryPath 为空时远程工具返回引导错误。
func newSSHExecutor(cfg RemoteConfig) *sshExecutor {
	if cfg.DefaultTimeout <= 0 {
		cfg.DefaultTimeout = 30 * time.Second
	}
	return &sshExecutor{cfg: cfg}
}

// NewSSHExecutor 返回真实的 SSH/SFTP 远程执行器（NewAgentWithRemote 配合
// 使用）；OnProgress 在命令输出块与传输进度时实时回调。
func NewSSHExecutor(cfg RemoteConfig) RemoteExecutor {
	return newSSHExecutor(cfg)
}

// progress 返回本调用的进度回调：优先 context 注入的 sink，其次配置级
// OnProgress；都没有返回 nil（执行不流式）。
func (e *sshExecutor) progress(ctx context.Context) func(RemoteProgress) {
	if s := RemoteProgressSink(ctx); s != nil {
		return s
	}
	if e.cfg.OnProgress != nil {
		return e.cfg.OnProgress
	}
	return nil
}

// emit 便捷发送进度事件（sink 为 nil 时静默丢弃）。
func emit(sink func(RemoteProgress), p RemoteProgress) {
	if sink != nil {
		sink(p)
	}
}

// ── 清单与解析 ────────────────────────────────────────────────────────

// loadInventory 从清单文件读取主机列表。带基于文件 mtime 的缓存：同路径
// 且文件未变更时直接返回缓存，避免每次远程执行都重读+重解析 hosts.yaml
// （数百主机 × 多命令场景下纯 IO/解析开销显著）；操作员改配置（mtime
// 变化）后下次调用自动重新加载，保留“无需重启”语义。返回的 *Inventory 为
// 只读共享，调用方不得原地修改。
func (e *sshExecutor) loadInventory() (*Inventory, error) {
	path := strings.TrimSpace(e.cfg.InventoryPath)
	if path == "" {
		return nil, errors.New("未配置远程主机清单：请先运行 gocode-ops init 生成 .gocode/hosts.yaml 模板")
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("读取主机清单失败: %w", err)
	}
	e.invMu.Lock()
	if e.invCache != nil && e.invPath == path && e.invModTime.Equal(fi.ModTime()) {
		inv := e.invCache
		e.invMu.Unlock()
		return inv, nil
	}
	e.invMu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取主机清单失败: %w", err)
	}
	var inv Inventory
	if err := yaml.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("解析主机清单失败: %w", err)
	}
	if len(inv.Hosts) == 0 {
		return nil, errors.New("主机清单为空（请编辑 " + path + "）")
	}
	// 以读取后的 mtime 为准缓存，保证缓存内容与 mtime 一致（避免 stat 与
	// read 之间的变更被误判为未变更）。
	if fi2, err2 := os.Stat(path); err2 == nil {
		fi = fi2
	}
	e.invMu.Lock()
	e.invCache = &inv
	e.invPath = path
	e.invModTime = fi.ModTime()
	e.invMu.Unlock()
	return &inv, nil
}

// resolveHosts 把别名（含 "all"）解析为主机列表；未知别名报错。
// 按名去重（保持输入顺序）：["all"] 中已含的主机再显式列出时不得重复
// 执行——副作用命令（重启/删除/写文件）重复执行会翻倍（P2 修复）。
func (e *sshExecutor) resolveHosts(inv *Inventory, aliases []string) ([]Host, error) {
	if len(aliases) == 0 {
		return nil, errors.New("hosts 不能为空（别名或 [\"all\"]）")
	}
	byName := map[string]Host{}
	for _, h := range inv.Hosts {
		byName[h.Name] = h
	}
	seen := map[string]bool{}
	var out []Host
	for _, a := range aliases {
		if a == "all" {
			for _, h := range inv.Hosts {
				if !seen[h.Name] {
					seen[h.Name] = true
					out = append(out, h)
				}
			}
			continue
		}
		if seen[a] {
			continue
		}
		h, ok := byName[a]
		if !ok {
			return nil, fmt.Errorf("未知主机别名 %q（清单里有: %s）", a, inventoryNames(inv))
		}
		seen[a] = true
		out = append(out, h)
	}
	if len(out) == 0 {
		return nil, errors.New("没有可执行的主机")
	}
	return out, nil
}

// Resolve 返回别名对应的真实主机名（含 "all" 展开）。
func (e *sshExecutor) Resolve(aliases []string) ([]string, error) {
	inv, err := e.loadInventory()
	if err != nil {
		return nil, err
	}
	hosts, err := e.resolveHosts(inv, aliases)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(hosts))
	for _, h := range hosts {
		names = append(names, h.Name)
	}
	return names, nil
}

// RemoteCopier 支持远端→远端复制的执行器（sshExecutor 实现；fake 可
// 不实现——工具层报“不支持”引导模型用下载+上传双程）。
type RemoteCopier interface {
	Copy(ctx context.Context, sourceHost, sourcePath string, targetHosts []string, targetPath string) (string, error)
}

// Copy 远端到远端复制：本机 SFTP 双程中转（下载到临时目录再上传），
// 凭证不出本机——scp/rsync 被守卫硬拦截的场景（集群间同步、配置分发）
// 用本通道。临时文件用完即删。
// 防御护栏（P3 修复）：拒绝根路径（远端 / 会递归下载整棵文件系统到
// 本机 tmp）；下载体积上限（copyMaxBytes）超限中止——tmp 盘不可被打满。
func (e *sshExecutor) Copy(ctx context.Context, sourceHost, sourcePath string, targetHosts []string, targetPath string) (string, error) {
	inv, err := e.loadInventory()
	if err != nil {
		return "", err
	}
	srcHosts, err := e.resolveHosts(inv, []string{sourceHost})
	if err != nil {
		return "", err
	}
	dstHosts, err := e.resolveHosts(inv, targetHosts)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(sourcePath) == "/" || strings.TrimSpace(targetPath) == "/" {
		return "", errors.New("remote_copy: 不允许复制根路径（/）——请指定具体文件/目录")
	}
	tmp, err := os.MkdirTemp("", "gocode-ops-copy-")
	if err != nil {
		return "", fmt.Errorf("创建临时目录失败: %w", err)
	}
	defer os.RemoveAll(tmp)
	sink := e.progress(ctx)

	// 1) 源主机 → 临时目录（带体积护栏）。
	if _, err := e.downloadOne(ctx, srcHosts[0], sourcePath, tmp, false, sink); err != nil {
		return "", fmt.Errorf("从 %s 读取失败: %w", sourceHost, err)
	}
	// 体积护栏：下载完成后校验临时副本总大小（downloadOne 已带单文件
	// 上限，这里兜住目录递归的总量）。
	if sz := dirSize(tmp); sz > copyMaxBytes {
		return "", fmt.Errorf("复制内容过大（%.1f MB > 上限 %.0f MB）——请缩小范围（目录/文件）", float64(sz)/(1<<20), float64(copyMaxBytes)/(1<<20))
	}
	localPath := filepath.Join(tmp, filepath.Base(sourcePath))
	info, err := os.Stat(localPath)
	if err != nil {
		return "", fmt.Errorf("读取临时副本失败: %w", err)
	}

	// 2) 临时目录 → 各目标主机。
	var sections []string
	failed := 0
	for _, h := range dstHosts {
		select {
		case <-ctx.Done():
			return strings.TrimRight(strings.Join(sections, "\n"), "\n"), ctx.Err()
		default:
		}
		if _, err := e.uploadOne(ctx, h, localPath, targetPath, info.IsDir(), 0, sink); err != nil {
			failed++
			sections = append(sections, fmt.Sprintf("## %s\n错误: %v", h.Name, err))
			continue
		}
		sections = append(sections, fmt.Sprintf("复制完成: %s:%s → %s:%s", sourceHost, sourcePath, h.Name, targetPath))
	}
	out := strings.TrimRight(strings.Join(sections, "\n"), "\n")
	if failed > 0 && failed == len(dstHosts) {
		return out, fmt.Errorf("全部 %d 台主机复制失败（详见输出）", failed)
	}
	return out, nil
}

// ConnFacts 返回别名对应主机的连接事实（自影响审查用）。
// 凭据本身不外传，只给通道判定所需的用户/认证方式/管理端口。
// 地址解析失败时端口回退 22（SSH 默认）。
func (e *sshExecutor) ConnFacts(aliases []string) map[string]model.ConnFact {
	inv, err := e.loadInventory()
	if err != nil {
		return nil
	}
	hosts, err := e.resolveHosts(inv, aliases)
	if err != nil {
		return nil
	}
	out := make(map[string]model.ConnFact, len(hosts))
	for _, h := range hosts {
		cf := model.ConnFact{Host: h.Name, User: h.User}
		switch {
		case strings.TrimSpace(h.KeyFile) != "":
			cf.Auth = "key"
		case strings.TrimSpace(h.Password) != "":
			cf.Auth = "password"
		default:
			cf.Auth = "none"
		}
		cf.Port = addrPort(h.Address)
		out[h.Name] = cf
	}
	return out
}

// copyMaxBytes remote_copy 中转体积上限（512MB：集群间同步/配置分发
// 的常规规模足够；tmp 盘防被打满）。
const copyMaxBytes = 512 << 20

// dirSize 递归统计目录总大小（复制中转体积护栏用）。
func dirSize(dir string) int64 {
	var total int64
	_ = filepath.Walk(dir, func(_ string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			total += fi.Size()
		}
		return nil
	})
	return total
}

// addrPort 从 host[:port] 提取端口；无端口或解析失败回退 22。
