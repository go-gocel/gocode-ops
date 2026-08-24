package remote

// remote_file.go — 远程文件信息、主机清单展示与连通性探测（FileInfo/ListHosts/Probe）。

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
)

// FileInfo returns the info of a remote path (stat for a single file or
// ls-style listing for a directory).
// FileInfo 返回远端路径信息（stat 单文件或 ls 目录内容）。
func (e *sshExecutor) FileInfo(ctx context.Context, host, remotePath string, list bool) (string, error) {
	inv, err := e.loadInventory()
	if err != nil {
		return "", err
	}
	hosts, err := e.resolveHosts(inv, []string{host})
	if err != nil {
		return "", err
	}
	h := hosts[0]
	client, err := e.getClient(h)
	if err != nil {
		return "", err
	}
	defer e.releaseClient(h)
	sc, err := sftp.NewClient(client)
	if err != nil {
		return "", fmt.Errorf("SFTP 初始化失败: %w", err)
	}
	defer sc.Close()
	// 链路僵死时 ctx 取消强制关闭通道打断阻塞的读取（与传输同机制）。
	stop := closeOnCancel(ctx, sc)
	defer stop()

	if list {
		entries, err := sc.ReadDir(remotePath)
		if err != nil {
			return "", fmt.Errorf("读取目录失败: %w", err)
		}
		var sb strings.Builder
		for _, ent := range entries {
			sb.WriteString(fmt.Sprintf("%s %12d %s %s\n", ent.Mode().String(), ent.Size(), ent.ModTime().Format("2006-01-02 15:04"), ent.Name()))
		}
		return strings.TrimRight(sb.String(), "\n"), nil
	}
	info, err := sc.Stat(remotePath)
	if err != nil {
		return "", fmt.Errorf("读取路径信息失败: %w", err)
	}
	kind := "文件"
	if info.IsDir() {
		kind = "目录"
	}
	return fmt.Sprintf("%s %s: %s %s %s", info.Mode().String(), kind, remotePath, humanBytes(info.Size()), info.ModTime().Format("2006-01-02 15:04")), nil
}

// ListHosts returns a model-readable host inventory (aliases, auth methods,
// and recent probe status when available).
// ListHosts 返回模型可读的主机清单：别名 + 认证方式 + 最近探测状态
// （如有）。地址与用户不在模型上下文出现（保持凭证零泄露承诺）；
// 界面侧用 ListInventory 展示。
func (e *sshExecutor) ListHosts() (string, error) {
	inv, err := e.loadInventory()
	if err != nil {
		return "", err
	}
	e.probeMu.Lock()
	probed := len(e.probe) > 0
	e.probeMu.Unlock()
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("主机清单（%d 台）：\n", len(inv.Hosts)))
	for _, h := range inv.Hosts {
		auth := "密钥认证"
		if strings.TrimSpace(h.KeyFile) == "" {
			auth = "密码认证"
		}
		line := fmt.Sprintf("- %s（%s）", h.Name, auth)
		if probed {
			e.probeMu.Lock()
			status := e.probe[h.Name]
			e.probeMu.Unlock()
			if status != "" {
				line += fmt.Sprintf("（最近探测: %s）", status)
			}
		}
		sb.WriteString(line + "\n")
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

// Aliases returns the list of inventory aliases.
// Aliases 返回清单别名列表（P0 修复：单主机清单下 remote_terminal 的
// host 参数可由引擎回填）。
func (e *sshExecutor) Aliases() ([]string, error) {
	inv, err := e.loadInventory()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(inv.Hosts))
	for _, h := range inv.Hosts {
		if strings.TrimSpace(h.Name) != "" {
			out = append(out, h.Name)
		}
	}
	return out, nil
}

// Probe concurrently probes host connectivity and returns a map of alias
// to status description.
// Probe 并发探测主机连通性（并发上限 8，dial 超时取调用方 timeout，
// 缺省 10s），返回 别名 → 状态描述。结果缓存进执行器（ListHosts 附
// 最近探测状态，只存脱敏状态——错误细节含地址，模型侧只拿结论）。
func (e *sshExecutor) Probe(ctx context.Context, aliases []string, timeout time.Duration) map[string]string {
	inv, err := e.loadInventory()
	if err != nil {
		return map[string]string{}
	}
	hosts, err := e.resolveHosts(inv, aliases)
	if err != nil {
		return map[string]string{}
	}
	results := make(map[string]string, len(hosts))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, probeConcurrency)
	for _, h := range hosts {
		wg.Add(1)
		go func(h Host) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			select {
			case <-ctx.Done():
				return // 已取消：不等待逐个 dial 超时
			default:
			}
			status := "在线"
			client, err := e.dialTimeout(h, timeout)
			if err != nil {
				status = "连接失败: " + err.Error()
			} else {
				_ = client.Close()
			}
			mu.Lock()
			results[h.Name] = status
			mu.Unlock()
		}(h)
	}
	wg.Wait()
	// 缓存脱敏状态：错误细节含地址，模型侧只拿“在线/连接失败”两类结论。
	e.probeMu.Lock()
	if e.probe == nil {
		e.probe = map[string]string{}
	}
	for k, v := range results {
		if v == "在线" {
			e.probe[k] = v
		} else {
			e.probe[k] = "连接失败"
		}
	}
	e.probeMu.Unlock()
	return results
}

// ── 连接 ──────────────────────────────────────────────────────────────

// withDefaultPort 为地址补全缺省 SSH 端口（22）。区分 hostname/IPv4 与
// 裸 IPv6 字面量：后者必须加 [] 成 [2001:db8::1]:22，否则会被误判为
// “已带端口”导致 dial 与 known_hosts 匹配失败。
