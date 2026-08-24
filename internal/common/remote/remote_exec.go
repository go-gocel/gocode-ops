package remote

// remote_exec.go — 远程命令执行：输出预算/头尾截断、批量结果格式化、远端 shell 探测与命令回显。

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

const (
	perHostCap       = 8 << 10
	totalCap         = 64 << 10
	remoteCollectCap = 1 << 20 // 1MB：诊断足够，超大输出（cat 大文件等）不炸内存
	remoteMaxTimeout = 10 * time.Minute
)

// capRemoteTimeout 封顶远程命令超时（防模型声明超大秒数干等）。
func capRemoteTimeout(d time.Duration) time.Duration {
	if d > remoteMaxTimeout {
		return remoteMaxTimeout
	}
	return d
}

// truncateHeadTail 超长输出保留头尾：头部给命令起始上下文，尾部给结论/
// 错误（错误几乎总在尾部，只留头会把可诊断信息截掉——与本地 terminal
// 的头尾截断保持一致）。截断点回退到完整 UTF-8 rune 边界（裸字节切片
// 会把中文/emoji 切半，非法 UTF-8 进模型上下文/审计日志）。
func truncateHeadTail(s string, cap int) string {
	if len(s) <= cap {
		return s
	}
	half := cap / 2
	head := s[:runeSafeCut(s, half)]
	tailStart := runeSafeCut(s, len(s)-half)
	return head + fmt.Sprintf("\n…（输出过长，省略 %d 字符）…\n", len(s)-cap) + s[tailStart:]
}

// runeSafeCut 把字节截断点回退到完整 rune 边界（n>0 保证索引合法；
// n 处恰为 rune 起点则不动）。
func runeSafeCut(s string, n int) int {
	if n <= 0 || n >= len(s) {
		return n
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return n
}

// remoteProgressWriter 收集输出供模型侧使用（读取时限量截断），同时
// 保留未发送的增量供进度回调。并发安全：命令拷贝 goroutine 写入，
// 节流 ticker 读取。
type remoteProgressWriter struct {
	total   cappedBuffer // 完整输出（限量收集，自带锁）
	mu      sync.Mutex
	pending strings.Builder
}

func (w *remoteProgressWriter) Write(p []byte) (int, error) {
	w.total.Write(p) // cappedBuffer 内部加锁
	w.mu.Lock()
	w.pending.Write(p)
	w.mu.Unlock()
	return len(p), nil
}

// flush 返回未发送的增量并清空。
func (w *remoteProgressWriter) flush() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.pending.String()
	w.pending.Reset()
	return s
}

// output 返回完整输出。
func (w *remoteProgressWriter) output() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return []byte(w.total.String())
}

// Exec 并行执行（并发上限 8），按输入顺序返回分段输出；注入进度回调时
// 每台输出按 ~50ms 节流实时回传。展示路径：单台输出上限 8K。
func (e *sshExecutor) Exec(ctx context.Context, aliases []string, command string, timeout time.Duration) (string, error) {
	return e.execWithCap(ctx, aliases, command, timeout, perHostCap, true)
}

// ExecCollect 收集路径执行：L0 快检一条命令输出可达 10K+，展示路径的
// 8K 单台上限会把尾部探针（facts/cpu/load）截掉导致静默漏采——收集路径
// 用 maxCollectOut 同款上限（解析后不展示，不吃模型上下文）。
func (e *sshExecutor) ExecCollect(ctx context.Context, aliases []string, command string, timeout time.Duration) (string, error) {
	return e.execWithCap(ctx, aliases, command, timeout, maxCollectOut, false)
}

// execWithCap 共享实现：单台输出截断上限由调用方给定。
func (e *sshExecutor) execWithCap(ctx context.Context, aliases []string, command string, timeout time.Duration, hostCap int, echo bool) (string, error) {
	inv, err := e.loadInventory()
	if err != nil {
		return "", err
	}
	hosts, err := e.resolveHosts(inv, aliases)
	if err != nil {
		return "", err
	}
	if timeout <= 0 {
		timeout = e.cfg.DefaultTimeout
	}
	timeout = capRemoteTimeout(timeout)
	sink := e.progress(ctx)

	results := make([]execResult, len(hosts))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, h := range hosts {
		wg.Add(1)
		go func(i int, h Host) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out, err := e.execOne(ctx, h, command, timeout, sink, hostCap, echo)
			if err != nil {
				out = "错误: " + err.Error()
			}
			results[i] = execResult{host: h.Name, output: out, err: err}
		}(i, h)
	}
	wg.Wait()
	// 总预算按路径区分：展示路径 64K（模型上下文护栏）；收集路径
	// remoteCollectCap（1MB，与内存收集上限对齐）——L0 采集一条命令
	// 输出可超 64K（多探针拼接），展示预算会把唯一主机的整段输出跳过，
	// 采集侧静默失明（指标/状态探针 0 项）。
	totalBudget := totalCap
	if !echo {
		totalBudget = remoteCollectCap
	}
	return formatExecResults(results, hostCap, totalBudget)
}

// formatExecResults 渲染批量执行结果：部分失败时失败主机名置顶聚合
// （完整名单不随总预算截断丢失——模型必须知道哪台失败，否则把部分失败
// 当全部成功）；全部失败返回 error（工具框架才能标记失败）。
// totalBudget 按路径传入（展示 64K / 收集 1MB，见 execWithCap）。
type execResult struct {
	host   string
	output string
	err    error
}

func formatExecResults(results []execResult, hostCap, totalBudget int) (string, error) {
	var sb strings.Builder
	total := 0
	skipped := 0
	failed := 0
	for _, r := range results {
		if r.err != nil {
			failed++
		}
	}
	if failed > 0 && failed < len(results) {
		var names []string
		for _, r := range results {
			if r.err != nil {
				names = append(names, r.host)
			}
		}
		sb.WriteString(fmt.Sprintf("部分失败（%d/%d）: %s\n", failed, len(results), strings.Join(names, ", ")))
		total += sb.Len()
	}
	for _, r := range results {
		section := fmt.Sprintf("## %s\n%s\n", r.host, truncateHeadTail(r.output, hostCap))
		if total+len(section) > totalBudget {
			skipped++
			continue
		}
		sb.WriteString(section)
		total += len(section)
	}
	if skipped > 0 {
		sb.WriteString(fmt.Sprintf("... 其余 %d 台主机输出超出总上限已省略（单台上限 %d，总上限 %d）\n", skipped, hostCap, totalBudget))
	}
	out := strings.TrimRight(sb.String(), "\n")
	// 全部主机失败必须返回 error（工具框架才能标记失败，TUI/引擎才能感知）；
	// 部分失败保留 nil error，逐台错误在分段文本里可见。
	if failed == len(results) && len(results) > 0 {
		return out, fmt.Errorf("全部 %d 台主机执行失败（详见输出）", failed)
	}
	return out, nil
}

// ── 远端 shell 探测（黑盒目标主机） ───────────────────────────────────

// shellProbeMark 探测成功标记（输出含标记即该 shell 可用）。
const shellProbeMark = "__GOCEL_SHELL_PROBE_OK__"

// remoteShellCandidates 探测优先级：sh 是最小公分母（dash/busybox 均提供），
// bash 覆盖 bash-only 容器，其余 POSIX 系兜底。
var remoteShellCandidates = []string{"sh", "bash", "dash", "ksh", "zsh", "ash"}

// probeOneShell 在 client 上试执行一个候选 shell。探测命令经登录 shell
// 执行——命令必须对任意登录 shell（csh/fish/cmd）都安全：无重定向、
// 单引号内容不含单引号，仅是"执行外部命令 <shell> -c 'echo <标记>'"。
// 返回该 shell 的启动名（探测到的路径，Start 时用）。
func probeOneShell(ctx context.Context, client *ssh.Client, name string) (string, bool) {
	sess, err := client.NewSession()
	if err != nil {
		return "", false
	}
	defer sess.Close()
	probe := name + " -c 'echo " + shellProbeMark + "'"
	type outErr struct {
		out string
		err error
	}
	ch := make(chan outErr, 1)
	go func() {
		out, err := sess.Output(probe)
		ch <- outErr{out: string(out), err: err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return "", false // 命令不存在/退出码非零：该候选不可用
		}
		if strings.Contains(r.out, shellProbeMark) {
			return name, true
		}
		return "", false
	case <-ctx.Done():
		sess.Close()
		return "", false
	case <-time.After(shellProbeTimeout):
		sess.Close()
		return "", false
	}
}

// shellProbeTimeout 单候选探测超时：登录 shell 挂死时不能卡住执行
// （最坏 6 候选 × 超时只发生在首个不可用环境，且结果按连接缓存）。
const shellProbeTimeout = 3 * time.Second

// remoteShell 返回连接缓存的远端 POSIX shell 名（空串=无可用 shell，
// 调用方回退裸命令）。探测一次并缓存：目标主机对引擎是黑盒，登录
// shell 不可假设为 sh——csh/fish 登录 shell 下 POSIX 命令串直接裸发
// 会整片语法失败，探测后命令经显式 shell 的 stdin 传输执行（见
// execOne），绕开登录 shell 的解析语义。
func (e *sshExecutor) remoteShell(ctx context.Context, client *ssh.Client, h Host) string {
	key := clientKey(h)
	e.mu.Lock()
	if s, ok := e.shells[key]; ok {
		e.mu.Unlock()
		return s
	}
	e.mu.Unlock()
	// 并发首探：重复探测无害（结果幂等），map 写回有锁。
	found := ""
	for _, name := range remoteShellCandidates {
		if p, ok := probeOneShell(ctx, client, name); ok {
			found = p
			break
		}
	}
	e.mu.Lock()
	if e.shells == nil {
		e.shells = map[string]string{}
	}
	e.shells[key] = found
	e.mu.Unlock()
	return found
}

// execOne 连接单台主机执行命令：输出实时流式回传（sink 非 nil 时），
// 同时收集完整输出供模型侧；超时/取消时主动断开会话。hostCap 为输出
// 截断上限（展示路径 8K，收集路径 maxCollectOut）。
//
// 黑盒目标主机（登录 shell 不可假设）：remoteShell 探测到 POSIX shell 时，
// 命令经该 shell 的 stdin 传输执行（session.Start(shell) + 命令写入
// stdin）——命令内容完全不经过登录 shell 解析，csh/fish 登录 shell、
// 引号失衡的命令都能正确执行；探测失败（无任何 POSIX shell，如
// Windows SSH 目标）回退裸命令（历史行为，错误可读）。执行壳的
// 命令行只有 shell 名，模型命令的 pkill -f 自匹配面反而更小。
func (e *sshExecutor) execOne(ctx context.Context, h Host, command string, timeout time.Duration, sink func(RemoteProgress), hostCap int, echo bool) (string, error) {
	// 连接复用：连接级错误（NewSession 失败）剔除缓存后重建一次；
	// 命令退出码非零是命令语义，不关连接。
	client, err := e.getClient(h)
	if err != nil {
		return "", err
	}
	defer e.releaseClient(h)

	session, err := client.NewSession()
	if err != nil {
		e.dropClient(h)
		if c2, err2 := e.getClient(h); err2 == nil {
			client = c2
			session, err = client.NewSession()
		}
	}
	if err != nil {
		return "", fmt.Errorf("创建会话失败: %w", err)
	}
	defer session.Close()

	stdout, err := session.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("获取 stdout 管道失败: %w", err)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return "", fmt.Errorf("获取 stderr 管道失败: %w", err)
	}
	// stdin 传输模式：远端 POSIX shell 从 stdin 读命令脚本——命令文本
	// 不经登录 shell 解析，黑盒目标（csh/fish 登录 shell）也能执行。
	// shellName 为空时回退裸命令（无可用 POSIX shell）。
	shellName := e.remoteShell(ctx, client, h)
	startCmd := command
	var stdin io.WriteCloser
	if shellName != "" {
		stdin, err = session.StdinPipe()
		if err != nil {
			return "", fmt.Errorf("获取 stdin 管道失败: %w", err)
		}
		startCmd = shellName
	}
	if err := session.Start(startCmd); err != nil {
		return "", fmt.Errorf("启动命令失败: %w", err)
	}
	if stdin != nil {
		// 写命令脚本 + EOF：sh 读完整段脚本后执行，退出码=命令退出码。
		// 写入放 goroutine：远端 handler 不消费 stdin（异常登录 shell）
		// 时写入可能被流控阻塞——主循环的 timeout/取消分支会 Close
		// 会话打断，不会永久挂起。
		go func() {
			_, _ = io.WriteString(stdin, command+"\n")
			_ = stdin.Close()
		}()
	}

	pw := &remoteProgressWriter{total: *newCappedBuffer(remoteCollectCap)}
	done := make(chan error, 1)
	go func() {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = io.Copy(pw, stdout) }()
		go func() { defer wg.Done(); _, _ = io.Copy(pw, stderr) }()
		wg.Wait()
		done <- session.Wait()
	}()

	flush := func() {
		chunk := pw.flush()
		if chunk == "" || sink == nil {
			return
		}
		if len(chunk) > progressChunkCap {
			chunk = truncate(chunk, progressChunkCap)
		}
		emit(sink, RemoteProgress{Host: h.Name, Phase: "output", Text: chunk})
	}

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	timeoutCh := time.After(timeout)

	for {
		select {
		case runErr := <-done:
			flush()
			return formatCommandResult(command, pw.output(), runErr, hostCap, echo), nil
		case <-ticker.C:
			flush()
		case <-timeoutCh:
			session.Close() // 中断远端命令，管道 EOF 使拷贝 goroutine 退出
			select {
			case <-done:
			case <-time.After(2 * time.Second):
			}
			flush()
			return "", fmt.Errorf("执行超时（%s），会话已断开——如命令确实需要更长时间，请拆分命令，或在远端 nohup 后台执行后轮询", timeout)
		case <-ctx.Done():
			session.Close()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
			}
			flush()
			return "", ctx.Err()
		}
	}
}

// formatCommandResult 渲染模型侧命令输出：echo=true（展示路径）回显命令 +
// 截断输出 + 退出码尾注；echo=false（收集路径）只返回截断输出——采集
// 经 splitFragments 按标记切分，回显行会污染空输出探针（world_writable 等
// 被误当对象，见 R22）。
func formatCommandResult(command string, output []byte, runErr error, hostCap int, echo bool) string {
	var sb strings.Builder
	outStr := string(output)
	if len(outStr) > hostCap {
		outStr = truncateHeadTail(outStr, hostCap)
	}
	if echo {
		sb.WriteString("$ " + command + "\n")
	}
	sb.WriteString(outStr)
	if echo && runErr != nil {
		if exitErr, ok := runErr.(*ssh.ExitError); ok {
			sb.WriteString(fmt.Sprintf("\n[exit: %d]", exitErr.ExitStatus()))
		} else {
			sb.WriteString(fmt.Sprintf("\n[error: %v]", runErr))
		}
	}
	return sb.String()
}

// ── SFTP 传输（上传/下载，带进度） ────────────────────────────────────

// closeOnCancel 在 ctx 取消时强制关闭 c（SFTP 通道）：链路僵死（拔网线/
// 防火墙丢包）时底层 Read 无限阻塞，只有关闭通道才能打断传输——否则
// ctx 取消不生效，任务永久悬挂。返回的 stop 在传输完成后调用（避免
// goroutine 泄漏）。
