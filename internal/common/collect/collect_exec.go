package collect

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/go-gocel/gocode-ops/internal/common/env"
)

// collect_exec.go — 采集执行：本地/远程命令执行、CPU 与负载解析。

func (c *Collector) run(ctx context.Context, host, cmd string, timeout time.Duration) (string, error) {
	if host == "" || host == c.cfg.LocalHost && c.cfg.Local {
		return ExecLocal(ctx, cmd, timeout)
	}
	if c.remote == nil {
		return "", fmt.Errorf("ops: 未配置远程执行器，无法巡检 %s", host)
	}
	if ce, ok := c.remote.(interface {
		ExecCollect(ctx context.Context, aliases []string, command string, timeout time.Duration) (string, error)
	}); ok {
		out, err := ce.ExecCollect(ctx, []string{host}, cmd, timeout)
		if err != nil {
			return "", err
		}
		return StripSectionHeader(out), nil
	}
	out, err := c.remote.Exec(ctx, []string{host}, cmd, timeout)
	if err != nil {
		return "", err
	}
	return StripSectionHeader(out), nil
}

// ExecLocal 在本地执行命令（确定性快检，见包文档豁免说明）。
// timeout 落实为命令级超时（与远程执行一致）：≤0 时回退 30s——挂死
// 的探针（NFS/阻塞的 journalctl 等）不得卡死整轮快检。
// 输出读取时截断（cappedBuffer）——命令输出多大，内存只吃上限，
// 防止模型/探针误跑大输出命令（cat 大文件等）吃满内存。
func ExecLocal(ctx context.Context, cmd string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// 本地 shell 探测（见 shell.go）：bash-only 容器/无 Git Bash 的
	// Windows 不再因硬编码 sh 整片失败。
	c := execWithLocalShell(cctx, cmd)
	// WaitDelay：sh 被杀后其孤儿子进程可能仍持有 stdout/stderr 管道
	// （如 sleep/挂死探针），Run() 会等管道 EOF 而永久阻塞——超时后
	// 强制关闭管道，调用方按时拿回超时错误。
	c.WaitDelay = timeout
	c.Env = []string{"PATH=" + os.Getenv("PATH")}
	cap := newCappedBuffer(maxCollectOut)
	c.Stdout = cap
	c.Stderr = cap
	if err := c.Run(); err != nil {
		if cctx.Err() == context.DeadlineExceeded {
			return cap.String(), fmt.Errorf("执行超时（%s），命令已终止", timeout)
		}
		return cap.String(), fmt.Errorf("执行失败: %w", err)
	}
	// 截断告警：L0 探针输出被截断时尾部片段（cpu/load 恒在命令末尾）
	// 静默缺失会误导“全绿”——stderr 留痕，操作员/引擎日志可查。
	if cap.Truncated() {
		fmt.Fprintf(os.Stderr, "[gocode-ops] L0 采集输出截断（>%d 字节）: %s\n", maxCollectOut, firstWords(cmd, 8))
	}
	return cap.String(), nil
}

// firstWords 取命令前 n 个词（截断告警的上下文标识）。

func (c *Collector) cpuUsage(host, statOut, loadOut string) *CPUInfo {
	cur, err := parseCPUStat(statOut)
	if err != nil {
		return nil
	}
	info := &CPUInfo{NProc: c.env.NProc, Pct: -1}
	if load1, ok := parseLoad1(loadOut); ok {
		info.Load1 = load1
	}
	// prevCPU 由轮内多主机 goroutine 并发读写（见 CollectMetrics）——
	// 必须持锁，无锁并发 map 写触发 Go 运行时 fatal（P0 级崩溃）。
	c.cpuMu.Lock()
	defer c.cpuMu.Unlock()
	if prev, ok := c.prevCPU[host]; ok && cur.total > prev.total {
		dt := cur.total - prev.total
		di := cur.idle - prev.idle
		if dt > 0 {
			pct := (1 - di/dt) * 100
			if pct < 0 {
				pct = 0
			}
			if pct > 100 {
				pct = 100
			}
			info.Pct = pct
		}
	}
	c.prevCPU[host] = cur
	return info
}

// parseCPUStat 解析 /proc/stat 第一行（cpu 聚合）。
func parseCPUStat(out string) (*cpuStat, error) {
	line := firstLine(out)
	fields := strings.Fields(line)
	if len(fields) < 8 || fields[0] != "cpu" {
		return nil, fmt.Errorf("cpu: 无法解析 /proc/stat")
	}
	var total float64
	for _, f := range fields[1:] {
		v, _ := strconv.ParseFloat(f, 64)
		total += v
	}
	idle := 0.0
	if len(fields) > 4 {
		idle, _ = strconv.ParseFloat(fields[4], 64)
	}
	if len(fields) > 5 {
		iw, _ := strconv.ParseFloat(fields[5], 64)
		idle += iw
	}
	return &cpuStat{at: time.Now(), total: total, idle: idle}, nil
}

// parseLoad1 解析 /proc/loadavg 第一个字段（1 分钟平均负载）。
func parseLoad1(out string) (float64, bool) {
	f := strings.Fields(firstLine(out))
	if len(f) == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// fragRe 匹配 "__M_<id>__" 输出标记。

// execWithLocalShell 用探测到的本地 shell 构造执行命令
// （ExecLocal 与 gocel terminal 注入共用同一规格）。
func execWithLocalShell(ctx context.Context, cmd string) *exec.Cmd {
	spec := env.LocalShell()
	return exec.CommandContext(ctx, spec.Name, append(append([]string{}, spec.Args...), cmd)...)
}

// cpuStat /proc/stat 采样点，用于增量计算。
type cpuStat struct {
	at          time.Time
	total, idle float64
}
