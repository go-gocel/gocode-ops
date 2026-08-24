package probe

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// metrics_parse.go — 指标输出解析器：meminfo/df/zombie/容器/内核事件/网络错误/交换/删除文件/D 状态/文件句柄。

func parseMemInfo(out string) (map[string]float64, error) {
	var total, avail float64
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			total, _ = strconv.ParseFloat(fields[1], 64)
		case "MemAvailable:":
			avail, _ = strconv.ParseFloat(fields[1], 64)
		}
	}
	if total <= 0 {
		return nil, fmt.Errorf("mem: 无法解析 MemTotal")
	}
	if avail <= 0 {
		return nil, fmt.Errorf("mem: 无法解析 MemAvailable")
	}
	return map[string]float64{"avail_pct": avail / total * 100}, nil
}

// parseDF 解析 df -P 输出：返回 挂载点→百分比。mode 支持 "capacity"（使用率）
// 与 "inode"（inode 使用率，同样在第 5 列）。
func parseDF(mode string) func(string) (map[string]float64, error) {
	return func(out string) (map[string]float64, error) {
		res := map[string]float64{}
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 6 || strings.HasPrefix(fields[0], "Filesystem") {
				continue
			}
			pct, err := strconv.ParseFloat(strings.TrimSuffix(fields[4], "%"), 64)
			if err != nil || pct < 0 || pct > 100 {
				continue // 非标准 df 输出（如 Windows 盘符列），跳过
			}
			res[fields[5]] = pct
		}
		return res, nil
	}
}

// parseZombie 数 ps -eo stat 中的僵尸进程（stat 首字符 Z）。
func parseZombie(out string) (map[string]float64, error) {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		s := strings.TrimSpace(line)
		if len(s) > 0 && s[0] == 'Z' {
			n++
		}
	}
	return map[string]float64{"count": float64(n)}, nil
}

// parseDockerPS 解析 docker ps 输出：返回 容器名→状态码（Up=0，
// Exited/Restarting/Paused=1），供"停止容器"指标判定使用。
func parseDockerPS(out string) (map[string]float64, error) {
	res := map[string]float64{}
	for _, line := range strings.Split(out, "\n") {
		name, status, ok := strings.Cut(line, "|")
		if !ok || strings.TrimSpace(name) == "" {
			continue
		}
		if strings.HasPrefix(status, "Up") {
			continue
		}
		res[strings.TrimSpace(name)] = 1
	}
	return res, nil
}

// SecurityMetrics 安全专项探针（Security 模型阶段失败时确定性兜底用）。
//
// 不参与常规 L0 采集：find 全盘扫描较重，不值得每轮跑；只在兜底时
// 采一次。判定均不依赖知识库——检出即产"线索"，由 DeepDive 验证回路
// 裁决，符合 L0 只产痕迹不产结论的哲学。
// 注：覆盖面小于模型审计，但覆盖最硬的痕迹（可被任意用户篡改的
// 弱配置、提权载体、root 直登入口）。

func parseCountLines(out string) (map[string]float64, error) {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return map[string]float64{"count": float64(n)}, nil
}

// parseProcTop 解析 ps -eo pid=,comm=,pcpu= --sort=-pcpu 输出：返回
// "pid(comm)" → %CPU 的对象级映射（键参与去重与复检——同 PID 持续
// 高占用才是对象级痕迹，PID 变化由 L0 下一轮以新线索覆盖）。
// 单进程多线程的 %CPU 可超 100（多核并行），解析不做上限裁剪。
func parseProcTop(out string) (map[string]float64, error) {
	res := map[string]float64{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pcpu, err := strconv.ParseFloat(fields[2], 64)
		if err != nil || pcpu < 0 {
			continue
		}
		res[fields[0]+"("+fields[1]+")"] = pcpu
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("proc_top: 无有效进程行")
	}
	return res, nil
}

// kernelEventRe 内核事件痕迹行匹配：OOM 杀进程、内核 panic/BUG、
// 调用栈。dmesg 输出按行匹配，模式与具体故障解耦（内核级故障的
// 通用痕迹形态）。
var kernelEventRe = regexp.MustCompile(`(?i)(out of memory|killed process|kernel panic|BUG:|oops|call trace)`)

// parseKernelEvents 数 journald 内核日志输出中的内核事件行（dmesg 受限
// 或 journalctl 不可用时输出为空，返回 0 条——无数据，不产线、不报错，
// 采集受限如实降级）。
func parseKernelEvents(out string) (map[string]float64, error) {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if kernelEventRe.MatchString(line) {
			n++
		}
	}
	return map[string]float64{"count": float64(n)}, nil
}

// parseClock 解析目标系统当前 epoch 秒（date +%s）。输出非数字时返回
// 空 map（无数据不产线）。
func parseClock(out string) (map[string]float64, error) {
	fields := strings.Fields(out)
	if len(fields) == 0 {
		return nil, nil
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || v <= 0 {
		return nil, nil
	}
	return map[string]float64{"epoch": v}, nil
}

// parseNetDevErrors 解析 /proc/net/dev：返回 网卡名 → 收发错误合计
// （rx errs + tx errs）。只保留错误数非零的网卡（健康环境无数据，
// 无噪音）；lo 排除（回环无物理链路错误语义）。
func parseNetDevErrors(out string) (map[string]float64, error) {
	res := map[string]float64{}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, ":") {
			continue
		}
		fields := strings.Fields(line)
		// face: rx_bytes rx_packets rx_errs rx_drop ... tx_bytes tx_packets tx_errs ...
		if len(fields) < 12 {
			continue
		}
		iface := strings.TrimSuffix(fields[0], ":")
		if iface == "lo" {
			continue
		}
		rx, err1 := strconv.ParseFloat(fields[3], 64)
		tx, err2 := strconv.ParseFloat(fields[11], 64)
		if err1 != nil || err2 != nil {
			continue
		}
		if n := rx + tx; n > 0 {
			res[iface] = n
		}
	}
	return res, nil
}

// parseSwap 解析 /proc/meminfo 的交换分区使用率。SwapTotal=0（无
// swap 配置）返回空 map：无数据不产线，也不报错。
func parseSwap(out string) (map[string]float64, error) {
	var total, free float64
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "SwapTotal:":
			total, _ = strconv.ParseFloat(fields[1], 64)
		case "SwapFree:":
			free, _ = strconv.ParseFloat(fields[1], 64)
		}
	}
	if total <= 0 {
		return nil, nil // 无 swap：无数据
	}
	return map[string]float64{"swap_pct": (total - free) / total * 100}, nil
}

// parseProcDeleted 数 /proc/*/exe 中指向已删除二进制的进程（内核在
// 符号链接目标后追加 " (deleted)" 标记）。ls 输出按行匹配该标记；
// 读取受限/无匹配返回 0 条（无数据，不产线）。
func parseProcDeleted(out string) (map[string]float64, error) {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, " (deleted)") {
			n++
		}
	}
	return map[string]float64{"count": float64(n)}, nil
}

// parseDState 解析 ps -eo stat=,pid=,comm= 输出：D 状态（不可中断睡眠）
// 进程 → "pid(comm)" 对象级键。0 个 D 状态是健康态（非采集失败），
// 返回空 map 不产线不报错；键风格与 proc_top 一致（对象级去重）。
func parseDState(out string) (map[string]float64, error) {
	res := map[string]float64{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.HasPrefix(fields[0], "D") {
			continue
		}
		res[fields[1]+"("+fields[2]+")"] = 1
	}
	return res, nil
}

// parseFileNR 解析 /proc/sys/fs/file-nr："已分配 未使用 上限" 三个计数。
// fd 使用率 = (已分配−未使用)/上限——未使用槽位不占资源，须扣除。
func parseFileNR(out string) (map[string]float64, error) {
	fields := strings.Fields(firstLine(out))
	if len(fields) < 3 {
		return nil, fmt.Errorf("file_desc: 无法解析 /proc/sys/fs/file-nr")
	}
	alloc, err1 := strconv.ParseFloat(fields[0], 64)
	unused, err2 := strconv.ParseFloat(fields[1], 64)
	max, err3 := strconv.ParseFloat(fields[2], 64)
	if err1 != nil || err2 != nil || err3 != nil || max <= 0 || alloc < unused {
		return nil, fmt.Errorf("file_desc: 非法数值（%s %s %s）", fields[0], fields[1], fields[2])
	}
	return map[string]float64{"fd_pct": (alloc - unused) / max * 100}, nil
}

// parseHTTPHealth 解析站点健康探测输出（演练 R5 快检进化）：
//   2xx/3xx → 空（健康，不产线）；
//   4xx/5xx → {"code": <状态码>}（站点响应异常）；
//   NONE/空（连接失败/无响应/无服务）→ {"none": 1}（站点不可达，
//   判定层按 Web 服务单元门控，无 Web 服务的主机不产线）。
func parseHTTPHealth(out string) (map[string]float64, error) {
	code := strings.TrimSpace(out)
	if code == "" || code == "NONE" {
		return map[string]float64{"none": 1}, nil
	}
	n, err := strconv.Atoi(code)
	if err != nil {
		return nil, nil // 异常输出（非状态码）：无数据，不臆断
	}
	if n >= 200 && n < 400 {
		return nil, nil
	}
	return map[string]float64{"code": float64(n)}, nil
}
