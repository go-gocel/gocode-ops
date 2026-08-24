package remediate

// business.go — 业务面校验：等保合规（默认拒绝/来源收窄）不得锁死
// 业务流量。处置前/后对比业务端口清单（business_ports 探针：监听中
// 且非管理面进程的端口），非处置目标的业务端口消失 = 业务中断事故
// （历史实测：管理面收窄锁死全部业务端口，引擎自己的通道仍通——
// 自通道校验只验管理面，验不了业务面，必须由本校验闭环兜底）。

import (
	"regexp"
	"strings"
)

// ParseBusinessPorts 解析 business_ports 探针输出（行格式 <端口>|<进程>）
// 为 端口→进程 映射。畸形行跳过。
func ParseBusinessPorts(raw string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
			continue
		}
		out[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return out
}

// BusinessDiff 处置前/后业务端口对比：返回"非处置目标却消失"的端口
// （业务中断事故，行格式 <端口>|<进程>）。targetCmds 是已执行动作的
// 命令文本集合——命令提及该端口号或进程名 = 处置目标（如杀后门
// 进程、关后门监听），端口消失属预期；否则为事故。
func BusinessDiff(before, after map[string]string, targetCmds []string) []string {
	var lost []string
	for port, proc := range before {
		if _, ok := after[port]; ok {
			continue
		}
		if actionTargetsPort(targetCmds, port, proc) {
			continue // 处置目标：预期消失
		}
		lost = append(lost, port+"|"+proc)
	}
	return lost
}

// portTokenRe 命令中的端口号 token（独立数字，防 "80" 误匹配 "8080"
// 之类——\b 边界保证）。
var portTokenRe = regexp.MustCompile(`\b\d{1,5}\b`)

// actionTargetsPort 判定动作命令是否针对该端口/进程（命令含进程名
// 子串或端口号独立 token = 处置目标）。
func actionTargetsPort(cmds []string, port, proc string) bool {
	for _, c := range cmds {
		if proc != "" && strings.Contains(c, proc) {
			return true
		}
		for _, tok := range portTokenRe.FindAllString(c, -1) {
			if tok == port {
				return true
			}
		}
	}
	return false
}
