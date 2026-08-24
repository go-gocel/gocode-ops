package probe

// desired_parse.go — 观测解析辅助：端口/UID0 用户/服务/路径清单解析与集合工具。

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var portRe = regexp.MustCompile(`[:.](\d{1,5})\s*$`)

func parseListenPorts(raw string) []int {
	var out []int
	seen := map[int]bool{}
	for _, line := range strings.Split(raw, "\n") {
		// ss -tlnp：State Recv-Q Send-Q Local:Port Peer:Port Process
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if m := portRe.FindStringSubmatch(fields[3]); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil && n > 0 && n <= 65535 && !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	sort.Ints(out)
	return out
}

// parseUID0Users 解析 "user:shell" 行。
func parseUID0Users(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if i := strings.IndexByte(line, ':'); i > 0 {
			line = line[:i]
		}
		out = append(out, line)
	}
	return out
}

// parseServices 解析服务单元行（去 .service 后缀）。
func parseServices(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		line = strings.TrimSuffix(line, ".service")
		out = append(out, line)
	}
	return out
}

// parsePaths 解析路径行（find -printf 输出）。
func parsePaths(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "/") {
			out = append(out, line)
		}
	}
	return out
}

// pathUnder 路径是否在 dir 下（含相等）。
func pathUnder(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/")
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func uniqueInts(in []int) []int {
	seen := map[int]bool{}
	var out []int
	for _, n := range in {
		if n > 0 && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func containsInt(list []int, n int) bool {
	for _, v := range list {
		if v == n {
			return true
		}
	}
	return false
}
