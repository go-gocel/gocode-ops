package l0

// engine_drift.go — 配置漂移检测：基线对比/行 diff/漂移归属判定（是否被自身处置命令解释）。

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/go-gocel/gocode-ops/internal/common/fsutil"
)

func (e *Engine) stateDrift(pt *BaselinePoint, selfCmds []string, rebaseline bool) []*Finding {
	var prev map[string]map[string]string
	if bl := e.ws.Baseline(); len(bl) > 0 {
		prev = bl[len(bl)-1].State
	}
	var out []*Finding
	for host, probes := range pt.State {
		old, ok := prev[host]
		if !ok {
			continue // 首轮快照，无对比基线
		}
		var changed []string
		for id, cur := range probes {
			if rebaseline && ephemeralStateProbes[id] {
				continue // 进程派生类探针：自身处置必变，静默重基线
			}
			before, ok := old[id]
			if !ok || stateUnchanged(id, before, cur) {
				continue
			}
			if rebaseline {
				removed, added := lineDiff(before, cur)
				if len(removed)+len(added) == 0 || driftExplained(id, removed, added, selfCmds) {
					continue // 变化全部由自身动作解释 → 静默重基线
				}
			}
			changed = append(changed, id)
		}
		if len(changed) > 0 {
			sort.Strings(changed)
			// 线索必须携带足以裁决的上下文：变化源、采集命令、删除/新增
			// 行（R13 实测：只报"摘要变更"的线索模型无法裁决——不知道
			// 变了什么、在哪看；R14 实测：自身处置与攻击者变更交错时，
			// 模型需自身动作清单才能裁决哪部分是引擎干的）。
			var det strings.Builder
			for _, id := range changed {
				removed, added := lineDiff(old[id], probes[id])
				fmt.Fprintf(&det, "\n- %s（采集: %s）\n  删除行: %s\n  新增行: %s",
					id, StateProbeFragment(e.col.Env(), id),
					formatDiffLines(removed), formatDiffLines(added))
			}
			if rebaseline && len(selfCmds) > 0 {
				det.WriteString("\n  本轮引擎自身动作（对比时请先扣除这些命令的效应）：")
				for i, c := range selfCmds {
					if i >= 3 {
						det.WriteString(fmt.Sprintf("\n  - …其余 %d 条", len(selfCmds)-3))
						break
					}
					det.WriteString("\n  - " + fsutil.TruncateStr(c, 160))
				}
			}
			f := NewFinding(host, "config", "config_drift",
				fmt.Sprintf("配置/状态漂移：%s 内容变更（%d 项，需确认是否预期）：%s",
					strings.Join(changed, ","), len(changed), det.String()))
			// 漂移源子键参与去重：同 signal 不同源（state_sshd vs
			// state_mounts）不互吞——否则已处置的 config_drift 会把后续
			// 新漂移源静默吃掉（R8 实测：+270s 新挂载漂移被已处置的
			// config_drift 吞掉）。
			f.Key = strings.Join(changed, ",")
			f.Source = SourceL0
			out = append(out, f)
		}
	}
	return out
}

// stateUnchanged 判断状态值是否"未变化"（内容恒变探针的漂移语义修正，
// P2 修复）：
//   - state_uptime：/proc/uptime 单调累计属正常（每轮必变），新值 ≥
//     旧值即"未变化"；数值回退（重启）才是痕迹；
//   - state_timers：systemd 定时器的 NEXT/LEFT/LAST/PASSED 时间列每轮
//     必变，归一化后只对比 UNIT/ACTIVATES 面（定时器增删/启停才是
//     痕迹，stateValue 剥离行首时间列）。
func stateUnchanged(id, before, cur string) bool {
	if id == "state_uptime" {
		b, ok1 := parseFirstFloat(before)
		c, ok2 := parseFirstFloat(cur)
		if ok1 && ok2 {
			return c >= b // 单调累计：未变化；回退（重启）：变化
		}
	}
	return stateValue(id, before) == stateValue(id, cur)
}

// parseFirstFloat 取文本首段浮点数。
func parseFirstFloat(s string) (float64, bool) {
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// stateValue 漂移对比用的归一化值：state_timers 只保留行末 UNIT 与
// ACTIVATES 两列（时间列恒在行首且每轮必变——静态按 token 位置剥离
// 在 NEXT 为空（"-"）时列位漂移，取末两列最稳）。
func stateValue(id, raw string) string {
	switch id {
	case "state_timers":
		var b strings.Builder
		for _, line := range strings.Split(raw, "\n") {
			fs := strings.Fields(line)
			if len(fs) >= 2 {
				fs = fs[len(fs)-2:] // UNIT ACTIVATES
			}
			b.WriteString(strings.Join(fs, " "))
			b.WriteString("\n")
		}
		return b.String()
	}
	return raw
}

// lineDiff 行级 diff（LCS）：增删行精确判定。公共前缀/后缀差在
// 多处间隔编辑时把中间整段报为变更（R17 实测两处单行删除报 85/83
// 行伪差——线索不可裁决），LCS 只报真正增删的行。内容上限 2KB、
// 行数 ≤ ~100，O(n·m) 代价可忽略。空串伪行（空内容 vs 非空内容）
// 不参与报告。
// lineDiffMaxLines LCS 规模护栏：超限（异常主机状态被灌入海量短行）时
// 不做全量 O(n·m) dp——数万行会数十 GB 分配 OOM；降级为整体变化粗报
// （线索照常产出，行级归属缺失可接受）。
const lineDiffMaxLines = 2000

func lineDiff(oldS, newS string) (removed, added []string) {
	oldL := strings.Split(oldS, "\n")
	newL := strings.Split(newS, "\n")
	n, m := len(oldL), len(newL)
	if n > lineDiffMaxLines || m > lineDiffMaxLines {
		return nil, []string{fmt.Sprintf("…状态内容超出行级 diff 上限（%d 行），仅报整体变化…", lineDiffMaxLines)}
	}
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			if oldL[i-1] == newL[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else if dp[i-1][j] >= dp[i][j-1] {
				dp[i][j] = dp[i-1][j]
			} else {
				dp[i][j] = dp[i][j-1]
			}
		}
	}
	i, j := n, m
	for i > 0 || j > 0 {
		switch {
		case i > 0 && j > 0 && oldL[i-1] == newL[j-1]:
			i--
			j--
		case j > 0 && (i == 0 || dp[i][j-1] >= dp[i-1][j]):
			if newL[j-1] != "" {
				added = append(added, newL[j-1])
			}
			j--
		default:
			if oldL[i-1] != "" {
				removed = append(removed, oldL[i-1])
			}
			i--
		}
	}
	for l, r := 0, len(removed)-1; l < r; l, r = l+1, r-1 {
		removed[l], removed[r] = removed[r], removed[l]
	}
	for l, r := 0, len(added)-1; l < r; l, r = l+1, r-1 {
		added[l], added[r] = added[r], added[l]
	}
	return removed, added
}

// formatDiffLines 把增删行格式化为线索文本（每行截断、最多 8 行）。
func formatDiffLines(lines []string) string {
	if len(lines) == 0 {
		return "（无）"
	}
	var b strings.Builder
	for i, l := range lines {
		if i >= 8 {
			b.WriteString(fmt.Sprintf(" …等 %d 行", len(lines)-8))
			break
		}
		if i > 0 {
			b.WriteString(" | ")
		}
		b.WriteString(fsutil.TruncateStr(strings.TrimSpace(l), 80))
	}
	return b.String()
}

// pathTokenRe 提取命令/片段文本中的路径 token（/ 开头、含常规路径字符）。
var pathTokenRe = regexp.MustCompile(`/[A-Za-z0-9_][A-Za-z0-9_./*-]*`)

// PathTokens extracts the path tokens from a text (shared by kernel drift attribution and engine evidence matching).
// PathTokens 提取文本中的路径 token 列表（公用内核漂移归属与
// 引擎证据对应校验共用）。
func PathTokens(s string) []string {
	return pathTokenRe.FindAllString(s, -1)
}

// driftExplained 判断内容类探针的变化是否全部由引擎自身动作解释：
//   - 删除行：有“持有”该探针目标路径的自身动作（rm 整体删除，或 sed
//     类编辑命令包含删除行的任一特征 token——sed 模式如 URL/配置行
//     片段就是定位证据，R17 实测全 token 覆盖要求把引擎自己的 URL 式
//     删除误报为漂移）；
//   - 新增行：行全文出现在某自身动作命令里（echo/printf 追加、sed 替换
//     体均为命令原文）——token 部分重叠不算（R15 防御：攻击者新增行
//     与自身动作仅 token 重叠不得豁免）。
//
// 解释不了的变化（R14 实测：攻击者在引擎自身 sed 前交错追加的
// MaxAuthTries 行）照常产漂移线索。
func driftExplained(probeID string, removed, added []string, selfCmds []string) bool {
	if len(selfCmds) == 0 {
		return false
	}
	frag := StateProbeFragment(nil, probeID)
	fragPaths := PathTokens(frag)
	for _, r := range removed {
		if !removedLineExplained(r, fragPaths, selfCmds) {
			return false
		}
	}
	for _, a := range added {
		if !addedLineExplained(a, selfCmds) {
			return false
		}
	}
	return true
}

// removedLineExplained 删除行是否可归属引擎自身动作：有引用探针目标
// 路径的自身动作（rm 整体删除直接归属；sed 类编辑与删除行共享任一
// ≥4 token 即归属——sed 模式里的 URL/配置行片段就是定位证据）。
func removedLineExplained(line string, fragPaths, selfCmds []string) bool {
	toks := WordTokens(line)
	if len(toks) == 0 {
		return true // 无特征 token 的行（空行/纯符号）无归属信息，不误报
	}
	for _, c := range selfCmds {
		if !ownsPath(c, fragPaths) {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(c), "rm ") {
			return true // 删除目标文件本身 → 全部删除行归属
		}
		for _, t := range toks {
			if strings.Contains(c, t) {
				return true
			}
		}
	}
	return false
}

// addedLineExplained 新增行是否可归属引擎自身动作：行全文（echo/printf
// 追加、sed 替换体）出现在某自身动作命令里——token 部分重叠不算
// （R15 实测 backup-sync 被 backup-check 误豁免吞掉 state_sudoersd）。
func addedLineExplained(line string, selfCmds []string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return true
	}
	for _, c := range selfCmds {
		if strings.Contains(c, trimmed) {
			return true
		}
	}
	return false
}

// ownsPath 命令是否引用探针目标路径（精确或子路径）。探针片段路径
// 可能含通配符（/etc/cron.d/*、/etc/profile.d/*）——归一化为目录前缀
// 后与命令中的具体路径匹配（R20 实测：rm /etc/cron.d/0backup 未能归属
// 到 /etc/cron.d/* 片段，引擎自身处置被误报为漂移）。
func ownsPath(cmd string, fragPaths []string) bool {
	for _, cp := range PathTokens(cmd) {
		for _, fp := range fragPaths {
			fp = strings.TrimSuffix(fp, "/*")
			if cp == fp || strings.HasPrefix(cp, fp+"/") || strings.HasPrefix(fp, cp+"/") {
				return true
			}
		}
	}
	return false
}

// WordTokens 提取长度 ≥4 的单词/数字 token（归属匹配的区分度：太短的
// token 如 rm/sed/80 会误匹配无关动作）。
