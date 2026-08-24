package autopilot

// 通道约束兜底（机制 2）：模型把疑点写进自由文本（notes/next/desc）
// 而非结构化 findings 时，发现会因通道错位而丢失（4444 后门漏检的
// 直接断点之一）。本模块从阶段小结的自由文本提取疑点，实例化为
// pending 线索，进入既有 DeepDive 验证回路。
//
// 定位：兜底，不承担主责。主责在机制 1（确定性事实保障——枚举探针
// 让大脑必须看见）。本模块只做"模型已表述的疑点不丢"，语义锚点是
// 通用疑点用语（与具体漏洞/端口/样本无关），否定语境（无异常/未发现）
// 先排除再匹配。

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/go-gocel/gocode-ops/internal/common/collect"
	"github.com/go-gocel/gocode-ops/internal/common/model"
)

// doubtAnchor 语义锚点 → 实例化线索的稳定信号名。
// 只保留高信号疑点用语（后门/植入/篡改/伪造/未授权等明确指控），
// 不收"异常/风险/可疑"等低信号词——正常巡检描述里高频出现，实例化
// 会产大量噪音线索稀释 DeepDive/respond 焦点（run6 实测 7 条噪音）。
// 模型用这些词表述任何可疑事物都会被同一机制捕获——不针对具体形态。
var doubtAnchors = []struct {
	anchor string
	signal string
}{
	{"后门", "backdoor_hint"},
	{"植入", "implanted_hint"},
	{"被篡改", "tampered_hint"},
	{"篡改", "tampered_hint"},
	{"伪造", "forged_hint"},
	{"未授权", "unauthorized_hint"},
	{"待查", "pending_hint"},
	{"待诊断", "pending_hint"},
}

// doubtObjectRe 疑点对象的实体特征：锚点上下文必须含具体对象
// （端口/路径/进程/用户/文件/域名），否则是泛泛描述不实例化。
var doubtObjectRe = regexp.MustCompile(
	`\d{2,5}|/[a-zA-Z0-9_./-]{3,}|[a-zA-Z0-9_-]{3,}\.(?:sh|py|so|conf|service|local|com|cn|net|org)|` +
		`pid\s*\d+|用户\s*\S+|进程\s*\S+|端口\s*\S+|文件\s*\S+|服务\s*\S+`)

// doubtNegationRe 否定语境：明确表达"没有/无"时不实例化（防止把
// "无异常/未发现可疑"误判为疑点）。
var doubtNegationRe = regexp.MustCompile(
	`无(?:任何|明显|重大|大)?(?:异常|可疑|风险|后门|问题|暴露|发现)|` +
		`未发现(?:任何)?(?:异常|可疑|风险|后门|问题)|` +
		`均正常|一切正常|无风险`)

// extractDoubtLeads 从阶段小结自由文本提取疑点 → pending 线索。
// 去重按 (host, signal)：同阶段同信号只产一条；AddFindings 再做全局去重。
// 单目标时 host 明确归属；多目标时 host 留空（待 DeepDive 按 desc 定位，
// 错挂 targets[0] 会让疑点线索在错误主机上追查）。
func extractDoubtLeads(sum *PhaseSummary, targets []string) []*Finding {
	if sum == nil {
		return nil
	}
	host := ""
	// 单目标明确归属；多目标时 host 留空（待 DeepDive 按 desc 定位）——
	// 错挂 targets[0] 会让疑点线索分裂/在错误主机上追查（P3 修复）。
	if len(targets) == 1 {
		host = targets[0]
	}
	var out []*Finding
	seen := map[string]bool{}
	texts := []string{sum.Notes, sum.Next}
	for _, f := range sum.Findings {
		texts = append(texts, f.Desc)
		texts = append(texts, f.Evidence...)
	}
	for _, text := range texts {
		if text == "" || doubtNegationRe.MatchString(text) {
			continue
		}
		for _, p := range doubtAnchors {
			if !strings.Contains(text, p.anchor) {
				continue
			}
			key := host + "\x00" + p.signal
			if seen[key] {
				continue
			}
			// 对象存在性：锚点上下文须含具体实体（端口/路径/进程/用户/文件），
			// 泛泛描述（"存在风险""可能有后门"）不实例化——防噪音线索。
			if !doubtObjectRe.MatchString(doubtSentence(text, p.anchor)) {
				continue
			}
			seen[key] = true
			f := model.NewFinding(host, "security", p.signal,
				fmt.Sprintf("模型文本疑点（%s）：%s（host 待 DeepDive 验证）", p.anchor, doubtSentence(text, p.anchor)))
			f.Evidence = []string{collect.TruncateStr(text, 200)}
			out = append(out, f)
		}
	}
	return out
}

// doubtSentence 提取锚点所在分句（前后各 40 字），供线索描述使用。
func doubtSentence(text, anchor string) string {
	i := strings.Index(text, anchor)
	if i < 0 {
		return collect.TruncateStr(text, 120)
	}
	start := i - 40
	if start < 0 {
		start = 0
	}
	end := i + len(anchor) + 40
	if end > len(text) {
		end = len(text)
	}
	return strings.TrimSpace(text[start:end])
}
