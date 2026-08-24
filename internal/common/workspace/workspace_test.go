package workspace

import (
	"fmt"
	"github.com/go-gocel/gocode-ops/internal/common/fsutil"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestWriteFileAtomic_Concurrent 并发落盘不互相截断：唯一 tmp 名 + rename
// 原子性保证终态是两个版本之一（不会读到半截/交叉内容）。
func TestWriteFileAtomic_Concurrent(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/findings.json"
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			data := []byte(strings.Repeat(fmt.Sprintf("%d", i), 1000))
			if err := fsutil.WriteFileAtomic(path, data, 0o644); err != nil {
				t.Errorf("writeFileAtomic: %v", err)
			}
		}(i)
	}
	wg.Wait()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// 终态必须是完整单版本（1000 字符单一数字，而非交叉/半截）。
	if len(got) != 1000 {
		t.Fatalf("终态文件应完整: %d 字节", len(got))
	}
	if strings.Count(string(got), string(got[0])) != 1000 {
		t.Fatal("终态文件不应是交叉内容")
	}
	// 无残留 tmp 文件。
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, ent := range entries {
		if strings.HasSuffix(ent.Name(), ".tmp") {
			t.Errorf("不应残留 tmp 文件: %s", ent.Name())
		}
	}
}

// TestAddFindings_EvidenceDedupAndConfirmedAt 入库瘦身与时间线：
// 1) evidence 首条与 desc 完全重复时省略（findings.json 体积瘦身）；
// 2) 首次升为 confirmed 记录 ConfirmedAt（处置节奏指标）。
func TestAddFindings_EvidenceDedupAndConfirmedAt(t *testing.T) {
	ws, err := NewWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := &Finding{Host: "node1", Domain: "security", Signal: "suid_files",
		Key: "/tmp/x", Desc: "SUID 文件 /tmp/x", Status: FindingPending,
		Evidence: []string{"SUID 文件 /tmp/x"}} // 与 desc 重复
	if err := ws.AddFindings([]*Finding{f}); err != nil {
		t.Fatal(err)
	}
	if len(ws.FindingList) != 1 {
		t.Fatalf("应入库 1 条: %d", len(ws.FindingList))
	}
	if got := ws.FindingList[0].Evidence; len(got) != 0 {
		t.Errorf("evidence 与 desc 重复应省略: %v", got)
	}
	if !ws.FindingList[0].ConfirmedAt.IsZero() {
		t.Error("pending 不应有 ConfirmedAt")
	}
	// 升级 confirmed → 记录确认时间。
	f2 := &Finding{Host: "node1", Domain: "security", Signal: "suid_files",
		Key: "/tmp/x", Desc: "SUID 文件 /tmp/x", Status: FindingConfirmed,
		Evidence: []string{"stat /tmp/x 确认 SUID"}, RootCause: "植入", Tried: 1}
	if err := ws.AddFindings([]*Finding{f2}); err != nil {
		t.Fatal(err)
	}
	got := ws.FindingList[0]
	if got.Status != FindingConfirmed || got.ConfirmedAt.IsZero() {
		t.Fatalf("confirmed 应记录确认时间: status=%s confirmed_at=%v", got.Status, got.ConfirmedAt)
	}
	// 重复 confirmed 上报不刷新 ConfirmedAt（保持首次确认时间）。
	first := got.ConfirmedAt
	f3 := &Finding{Host: "node1", Domain: "security", Signal: "suid_files",
		Key: "/tmp/x", Desc: "x", Status: FindingConfirmed, Tried: 1}
	if err := ws.AddFindings([]*Finding{f3}); err != nil {
		t.Fatal(err)
	}
	if !ws.FindingList[0].ConfirmedAt.Equal(first) {
		t.Error("ConfirmedAt 应保持首次确认时间")
	}
}

// TestMerge_DriftSourceKey 漂移线索子键参与去重：同 signal（config_drift）
// 不同漂移源（state_sshd vs state_mounts）不互吞——已处置的源不吞掉
// 后续新源的线索（R8 实测：+270s 新挂载漂移被已处置的 config_drift
// 静默吞掉）。
func TestMerge_DriftSourceKey(t *testing.T) {
	ws, err := NewWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// 已处置的 sshd 漂移。
	done := &Finding{Host: "node1", Domain: "config", Signal: "config_drift",
		Key: "state_sshd", Status: FindingConfirmed, Remediated: true}
	if err := ws.AddFindings([]*Finding{done}); err != nil {
		t.Fatal(err)
	}
	// 同 signal 同源的 L0 重检出 → 不复活（终态保持）。
	sameSrc := &Finding{Host: "node1", Domain: "config", Signal: "config_drift",
		Key: "state_sshd", Status: FindingPending, Source: SourceL0}
	if err := ws.AddFindings([]*Finding{sameSrc}); err != nil {
		t.Fatal(err)
	}
	if len(ws.FindingList) != 1 {
		t.Fatalf("同源重检出不应新增: %d", len(ws.FindingList))
	}
	// 不同漂移源（新挂载）→ 独立新线索，不被已处置项吞掉。
	newSrc := &Finding{Host: "node1", Domain: "config", Signal: "config_drift",
		Key: "state_mounts", Status: FindingPending, Source: SourceL0}
	if err := ws.AddFindings([]*Finding{newSrc}); err != nil {
		t.Fatal(err)
	}
	if len(ws.FindingList) != 2 {
		t.Fatalf("新漂移源应独立成线索: %d (%+v)", len(ws.FindingList), ws.FindingList)
	}
	if got := ws.FindingList[1].Key; got != "state_mounts" {
		t.Errorf("新线索应保留子键: %q", got)
	}
}

// TestMerge_LayeredState 行为层与发现层分层：
// 已处置 confirmed 被模型重复上报（无行为字段）→ 处置状态保留。
func TestMerge_LayeredState(t *testing.T) {
	ws, err := NewWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// 引擎处置完成：confirmed + remediated + 动作记录。
	done := &Finding{Host: "web-01", Domain: "svc", Signal: "svc_failed",
		Status: FindingConfirmed, Remediated: true, RespondTried: 2,
		Actions:         []Action{{Name: "restart", Verified: true}},
		RemediationNote: "restart✓", SuggestedFix: []string{"systemctl restart nginx"},
		Tried: 1}
	if err := ws.AddFindings([]*Finding{done}); err != nil {
		t.Fatal(err)
	}
	// 模型重复上报同 key confirmed（Tried=0 无行为字段）。
	again := &Finding{Host: "web-01", Domain: "svc", Signal: "svc_failed",
		Status: FindingConfirmed, Desc: "nginx 服务 failed（模型重报）",
		Evidence: []string{"systemctl status"}}
	if err := ws.AddFindings([]*Finding{again}); err != nil {
		t.Fatal(err)
	}
	f := ws.Confirmed()[0]
	if !f.Remediated || f.RespondTried != 2 || len(f.Actions) != 1 {
		t.Errorf("模型重复上报不得清零处置状态: %+v", f)
	}
	if f.Desc != "nginx 服务 failed（模型重报）" {
		t.Errorf("发现层描述应随新上报更新: %q", f.Desc)
	}
}

// TestMerge_L0RelapseKeepsTerminal L0 探针残留信号（处置成功后 journal
// 窗口/漂移对比仍检出同 key pending）不触碰 confirmed 终态——防止
// "处置成功→重置→重处置"循环（run8 实测 log_errors 重复处置 7 次）。
// 真复发由不同 key 的新线索走 DeepDive 重新处置。
func TestMerge_L0RelapseKeepsTerminal(t *testing.T) {
	ws, err := NewWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	done := &Finding{Host: "web-01", Domain: "security", Signal: "world_writable",
		Status: FindingConfirmed, Remediated: true, RespondTried: 3,
		Actions:         []Action{{Name: "chmod", Verified: true}},
		RemediationNote: "chmod✓"}
	if err := ws.AddFindings([]*Finding{done}); err != nil {
		t.Fatal(err)
	}
	// L0 探针残留检出（Source=l0 的 pending 线索，同 key）。
	residual := &Finding{Host: "web-01", Domain: "security", Signal: "world_writable",
		Status: FindingPending, Source: SourceL0,
		Desc: "世界可写文件数=1（探针残留）"}
	if err := ws.AddFindings([]*Finding{residual}); err != nil {
		t.Fatal(err)
	}
	f := ws.Confirmed()[0]
	if !f.Remediated || f.RespondTried != 3 || len(f.Actions) != 1 {
		t.Errorf("探针残留不得重置行为层: %+v", f)
	}
	if f.Status != FindingConfirmed {
		t.Errorf("confirmed 终态保持: %q", f.Status)
	}
}

// TestMerge_ModelPendingDoesNotTouch 模型 pending 上报（非确定性证据）
// → 不触碰行为层（避免每次模型阶段上报都重置达限计数）。
func TestMerge_ModelPendingDoesNotTouch(t *testing.T) {
	ws, err := NewWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	done := &Finding{Host: "web-01", Domain: "security", Signal: "svc_failed",
		Status: FindingConfirmed, Remediated: true, RespondTried: 3}
	if err := ws.AddFindings([]*Finding{done}); err != nil {
		t.Fatal(err)
	}
	// 模型上报 pending（Source 空）。
	modelPending := &Finding{Host: "web-01", Domain: "svc", Signal: "svc_failed",
		Status: FindingPending, Desc: "疑似复发（模型口径）"}
	if err := ws.AddFindings([]*Finding{modelPending}); err != nil {
		t.Fatal(err)
	}
	f := ws.Confirmed()[0]
	if !f.Remediated || f.RespondTried != 3 {
		t.Errorf("模型 pending 上报不得触碰行为层: %+v", f)
	}
}

// TestMerge_EngineWritebackAdopted 引擎写回（respond 对象，携带行为
// 字段）→ 全量采用（处置状态以引擎为准）。
func TestMerge_EngineWritebackAdopted(t *testing.T) {
	ws, err := NewWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first := &Finding{Host: "web-01", Domain: "svc", Signal: "svc_failed",
		Status: FindingConfirmed, Tried: 1}
	if err := ws.AddFindings([]*Finding{first}); err != nil {
		t.Fatal(err)
	}
	// respond 写回：同一对象带行为字段。
	first.Remediated = true
	first.RespondTried = 1
	first.Actions = []Action{{Name: "restart", Verified: true}}
	first.RemediationNote = "restart✓"
	if err := ws.AddFindings([]*Finding{first}); err != nil {
		t.Fatal(err)
	}
	f := ws.Confirmed()[0]
	if !f.Remediated || f.RespondTried != 1 || len(f.Actions) != 1 {
		t.Errorf("引擎写回应全量采用: %+v", f)
	}
}

// TestAddFindings_BackfillAt 模型 finding 无 at（零值）→ 入库补创建时间。
func TestAddFindings_BackfillAt(t *testing.T) {
	ws, err := NewWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().Add(-time.Second)
	f := &Finding{Host: "web-01", Domain: "svc", Signal: "svc_failed",
		Status: FindingPending, Desc: "无时间戳的模型上报"}
	if err := ws.AddFindings([]*Finding{f}); err != nil {
		t.Fatal(err)
	}
	if f.At.IsZero() {
		t.Fatal("入库应补创建时间")
	}
	if f.At.Before(before) || f.At.After(time.Now().Add(time.Second)) {
		t.Errorf("创建时间应在入库时刻附近: %v", f.At)
	}
}

// TestStateSummary_Caps 阶段摘要上下文护栏：超限的事实文本与 findings
// 条数被截断并带显式标记（模型必须知道摘要不完整），落盘工作区不裁剪，
// 共享 L0Facts 不被截断污染（摘要只读副本）。
func TestStateSummary_Caps(t *testing.T) {
	ws, err := NewWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bigFact := strings.Repeat("x", stateSummaryFactsPerHost+1000)
	ws.SetL0Facts(map[string]string{"web-01": bigFact})
	for i := 0; i < stateSummaryMaxPending+10; i++ {
		if err := ws.AddFindings([]*Finding{{
			ID: fmt.Sprintf("web-01/svc_failed/%d", i), Host: "web-01",
			Signal: "svc_failed", Key: fmt.Sprintf("k%d", i), Status: FindingPending,
			Desc: fmt.Sprintf("线索 %d", i),
		}}); err != nil {
			t.Fatal(err)
		}
	}
	sum := ws.StateSummary()
	if !strings.Contains(sum, "事实文本已截断") {
		t.Error("超限事实应带截断标记")
	}
	if !strings.Contains(sum, "其余 10 条待查线索未注入上下文") {
		t.Errorf("超限 findings 应带省略标记: %.200s", sum)
	}
	// 截断不得污染共享状态：原始事实文本保持完整。
	snap := ws.L0FactsSnapshot()
	if snap["web-01"] != bigFact {
		t.Error("StateSummary 截断污染了共享 L0Facts")
	}
	// 落盘工作区不裁剪。
	if len(ws.Pending()) != stateSummaryMaxPending+10 {
		t.Errorf("落盘工作区被裁剪: %d", len(ws.Pending()))
	}
}
