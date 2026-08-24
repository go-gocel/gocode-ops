package workspace

import (
	"strings"
	"testing"
)

// finding ID 唯一性/确定性测试：ID 是"对象身份"不是"时间戳"——
// 同一去重键跨轮恒同 ID（模型可复述、respond 可定位），不同对象
// 必不同 ID（历史 UnixNano()%100000 同批冲突导致 byID 覆盖丢失与
// 处置目标错配）。

func TestFindingID_Deterministic(t *testing.T) {
	f1 := &Finding{Host: "web-01", Signal: "exposed_listen", Key: "telnet.socket:23"}
	f2 := &Finding{Host: "web-01", Signal: "exposed_listen", Key: "telnet.socket:23"}
	if findingID(f1) != findingID(f2) {
		t.Errorf("同一去重键应恒同 ID: %q vs %q", findingID(f1), findingID(f2))
	}
	// 大小写/空白差异（模型上报不稳定）归一化后同 ID。
	f3 := &Finding{Host: "Web-01", Signal: "Exposed_Listen", Key: "  telnet.socket:23  "}
	if findingID(f1) != findingID(f3) {
		t.Errorf("归一化去重键应同 ID: %q vs %q", findingID(f1), findingID(f3))
	}
}

func TestFindingID_UniquePerObject(t *testing.T) {
	// 同 signal 多对象（exposed_listen 的 telnet/db/app-agent）：ID 必须
	// 互不相同——历史缺陷：3 条同批入库全取到 44600。
	objs := []*Finding{
		{Host: "web-01", Signal: "exposed_listen", Key: "telnet.socket:23"},
		{Host: "web-01", Signal: "exposed_listen", Key: "0.0.0.0:3306/6379/11211/873/111"},
		{Host: "web-01", Signal: "exposed_listen", Key: "app-agent.service:8080"},
		{Host: "web-01", Signal: "passwd_policy_weak", Key: "PASS_MAX_DAYS"},
		{Host: "web-01", Signal: "passwd_policy_weak", Key: "PASS_MIN_LEN"},
	}
	seen := map[string]bool{}
	for _, f := range objs {
		id := findingID(f)
		if seen[id] {
			t.Errorf("对象 %s/%s 的 ID %q 与其他对象冲突（同批唯一性）", f.Signal, f.Key, id)
		}
		seen[id] = true
	}
	// 无 key 的同 signal 冲突：不同 host 也不同 ID。
	a := findingID(&Finding{Host: "web-01", Signal: "svc_failed"})
	b := findingID(&Finding{Host: "db-01", Signal: "svc_failed"})
	if a == b {
		t.Errorf("不同主机同 signal 应不同 ID: %q", a)
	}
}

func TestAddFindings_AssignsStableUniqueIDs(t *testing.T) {
	ws, err := NewWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// 同批入库（模型上报无 ID）：同对象两轮重报保持同一 ID；不同对象
	// ID 不同；无随机尾数（respond 契约可精确复述）。
	first := []*Finding{
		{Host: "web-01", Signal: "exposed_listen", Key: "telnet.socket:23", Status: FindingPending, Desc: "telnet"},
		{Host: "web-01", Signal: "exposed_listen", Key: "0.0.0.0:3306", Status: FindingPending, Desc: "db"},
	}
	if err := ws.AddFindings(first); err != nil {
		t.Fatal(err)
	}
	list := ws.Findings()
	if len(list) != 2 {
		t.Fatalf("len = %d, want 2", len(list))
	}
	if list[0].ID == list[1].ID {
		t.Fatalf("同批入库的 ID 冲突: %q", list[0].ID)
	}
	idTelnet := list[0].ID
	// 第二轮 L0 重报同一对象（Key 相同）：merge 保持原 ID（不新增条目、
	// 不换 ID）——respond 定位稳定。
	if err := ws.AddFindings([]*Finding{
		{Host: "web-01", Signal: "exposed_listen", Key: "telnet.socket:23", Status: FindingPending, Desc: "telnet"},
	}); err != nil {
		t.Fatal(err)
	}
	list = ws.Findings()
	if len(list) != 2 {
		t.Fatalf("重报后 len = %d, want 2（去重合并）", len(list))
	}
	kept := false
	for _, f := range list {
		if f.Key == "telnet.socket:23" && f.ID == idTelnet {
			kept = true
		}
	}
	if !kept {
		t.Errorf("重报对象应保持原 ID %q（%v）", idTelnet, list)
	}
}

// TestNewFindingBatch_UniqueIDsPerObject 回归：NewFinding 不再预设
// UnixNano 随机 ID 后，同批批量创建的不同对象必须拿到互不相同的
// 确定性 ID——历史缺陷：UnixNano()%100000 在低时钟分辨率环境
// （Hyper-V/容器）同一 tick 内批量创建全部同 ID，respond 处置
// 定位错配（byID 覆盖丢失，同 signal 多 finding 只剩一个可处置）。
func TestNewFindingBatch_UniqueIDsPerObject(t *testing.T) {
	ws, err := NewWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// 模拟 L0 一轮批量产线（同 signal 多子键 + 多信号）：全部经
	// NewFinding 创建（ID 为空）→ AddFindings 确定性补全。
	first := []*Finding{
		NewFinding("web-01", "security", "firewall_permissive", "INPUT"),
		NewFinding("web-01", "security", "firewall_permissive", "FORWARD"),
		NewFinding("web-01", "security", "ssh_chain_anomaly", "MaxAuthTries 999"),
		NewFinding("web-01", "security", "ssh_chain_anomaly", "LoginGraceTime 600"),
		NewFinding("web-01", "config", "passwd_policy_weak", "PASS_MAX_DAYS"),
		NewFinding("web-01", "config", "passwd_policy_weak", "PASS_MIN_LEN"),
		NewFinding("web-01", "config", "passwd_policy_weak", "minlen"),
	}
	for i := range first {
		first[i].Key = first[i].Desc // 探针路径经 ToFinding 带对象键
	}
	if err := ws.AddFindings(first); err != nil {
		t.Fatal(err)
	}
	list := ws.Findings()
	if len(list) != len(first) {
		t.Fatalf("len = %d, want %d（同 signal 不同 key 不得互吞）", len(list), len(first))
	}
	seen := map[string]bool{}
	for _, f := range list {
		if f.ID == "" {
			t.Fatalf("入库后 ID 不得为空: %s/%s", f.Signal, f.Key)
		}
		if seen[f.ID] {
			t.Fatalf("同批入库 ID 冲突 %q（%s/%s）——UnixNano 回归", f.ID, f.Signal, f.Key)
		}
		seen[f.ID] = true
	}
	// 响应处置定位：模型用 "信号:子键" 复述时按 key 精确命中。
	for _, f := range list {
		found := false
		for _, g := range list {
			if normKey(f.Key) == normKey(g.Key) && f.ID == g.ID && f != g {
				t.Fatalf("同 key 双对象: %q", f.Key)
			}
			if f.Key == "FORWARD" && g.Key == "FORWARD" {
				found = true
			}
		}
		_ = found
	}
}

// TestStateSummary_ClosedItemsBriefed 已关闭项简报化：dismissed 与已处置
// confirmed 在阶段摘要中只保留身份与一行现象（上下文预算），未处置项
// 保持全量（模型要裁决/处置它们）。
func TestStateSummary_ClosedItemsBriefed(t *testing.T) {
	ws, err := NewWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	closedEv := []string{"已关闭项长证据内容不应进阶段摘要-12345"}
	openEv := []string{"未处置项长证据内容应该保留-67890"}
	if err := ws.AddFindings([]*Finding{
		{Host: "web-01", Signal: "dismissed_sig", Status: FindingDismissed, Desc: "已排除项详情", Evidence: closedEv, RootCause: "已关闭根因不应进摘要-111"},
		{Host: "web-01", Signal: "fixed_sig", Status: FindingConfirmed, Remediated: true, Desc: "已处置项详情", Evidence: closedEv, RootCause: "已关闭根因不应进摘要-111"},
		{Host: "web-01", Signal: "open_sig", Status: FindingConfirmed, Desc: "未处置项详情", Evidence: openEv, RootCause: "未处置根因应该保留-222"},
		{Host: "web-01", Signal: "pending_sig", Status: FindingPending, Desc: "待查项详情", Evidence: openEv},
	}); err != nil {
		t.Fatal(err)
	}
	sum := ws.StateSummary()
	if !strings.Contains(sum, "open_sig") || !strings.Contains(sum, "未处置项详情") {
		t.Error("未处置 confirmed 应保持全量详情")
	}
	if !strings.Contains(sum, "pending_sig") {
		t.Error("pending 应保持全量详情")
	}
	if !strings.Contains(sum, "未处置根因应该保留-222") || !strings.Contains(sum, "未处置项长证据内容应该保留-67890") {
		t.Error("未处置项的证据/根因应保持全量（模型要处置它们）")
	}
	// 已关闭项：保留身份与现象，但不携带证据/根因详情（上下文瘦身）。
	for _, want := range []string{"dismissed_sig", "fixed_sig"} {
		if !strings.Contains(sum, want) {
			t.Errorf("已关闭项 %s 应保留身份", want)
		}
	}
	if strings.Contains(sum, "已关闭项长证据内容不应进阶段摘要-12345") {
		t.Error("已关闭项的证据详情不应进阶段摘要")
	}
	if strings.Contains(sum, "已关闭根因不应进摘要-111") {
		t.Error("已关闭项的根因详情不应进阶段摘要")
	}
}
