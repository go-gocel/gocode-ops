package remediate

// recheck_fix_test.go — 确定性复检假放行修复回归测试（P1）：
//   - 聚合信号（Key=""）进信号级复检：信号仍存在 → 不标已处置；
//   - 复检指标探针无数据（快照缺 Metrics）→ fail-closed 不标已处置
//     （探针失败被当"线索消失"是假修复成功路径）；
//   - 无判定层映射的模型自创信号 → 验证阶梯第 2 级（P0：模型验证
//     通过即标已处置，报告标注待人工复核，不阻塞收敛）。

import (
	"context"
	"strings"
	"testing"

	"github.com/go-gocel/gocode-ops/internal/common/env"
	"github.com/go-gocel/gocode-ops/internal/common/model"
	"github.com/go-gocel/gocode-ops/internal/common/probe"
)

// fakeRecheckL0 实现 Rechecker.L0：返回预置快照（或错误）。
type fakeRecheckL0 struct {
	snap *probe.Snapshot
	err  error
}

func (f *fakeRecheckL0) Env() *env.Env { return &env.Env{HasSystemd: true} }
func (f *fakeRecheckL0) CollectProbes(ctx context.Context, ms []probe.Metric, factIDs []string) (*probe.Snapshot, error) {
	return f.snap, f.err
}

func recheckOne(t *testing.T, l0 *fakeRecheckL0, f *model.Finding) {
	t.Helper()
	r := &Rechecker{L0: l0, Thresholds: model.DefaultThresholds()}
	r.Recheck(context.Background(), []*model.Finding{f})
}

// TestRecheck_AggregateSignal 聚合信号（Key=""）信号级复检：处置后信号
// 仍存在（count 未归零）→ 不标已处置（此前 Key="" 直接放行，假修复）。
func TestRecheck_AggregateSignal(t *testing.T) {
	f := &model.Finding{Host: "web-01", Signal: "svc_failed", Status: model.FindingConfirmed,
		Actions: []model.Action{{Name: "a", Command: "systemctl restart nginx", Auto: true, Verified: true}}}
	// 复检快照：svc_failed 探针有数据且 count=1（故障仍在）。
	l0 := &fakeRecheckL0{snap: &probe.Snapshot{Hosts: []probe.HostMetric{{
		Host: "web-01", Metrics: map[string]map[string]float64{"svc_failed": {"count": 1}},
	}}}}
	recheckOne(t, l0, f)
	if f.Remediated {
		t.Fatal("聚合信号仍存在时不得标已处置")
	}
	if f.Disposition != nil {
		t.Fatal("复检未通过应撤销已修复去向")
	}
	// 复检快照：count=0（处置生效）→ 标已处置。
	f2 := &model.Finding{Host: "web-01", Signal: "svc_failed", Status: model.FindingConfirmed}
	l02 := &fakeRecheckL0{snap: &probe.Snapshot{Hosts: []probe.HostMetric{{
		Host: "web-01", Metrics: map[string]map[string]float64{"svc_failed": {"count": 0}},
	}}}}
	recheckOne(t, l02, f2)
	if !f2.Remediated {
		t.Fatal("聚合信号消失应标已处置")
	}
}

// TestRecheck_MetricMissingFailClosed 复检指标探针无数据（快照缺该信号
// 的指标——探针超时/失败/整机失联）→ 无法确认线索消失，不标已处置。
func TestRecheck_MetricMissingFailClosed(t *testing.T) {
	f := &model.Finding{Host: "web-01", Signal: "svc_failed", Key: "nginx", Status: model.FindingConfirmed}
	// 快照 Metrics 为空（探针未运行）且无错误——标记缺失即"无数据"。
	l0 := &fakeRecheckL0{snap: &probe.Snapshot{Hosts: []probe.HostMetric{{
		Host: "web-01", Metrics: map[string]map[string]float64{},
	}}}}
	recheckOne(t, l0, f)
	if f.Remediated {
		t.Fatal("指标探针无数据时不得标已处置（探针失败 ≠ 线索消失）")
	}
	if f.Disposition != nil {
		t.Fatal("复检未完成应撤销已修复去向")
	}
}

// TestRecheck_UnknownSignalVerificationLadder 模型自创信号（无判定层
// 映射）：验证阶梯第 2 级（P0 修复）——判定层无法重采的信号，模型
// verify 通过 + 动作执行成功即标记已处置（报告标注"待人工复核"），
// 不再永久阻塞收敛（chaos-r1 实测：config_drift 系 7 项处置全部生效
// 仍因"无判定层映射"永不置 remediated，引擎 14 轮停滞退出）。
func TestRecheck_UnknownSignalVerificationLadder(t *testing.T) {
	f := &model.Finding{Host: "web-01", Signal: "backdoor_hint_xyz", Status: model.FindingConfirmed}
	l0 := &fakeRecheckL0{snap: &probe.Snapshot{Hosts: []probe.HostMetric{{
		Host: "web-01", Metrics: map[string]map[string]float64{},
	}}}}
	recheckOne(t, l0, f)
	if !f.Remediated {
		t.Fatal("验证阶梯：无判定层映射但模型验证通过应标已处置（待人工复核）")
	}
	if !strings.Contains(f.RemediationNote, "待人工复核") {
		t.Fatalf("应记录待人工复核标注: %q", f.RemediationNote)
	}
}

// TestRecheck_ObjectKeyPrecise 对象键精确复检：同信号其他对象仍存在
// 不影响本对象（Key 精确到对象）。
func TestRecheck_ObjectKeyPrecise(t *testing.T) {
	f := &model.Finding{Host: "web-01", Signal: "suid_unowned", Key: "/usr/bin/x",
		Status: model.FindingConfirmed}
	// 快照判定层命中同一信号但不同对象（/usr/bin/y）——本对象（x）已消失。
	l0 := &fakeRecheckL0{snap: &probe.Snapshot{Hosts: []probe.HostMetric{{
		Host: "web-01", Metrics: map[string]map[string]float64{"suid_unowned": {"": 0}},
	}}}}
	recheckOne(t, l0, f)
	if !f.Remediated {
		t.Fatal("对象键精确复检：其他对象存在不影响本对象")
	}
}
