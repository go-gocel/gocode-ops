package probe

// metrics_lvm.go — LVM 探针（磁盘扩容场景的数据面补充）：df 只能看到
// 挂载点使用率，PV/VG/LV 拓扑与剩余空间不可见——LV 使用率数值指标
// + VG/LV 拓扑事实探针由此补齐。无 LVM 工具链的主机自动无数据。

import (
	"strconv"
	"strings"
)

// lvmMetrics 返回 LVM 数值指标（每轮采集；无 lvs 的主机自动无数据）。
func lvmMetrics() []Metric {
	return []Metric{
		{ID: "lvm_lv_full", Name: "逻辑卷使用率", Warn: 85, Crit: 95,
			Fragment: func(*Env) string {
				return BoundedProbe("command -v lvs >/dev/null 2>&1 && lvs --noheadings --separator '|' -o lv_name,vg_name,lv_size,lv_used --units b --nosuffix 2>/dev/null || true", 20)
			},
			Parse: parseLvsUsage,
		},
	}
}

// parseLvsUsage 解析 lvs 输出（lv_name|vg_name|lv_size|lv_used，字节
// 无后缀）：返回 "vg/lv" → 使用率%。size<=0 或 used 为 "-"/非法
// （thin/未挂载形态）时跳过该行。全空返回空 map（无数据，不产线）。
func parseLvsUsage(out string) (map[string]float64, error) {
	res := map[string]float64{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Split(line, "|")
		if len(fields) < 4 {
			continue
		}
		sz, err1 := strconv.ParseFloat(strings.TrimSpace(fields[2]), 64)
		used, err2 := strconv.ParseFloat(strings.TrimSpace(fields[3]), 64)
		if err1 != nil || err2 != nil || sz <= 0 || used < 0 {
			continue
		}
		res[strings.TrimSpace(fields[1])+"/"+strings.TrimSpace(fields[0])] = used / sz * 100
	}
	if len(res) == 0 {
		return nil, nil
	}
	return res, nil
}

// lvmFacts 返回 LVM 拓扑事实探针（VG 空间/剩余 + LV 尺寸/属性，进模型
// 上下文——LV 满但 VG 有余量时模型可直接给出 lvextend 扩容方案；
// 归属规则不产线，纯决策数据面）。
func lvmFacts() []Metric {
	return []Metric{
		{ID: "lvm_state", Name: "LVM 拓扑（VG/LV）",
			Fragment: func(*Env) string {
				return BoundedProbe("command -v vgs >/dev/null 2>&1 && vgs --noheadings -o vg_name,pv_count,lv_count,vg_size,vg_free --units g 2>/dev/null; command -v lvs >/dev/null 2>&1 && lvs --noheadings --separator '|' -o lv_name,vg_name,lv_attr,lv_size,lv_used --units b --nosuffix 2>/dev/null || true", 20)
			}},
	}
}
