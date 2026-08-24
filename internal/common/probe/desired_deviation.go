package probe

// desired_deviation.go — 偏差计算：期望×观测 → Deviation（期望/策略/横向对比三来源）。

import (
	"fmt"
	"strconv"
	"strings"
)

func sevRank(s Severity) int {
	switch s {
	case SevCrit:
		return 2
	case SevWarn:
		return 1
	}
	return 0
}

// mergeExpect 合并角色模板与显式期望（显式覆盖模板同名项）。
func mergeExpect(d *DesiredState, des HostDesire) ExpectSpec {
	var tpl RoleTemplate
	if des.Role != "" && d.RoleTemplates != nil {
		tpl = d.RoleTemplates[des.Role]
	}
	return ExpectSpec{
		Services:        append([]string{}, append(tpl.Services, des.Expect.Services...)...),
		Ports:           append([]int{}, append(tpl.Ports, des.Expect.Ports...)...),
		Users:           append([]string{}, append(tpl.Users, des.Expect.Users...)...),
		NoPorts:         append([]int{}, append(tpl.NoPorts, des.Expect.NoPorts...)...),
		NoUsers:         append([]string{}, append(tpl.NoUsers, des.Expect.NoUsers...)...),
		NoSUID:          append([]string{}, append(tpl.NoSUID, des.Expect.NoSUID...)...),
		NoWorldWritable: append([]string{}, append(tpl.NoWorldWritable, des.Expect.NoWorldWritable...)...),
	}
}

// devExpect 单台主机的 must/禁项偏差。数据缺失语义（P2 修复）：探针
// 采集失败/无数据时跳过对应组检查——"无数据"与"服务缺失"语义不同，
// 空数据批量误报（missing_service/missing_port/missing_user）会驱动
// 错误处置（与 JudgeSecurityFacts 的覆盖语义同口径：partial 不产结论）。
func devExpect(hm *HostMetric, spec ExpectSpec) []Deviation {
	var out []Deviation
	if len(spec.Services) > 0 && hasData(hm, "svc_units") {
		svcs := parseServices(hm.Raw["svc_units"])
		for _, want := range unique(spec.Services) {
			if !containsStr(svcs, want) {
				out = append(out, Deviation{Host: hm.Host, Kind: "missing_service",
					Expect: "服务 " + want + " 运行中", Actual: "未运行", Severity: SevWarn,
					Evidence: "svc_units 无 " + want})
			}
		}
	}
	if (len(spec.Ports) > 0 || len(spec.NoPorts) > 0) && hasData(hm, "listen_ports") {
		ports := parseListenPorts(hm.Raw["listen_ports"])
		for _, want := range uniqueInts(spec.Ports) {
			if !containsInt(ports, want) {
				out = append(out, Deviation{Host: hm.Host, Kind: "missing_port",
					Expect: "端口 " + strconv.Itoa(want) + " 监听中", Actual: "未监听", Severity: SevWarn,
					Evidence: "listen_ports 无 " + strconv.Itoa(want)})
			}
		}
		for _, banned := range uniqueInts(spec.NoPorts) {
			if containsInt(ports, banned) {
				out = append(out, Deviation{Host: hm.Host, Kind: "unexpected_port",
					Expect: "端口 " + strconv.Itoa(banned) + " 禁止监听", Actual: "监听中", Severity: SevCrit,
					Evidence: "listen_ports 命中 " + strconv.Itoa(banned)})
			}
		}
	}
	if (len(spec.Users) > 0 || len(spec.NoUsers) > 0) && hasData(hm, "uid0_users") {
		users := parseUID0Users(hm.Raw["uid0_users"])
		for _, want := range unique(spec.Users) {
			if !containsStr(users, want) {
				out = append(out, Deviation{Host: hm.Host, Kind: "missing_user",
					Expect: "账户 " + want + " 存在", Actual: "不存在", Severity: SevWarn,
					Evidence: "uid0_users 无 " + want})
			}
		}
		for _, banned := range unique(spec.NoUsers) {
			if containsStr(users, banned) {
				out = append(out, Deviation{Host: hm.Host, Kind: "unexpected_user",
					Expect: "账户 " + banned + " 禁止存在", Actual: "存在", Severity: SevCrit,
					Evidence: "uid0_users 命中 " + banned})
			}
		}
	}
	if len(spec.NoSUID) > 0 && hasData(hm, "suid_files") {
		for _, dir := range unique(spec.NoSUID) {
			for _, p := range parsePaths(hm.Raw["suid_files"]) {
				if pathUnder(p, dir) {
					out = append(out, Deviation{Host: hm.Host, Kind: "unexpected_suid",
						Expect: "路径 " + dir + " 下禁止 SUID", Actual: p, Severity: SevCrit,
						Evidence: "suid_files 命中 " + p})
				}
			}
		}
	}
	if len(spec.NoWorldWritable) > 0 && hasData(hm, "world_writable") {
		for _, dir := range unique(spec.NoWorldWritable) {
			for _, p := range parsePaths(hm.Raw["world_writable"]) {
				if pathUnder(p, dir) {
					out = append(out, Deviation{Host: hm.Host, Kind: "unexpected_world_writable",
						Expect: "路径 " + dir + " 下禁止世界可写", Actual: p, Severity: SevWarn,
						Evidence: "world_writable 命中 " + p})
				}
			}
		}
	}
	return out
}

// hasData 探针数据可用性（期望偏差的覆盖语义）：partial 覆盖（采集
// 失败/未完整）一律视为无数据；覆盖 full（探针运行、可能零命中）视为
// 有数据；覆盖位缺失（非安全事实探针/旧数据）按 Raw 非空兜底。
func hasData(hm *HostMetric, id string) bool {
	if hm.FactCoverage[id] == "partial" {
		return false
	}
	if hm.FactCoverage[id] == "full" {
		return true
	}
	return strings.TrimSpace(hm.Raw[id]) != ""
}

// devPolicy 全局策略偏差（基于现有事实可判的）。
func devPolicy(hm *HostMetric, p PolicyDesire) []Deviation {
	var res []Deviation
	if p.NoLdPreload {
		if raw := strings.TrimSpace(hm.Raw["ld_preload"]); raw != "" {
			res = append(res, Deviation{Host: hm.Host, Kind: "policy_ld_preload",
				Expect: "策略禁止 /etc/ld.so.preload", Actual: raw, Severity: SevCrit,
				Evidence: "ld_preload 事实命中"})
		}
	}
	if p.NoRootSSH {
		// 语义与 ssh_root_login 探针一致（单一来源 parseSSHRootLogin）：
		// 仅 root 密码直登（PermitRootLogin yes 且 PasswordAuthentication
		// 未禁用）违规；root 密钥直登（prohibit-password/without-password）
		// 是等保认可形态，不产偏差。
		if vals, err := parseSSHRootLogin(hm.Raw["ssh_chain"]); err == nil && vals["count"] > 0 {
			res = append(res, Deviation{Host: hm.Host, Kind: "policy_root_ssh",
				Expect: "策略禁止 sshd root 密码直登（PermitRootLogin yes + PasswordAuthentication 未禁用）",
				Actual: "sshd 配置开放 root 密码直登", Severity: SevWarn, Evidence: "ssh_chain 命中"})
		}
	}
	return res
}

// devPeerGroups 同构组横向对比：组内多数主机都监听的端口是"组基线"，
// 某主机监听了组内少数派端口（且不在自身 must 清单）→ 偏差。
func devPeerGroups(d *DesiredState, snap *Snapshot) []Deviation {
	if len(d.PeerGroups) == 0 {
		return nil
	}
	portsByHost := map[string][]int{}
	for i := range snap.Hosts {
		portsByHost[snap.Hosts[i].Host] = parseListenPorts(snap.Hosts[i].Raw["listen_ports"])
	}
	var out []Deviation
	for _, group := range d.PeerGroups {
		count := map[int]int{}
		for _, h := range group {
			for _, p := range portsByHost[h] {
				count[p]++
			}
		}
		threshold := (len(group) + 1) / 2 // 组内多数
		for _, h := range group {
			// 该主机有、但组内多数（≥半数）没有的端口。
			for _, p := range portsByHost[h] {
				if count[p] < threshold {
					if des, ok := d.Hosts[h]; ok && containsInt(mergeExpect(d, des).Ports, p) {
						continue // 自身 must 清单内的不算偏差
					}
					out = append(out, Deviation{Host: h, Kind: "unexpected_vs_peers",
						Expect: fmt.Sprintf("端口 %d 在同构组 %v 中属少数派（%d/%d 台）", p, group, count[p], len(group)),
						Actual: "本机监听 " + strconv.Itoa(p), Severity: SevWarn,
						Evidence: "peer 横向对比"})
				}
			}
		}
	}
	return out
}

// ── 事实解析（确定性） ────────────────────────────────────────────────

// portRe 从 ss -tlnp 行提取监听地址列中的端口（0.0.0.0:80 / [::]:443）。
