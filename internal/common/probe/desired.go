package probe

// 状态模型（架构支柱一：懂系统）：期望状态 DesiredState vs 观测状态
// Snapshot 的偏差计算——"正常"由期望状态定义，而非阈值规则。
//
// 期望状态声明在 .gocode/desired.json（数据不是代码）：
//   - hosts.<host>.role：角色 → 角色模板（内置 web/db/cache/basic + 可扩展）；
//   - hosts.<host>.expect：显式覆盖（服务/端口/用户白名单、禁项清单）；
//   - policies：全局策略（禁 LD_PRELOAD、禁 root SSH 直登等）；
//   - peer_groups：同构组（横向对比：这台与兄弟们不同即偏差）。
//
// 偏差计算是纯函数（期望-观测），可单测、可审计；冷启动自动基线
// （AutoDesiredFromSnapshot）保证无声明时引擎照常可用（首次观测即期望）。

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/go-gocel/gocode-ops/internal/common/fsutil"
	"github.com/go-gocel/gocode-ops/internal/common/model"
)

// DesiredState is the desired state declared in .gocode/desired.json.
// DesiredState 期望状态（.gocode/desired.json）。
type DesiredState struct {
	Hosts         map[string]HostDesire   `json:"hosts,omitempty"`
	RoleTemplates map[string]RoleTemplate `json:"role_templates,omitempty"`
	Policies      PolicyDesire            `json:"policies,omitempty"`
	PeerGroups    [][]string              `json:"peer_groups,omitempty"`
}

// HostDesire is the desired state for a single host.
// HostDesire 单台主机的期望。
type HostDesire struct {
	Role   string     `json:"role,omitempty"`
	Expect ExpectSpec `json:"expect,omitempty"`
}

// ExpectSpec is an expectation spec: a must list (things that must be
// present) plus a forbidden list (things that must not be present).
// ExpectSpec 期望规格：must 清单（该在的必须在）+ 禁项清单（不该在的必须不在）。
type ExpectSpec struct {
	Services        []string `json:"services,omitempty"`          // 必须运行的服务单元
	Ports           []int    `json:"ports,omitempty"`             // 必须监听的端口
	Users           []string `json:"users,omitempty"`             // 必须存在的账户
	NoPorts         []int    `json:"no_ports,omitempty"`          // 禁止监听的端口
	NoUsers         []string `json:"no_users,omitempty"`          // 禁止存在的账户
	NoSUID          []string `json:"no_suid,omitempty"`           // 禁止出现 SUID 的路径前缀
	NoWorldWritable []string `json:"no_world_writable,omitempty"` // 禁止世界可写的路径前缀
}

// RoleTemplate is a role template, the reusable unit of expectation
// specs.
// RoleTemplate 角色模板（期望规格的复用单元）。
type RoleTemplate struct {
	Services        []string `json:"services,omitempty"`
	Ports           []int    `json:"ports,omitempty"`
	Users           []string `json:"users,omitempty"`
	NoPorts         []int    `json:"no_ports,omitempty"`
	NoUsers         []string `json:"no_users,omitempty"`
	NoSUID          []string `json:"no_suid,omitempty"`
	NoWorldWritable []string `json:"no_world_writable,omitempty"`
}

// PolicyDesire is the global policy.
// PolicyDesire 全局策略。
type PolicyDesire struct {
	NoLdPreload bool `json:"no_ld_preload,omitempty"` // 禁 /etc/ld.so.preload
	NoRootSSH   bool `json:"no_root_ssh,omitempty"`   // 禁 sshd PermitRootLogin yes
}

// ── 加载/保存 ──────────────────────────────────────────────────────────

// DesiredPath returns the desired-state file path.
// DesiredPath 期望状态文件路径。
func DesiredPath(workDir string) string {
	return filepath.Join(model.ConfigDir(workDir), "desired.json")
}

// LoadDesired loads the desired state, returning (nil, nil) when the
// file does not exist (deviation computation then skips it).
// LoadDesired 加载期望状态；文件不存在返回 (nil, nil)（偏差计算跳过）。
func LoadDesired(workDir string) (*DesiredState, error) {
	p := DesiredPath(workDir)
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("读取期望状态失败: %w", err)
	}
	var d DesiredState
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("解析期望状态 %s 失败: %w", p, err)
	}
	return &d, nil
}

// SaveDesired saves the desired state with an atomic write.
// SaveDesired 保存期望状态（原子写）。
func SaveDesired(workDir string, d *DesiredState) error {
	if d == nil {
		return nil
	}
	if err := os.MkdirAll(model.ConfigDir(workDir), 0o755); err != nil {
		return fmt.Errorf("创建配置目录失败: %w", err)
	}
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(DesiredPath(workDir), append(data, '\n'), 0o644)
}

// InitDesired initializes the desired-state file: it writes the template
// when missing and leaves an existing file untouched.
// InitDesired 初始化期望状态文件（不存在时写模板；已存在不动）。
// 返回是否新建。
func InitDesired(workDir string) (bool, error) {
	p := DesiredPath(workDir)
	if _, err := os.Stat(p); err == nil {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return false, fmt.Errorf("创建配置目录失败: %w", err)
	}
	tpl := `{
  "role_templates": {
    "basic": { "services": ["sshd"], "ports": [22] }
  },
  "hosts": {
    "example": { "role": "basic", "expect": {} }
  },
  "policies": { "no_ld_preload": true, "no_root_ssh": true },
  "peer_groups": [["example"]]
}
`
	if err := fsutil.WriteFileAtomic(p, []byte(tpl), 0o644); err != nil {
		return false, err
	}
	return true, nil
}

// ── 冷启动自动基线：首次观测即期望 ───────────────────────────────────

// AutoDesiredFromSnapshot generates the desired state from the
// first-round snapshot (role inference plus observed-as-desired).
// AutoDesiredFromSnapshot 用首轮快照生成期望状态（角色推断 + 观测即期望）。
// 生成的期望是保守的（服务/端口/用户白名单 = 当前观测），用户可按角色
// 模板细化。hosts 映射按快照主机名；role 统一 basic（模板可改）。
func AutoDesiredFromSnapshot(snap *Snapshot) *DesiredState {
	d := &DesiredState{
		RoleTemplates: map[string]RoleTemplate{
			"basic": {Services: []string{"sshd"}, Ports: []int{22}},
		},
		Hosts:    map[string]HostDesire{},
		Policies: PolicyDesire{NoLdPreload: true, NoRootSSH: true},
	}
	for i := range snap.Hosts {
		hm := &snap.Hosts[i]
		exp := ExpectSpec{
			Services: parseServices(hm.Raw["svc_units"]),
			Ports:    parseListenPorts(hm.Raw["listen_ports"]),
			Users:    parseUID0Users(hm.Raw["uid0_users"]),
		}
		d.Hosts[hm.Host] = HostDesire{Role: "basic", Expect: exp}
	}
	return d
}

// ── 偏差计算（纯函数） ────────────────────────────────────────────────

// Deviation is an expected-versus-observed deviation, the raw material
// of a structured finding.
// Deviation 期望-观测偏差（结构化 finding 的原料）。
type Deviation struct {
	Host     string   `json:"host"`
	Kind     string   `json:"kind"` // missing_service / unexpected_port / ...
	Expect   string   `json:"expect"`
	Actual   string   `json:"actual"`
	Severity Severity `json:"severity"`
	Evidence string   `json:"evidence,omitempty"`
}

// Signal returns the deviation signal name, kept separate from the L0
// signal table (deviations are expectation-side conclusions with
// independent dedup keys).
// Signal 偏差信号名（与 L0 信号词表隔离——偏差是期望侧结论，去重键独立）。
func (d Deviation) Signal() string { return "deviation_" + d.Kind }

// ToFinding converts the deviation into a structured finding
// (Source=deviation, Key=object).
// ToFinding 转结构化 finding（Source=deviation，Key=对象）。
func (d Deviation) ToFinding() *Finding {
	f := NewFinding(d.Host, "config", d.Signal(),
		fmt.Sprintf("期望状态偏差[%s][%s]：期望 %s；实际 %s", d.Severity, d.Kind, d.Expect, d.Actual))
	f.Source = "deviation"
	f.Evidence = []string{d.Evidence}
	f.Key = d.Expect
	return f
}

// ComputeDeviations computes all deviations deterministically as a pure
// function over the desired state and the snapshot.
// ComputeDeviations 计算全部偏差（确定性纯函数）：
//   - 每台主机：角色模板 + 显式期望合并 → must/禁项检查；
//   - 全局策略：LD_PRELOAD / root SSH；
//   - peer_groups：组内横向对比（与多数兄弟不同的监听端口）。
//
// 快照缺事实（Raw 空）时跳过对应检查（无数据不臆断）。
func ComputeDeviations(d *DesiredState, snap *Snapshot) []Deviation {
	if d == nil || snap == nil {
		return nil
	}
	var out []Deviation
	for i := range snap.Hosts {
		hm := &snap.Hosts[i]
		des, ok := d.Hosts[hm.Host]
		if !ok {
			continue // 未声明期望的主机不做偏差检查（声明即守护）
		}
		spec := mergeExpect(d, des)
		out = append(out, devExpect(hm, spec)...)
		out = append(out, devPolicy(hm, d.Policies)...)
	}
	out = append(out, devPeerGroups(d, snap)...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return sevRank(out[i].Severity) > sevRank(out[j].Severity)
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}
