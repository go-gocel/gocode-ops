package remediate

// remediate_test.go — 处置执行器测试（原 autopilot/respond_test.go 中
// 执行侧测试随机制下沉；引擎集成测试保留在 autopilot）。

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-gocel/gocode-ops/internal/common/audit"
	"github.com/go-gocel/gocode-ops/internal/common/guard"
)

// fakeRemote 最小 RemoteExecutor 测试实现（按命令返回预设输出）。
type fakeRemote struct {
	out string
	err error
}

func (f *fakeRemote) Exec(ctx context.Context, hosts []string, command string, timeout time.Duration) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.out, nil
}
func (f *fakeRemote) Upload(ctx context.Context, hosts []string, localPath, remotePath string, mode os.FileMode) (string, error) {
	return "", nil
}
func (f *fakeRemote) Download(ctx context.Context, hosts []string, remotePath, localDir string) (string, error) {
	return "", nil
}
func (f *fakeRemote) FileInfo(ctx context.Context, host, remotePath string, list bool) (string, error) {
	return "", nil
}
func (f *fakeRemote) ListHosts() (string, error) { return "", nil }
func (f *fakeRemote) Aliases() ([]string, error) { return nil, nil }
func (f *fakeRemote) Probe(ctx context.Context, aliases []string, timeout time.Duration) map[string]string {
	res := map[string]string{}
	for _, a := range aliases {
		res[a] = "在线"
	}
	return res
}
func (f *fakeRemote) Resolve(aliases []string) ([]string, error) { return aliases, nil }

// TestExecutor_AuditWritten 处置直连 exec 通道审计留痕（此前无人值守下
// 最危险的命令是唯一不落盘的部分）：Kind=respond、真实主机、命令经
// SanitizeArgs 脱敏。
func TestExecutor_AuditWritten(t *testing.T) {
	al, err := audit.NewAuditLog(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gd := guard.NewRiskyCommandGuard(nil, guard.PolicyAuto)
	gd.Audit = al
	ex := NewExecutor(Config{}, gd, nil, nil, nil)
	ex.findingID = "web-01/svc_failed/123"

	ex.auditRespond("web-01", "restart nginx", "mysql -uroot -psecret -e 'x'", "executed", "ok")
	ex.auditRespond("", "cleanup", "uptime", "failed", "boom")

	data, err := os.ReadFile(al.Path())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("应有两行审计: %d", len(lines))
	}
	var ev audit.AuditEvent
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Kind != "respond" || ev.Tool != "engine" {
		t.Fatalf("审计来源应 respond/engine: %+v", ev)
	}
	if len(ev.Hosts) != 1 || ev.Hosts[0] != "web-01" {
		t.Fatalf("主机应记录: %v", ev.Hosts)
	}
	if strings.Contains(ev.Args, "secret") || !strings.Contains(ev.Args, "-p ***") {
		t.Fatalf("命令应脱敏: %q", ev.Args)
	}
	if ev.Decision != "executed" {
		t.Fatalf("Decision = %q, want executed", ev.Decision)
	}
	// 处置审计追溯键：审计事件必须关联到故障与动作（复盘"这条命令处置
	// 了哪个故障"）。此前 respond 审计只有命令文本无法回溯。
	if ev.FindingID != "web-01/svc_failed/123" || ev.ActionName != "restart nginx" {
		t.Fatalf("审计应携带 finding 关联: %+v", ev)
	}
}

// TestPrecheckObjectToken 预检对象关键词提取：verify 必须引用处置对象
// 否则预检判据脱靶（R24 实测 "sshd -t && echo OK" 只验语法不验配置行，
// 预检假通过导致已确认后门残留并收敛）。
func TestPrecheckObjectToken(t *testing.T) {
	cases := []struct {
		key  string
		want string
	}{
		{"AuthorizedKeysFile .ssh/authorized_keys /root/.ssh/.evil-keys", "evil-keys"},
		{"0.0.0.0:9090", "0.0.0.0:9090"},
		{"vm.dirty_ratio", "vm.dirty_ratio"},
		{"/etc/cron.d/keepalive", "keepalive"},
		{"/etc/pam.d/backdoor-pam", "backdoor-pam"},
		{"", ""},
		{"ab", ""}, // 过短不强制
	}
	for _, c := range cases {
		if got := precheckObjectToken(c.key); got != c.want {
			t.Errorf("precheckObjectToken(%q) = %q, want %q", c.key, got, c.want)
		}
	}
}

// TestPrecheckSatisfied_ObjectMismatch R24 回归：处置对象与 verify 无关
// 时（判据脱靶）不得预检通过——走真实执行让副作用真正发生。
func TestPrecheckSatisfied_ObjectMismatch(t *testing.T) {
	rmt := &fakeRemote{out: "syntax is ok\n"}
	// verify 只验 sshd 语法（恒真于配置行是否被删）——不引用对象
	// token（evil-keys）→ 预检必须拒绝。
	plan := &Plan{
		FindingID: "f",
		Actions: []PlanAction{{
			Name:    "remove evil akf",
			Command: "sed -i '/evil-keys/d' /etc/ssh/sshd_config",
			Verify:  "sshd -t && echo AKF_RESTORED",
			CheckUp: "AKF_RESTORED",
		}},
	}
	cfg := Config{VerifyTimeout: 2 * time.Second}
	ok, _ := PrecheckSatisfied(context.Background(), cfg, rmt, "web-01", plan, "AuthorizedKeysFile .ssh/authorized_keys /root/.ssh/.evil-keys")
	if ok {
		t.Fatal("verify 未引用处置对象（判据脱靶），预检不得通过")
	}
	// 对照：verify 引用对象（grep evil-keys 确认行消失）→ 判据有效。
	plan.Actions[0].Verify = "grep -q 'evil-keys' /etc/ssh/sshd_config && echo GONE || echo STILL_POISONED"
	plan.Actions[0].CheckUp = "GONE"
	rmt.out = "STILL_POISONED\n"
	ok, _ = PrecheckSatisfied(context.Background(), cfg, rmt, "web-01", plan, "AuthorizedKeysFile .ssh/authorized_keys /root/.ssh/.evil-keys")
	if ok {
		t.Fatal("对象仍在（STILL_POISONED），预检不得通过")
	}
	rmt.out = "GONE\n"
	ok, _ = PrecheckSatisfied(context.Background(), cfg, rmt, "web-01", plan, "AuthorizedKeysFile .ssh/authorized_keys /root/.ssh/.evil-keys")
	if !ok {
		t.Fatal("对象已消失且 verify 引用对象，预检应通过")
	}
}

// TestTautologicalVerify 恒真验证检测：check_up 与 verify 中无条件
// echo/printf 的输出相同即恒真（状态检查失败也照常输出标记，不算
// 恢复证据）；&&/|| 门控在状态检查之后的标记不是恒真。
func TestTautologicalVerify(t *testing.T) {
	cases := []struct {
		verify, checkUp string
		want            bool
	}{
		{"echo removed", "removed", true},
		{"grep -c X /etc/hosts; echo removed", "removed", true},
		{"printf 'gone'", "gone", true},
		{"test ! -f /tmp/x && echo removed", "removed", false},
		{"grep -q svc-check /etc/hosts || echo removed", "removed", false},
		{"grep -c X /etc/hosts", "removed", false},
		{"echo removed", "", false},
	}
	for _, c := range cases {
		if got := tautologicalVerify(c.verify, c.checkUp); got != c.want {
			t.Errorf("tautologicalVerify(%q, %q) = %v, want %v", c.verify, c.checkUp, got, c.want)
		}
	}
}

func TestCheckUpMatches(t *testing.T) {
	cases := []struct {
		out, want string
		ok        bool
		why       string
	}{
		// 短文本：完整行相等（精确）。
		{"active\n", "active", true, "整行 active"},
		{"inactive\n", "active", false, "inactive 不得误配 active（子串陷阱）"},
		{"644\nroot\n", "644", true, "单行 644"},
		{"644\nroot\n", "root", true, "单行 root"},
		// 短语：长文本子串匹配（模型自然写法）。
		{"nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\n", "syntax is ok", true, "短语是输出行的一部分"},
		{"ss -tlnp: LISTEN 127.0.0.1:6379 0.0.0.0:*\n", "127.0.0.1:6379", true, "短语含端口"},
		{"no such thing here\n", "syntax is ok", false, "短语不存在"},
		// 多行：按顺序完整行匹配。
		{"644\nroot\n", "644\nroot", true, "两行顺序出现"},
		{"root\n644\n", "644\nroot", false, "顺序不符"},
		{"644\nother\nroot\n", "644\nroot", true, "两行非连续但顺序出现"},
		// 错误行不作恢复证据：报错文本里的同名短语/整行不得冒充验证通过。
		{"ERROR: ld.so: object cannot be preloaded: ignored.\nactive\n", "active", true, "错误行之后仍有正常行"},
		{"ERROR: userdel: user backdoor is currently used by process 1\n", "backdoor", false, "错误行中的短语不算证据"},
		{"failed to connect\nsyntax is ok\n", "syntax is ok", true, "正常行短语照常匹配"},
		{"permission denied\n644\n", "644", true, "错误行后的正常行"},
		{"command not found\nactive\n", "command not found", false, "check_up 本身是错误文本不算恢复"},
		{"Active: failed (Result: exit-code)\n", "Active", false, "非失败行整行匹配仍按整行语义"},
		{"ERROR: x\n644\nERROR: y\nroot\n", "644\nroot", true, "多行匹配跳过错误行"},
		// 边界。
		{"", "active", false, "空输出"},
		{"x\n", "", false, "空期望"},
	}
	for _, c := range cases {
		if got := checkUpMatches(c.out, c.want); got != c.ok {
			t.Errorf("%s：checkUpMatches(%q, %q) = %v, want %v", c.why, c.out, c.want, got, c.ok)
		}
	}
}

// TestCheckUpMatches_Chinese 中文（rune 计数，非字节）。
func TestCheckUpMatches_Chinese(t *testing.T) {
	out := "服务状态：运行中，端口 80 正常监听\n"
	// 长短语（≥8 rune）子串匹配。
	if !checkUpMatches(out, "端口 80 正常监听") {
		t.Error("长中文短语应子串匹配")
	}
	// 短文本（<8 rune）走完整行精确匹配，行内短语不命中。
	if checkUpMatches(out, "运行中") {
		t.Error("短中文文本应走完整行匹配，行内短语不应命中")
	}
	if !checkUpMatches("运行中\n", "运行中") {
		t.Error("整行相等应命中")
	}
}

// TestIsErrorLine_LdSoPreloadNoise 动态链接器预载失败是环境噪声（进程
// 启动阶段、先于命令逻辑），不是命令失败证据——R21 实测攻击者注入
// ld.so.preload 后每条命令 stderr 刷此噪声，处置动作被"错误行即失败"
// 误判；真实错误行照旧判定。
func TestIsErrorLine_LdSoPreloadNoise(t *testing.T) {
	noise := []string{
		"ERROR: ld.so: object '/tmp/libx.so' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.",
		"error: ld.so: object '/tmp/x' from /etc/ld.so.preload cannot be preloaded: ignored.",
	}
	for _, l := range noise {
		if isErrorLine(l) {
			t.Errorf("预载噪声不得判为错误行: %q", l)
		}
	}
	for _, l := range []string{
		"ERROR: something real failed",
		"sed: cannot rename /etc/sedXXX: Device or resource busy",
		"cp: cannot stat 'x': No such file or directory",
		"fatal: git error",
	} {
		if !isErrorLine(l) {
			t.Errorf("真实错误行应判定失败: %q", l)
		}
	}
}

// TestPkillSelfCheck pkill/pgrep -f 自杀预检：-f 全命令行匹配会命中
// 执行 shell 自身（其命令行包含模式字面）——R22 实测
// `rm /tmp/keepalive.sh; pkill -f 'keepalive[.]sh'` 退出码 143（自杀）
// 导致处置失败。
func TestPkillSelfCheck(t *testing.T) {
	cases := []struct {
		cmd  string
		want string // 期望命中；空=不命中
	}{
		{"rm -f /tmp/keepalive.sh; pkill -f 'keepalive[.]sh'", "自杀"},
		{"rm -f /etc/cron.d/grow /tmp/grow.sh; pkill -f 'grow[.]sh'", "自杀"},
		{"systemctl restart nginx; pkill -f 'nginx'", "自杀"},
		{"pkill -f 'keepalive[.]sh'", ""},
		{"pkill -f 'http\\.serve[r] 9090'; true", ""},
		{"pgrep -f 'grow[.]sh' | xargs -r kill", ""},
		{"systemctl stop nginx", ""},
	}
	for _, c := range cases {
		got := pkillSelfCheck(c.cmd)
		if (c.want == "") != (got == "") {
			t.Errorf("pkillSelfCheck(%q) = %q, want 命中=%v", c.cmd, got, c.want != "")
		}
		if c.want != "" && !strings.Contains(got, "自杀") {
			t.Errorf("pkillSelfCheck(%q) 原因应含自杀说明: %q", c.cmd, got)
		}
	}
}

// TestPkillAutoFix pkill/pgrep -f 机械改写：模式括号化或顶层拆段，
// 保证执行 shell 命令行不被自身模式命中——处置自由度与执行安全兼得。
func TestPkillAutoFix(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want []string // 期望执行段（nil=期望不可改写）
	}{
		{"无风险原样单段", "systemctl stop nginx", []string{"systemctl stop nginx"}},
		{"已防自匹配单段", "pkill -f 'keepalive[.]sh'", []string{"pkill -f 'keepalive[.]sh'"}},
		{"裸模式括号化单段", "pkill -f 'http.server 9090'", []string{"pkill -f '[h]ttp.server 9090'"}},
		{"多模式全部括号化", "pkill -f 'http.server 8088'; pkill -f 'http.server 9090'",
			[]string{"pkill -f '[h]ttp.server 8088'; pkill -f '[h]ttp.server 9090'"}},
		{"跨段字面拆段执行", "rm -f /tmp/keepalive.sh; pkill -f 'keepalive[.]sh'",
			[]string{"rm -f /tmp/keepalive.sh", "pkill -f '[k]eepalive[.]sh'"}},
		{"其他部分含字面拆段", "systemctl restart nginx; pkill -f 'nginx'",
			[]string{"systemctl restart nginx", "pkill -f '[n]ginx'"}},
		{"R22 形态拆段", "rm -f /etc/cron.d/grow /tmp/grow.sh; pkill -f 'grow[.]sh'",
			[]string{"rm -f /etc/cron.d/grow /tmp/grow.sh", "pkill -f '[g]row[.]sh'"}},
	}
	for _, c := range cases {
		got, ok := PkillAutoFix(c.cmd)
		if c.want == nil {
			if ok {
				t.Errorf("%s: 应不可改写，got %v", c.name, got)
			}
			continue
		}
		if !ok {
			t.Errorf("%s: 应可改写: %q", c.name, c.cmd)
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("%s: segs = %v, want %v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: seg[%d] = %q, want %q", c.name, i, got[i], c.want[i])
			}
		}
		// 每个执行段都必须通过自杀预检（改写的目的）。
		for i, s := range got {
			if note := pkillSelfCheck(s); note != "" {
				t.Errorf("%s: 执行段 %d 仍自匹配: %s（%q）", c.name, i, note, s)
			}
		}
	}
}

// TestParseExitCode 从远程输出尾部解析退出码尾注（处置路径把非零退出码视为失败）。
func TestParseExitCode(t *testing.T) {
	cases := []struct {
		out  string
		code int
		ok   bool
	}{
		{"", 0, false},
		{"done\n", 0, false},
		{"$ cmd\n[exit: 143]", 143, true},
		{"output\n[exit: 6]", 6, true},
		{"a[exit: 0]b", 0, true},
		{"tail\n[exit: notnum]", 0, false},
	}
	for _, c := range cases {
		code, ok := parseExitCode(c.out)
		if code != c.code || ok != c.ok {
			t.Errorf("parseExitCode(%q) = (%d, %v), want (%d, %v)", c.out, code, ok, c.code, c.ok)
		}
	}
}
