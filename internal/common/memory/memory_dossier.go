package memory

// memory_dossier.go — 主机档案只读访问（任务上下文注入用）。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// LoadDossier 只读读取主机档案摘要（任务上下文注入；无档案返回空串）。
// 与 Memory 实例的写并发安全（原子替换落盘，读可能拿到旧版本，无碍）。
func LoadDossier(workDir, host string) string {
	if host == "" {
		return ""
	}
	p := filepath.Join(memoryDir(workDir), "dossiers", host+".json")
	data, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	var d HostDossier
	if err := json.Unmarshal(data, &d); err != nil {
		return ""
	}
	var b strings.Builder
	if len(d.History) > 0 {
		hist := d.History
		if n := len(hist); n > 5 {
			hist = hist[n-5:]
		}
		b.WriteString("历史操作: " + strings.Join(hist, " | "))
	}
	if len(d.Recovery) > 0 {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString("恢复模式: " + strings.Join(d.Recovery, " | "))
	}
	if len(d.Quirks) > 0 {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString("易错点: " + strings.Join(d.Quirks, " | "))
	}
	return strings.TrimSpace(b.String())
}
