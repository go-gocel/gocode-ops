package remote

// remote_inventory.go — 主机清单读取与展示（HostView/ListInventory；凭证只在本机，模型不可见）。

import (
	"strings"
)

func inventoryNames(inv *Inventory) string {
	names := make([]string, 0, len(inv.Hosts))
	for _, h := range inv.Hosts {
		names = append(names, h.Name)
	}
	return strings.Join(names, ", ")
}

// HostView is the display view of the host inventory.
// HostView 是主机清单的展示视图（供界面渲染；密码等敏感字段不导出）。
type HostView struct {
	Name    string
	Address string
	User    string
	Auth    string // "密钥" / "密码"
}

// ListInventory reads the inventory and returns display views for the UI.
// ListInventory 读取清单并返回展示视图（界面使用，不进入模型上下文）。
func ListInventory(path string) ([]HostView, error) {
	e := newSSHExecutor(RemoteConfig{InventoryPath: path})
	inv, err := e.loadInventory()
	if err != nil {
		return nil, err
	}
	views := make([]HostView, 0, len(inv.Hosts))
	for _, h := range inv.Hosts {
		auth := "密钥"
		if strings.TrimSpace(h.KeyFile) == "" {
			auth = "密码"
		}
		views = append(views, HostView{Name: h.Name, Address: h.Address, User: h.User, Auth: auth})
	}
	return views, nil
}

// ── 命令执行（实时流式） ──────────────────────────────────────────────

// perHostCap 单台主机输出上限，totalCap 批量总输出上限。
// remoteCollectCap 单命令收集上限：最终展示另有 perHostCap 截断，
// 收集上限只防内存（读取时截断，见 cappedBuffer）。
// remoteMaxTimeout 单次远程命令超时上限（与本地 terminal 的 10m 对齐；
// 更长任务在远端 nohup 后台执行后轮询）。
