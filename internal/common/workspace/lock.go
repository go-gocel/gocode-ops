package workspace

// lock.go — 跨进程状态写锁：同一工作目录多形态并行（全自动引擎 +
// 交互运维助手同时运行）时，findings.json 等状态文件的"读-改-写"
// 必须互斥，否则后写覆盖先写、处置状态丢失。
//
// 实现下沉到 common/fsutil（FileLock：O_EXCL 锁文件 + 归属令牌 +
// 陈旧清理，跨平台）——memory/workbench 等并行写路径共用同一套
// 跨进程锁原语，避免锁语义分裂。本文件只保留状态目录锁的路径约定。

import (
	"path/filepath"

	"github.com/go-gocel/gocode-ops/internal/common/fsutil"
)

// stateLockName 锁文件名（工作区状态目录内）。
const stateLockName = ".lock"

// acquireStateLock 获取跨进程状态写锁（阻塞式重试）。返回释放函数；
// 失败返回错误（调用方按无锁降级处理，不阻塞业务——锁是防丢更新
// 的优化，不是正确性前提）。
func acquireStateLock(stateDir string) (func(), error) {
	return fsutil.FileLock(filepath.Join(stateDir, stateLockName))
}

// withStateLock 持锁执行 fn（锁获取失败时直接执行——降级不阻塞）。
func withStateLock(stateDir string, fn func() error) error {
	return fsutil.WithFileLock(filepath.Join(stateDir, stateLockName), fn)
}
