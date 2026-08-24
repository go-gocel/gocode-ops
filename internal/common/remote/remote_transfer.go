package remote

// remote_transfer.go — 上传/下载：进度回调、断点续传、目录递归、取消打断。

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
)

func closeOnCancel(ctx context.Context, c io.Closer) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-done:
		}
	}()
	return func() { close(done) }
}

// progressReader 包装 io.Reader：读数据时按节流间隔回调进度；ctx 取消时
// 返回错误（上传/下载可中断）。
type progressReader struct {
	r          io.Reader
	ctx        context.Context
	total      int64
	done       int64
	lastReport time.Time
	sink       func(done, total int64)
}

// Read reads data from the wrapped reader, reporting progress at throttled
// intervals and returning an error when the context is cancelled.
// Read 从包装的读取器读取数据，按节流间隔回调进度；ctx 取消时返回错误。
func (p *progressReader) Read(b []byte) (int, error) {
	if p.ctx != nil {
		select {
		case <-p.ctx.Done():
			return 0, p.ctx.Err()
		default:
		}
	}
	n, err := p.r.Read(b)
	if n > 0 {
		p.done += int64(n)
		if p.sink != nil && time.Since(p.lastReport) >= 100*time.Millisecond {
			p.lastReport = time.Now()
			p.sink(p.done, p.total)
		}
	}
	return n, err
}

// Upload uploads a local file or directory to multiple hosts serially,
// streaming progress in real time.
// Upload 上传本地文件/目录到多台主机（逐台串行，进度实时回传）。
func (e *sshExecutor) Upload(ctx context.Context, aliases []string, localPath, remotePath string, mode os.FileMode) (string, error) {
	inv, err := e.loadInventory()
	if err != nil {
		return "", err
	}
	hosts, err := e.resolveHosts(inv, aliases)
	if err != nil {
		return "", err
	}
	localPath = strings.TrimSpace(localPath)
	remotePath = strings.TrimSpace(remotePath)
	if localPath == "" {
		return "", errors.New("local_path 必填")
	}
	if remotePath == "" {
		return "", errors.New("remote_path 必填")
	}
	abs, err := filepath.Abs(localPath)
	if err != nil {
		return "", fmt.Errorf("解析本地路径失败: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("本地路径不存在: %w", err)
	}
	// mode 为 0 时逐文件继承本地权限（脚本 +x 不丢）；显式传入则统一使用。
	sink := e.progress(ctx)

	var sections []string
	failed := 0
	for _, h := range hosts {
		select {
		case <-ctx.Done():
			return strings.TrimRight(strings.Join(sections, "\n"), "\n"), ctx.Err()
		default:
		}
		out, err := e.uploadOne(ctx, h, abs, remotePath, info.IsDir(), mode, sink)
		if err != nil {
			failed++
			sections = append(sections, fmt.Sprintf("## %s\n错误: %v", h.Name, err))
			continue
		}
		sections = append(sections, out)
	}
	out := strings.TrimRight(strings.Join(sections, "\n"), "\n")
	// 全部主机失败必须返回 error（工具框架才能标记失败，助手/引擎才能
	// 感知）；部分失败保留 nil error，逐台错误在分段文本里可见。
	if failed > 0 && failed == len(hosts) {
		return out, fmt.Errorf("全部 %d 台主机上传失败（详见输出）", failed)
	}
	return out, nil
}

func (e *sshExecutor) uploadOne(ctx context.Context, h Host, localPath, remotePath string, isDir bool, mode os.FileMode, sink func(RemoteProgress)) (string, error) {
	client, err := e.getClient(h)
	if err != nil {
		return "", err
	}
	defer e.releaseClient(h)
	sc, err := sftp.NewClient(client)
	if err != nil {
		return "", fmt.Errorf("SFTP 初始化失败: %w", err)
	}
	defer sc.Close()
	// 链路僵死（拔网线/防火墙丢包）时底层 Read 无限阻塞：ctx 取消后
	// 强制关闭 SFTP 通道打断传输（exec 路径有 ticker+timeout 兜底，
	// SFTP 路径此前没有对应机制——任务永久悬挂）。
	stop := closeOnCancel(ctx, sc)
	defer stop()

	var files, bytes int64
	if isDir {
		files, bytes, err = e.uploadDir(ctx, sc, h.Name, localPath, remotePath, mode, sink)
	} else {
		var n int64
		n, err = e.uploadFile(ctx, sc, h.Name, localPath, remotePath, mode, sink)
		files, bytes = 1, n
	}
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("上传完成: %s → %s:%s（%d 个文件，%s）", localPath, h.Name, remotePath, files, humanBytes(bytes)), nil
}

// uploadFile 上传单个文件：自动创建父目录、断点续传（远端已存在且比
// 本地小 → 从已有字节数继续）、写完再设权限、实时回传进度。
func (e *sshExecutor) uploadFile(ctx context.Context, sc *sftp.Client, host, localPath, remotePath string, mode os.FileMode, sink func(RemoteProgress)) (int64, error) {
	f, err := os.Open(localPath)
	if err != nil {
		return 0, fmt.Errorf("打开本地文件失败: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return 0, fmt.Errorf("读取本地文件信息失败: %w", err)
	}
	if mode == 0 {
		// 缺省继承本地文件权限（脚本 +x 不再丢）。
		mode = info.Mode().Perm()
	}
	if err := sc.MkdirAll(path.Dir(remotePath)); err != nil {
		return 0, fmt.Errorf("创建远端目录失败: %w", err)
	}
	// 断点续传：远端已存在且比本地小 → 从已有字节数续写。续传前校验
	// 远端首块与本地源一致——中断后源文件可能已被修改（同尺寸内容
	// 变化），按大小续传会拼接损坏且大小校验通过（P2 修复）。
	offset := resumeOffset(info.Size(), remoteSize(sc, remotePath))
	if offset > 0 && !resumeHeadMatches(sc, remotePath, f, offset) {
		offset = 0 // 头不匹配：源已变化，整文件重传
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if offset > 0 {
		flags = os.O_WRONLY | os.O_CREATE
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return 0, fmt.Errorf("本地文件定位续传偏移失败: %w", err)
		}
	}
	rf, err := sc.OpenFile(remotePath, flags)
	if err != nil {
		return 0, fmt.Errorf("打开远端文件失败: %w", err)
	}
	if offset > 0 {
		if _, err := rf.Seek(offset, io.SeekStart); err != nil {
			rf.Close()
			return 0, fmt.Errorf("远端文件定位续传偏移失败: %w", err)
		}
	}
	pr := &progressReader{
		r:     f,
		ctx:   ctx,
		total: info.Size(),
		done:  offset,
		sink: func(done, total int64) {
			emit(sink, RemoteProgress{Host: host, Phase: "upload", Path: remotePath, Done: done, Total: total})
		},
	}
	written, err := io.Copy(rf, pr)
	written += offset
	if err != nil {
		rf.Close()
		return 0, fmt.Errorf("上传中断: %w", err)
	}
	// 写完再收尾：先关闭（冲刷 SFTP 缓冲）、再设权限——中断不会留下
	// “权限已设但内容不全”的半成品。
	if err := rf.Close(); err != nil {
		return 0, fmt.Errorf("关闭远端文件失败: %w", err)
	}
	if err := sc.Chmod(remotePath, mode); err != nil {
		return 0, fmt.Errorf("设置远端权限失败: %w", err)
	}
	// 完整性校验：传输完成即对字节数（部署场景传坏代价高，SFTP Stat
	// 成本可忽略）。
	st, err := sc.Stat(remotePath)
	if err != nil {
		return 0, fmt.Errorf("完整性校验（stat 远端）失败: %w", err)
	}
	if st.Size() != written {
		return 0, fmt.Errorf("完整性校验失败：本地 %d 字节，远端实际 %d 字节（请重传）", written, st.Size())
	}
	emit(sink, RemoteProgress{Host: host, Phase: "upload", Path: remotePath, Done: written, Total: info.Size()})
	return written, nil
}

// remoteSize 返回远端文件大小；不存在/不可读返回 0（重新传输）。
func remoteSize(sc *sftp.Client, remotePath string) int64 {
	if st, err := sc.Stat(remotePath); err == nil {
		return st.Size()
	}
	return 0
}

// resumeOffset 计算断点续传偏移：目标已存在且比源小 → 从目标大小续传；
// 目标缺失/相同/更大 → 0（重新传输）。
func resumeOffset(srcSize, dstSize int64) int64 {
	if dstSize > 0 && dstSize < srcSize {
		return dstSize
	}
	return 0
}

// resumeHeadMatches 校验目标部分文件首块与源一致（断点续传前的内容
// 一致性检查）：按大小续传无法发现"源在中断后已修改"——首块（≤4KB）
// 对比不匹配即重传（拼接损坏比重传代价高）。校验后本地文件偏移复位。
// 任何读取失败视为不匹配（fail-closed：重传更安全）。
func resumeHeadMatches(sc *sftp.Client, remotePath string, local *os.File, offset int64) bool {
	check := offset
	if check > resumeHeadCheckBytes {
		check = resumeHeadCheckBytes
	}
	if check == 0 {
		return true
	}
	rf, err := sc.Open(remotePath)
	if err != nil {
		return false
	}
	defer rf.Close()
	rh := make([]byte, check)
	if _, err := io.ReadFull(rf, rh); err != nil {
		return false
	}
	if _, err := local.Seek(0, io.SeekStart); err != nil {
		return false
	}
	lh := make([]byte, check)
	if _, err := io.ReadFull(local, lh); err != nil {
		return false
	}
	return bytes.Equal(rh, lh)
}

// resumeHeadCheckBytes 续传前首块校验字节数（4KB：覆盖配置文件头部/
// 脚本 shebang/二进制魔数等大部分变更面，成本可忽略）。
const resumeHeadCheckBytes = 4096

// symlinkMaxDepth 目录递归深度上限（符号链接环防护的第二道闸：即使
// visited 追踪被相对路径绕过，深度上限也保证终止）。
const symlinkMaxDepth = 32

// uploadDir 递归上传目录。
func (e *sshExecutor) uploadDir(ctx context.Context, sc *sftp.Client, host, localDir, remoteDir string, mode os.FileMode, sink func(RemoteProgress)) (files, bytes int64, err error) {
	return e.uploadDirRec(ctx, sc, host, localDir, remoteDir, mode, sink, map[string]bool{}, 0)
}

// uploadDirRec 递归上传目录：跟随符号链接（链接到目录的按目录内容上传，
// 部署目录里的 current → releases/xxx 类链接不能丢）；环防护用真实路径
// visited 集 + 深度上限——遇到环跳过不重复上传。
func (e *sshExecutor) uploadDirRec(ctx context.Context, sc *sftp.Client, host, localDir, remoteDir string, mode os.FileMode, sink func(RemoteProgress), visited map[string]bool, depth int) (files, bytes int64, err error) {
	if depth > symlinkMaxDepth {
		return 0, 0, fmt.Errorf("目录嵌套过深（疑似符号链接环）: %s", localDir)
	}
	if real, rerr := filepath.EvalSymlinks(localDir); rerr == nil {
		if visited[real] {
			return 0, 0, nil // 已访问（环）→ 跳过
		}
		visited[real] = true
	}
	if err = sc.MkdirAll(remoteDir); err != nil {
		return 0, 0, fmt.Errorf("创建远端目录失败: %w", err)
	}
	entries, err := os.ReadDir(localDir)
	if err != nil {
		return 0, 0, fmt.Errorf("读取本地目录失败: %w", err)
	}
	for _, ent := range entries {
		select {
		case <-ctx.Done():
			return files, bytes, ctx.Err()
		default:
		}
		lp := filepath.Join(localDir, ent.Name())
		rp := path.Join(remoteDir, ent.Name())
		isDir := ent.IsDir()
		if ent.Type()&os.ModeSymlink != 0 {
			// 跟随链接判定目标类型（ReadDir 的 IsDir 对链接目录返回 false）。
			if st, serr := os.Stat(lp); serr == nil {
				isDir = st.IsDir()
			}
		}
		if isDir {
			f, b, err := e.uploadDirRec(ctx, sc, host, lp, rp, mode, sink, visited, depth+1)
			if err != nil {
				return files, bytes, err
			}
			files += f
			bytes += b
			continue
		}
		b, err := e.uploadFile(ctx, sc, host, lp, rp, mode, sink)
		if err != nil {
			return files, bytes, err
		}
		files++
		bytes += b
	}
	return files, bytes, nil
}

// Download downloads a remote file or directory to the local machine,
// streaming progress in real time.
// Download 下载远端文件/目录到本地（逐台串行，进度实时回传）。
// 多台主机时保存到 <localDir>/<host>/<name>，避免同名覆盖。
func (e *sshExecutor) Download(ctx context.Context, aliases []string, remotePath, localDir string) (string, error) {
	inv, err := e.loadInventory()
	if err != nil {
		return "", err
	}
	hosts, err := e.resolveHosts(inv, aliases)
	if err != nil {
		return "", err
	}
	remotePath = strings.TrimSpace(remotePath)
	if remotePath == "" {
		return "", errors.New("remote_path 必填")
	}
	if strings.TrimSpace(localDir) == "" {
		localDir = "."
	}
	absDir, err := filepath.Abs(localDir)
	if err != nil {
		return "", fmt.Errorf("解析本地目录失败: %w", err)
	}
	if err := os.MkdirAll(absDir, 0o755); err != nil {
		return "", fmt.Errorf("创建本地目录失败: %w", err)
	}
	sink := e.progress(ctx)

	var sections []string
	failed := 0
	for _, h := range hosts {
		select {
		case <-ctx.Done():
			return strings.TrimRight(strings.Join(sections, "\n"), "\n"), ctx.Err()
		default:
		}
		out, err := e.downloadOne(ctx, h, remotePath, absDir, len(hosts) > 1, sink)
		if err != nil {
			failed++
			sections = append(sections, fmt.Sprintf("## %s\n错误: %v", h.Name, err))
			continue
		}
		sections = append(sections, out)
	}
	out := strings.TrimRight(strings.Join(sections, "\n"), "\n")
	if failed > 0 && failed == len(hosts) {
		return out, fmt.Errorf("全部 %d 台主机下载失败（详见输出）", failed)
	}
	return out, nil
}

func (e *sshExecutor) downloadOne(ctx context.Context, h Host, remotePath, localDir string, subDir bool, sink func(RemoteProgress)) (string, error) {
	dest := localDir
	if subDir {
		dest = filepath.Join(localDir, h.Name)
		if err := os.MkdirAll(dest, 0o755); err != nil {
			return "", fmt.Errorf("创建本地目录失败: %w", err)
		}
	}
	client, err := e.getClient(h)
	if err != nil {
		return "", err
	}
	defer e.releaseClient(h)
	sc, err := sftp.NewClient(client)
	if err != nil {
		return "", fmt.Errorf("SFTP 初始化失败: %w", err)
	}
	defer sc.Close()
	stop := closeOnCancel(ctx, sc)
	defer stop()

	info, err := sc.Stat(remotePath)
	if err != nil {
		return "", fmt.Errorf("远端路径不存在: %w", err)
	}
	var files, bytes int64
	if info.IsDir() {
		files, bytes, err = e.downloadDir(ctx, sc, h.Name, remotePath, dest, sink)
	} else {
		var n int64
		n, err = e.downloadFile(ctx, sc, h.Name, remotePath, filepath.Join(dest, filepath.Base(remotePath)), sink)
		files, bytes = 1, n
	}
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("下载完成: %s:%s → %s（%d 个文件，%s）", h.Name, remotePath, dest, files, humanBytes(bytes)), nil
}

// downloadFile 下载单个文件：创建本地父目录、断点续传（本地已存在且比
// 远端小 → 从已有字节数继续）、实时回传进度。
func (e *sshExecutor) downloadFile(ctx context.Context, sc *sftp.Client, host, remotePath, localPath string, sink func(RemoteProgress)) (int64, error) {
	rf, err := sc.Open(remotePath)
	if err != nil {
		return 0, fmt.Errorf("打开远端文件失败: %w", err)
	}
	defer rf.Close()
	info, err := rf.Stat()
	if err != nil {
		return 0, fmt.Errorf("读取远端文件信息失败: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		return 0, fmt.Errorf("创建本地目录失败: %w", err)
	}
	// 断点续传：本地已存在且比远端小 → 从已有字节数续写。续传前校验
	// 本地部分文件首块与远端一致——部分文件可能来自不同版本（同尺寸
	// 内容变化），按大小续传会拼接损坏且大小校验通过（P2 修复）。
	offset := resumeOffset(info.Size(), localSize(localPath))
	if offset > 0 {
		lf, err := os.Open(localPath)
		if err == nil {
			if !resumeHeadMatches(sc, remotePath, lf, offset) {
				offset = 0 // 头不匹配：远端已变化，整文件重下
			}
			lf.Close()
		} else {
			offset = 0 // 本地不可读：整文件重下
		}
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if offset > 0 {
		flags = os.O_WRONLY | os.O_CREATE
		if _, err := rf.Seek(offset, io.SeekStart); err != nil {
			return 0, fmt.Errorf("远端文件定位续传偏移失败: %w", err)
		}
	}
	f, err := os.OpenFile(localPath, flags, 0o644)
	if err != nil {
		return 0, fmt.Errorf("创建本地文件失败: %w", err)
	}
	pr := &progressReader{
		r:     rf,
		ctx:   ctx,
		total: info.Size(),
		done:  offset,
		sink: func(done, total int64) {
			emit(sink, RemoteProgress{Host: host, Phase: "download", Path: remotePath, Done: done, Total: total})
		},
	}
	written, err := io.Copy(f, pr)
	written += offset
	if err != nil {
		f.Close()
		return 0, fmt.Errorf("下载中断: %w", err)
	}
	if err := f.Close(); err != nil {
		return 0, fmt.Errorf("关闭本地文件失败: %w", err)
	}
	// 完整性校验：字节数与远端一致才算完成。
	st, err := os.Stat(localPath)
	if err != nil {
		return 0, fmt.Errorf("完整性校验（stat 本地）失败: %w", err)
	}
	if st.Size() != written {
		return 0, fmt.Errorf("完整性校验失败：本地实际 %d 字节，远端 %d 字节（请重新下载）", st.Size(), written)
	}
	// 保留远端权限位：中转副本（remote_copy 双程）与直接下载都不丢
	// x 位/0600/0700——否则脚本复制到目标后不可执行、敏感文件权限被放宽。
	if err := os.Chmod(localPath, info.Mode().Perm()); err != nil {
		return 0, fmt.Errorf("还原权限位失败: %w", err)
	}
	emit(sink, RemoteProgress{Host: host, Phase: "download", Path: remotePath, Done: written, Total: info.Size()})
	return written, nil
}

// localSize 返回本地文件大小；不存在返回 0（重新下载）。
func localSize(localPath string) int64 {
	if st, err := os.Stat(localPath); err == nil {
		return st.Size()
	}
	return 0
}

// downloadDir 递归下载远端目录。
func (e *sshExecutor) downloadDir(ctx context.Context, sc *sftp.Client, host, remoteDir, localDir string, sink func(RemoteProgress)) (files, bytes int64, err error) {
	return e.downloadDirRec(ctx, sc, host, remoteDir, localDir, sink, map[string]bool{}, 0)
}

// downloadDirRec 递归下载远端目录：跟随远端符号链接（ReadLink 解析目标
// 后归一化为绝对路径作环防护键），环/超深跳过不重复下载。
func (e *sshExecutor) downloadDirRec(ctx context.Context, sc *sftp.Client, host, remoteDir, localDir string, sink func(RemoteProgress), visited map[string]bool, depth int) (files, bytes int64, err error) {
	if depth > symlinkMaxDepth {
		return 0, 0, fmt.Errorf("目录嵌套过深（疑似符号链接环）: %s", remoteDir)
	}
	resolved := remoteDir
	if tgt, lerr := sc.ReadLink(remoteDir); lerr == nil {
		resolved = path.Clean(path.Join(path.Dir(remoteDir), tgt))
	}
	if visited[resolved] {
		return 0, 0, nil // 已访问（环）→ 跳过
	}
	visited[resolved] = true
	if err = os.MkdirAll(localDir, 0o755); err != nil {
		return 0, 0, fmt.Errorf("创建本地目录失败: %w", err)
	}
	entries, err := sc.ReadDir(remoteDir)
	if err != nil {
		return 0, 0, fmt.Errorf("读取远端目录失败: %w", err)
	}
	for _, ent := range entries {
		select {
		case <-ctx.Done():
			return files, bytes, ctx.Err()
		default:
		}
		rp := path.Join(remoteDir, ent.Name())
		lp := filepath.Join(localDir, ent.Name())
		isDir := ent.IsDir()
		if ent.Mode()&os.ModeSymlink != 0 {
			// 跟随链接判定目标类型（sftp FileInfo 的 IsDir 对链接目录返回 false）。
			if st, serr := sc.Stat(rp); serr == nil {
				isDir = st.IsDir()
			}
		}
		if isDir {
			f, b, err := e.downloadDirRec(ctx, sc, host, rp, lp, sink, visited, depth+1)
			if err != nil {
				return files, bytes, err
			}
			files += f
			bytes += b
			continue
		}
		b, err := e.downloadFile(ctx, sc, host, rp, lp, sink)
		if err != nil {
			return files, bytes, err
		}
		files++
		bytes += b
	}
	return files, bytes, nil
}

// ── 文件信息与清单 ────────────────────────────────────────────────────

// FileInfo 返回远端路径信息（stat 单文件或 ls 目录内容）。
