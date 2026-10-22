package desk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type DeletePlan struct {
	Token   string   `json:"token"`
	Alias   string   `json:"alias"`
	Files   []string `json:"files"`
	Warning string   `json:"warning"`
}
type RecreatePlan struct {
	Token                string   `json:"token"`
	Target               Target   `json:"target"`
	Host                 HostInfo `json:"host"`
	HostChanged          bool     `json:"hostChanged"`
	PreviousFingerprints []string `json:"previousFingerprints"`
	Files                []string `json:"files"`
	Warning              string   `json:"warning"`
}
type MaintenanceResult struct {
	Alias    string   `json:"alias"`
	State    string   `json:"state"`
	KeyPath  string   `json:"keyPath"`
	Backups  []string `json:"backups"`
	Detail   string   `json:"detail"`
	Warnings []string `json:"warnings"`
}
type maintenancePlan struct {
	Mode    string
	Alias   string
	Target  Target
	Edits   []ConfigEdit
	HostKey []byte
	Expires time.Time
}

func (s *Service) storeMaintenance(p maintenancePlan) (string, error) {
	data := make([]byte, 24)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	token := hex.EncodeToString(data)
	p.Expires = time.Now().Add(5 * time.Minute)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.maintenance == nil {
		s.maintenance = map[string]maintenancePlan{}
	}
	for id, old := range s.maintenance {
		if time.Now().After(old.Expires) {
			delete(s.maintenance, id)
		}
	}
	if len(s.maintenance) >= 32 {
		return "", errors.New("待确认操作过多，请稍后重新检查")
	}
	s.maintenance[token] = p
	return token, nil
}
func (s *Service) takeMaintenance(token, mode string, confirmed bool) (maintenancePlan, error) {
	if !confirmed {
		return maintenancePlan{}, errors.New("请先明确确认操作范围和服务器身份")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.maintenance[token]
	delete(s.maintenance, token)
	if !ok || p.Mode != mode || time.Now().After(p.Expires) {
		return maintenancePlan{}, errors.New("操作计划已过期或已使用，请重新检查")
	}
	return p, nil
}
func editFiles(edits []ConfigEdit, all bool) []string {
	paths := []string{}
	for _, e := range edits {
		if all || !bytes.Equal(e.Before, e.After) {
			paths = append(paths, e.Path)
		}
	}
	return paths
}
func (s *Service) PrepareDelete(ctx context.Context, alias string) (DeletePlan, error) {
	edits, err := PlanAliasRemoval(s.home, alias)
	if err != nil {
		return DeletePlan{}, err
	}
	token, err := s.storeMaintenance(maintenancePlan{Mode: "delete", Alias: alias, Edits: edits})
	if err != nil {
		return DeletePlan{}, err
	}
	return DeletePlan{Token: token, Alias: alias, Files: editFiles(edits, false), Warning: "只删除此电脑上的 SSH 别名和检测记录。保留密钥文件及服务器上的公钥；其他别名和其他电脑仍可能使用它们。删除前会备份配置。"}, nil
}
func (s *Service) DeleteConnection(ctx context.Context, token string, confirmed bool) (MaintenanceResult, error) {
	p, err := s.takeMaintenance(token, "delete", confirmed)
	if err != nil {
		return MaintenanceResult{}, err
	}
	s.installMu.Lock()
	defer s.installMu.Unlock()
	backups, err := CommitConfigEdits(s.home, p.Edits)
	if err != nil {
		return MaintenanceResult{}, err
	}
	result := MaintenanceResult{Alias: p.Alias, State: "deleted", Backups: backups, Detail: "本机连接已删除。共用私钥和服务器授权保持不变。", Warnings: []string{}}
	s.finishMaintenance(ctx, p.Alias, &result)
	return result, nil
}

func inspectForRecreation(ctx context.Context, home string, t Target) (HostInfo, bool, []string, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cb, err := knownCallback(home)
	if err != nil {
		return HostInfo{}, false, nil, nil, err
	}
	var info HostInfo
	var hostKey []byte
	changed := false
	previous := []string{}
	var trustErr error
	_, connErr := connect(ctx, t, nil, func(addr string, remote net.Addr, key ssh.PublicKey) error {
		e := cb(addr, remote, key)
		if e != nil {
			var ke *knownhosts.KeyError
			if !errors.As(e, &ke) {
				trustErr = fmt.Errorf("无法安全检查主机信任记录: %w", e)
				return trustErr
			}
			for _, want := range ke.Want {
				changed = true
				previous = append(previous, ssh.FingerprintSHA256(want.Key))
			}
		}
		info = HostInfo{Fingerprint: ssh.FingerprintSHA256(key), Algorithm: key.Type(), Known: e == nil}
		hostKey = append([]byte(nil), key.Marshal()...)
		return errors.New("host identity inspected without password")
	})
	if trustErr != nil {
		return HostInfo{}, false, nil, nil, trustErr
	}
	if len(hostKey) == 0 {
		return HostInfo{}, false, nil, nil, fmt.Errorf("读取主机指纹失败: %w", connErr)
	}
	return info, changed, previous, hostKey, nil
}
func (s *Service) PrepareRecreate(ctx context.Context, t Target) (RecreatePlan, error) {
	if err := t.Validate(); err != nil {
		return RecreatePlan{}, err
	}
	edits, err := PlanAliasRemoval(s.home, t.Alias)
	if err != nil {
		return RecreatePlan{}, err
	}
	if strings.ContainsAny(s.home, "\"%\r\n") {
		return RecreatePlan{}, errors.New("本机用户路径包含 SSH 配置不支持的引号、百分号或换行，无法自动重建")
	}
	resolved, err := s.configSnapshot(ctx, t.Alias)
	if err != nil {
		return RecreatePlan{}, err
	}
	if alias := first(parseResolved(resolved), "hostkeyalias"); alias != "" {
		return RecreatePlan{}, errors.New("此连接继承了 HostKeyAlias，无法自动替换独立指纹记录；请先手动处理该设置")
	}
	info, changed, old, key, err := inspectForRecreation(ctx, s.home, t)
	if err != nil {
		return RecreatePlan{}, err
	}
	token, err := s.storeMaintenance(maintenancePlan{Mode: "recreate", Alias: t.Alias, Target: t, Edits: edits, HostKey: key})
	if err != nil {
		return RecreatePlan{}, err
	}
	warning := "将为此连接生成独立的新密钥。安装并验证新密钥后才切换本机配置；保留旧私钥和远程旧公钥，以免影响其他电脑或连接。"
	if changed {
		warning = "服务器主机指纹已变化。请通过可信控制台核对下面的新指纹，确认后才发送密码。仅为此连接保存新指纹，不覆盖全局信任记录。\n" + warning
	}
	return RecreatePlan{Token: token, Target: t, Host: info, HostChanged: changed, PreviousFingerprints: old, Files: editFiles(edits, true), Warning: warning}, nil
}
func maintenanceSafePath(path string) error {
	current, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for {
		info, e := os.Lstat(current)
		if e == nil {
			_, _, err := configSafeNode(current, info.IsDir())
			return err
		}
		if e != nil && !os.IsNotExist(e) {
			return e
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return nil
}
func createConnectionIdentity(home string) (string, []byte, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, err
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return "", nil, err
	}
	id := sha256.Sum256(signer.PublicKey().Marshal())
	dir := filepath.Join(home, ".ssh", "keydesk", "keys", hex.EncodeToString(id[:]))
	if err := maintenanceSafePath(dir); err != nil {
		return "", nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", nil, err
	}
	block, err := ssh.MarshalPrivateKey(key, "server-keydesk-connection")
	if err != nil {
		return "", nil, err
	}
	data := pem.EncodeToMemory(block)
	defer clear(data)
	path := filepath.Join(dir, "id_ed25519")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", nil, err
	}
	if err := securePrivateFile(path); err != nil {
		f.Close()
		os.Remove(path)
		return "", nil, err
	}
	_, err = f.Write(data)
	closeErr := f.Close()
	if err != nil {
		return "", nil, err
	}
	if closeErr != nil {
		return "", nil, closeErr
	}
	pub := ssh.MarshalAuthorizedKey(signer.PublicKey())
	if err := os.WriteFile(path+".pub", pub, 0644); err != nil {
		return "", nil, err
	}
	return path, pub, nil
}
func recreationBlock(t Target, keyPath, pinPath string) string {
	extra := ""
	if sshSupportsKnownHostsCommand() {
		extra = "    KnownHostsCommand none\n"
	}
	return fmt.Sprintf("# BEGIN KEYDESK CONNECTION %s\nHost %s\n    HostName %s\n    User %s\n    Port %d\n    IdentityFile \"%s\"\n    IdentitiesOnly yes\n    IdentityAgent none\n    UserKnownHostsFile \"%s\"\n    GlobalKnownHostsFile %s\n%s    StrictHostKeyChecking yes\n    VerifyHostKeyDNS no\n    UpdateHostKeys no\n    ProxyCommand none\n    ProxyJump none\n# END KEYDESK CONNECTION %s\nHost *\n", t.Alias, t.Alias, strings.ReplaceAll(t.Host, "%", "%%"), t.User, t.Port, filepath.ToSlash(keyPath), filepath.ToSlash(pinPath), os.DevNull, extra, t.Alias)
}
func sshSupportsKnownHostsCommand() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh", "-G", "-F", os.DevNull, "-o", "KnownHostsCommand=none", "--", "keydesk-option-check.invalid")
	hide(cmd)
	return cmd.Run() == nil
}
func (s *Service) RecreateConnection(ctx context.Context, token, password string, confirmed bool) (MaintenanceResult, error) {
	if password == "" {
		return MaintenanceResult{}, errors.New("请输入服务器当前密码（不会保存）")
	}
	p, err := s.takeMaintenance(token, "recreate", confirmed)
	if err != nil {
		return MaintenanceResult{}, err
	}
	s.installMu.Lock()
	defer s.installMu.Unlock()
	// Check snapshots before any remote side effect and again during commit.
	if len(p.Edits) == 0 || p.Edits[0].plan == nil {
		return MaintenanceResult{}, errors.New("缺少 SSH 配置修改计划")
	}
	if err := configValidatePlan(p.Edits[0].plan); err != nil {
		return MaintenanceResult{}, fmt.Errorf("SSH 配置在检查后已变化，已停止重新创建；请重新检查：%w", err)
	}
	key, pub, err := createConnectionIdentity(s.home)
	if err != nil {
		return MaintenanceResult{}, err
	}
	peer, err := ssh.ParsePublicKey(p.HostKey)
	if err != nil {
		return MaintenanceResult{}, err
	}
	pinPath := filepath.Join(filepath.Dir(key), "known_hosts")
	pins := []byte(knownhosts.Line([]string{knownhosts.Normalize(hostAddress(p.Target))}, peer) + "\n")
	if err := os.WriteFile(pinPath, pins, 0600); err != nil {
		return MaintenanceResult{}, err
	}
	callback := func(addr string, remote net.Addr, actual ssh.PublicKey) error {
		if !bytes.Equal(actual.Marshal(), p.HostKey) {
			return errors.New("服务器指纹在检查后再次变化，未发送密码")
		}
		return nil
	}
	_, err = bootstrapWithCallback(ctx, p.Target, password, key, pub, callback)
	password = ""
	if err != nil {
		return MaintenanceResult{}, fmt.Errorf("原连接配置尚未切换。新密钥保存在 %s，可在排查后重试：%w", key, err)
	}
	main := filepath.Clean(filepath.Join(s.home, ".ssh", "config"))
	found := false
	for i := range p.Edits {
		if filepath.Clean(p.Edits[i].Path) == main {
			p.Edits[i].After = append([]byte(recreationBlock(p.Target, key, pinPath)), p.Edits[i].After...)
			found = true
			break
		}
	}
	if !found {
		return MaintenanceResult{}, fmt.Errorf("新公钥已安装，但计划缺少主配置；保留密钥 %s，原配置尚未切换", key)
	}
	backups, err := CommitConfigEdits(s.home, p.Edits)
	if err != nil {
		return MaintenanceResult{}, fmt.Errorf("新公钥已安装并验证，但本机配置切换失败；新密钥位于 %s：%w", key, err)
	}
	result := MaintenanceResult{Alias: p.Alias, State: "configured", KeyPath: key, Backups: backups, Detail: "独立新密钥已安装并验证，本机连接配置已切换。旧密钥及其他电脑的授权保留。", Warnings: []string{}}
	s.finishMaintenance(ctx, p.Alias, &result)
	row, err := s.Check(ctx, p.Alias)
	if err != nil {
		result.Warnings = append(result.Warnings, "配置已切换，但系统 SSH 检测未完成："+err.Error())
	} else {
		result.State = row.State
		if row.State != "key_ready" {
			result.Warnings = append(result.Warnings, "新密钥已验证并保存，但该别名的系统 SSH 检测未通过；请查看检测详情。")
		}
	}
	return result, nil
}
func (s *Service) finishMaintenance(ctx context.Context, alias string, result *MaintenanceResult) {
	if aliasRE.MatchString(alias) {
		meta := filepath.Join(s.home, ".ssh", "keydesk", "aliases", alias+".json")
		if _, err := os.Lstat(meta); err == nil {
			if e := maintenanceSafePath(meta); e != nil {
				result.Warnings = append(result.Warnings, e.Error())
			} else if e := os.Rename(meta, meta+".retired-"+time.Now().Format("20060102-150405.000000000")+".bak"); e != nil {
				result.Warnings = append(result.Warnings, "连接已更新，但旧导入记录归档失败："+e.Error())
			}
		}
	}
	s.mu.Lock()
	delete(s.results, alias)
	data, err := json.MarshalIndent(s.results, "", "  ")
	if err == nil {
		if e := os.MkdirAll(filepath.Dir(s.statusPath()), 0700); e != nil {
			err = e
		} else {
			err = atomicWrite(s.statusPath(), data, 0600)
		}
	}
	s.mu.Unlock()
	if err != nil {
		result.Warnings = append(result.Warnings, "连接已更新，但清理检测记录失败："+err.Error())
	}
	if _, err := os.Stat(s.inventoryPath()); err == nil {
		if _, e := s.Export(ctx); e != nil {
			result.Warnings = append(result.Warnings, "连接已更新，但刷新智能体清单失败："+e.Error())
		}
	}
}
