package desk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Server struct {
	Target
	State     string `json:"state"`
	Detail    string `json:"detail"`
	CheckedAt string `json:"checkedAt"`
}
type Overview struct {
	Servers       []Server `json:"servers"`
	ConfigPath    string   `json:"configPath"`
	KeyPath       string   `json:"keyPath"`
	KeyExists     bool     `json:"keyExists"`
	InventoryPath string   `json:"inventoryPath"`
}
type InstallRequest struct {
	PrivateKeyPath string `json:"privateKeyPath"`
	Passphrase     string `json:"-"`
	Target         Target `json:"target"`
	Password       string `json:"password"`
	Fingerprint    string `json:"fingerprint"`
	Trust          bool   `json:"trust"`
}
type Service struct {
	home         string
	mu           sync.Mutex
	installMu    sync.Mutex
	results      map[string]Server
	transfers    map[string]preparedTransfer
	maintenance  map[string]maintenancePlan
	remoteRunner remoteRunner
}

func NewService(home string) *Service {
	s := &Service{home: home, results: map[string]Server{}, transfers: map[string]preparedTransfer{}, maintenance: map[string]maintenancePlan{}}
	data, err := os.ReadFile(s.statusPath())
	if err == nil {
		json.Unmarshal(data, &s.results)
	}
	if s.results == nil {
		s.results = map[string]Server{}
	}
	return s
}
func (s *Service) statusPath() string { return filepath.Join(s.home, ".ssh", "keydesk", "status.json") }
func (s *Service) inventoryPath() string {
	return filepath.Join(s.home, ".ssh", "keydesk", "servers.md")
}

// Keep normal system/user config processing in production. An explicit -F is
// used only for an isolated home supplied by tests or another embedding app.
func (s *Service) configArgs() []string {
	home, err := os.UserHomeDir()
	if err == nil && filepath.Clean(home) == filepath.Clean(s.home) {
		return nil
	}
	return []string{"-F", filepath.Join(s.home, ".ssh", "config")}
}
func (s *Service) resolve(ctx context.Context, alias string) (Target, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	args := append(s.configArgs(), "-G", "--", alias)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	hide(cmd)
	out, err := cmd.Output()
	if err != nil {
		return Target{Alias: alias}, fmt.Errorf("解析 SSH 配置失败: %w", err)
	}
	t := Target{Alias: alias, Port: 22}
	for _, line := range strings.Split(string(out), "\n") {
		w := strings.Fields(line)
		if len(w) < 2 {
			continue
		}
		switch w[0] {
		case "hostname":
			t.Host = w[1]
		case "user":
			t.User = w[1]
		case "port":
			t.Port, _ = strconv.Atoi(w[1])
		}
	}
	return t, nil
}

func (s *Service) List(ctx context.Context) (Overview, error) {
	aliases, err := Aliases(s.home)
	if err != nil {
		return Overview{}, err
	}
	key := filepath.Join(s.home, ".ssh", "keydesk_ed25519")
	_, keyErr := os.Stat(key)
	o := Overview{Servers: []Server{}, ConfigPath: filepath.Join(s.home, ".ssh", "config"), KeyPath: key, KeyExists: keyErr == nil, InventoryPath: s.inventoryPath()}
	for _, a := range aliases {
		t, e := s.resolve(ctx, a)
		row := Server{Target: t, State: "unknown", Detail: "尚未检测；点击检测验证密钥登录"}
		if e != nil {
			row.State = "error"
			row.Detail = e.Error()
		} else {
			s.mu.Lock()
			old, ok := s.results[a]
			s.mu.Unlock()
			if ok && old.Host == t.Host && old.User == t.User && old.Port == t.Port {
				row = old
			}
		}
		o.Servers = append(o.Servers, row)
	}
	return o, nil
}

func (s *Service) Probe(ctx context.Context, t Target) (HostInfo, error) {
	if err := t.Validate(); err != nil {
		return HostInfo{}, err
	}
	if err := AliasAvailable(s.home, t.Alias); err != nil {
		return HostInfo{}, err
	}
	return Inspect(ctx, s.home, t)
}

func (s *Service) Install(ctx context.Context, r InstallRequest) (Server, error) {
	s.installMu.Lock()
	defer s.installMu.Unlock()
	if err := r.Target.Validate(); err != nil {
		return Server{}, err
	}
	if err := AliasAvailable(s.home, r.Target.Alias); err != nil {
		return Server{}, err
	}
	if r.PrivateKeyPath != "" {
		return s.useExistingKey(ctx, r)
	}
	if r.Password == "" {
		return Server{}, errors.New("请输入服务器密码（不会保存）")
	}
	if r.Fingerprint == "" {
		return Server{}, errors.New("请先检查服务器指纹")
	}
	path, pub, err := EnsureKey(s.home)
	if err != nil {
		return Server{}, err
	}
	_, err = Bootstrap(ctx, s.home, r.Target, r.Password, path, pub, r.Fingerprint, r.Trust)
	r.Password = ""
	if err != nil {
		return Server{}, err
	}
	if _, err = SaveAlias(s.home, r.Target, path); err != nil {
		return Server{}, fmt.Errorf("远程公钥已安装并验证，但本机 SSH 配置保存失败。可使用密钥 %s 手动连接，或解决配置问题后重试: %w", path, err)
	}
	row, err := s.Check(ctx, r.Target.Alias)
	if err != nil {
		return row, err
	}
	if row.State != "key_ready" {
		return row, fmt.Errorf("公钥安装已成功，但 SSH 别名检测未通过：%s", row.Detail)
	}
	return row, nil
}

func (s *Service) Check(ctx context.Context, alias string) (Server, error) {
	aliases, err := Aliases(s.home)
	if err != nil {
		return Server{}, err
	}
	if !slices.Contains(aliases, alias) {
		return Server{}, errors.New("找不到该 SSH 别名，请刷新列表")
	}
	target, err := s.resolve(ctx, alias)
	if err != nil {
		return Server{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	args := append(s.configArgs(), "-n", "-T", "-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=8", "-o", "ConnectionAttempts=1", "-o", "ClearAllForwardings=yes", "-o", "ControlMaster=no", "-o", "ControlPath=none", "--", alias, "printf '__KEYDESK_OK__'")
	cmd := exec.CommandContext(ctx, "ssh", args...)
	hide(cmd)
	cmd.Env = append(os.Environ(), "SSH_ASKPASS_REQUIRE=never", "LC_ALL=C", "LANG=C")
	out, e := cmd.CombinedOutput()
	row := Server{Target: target, CheckedAt: time.Now().Format(time.RFC3339)}
	if e == nil && strings.Contains(string(out), "__KEYDESK_OK__") {
		row.State = "key_ready"
		row.Detail = "已通过公钥认证并执行远程命令；此 SSH 别名可用于部署"
	} else {
		row.State = Classify(string(out))
		if ctx.Err() != nil {
			row.State = "unreachable"
			row.Detail = "检测超时：请检查网络、VPN、跳板机或代理"
		} else {
			row.Detail = strings.TrimSpace(string(out))
			if row.Detail == "" {
				row.Detail = fmt.Sprintf("SSH 检测失败: %v", e)
			}
		}
		if len(row.Detail) > 1800 {
			row.Detail = row.Detail[:1800]
		}
	}
	if err := s.remember(row); err != nil {
		return row, fmt.Errorf("检测完成，但保存检测记录失败: %w", err)
	}
	return row, nil
}

func (s *Service) remember(row Server) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results[row.Alias] = row
	path := s.statusPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.results, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, data, 0600)
}
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".keydesk-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	// Protect replacement contents before the first write, including included
	// configs whose parent directory has broader inherited Windows permissions.
	if err = preserveReplacementACL(path, tmp); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Service) Export(ctx context.Context) (string, error) {
	o, err := s.List(ctx)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("# SSH server inventory\n\nUse the local OpenSSH aliases below. Credentials and private key contents are never included.\nCheck host identity and the requested deployment target before changing a service.\nA recorded successful check is historical, not a guarantee of current access.\n\n")
	for _, r := range o.Servers {
		fmt.Fprintf(&b, "## %s\n\n- Connect: `ssh %s`\n- Host: %s:%d\n- User: %s\n- Last status: %s\n- Checked: %s\n\n", r.Alias, r.Alias, r.Host, r.Port, r.User, r.State, r.CheckedAt)
	}
	path := s.inventoryPath()
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", err
	}
	if err = atomicWrite(path, []byte(b.String()), 0600); err != nil {
		return "", err
	}
	return path, nil
}
