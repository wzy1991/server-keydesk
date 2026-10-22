package desk

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

//go:embed transfer_preflight.ps1
var transferPreflight string

//go:embed transfer_windows.ps1
var transferReceiver string

type TransferRequest struct {
	SourceAlias      string `json:"sourceAlias"`
	DestinationAlias string `json:"destinationAlias"`
	RemoteAlias      string `json:"remoteAlias"`
}
type TransferPlan struct {
	Token           string `json:"token"`
	Source          Target `json:"source"`
	Destination     Target `json:"destination"`
	RemoteAlias     string `json:"remoteAlias"`
	Fingerprint     string `json:"fingerprint"`
	ReceiverUser    string `json:"receiverUser"`
	ReceiverMachine string `json:"receiverMachine"`
	ReceiverHome    string `json:"receiverHome"`
	ExpiresAt       string `json:"expiresAt"`
	Warning         string `json:"warning"`
}
type TransferResult struct {
	OK      bool   `json:"ok"`
	Alias   string `json:"alias"`
	KeyPath string `json:"keyPath"`
	State   string `json:"state"`
	Detail  string `json:"detail"`
	Reused  bool   `json:"reused"`
}
type receiverInfo struct {
	OK             bool              `json:"ok"`
	Home           string            `json:"home"`
	User           string            `json:"user"`
	SID            string            `json:"sid"`
	Machine        string            `json:"machine"`
	Aliases        []string          `json:"aliases"`
	ManagedAliases map[string]string `json:"managedAliases"`
	Detail         string            `json:"detail"`
}
type transferPayload struct {
	Version int `json:"version"`
	Target
	KeyID           string `json:"keyId"`
	Fingerprint     string `json:"fingerprint"`
	PrivateKey      []byte `json:"privateKey"`
	PublicKey       []byte `json:"publicKey"`
	KnownHosts      []byte `json:"knownHosts"`
	ReceiverSID     string `json:"receiverSid"`
	ReceiverMachine string `json:"receiverMachine"`
}
type preparedTransfer struct {
	Request           TransferRequest
	Source            Target
	SourceDigest      [32]byte
	DestinationDigest [32]byte
	KeyPath           string
	KeyID             string
	Fingerprint       string
	Pins              []byte
	Receiver          receiverInfo
	Expires           time.Time
}
type remoteRunner func(context.Context, string, string, []byte) ([]byte, error)

func (s *Service) configSnapshot(ctx context.Context, alias string) ([]byte, error) {
	aliases, err := Aliases(s.home)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(aliases, alias) {
		return nil, fmt.Errorf("找不到 SSH 别名 %q，请刷新列表", alias)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	args := append(s.configArgs(), "-G", "--", alias)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	hide(cmd)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("解析 SSH 别名失败: %w", err)
	}
	return out, nil
}
func parseResolved(data []byte) map[string][]string {
	out := map[string][]string{}
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r", ""), "\n") {
		key, value, ok := strings.Cut(line, " ")
		if ok {
			out[key] = append(out[key], strings.TrimSpace(value))
		}
	}
	return out
}
func first(config map[string][]string, key string) string {
	if values := config[key]; len(values) > 0 {
		return values[0]
	}
	return ""
}
func targetFromSnapshot(alias string, config map[string][]string) Target {
	port, _ := strconv.Atoi(first(config, "port"))
	return Target{Alias: alias, Host: first(config, "hostname"), User: first(config, "user"), Port: port}
}
func expandSSHPath(home, path string) string {
	if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, "~\\") {
		path = filepath.Join(home, path[2:])
	}
	path = strings.ReplaceAll(path, "%d", filepath.ToSlash(home))
	return filepath.Clean(path)
}
func (s *Service) sourceIdentity(config map[string][]string) (string, []byte, ssh.Signer, error) {
	for _, key := range []string{"proxycommand", "proxyjump", "hostkeyalias", "certificatefile"} {
		if value := first(config, key); value != "" && value != "none" {
			return "", nil, nil, errors.New("当前仅支持本程序的直连密钥连接；不迁移代理、证书或自定义主机别名")
		}
	}
	var selected string
	for _, raw := range config["identityfile"] {
		path := expandSSHPath(s.home, raw)
		own := filepath.Join(s.home, ".ssh", "keydesk_ed25519")
		relative, err := filepath.Rel(filepath.Join(s.home, ".ssh", "keydesk", "imported"), path)
		imported := err == nil && len(strings.Split(filepath.ToSlash(relative), "/")) == 2 && !strings.HasPrefix(relative, "..") && filepath.Base(path) == "id_ed25519"
		rotatedRelative, rotatedErr := filepath.Rel(filepath.Join(s.home, ".ssh", "keydesk", "keys"), path)
		rotated := rotatedErr == nil && len(strings.Split(filepath.ToSlash(rotatedRelative), "/")) == 2 && !strings.HasPrefix(rotatedRelative, "..") && filepath.Base(path) == "id_ed25519"
		if strings.EqualFold(path, own) || imported || rotated {
			if selected != "" && !strings.EqualFold(path, selected) {
				return "", nil, nil, errors.New("源连接使用多个应用密钥，无法确定要发送哪一个")
			}
			selected = path
		}
	}
	if selected == "" {
		return "", nil, nil, errors.New("该连接未使用本程序管理的密钥，暂不支持发送个人密钥、仅在 SSH Agent 中的密钥或代理连接")
	}
	data, err := os.ReadFile(selected)
	if err != nil {
		return "", nil, nil, fmt.Errorf("读取所选连接密钥失败: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return "", nil, nil, errors.New("所选密钥无法读取，或带有口令；本功能仅发送应用管理的无口令密钥")
	}
	return selected, data, signer, nil
}

func (s *Service) sourcePin(ctx context.Context, t Target, cfg map[string][]string, signer ssh.Signer) ([]byte, error) {
	files := []string{}
	for _, raw := range cfg["userknownhostsfile"] {
		files = append(files, resolvedKnownHostFiles(s.home, raw)...)
	}
	if len(files) == 0 {
		return nil, errors.New("源连接没有可读取的主机指纹记录，请先在本机核对并信任 C 的主机指纹")
	}
	cb, err := knownhosts.New(files...)
	if err != nil {
		return nil, err
	}
	var hostKey ssh.PublicKey
	client, err := connect(ctx, t, []ssh.AuthMethod{ssh.PublicKeys(signer)}, func(addr string, remote net.Addr, key ssh.PublicKey) error {
		if err := cb(addr, remote, key); err != nil {
			return err
		}
		hostKey = key
		return nil
	})
	if err != nil {
		return nil, err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	var out boundedOutput
	session.Stdout = &out
	if err := session.Run("printf '__KEYDESK_OK__'"); err != nil || !strings.Contains(out.String(), "__KEYDESK_OK__") {
		return nil, errors.New("指定私钥未通过远程命令验证")
	}
	return []byte(knownhosts.Line([]string{knownhosts.Normalize(hostAddress(t))}, hostKey) + "\n"), nil
}

// ssh -G prints resolved known-host paths without preserving quotes. First
// accept a whole existing path; then resolve a list by existing-file prefixes.
// This handles imported profiles under Windows usernames containing spaces.
func resolvedKnownHostFiles(home, raw string) []string {
	exists := func(path string) bool { info, err := os.Stat(path); return err == nil && !info.IsDir() }
	full := expandSSHPath(home, raw)
	if exists(full) {
		return []string{full}
	}
	words := configWords(raw)
	out := []string{}
	for start := 0; start < len(words); {
		found := false
		for end := len(words); end > start; end-- {
			path := expandSSHPath(home, strings.Join(words[start:end], " "))
			if exists(path) {
				out = append(out, path)
				start = end
				found = true
				break
			}
		}
		if !found {
			start++
		}
	}
	return out
}

func (s *Service) PrepareTransfer(ctx context.Context, r TransferRequest) (TransferPlan, error) {
	if r.SourceAlias == r.DestinationAlias {
		return TransferPlan{}, errors.New("源服务器 C 与接收电脑 B 不能使用同一别名")
	}
	if !aliasRE.MatchString(r.RemoteAlias) {
		return TransferPlan{}, errors.New("请填写有效的接收端连接别名")
	}
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	sourceConfig, err := s.configSnapshot(ctx, r.SourceAlias)
	if err != nil {
		return TransferPlan{}, err
	}
	cfg := parseResolved(sourceConfig)
	keyPath, keyData, signer, err := s.sourceIdentity(cfg)
	if err != nil {
		return TransferPlan{}, err
	}
	defer clear(keyData)
	source := targetFromSnapshot(r.SourceAlias, cfg)
	if err := source.Validate(); err != nil {
		return TransferPlan{}, err
	}
	pins, err := s.sourcePin(ctx, source, cfg, signer)
	if err != nil {
		return TransferPlan{}, fmt.Errorf("验证 A → C 的指定密钥连接失败，尚未发送私钥: %w", err)
	}
	destConfig, err := s.configSnapshot(ctx, r.DestinationAlias)
	if err != nil {
		return TransferPlan{}, err
	}
	dest := targetFromSnapshot(r.DestinationAlias, parseResolved(destConfig))
	output, err := s.remote(ctx, r.DestinationAlias, transferPreflight, nil)
	if err != nil {
		return TransferPlan{}, fmt.Errorf("无法通过现有 SSH 连接检查 Windows 接收电脑 B: %w", err)
	}
	var receiver receiverInfo
	if err := decodeReceiver(output, &receiver); err != nil {
		return TransferPlan{}, err
	}
	if !receiver.OK || receiver.SID == "" || receiver.Machine == "" || receiver.Home == "" {
		return TransferPlan{}, fmt.Errorf("接收端未通过检查: %s", receiver.Detail)
	}
	keyID := sha256.Sum256(signer.PublicKey().Marshal())
	keyIDText := hex.EncodeToString(keyID[:])
	for _, alias := range receiver.Aliases {
		if strings.EqualFold(alias, r.RemoteAlias) && receiver.ManagedAliases[alias] != keyIDText {
			return TransferPlan{}, fmt.Errorf("B 上已存在别名 %q，请修改接收端别名；不会覆盖 B 原有连接", r.RemoteAlias)
		}
	}
	tokenBytes := make([]byte, 24)
	if _, err := rand.Read(tokenBytes); err != nil {
		return TransferPlan{}, err
	}
	token := hex.EncodeToString(tokenBytes)
	expiry := time.Now().Add(5 * time.Minute)
	p := preparedTransfer{Request: r, Source: source, SourceDigest: sha256.Sum256(sourceConfig), DestinationDigest: sha256.Sum256(destConfig), KeyPath: keyPath, KeyID: keyIDText, Fingerprint: ssh.FingerprintSHA256(signer.PublicKey()), Pins: pins, Receiver: receiver, Expires: expiry}
	s.mu.Lock()
	if s.transfers == nil {
		s.transfers = map[string]preparedTransfer{}
	}
	for id, old := range s.transfers {
		if time.Now().After(old.Expires) {
			delete(s.transfers, id)
		}
	}
	if len(s.transfers) >= 32 {
		s.mu.Unlock()
		return TransferPlan{}, errors.New("待发送计划过多，请稍后重试")
	}
	s.transfers[token] = p
	s.mu.Unlock()
	return TransferPlan{Token: token, Source: source, Destination: dest, RemoteAlias: r.RemoteAlias, Fingerprint: p.Fingerprint, ReceiverUser: receiver.User, ReceiverMachine: receiver.Machine, ReceiverHome: receiver.Home, ExpiresAt: expiry.Format(time.RFC3339), Warning: "将复制私钥，而不只是公钥。B 将获得该密钥对所有已授权服务器的访问能力，不仅是所选 C；仅所选连接别名会被复制。"}, nil
}

func (s *Service) SendTransfer(ctx context.Context, token string, confirmed bool) (TransferResult, error) {
	if !confirmed {
		return TransferResult{}, errors.New("请先确认你信任接收电脑并了解私钥的访问范围")
	}
	s.mu.Lock()
	p, ok := s.transfers[token]
	delete(s.transfers, token)
	s.mu.Unlock()
	if !ok || time.Now().After(p.Expires) {
		return TransferResult{}, errors.New("发送计划已过期或已使用，请重新检查")
	}
	ctx, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()
	for _, check := range []struct {
		alias  string
		digest [32]byte
	}{{p.Request.SourceAlias, p.SourceDigest}, {p.Request.DestinationAlias, p.DestinationDigest}} {
		data, err := s.configSnapshot(ctx, check.alias)
		if err != nil {
			return TransferResult{}, err
		}
		if sha256.Sum256(data) != check.digest {
			return TransferResult{}, errors.New("连接配置在检查后已变化，已停止发送；请重新检查")
		}
	}
	data, err := os.ReadFile(p.KeyPath)
	if err != nil {
		return TransferResult{}, err
	}
	defer clear(data)
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil || ssh.FingerprintSHA256(signer.PublicKey()) != p.Fingerprint {
		return TransferResult{}, errors.New("源私钥已变化，已停止发送，请重新检查")
	}
	payload := transferPayload{Version: 1, Target: p.Source, KeyID: p.KeyID, Fingerprint: p.Fingerprint, PrivateKey: data, PublicKey: ssh.MarshalAuthorizedKey(signer.PublicKey()), KnownHosts: p.Pins, ReceiverSID: p.Receiver.SID, ReceiverMachine: p.Receiver.Machine}
	payload.Alias = p.Request.RemoteAlias
	input, err := json.Marshal(payload)
	if err != nil {
		return TransferResult{}, err
	}
	defer clear(input)
	output, err := s.remote(ctx, p.Request.DestinationAlias, transferReceiver, input)
	if err != nil {
		return TransferResult{}, fmt.Errorf("发送或接收过程中断，B 上可能已保存部分配置；请检查 B 或重新准备后重试（未修改 C）: %w", err)
	}
	defer clear(output)
	// A trusted destination receives the key, but its output must never be
	// allowed to echo that key into frontend RPC results, errors or activity logs.
	// Accept only booleans and a fixed state enum; derive all text/paths locally.
	var wire struct {
		OK     bool   `json:"ok"`
		State  string `json:"state"`
		Reused bool   `json:"reused"`
	}
	if err := decodeReceiver(output, &wire); err != nil {
		return TransferResult{}, err
	}
	if !wire.OK {
		return TransferResult{}, errors.New("B 拒绝导入：请检查接收账号、目录权限、已有别名或导入记录冲突；不会覆盖原有连接。B 上可能已保存导入密钥，可检查后重试。")
	}
	states := map[string]string{
		"key_ready":      "连接已保存到 B，并已验证 B 使用公钥登录 C。",
		"auth_failed":    "连接已保存到 B，但 C 拒绝此次公钥认证。请检查账号和服务器 SSH 策略。",
		"unreachable":    "连接已保存到 B，但 B 无法通过网络连接 C。请检查 B 的网络、VPN 和防火墙。",
		"host_untrusted": "连接已保存到 B，但 C 的主机指纹验证未通过。请核实 C 是否更换了主机密钥。",
		"host_changed":   "连接已保存到 B，但 C 的主机密钥与传输的可信指纹不一致。",
		"error":          "连接已保存到 B，但远程命令验证失败。请在 B 上检查该 SSH 别名。",
	}
	state := wire.State
	if state == "host_key_failed" {
		state = "host_untrusted"
	}
	if state == "timeout" {
		state = "unreachable"
	}
	if _, ok := states[state]; !ok {
		state = "error"
	}
	return TransferResult{OK: true, Alias: p.Request.RemoteAlias, KeyPath: filepath.ToSlash(filepath.Join(p.Receiver.Home, ".ssh", "keydesk", "imported", p.KeyID, "id_ed25519")), State: state, Detail: states[state], Reused: wire.Reused}, nil
}

func (s *Service) remote(ctx context.Context, alias, script string, input []byte) ([]byte, error) {
	if s.remoteRunner != nil {
		return s.remoteRunner(ctx, alias, script, input)
	}
	return s.runRemote(ctx, alias, script, input)
}

func powerShellCommand(script string) string {
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	z.Write([]byte(script))
	z.Close()
	loader := "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';$g=[IO.Compression.GzipStream]::new([IO.MemoryStream]::new([Convert]::FromBase64String('" + base64.StdEncoding.EncodeToString(compressed.Bytes()) + "')),[IO.Compression.CompressionMode]::Decompress);& ([ScriptBlock]::Create([IO.StreamReader]::new($g,[Text.Encoding]::UTF8).ReadToEnd()))"
	words := utf16.Encode([]rune(loader))
	encoded := make([]byte, len(words)*2)
	for i, w := range words {
		binary.LittleEndian.PutUint16(encoded[i*2:], w)
	}
	return "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand " + base64.StdEncoding.EncodeToString(encoded)
}

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := 65536 - b.Len()
	if remaining > 0 {
		b.Buffer.Write(p[:min(len(p), remaining)])
	}
	return n, nil
}
func (s *Service) runRemote(ctx context.Context, alias, script string, input []byte) ([]byte, error) {
	args := append(s.configArgs(), "-T", "-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=8", "-o", "ConnectionAttempts=1", "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "ControlMaster=no", "-o", "ControlPath=none", "--", alias, powerShellCommand(script))
	cmd := exec.CommandContext(ctx, "ssh", args...)
	hide(cmd)
	cmd.Env = append(os.Environ(), "SSH_ASKPASS_REQUIRE=never", "LC_ALL=C", "LANG=C")
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	var out boundedOutput
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		// Do not include remote output: a compromised or failing receiver could
		// echo stdin. Only structured, fixed receiver fields are shown to the UI.
		return nil, fmt.Errorf("SSH 接收端执行失败（%s）；请确认 B 是 Windows、SSH 密钥登录正常且可运行 Windows PowerShell", Classify(out.String()))
	}
	return out.Bytes(), nil
}
func decodeReceiver(data []byte, value any) error {
	const marker = "KEYDESK_RESULT:"
	index := bytes.LastIndex(data, []byte(marker))
	if index < 0 {
		return errors.New("接收端没有返回有效结果；请检查 B 的 Windows PowerShell 和 OpenSSH 环境")
	}
	body := bytes.TrimSpace(data[index+len(marker):])
	if i := bytes.IndexByte(body, '\n'); i >= 0 {
		body = body[:i]
	}
	if err := json.Unmarshal(body, value); err != nil {
		return errors.New("接收端返回格式错误，未显示原始内容以避免泄露私钥")
	}
	return nil
}
