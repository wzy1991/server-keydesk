package desk

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
)

func receiverPS(t *testing.T, home, file string, payload any) map[string]any {
	t.Helper()
	script, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(script); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	bootstrap := "$ProgressPreference='SilentlyContinue';$m=New-Object IO.MemoryStream(,[Convert]::FromBase64String('" + base64.StdEncoding.EncodeToString(compressed.Bytes()) + "'));$g=New-Object IO.Compression.GzipStream($m,[IO.Compression.CompressionMode]::Decompress);$r=New-Object IO.StreamReader($g);& ([ScriptBlock]::Create($r.ReadToEnd()))"
	u := utf16.Encode([]rune(bootstrap))
	b := make([]byte, len(u)*2)
	for i, r := range u {
		b[i*2], b[i*2+1] = byte(r), byte(r>>8)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(b))
	cmd.Env = append(os.Environ(), "USERPROFILE="+home)
	if payload != nil {
		data, e := json.Marshal(payload)
		if e != nil {
			t.Fatal(e)
		}
		cmd.Stdin = bytes.NewReader(data)
	}
	hide(cmd)
	out, err := cmd.CombinedOutput()
	if fields, ok := payload.(map[string]any); ok {
		if encoded, ok := fields["privateKey"].(string); ok {
			secret, _ := base64.StdEncoding.DecodeString(encoded)
			if (len(secret) > 0 && bytes.Contains(out, secret)) || (len(encoded) > 32 && bytes.Contains(out, []byte(encoded))) {
				t.Fatal("receiver exposed private key bytes")
			}
		}
	}
	if err != nil {
		t.Fatalf("receiver process failed (%v); output omitted to protect payload", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "KEYDESK_RESULT:") {
		t.Fatalf("receiver emitted invalid protocol (%d bytes)", len(out))
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(lines[0], "KEYDESK_RESULT:")), &result); err != nil {
		t.Fatal("invalid receiver JSON")
	}
	return result
}

func receiverFixture(t *testing.T, home string) map[string]any {
	t.Helper()
	preflight := receiverPS(t, home, "transfer_preflight.ps1", nil)
	if preflight["ok"] != true {
		t.Fatalf("preflight failed: %v", preflight["detail"])
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "receiver-test")
	if err != nil {
		t.Fatal(err)
	}
	id := sha256.Sum256(sshPub.Marshal())
	return map[string]any{"version": 1, "alias": "test-import", "host": "127.0.0.1", "port": 1, "user": "receiver_test", "keyId": hex.EncodeToString(id[:]), "fingerprint": ssh.FingerprintSHA256(sshPub), "privateKey": base64.StdEncoding.EncodeToString(pem.EncodeToMemory(block)), "publicKey": base64.StdEncoding.EncodeToString(ssh.MarshalAuthorizedKey(sshPub)), "knownHosts": base64.StdEncoding.EncodeToString([]byte("[127.0.0.1]:1 " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + "\n")), "receiverSid": preflight["sid"], "receiverMachine": preflight["machine"]}
}

func TestReceiverPreflightPreservesUnicodeUserDirectory(t *testing.T) {
	home := filepath.Join(t.TempDir(), "电脑 B 的用户目录")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	result := receiverPS(t, home, "transfer_preflight.ps1", nil)
	actual, ok := result["home"].(string)
	if result["ok"] != true || !ok {
		t.Fatal("Unicode home preflight failed")
	}
	wantInfo, err := os.Stat(home)
	if err != nil {
		t.Fatal(err)
	}
	gotInfo, err := os.Stat(actual)
	if err != nil || !os.SameFile(wantInfo, gotInfo) {
		t.Fatal("preflight corrupted the Unicode receiver directory")
	}
}

func TestReceiverPreservesConfigAndProtectsKey(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home with spaces")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(home, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}
	original := []byte("# Host test-import\r\n# Include %unsupported/missing.conf\r\n# original bytes\r\nIgnoreUnknown OriginalUnsupported\r\nOriginalUnsupported preserved\r\nHost native # test-import\r\n    HostName original.example\r\n\tUser native-user\r\n")
	config := filepath.Join(home, ".ssh", "config")
	if err := os.WriteFile(config, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "keydesk_ed25519"), []byte("native-key-sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	p := receiverFixture(t, home)
	r := receiverPS(t, home, "transfer_windows.ps1", p)
	if r["ok"] != true || r["state"] == "key_ready" {
		t.Fatalf("expected stored key and closed-port failure; result: %v", r)
	}
	data, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(data, original) || !bytes.Contains(data, []byte("Host *\r\n")) {
		t.Fatal("original config bytes were not preserved under Host *")
	}
	if !bytes.Contains(data, []byte("IdentitiesOnly yes")) || !bytes.Contains(data, []byte("ProxyCommand none")) || !bytes.Contains(data, []byte("ProxyJump none")) || !bytes.Contains(data, []byte("UserKnownHostsFile")) {
		t.Fatal("direct pinned profile missing")
	}
	sshExe := filepath.Join(os.Getenv("SystemRoot"), "System32", "OpenSSH", "ssh.exe")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resolve := exec.CommandContext(ctx, sshExe, "-G", "-F", config, "native")
	resolve.Env = append(os.Environ(), "USERPROFILE="+home)
	hide(resolve)
	resolved, err := resolve.CombinedOutput()
	if err != nil {
		t.Fatalf("original alias no longer resolves after import: %v; %s", err, resolved)
	}
	if !bytes.Contains(resolved, []byte("hostname original.example")) || !bytes.Contains(resolved, []byte("user native-user")) {
		t.Fatal("import changed original alias resolution")
	}
	prefix := data[:len(data)-len(original)]
	if bytes.Contains(bytes.ToLower(prefix), []byte("ignoreunknown")) {
		t.Fatal("import overrides the original IgnoreUnknown list")
	}
	probe := exec.CommandContext(ctx, sshExe, "-G", "-F", "NUL", "-o", "KnownHostsCommand=none", "keydesk-option-check.invalid")
	probe.Env = append(os.Environ(), "USERPROFILE="+home)
	hide(probe)
	supported := probe.Run() == nil
	if bytes.Contains(prefix, []byte("    KnownHostsCommand none\r\n")) != supported {
		t.Fatal("persisted KnownHostsCommand does not match local OpenSSH support")
	}
	backups, _ := filepath.Glob(config + ".keydesk-backup-*")
	if len(backups) != 1 {
		t.Fatal("expected one original config backup")
	}
	backup, _ := os.ReadFile(backups[0])
	if !bytes.Equal(backup, original) {
		t.Fatal("backup changed original config bytes")
	}
	native, _ := os.ReadFile(filepath.Join(home, ".ssh", "keydesk_ed25519"))
	if string(native) != "native-key-sentinel" {
		t.Fatal("native key changed")
	}
	keyPath, _ := r["keyPath"].(string)
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	expect, _ := base64.StdEncoding.DecodeString(p["privateKey"].(string))
	if !bytes.Equal(key, expect) {
		t.Fatal("imported key differs")
	}
	sd, err := windows.GetNamedSecurityInfo(keyPath, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sd.String(), ";;;WD)") || strings.Contains(sd.String(), ";;;BU)") || !strings.Contains(sd.String(), "D:P") {
		t.Fatalf("private DACL not protected: %s", sd.String())
	}
	grant := exec.Command("icacls.exe", keyPath, "/grant", "*S-1-1-0:(R)")
	hide(grant)
	if err := grant.Run(); err != nil {
		t.Fatal("could not add explicit test grant")
	}
	repeat := receiverPS(t, home, "transfer_windows.ps1", p)
	if repeat["ok"] != true || repeat["reused"] != true {
		t.Fatalf("idempotent transfer failed: %v", repeat)
	}
	repaired, err := windows.GetNamedSecurityInfo(keyPath, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(repaired.String(), ";;;WD)") || strings.Contains(repaired.String(), ";;;S-1-1-0)") {
		t.Fatal("idempotent import retained explicit Everyone access")
	}
	after, _ := os.ReadFile(config)
	if !bytes.Equal(after, data) {
		t.Fatal("idempotent transfer changed config")
	}
	preflight := receiverPS(t, home, "transfer_preflight.ps1", nil)
	managed, _ := preflight["managedAliases"].(map[string]any)
	if managed["test-import"] != p["keyId"] {
		t.Fatal("preflight omitted managed alias")
	}
	p["host"] = "localhost"
	changed := receiverPS(t, home, "transfer_windows.ps1", p)
	if changed["ok"] != false {
		t.Fatal("changed existing profile accepted")
	}
}

func TestReceiverRejectsIdentityAndAliasConflicts(t *testing.T) {
	t.Run("identity", func(t *testing.T) {
		home := t.TempDir()
		p := receiverFixture(t, home)
		p["receiverSid"] = "S-1-0-0"
		r := receiverPS(t, home, "transfer_windows.ps1", p)
		if r["ok"] != false {
			t.Fatal("wrong receiver identity accepted")
		}
		if _, err := os.Stat(filepath.Join(home, ".ssh")); !os.IsNotExist(err) {
			t.Fatal("identity mismatch touched receiver files")
		}
	})
	t.Run("include collision", func(t *testing.T) {
		home := t.TempDir()
		p := receiverFixture(t, home)
		dir := filepath.Join(home, ".ssh")
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		original := []byte("include=extra*.conf\r\nHost *\r\n User default\r\n")
		if err := os.WriteFile(filepath.Join(dir, "config"), original, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "extra.conf"), []byte("host=test-import another\n HostName native.example\nHOST=UPPER\n"), 0600); err != nil {
			t.Fatal(err)
		}
		preflight := receiverPS(t, home, "transfer_preflight.ps1", nil)
		aliases, _ := preflight["aliases"].([]any)
		found := false
		upper := false
		for _, alias := range aliases {
			if alias == "test-import" {
				found = true
			}
			if alias == "UPPER" {
				upper = true
			}
		}
		if preflight["ok"] != true || !found || !upper {
			t.Fatal("preflight missed aliases in lowercase equals Include/Host config")
		}
		r := receiverPS(t, home, "transfer_windows.ps1", p)
		if r["ok"] != false {
			t.Fatal("included alias collision accepted")
		}
		after, _ := os.ReadFile(filepath.Join(dir, "config"))
		if !bytes.Equal(after, original) {
			t.Fatal("collision changed config")
		}
	})
}

func TestReceiverCreatesFreshHomeProfile(t *testing.T) {
	home := t.TempDir()
	p := receiverFixture(t, home)
	r := receiverPS(t, home, "transfer_windows.ps1", p)
	if r["ok"] != true {
		t.Fatalf("fresh-home profile failed: %v", r)
	}
	if _, err := os.Stat(filepath.Join(home, ".ssh", "config")); err != nil {
		t.Fatal(err)
	}
}

func TestReceiverRejectsMalformedMaterialAndReparsePaths(t *testing.T) {
	for _, field := range []string{"keyId", "fingerprint", "privateKey", "publicKey", "knownHosts", "receiverMachine", "alias"} {
		t.Run(field, func(t *testing.T) {
			home := t.TempDir()
			p := receiverFixture(t, home)
			p[field] = "invalid-value"
			if field == "alias" {
				p[field] = "../escape"
			}
			r := receiverPS(t, home, "transfer_windows.ps1", p)
			if r["ok"] != false {
				t.Fatalf("invalid %s accepted", field)
			}
		})
	}
	t.Run("directory junction", func(t *testing.T) {
		home := t.TempDir()
		target := t.TempDir()
		p := receiverFixture(t, home)
		cmd := exec.Command("cmd.exe", "/c", "mklink", "/J", filepath.Join(home, ".ssh"), target)
		hide(cmd)
		if err := cmd.Run(); err != nil {
			t.Skip("junction creation not available")
		}
		r := receiverPS(t, home, "transfer_windows.ps1", p)
		if r["ok"] != false {
			t.Fatal("reparse SSH directory accepted")
		}
		entries, _ := os.ReadDir(target)
		if len(entries) != 0 {
			t.Fatal("receiver wrote through junction")
		}
	})
}
