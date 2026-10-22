package desk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestHostTrustBlocksUnknownAndChangedKeys(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".ssh"), 0700)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	target := Target{Alias: "test", Host: "127.0.0.1", Port: 2222, User: "u"}
	cb := HostCallback(home, target, "", false)
	if err := cb("127.0.0.1:2222", &net.TCPAddr{}, signer.PublicKey()); err == nil {
		t.Fatal("unknown host silently trusted")
	}
	fp := ssh.FingerprintSHA256(signer.PublicKey())
	if err := HostCallback(home, target, fp, true)("127.0.0.1:2222", &net.TCPAddr{}, signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if err := HostCallback(home, target, "", false)("127.0.0.1:2222", &net.TCPAddr{}, signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := ssh.NewSignerFromKey(priv2)
	if err := HostCallback(home, target, ssh.FingerprintSHA256(other.PublicKey()), true)("127.0.0.1:2222", &net.TCPAddr{}, other.PublicKey()); err == nil {
		t.Fatal("changed host key replaced")
	}
}

func TestInstallScriptPreservesEntriesAndIsIdempotent(t *testing.T) {
	sh := "C:/Program Files/Git/bin/sh.exe"
	if _, err := os.Stat(sh); err != nil {
		sh = "D:/Program Files/Git/bin/sh.exe"
	}
	if _, err := os.Stat(sh); err != nil {
		var e error
		sh, e = exec.LookPath("sh")
		if e != nil {
			t.Skip("POSIX shell unavailable")
		}
	}
	home := t.TempDir()
	dir := filepath.Join(home, ".ssh")
	os.MkdirAll(dir, 0700)
	old := "# existing entry without final newline\nssh-ed25519 AAAAoriginal comment"
	path := filepath.Join(dir, "authorized_keys")
	os.WriteFile(path, []byte(old), 0600)
	keyHome := t.TempDir()
	_, pub, err := EnsureKey(keyHome)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		cmd := exec.Command(sh, "-s")
		cmd.Env = append(os.Environ(), "HOME="+filepath.ToSlash(home))
		cmd.Stdin = strings.NewReader(InstallScript(pub))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
	}
	data, _ := os.ReadFile(path)
	if !bytes.HasPrefix(data, []byte(old+"\n")) {
		t.Fatalf("existing keys corrupted: %s", data)
	}
	if bytes.Count(data, bytes.TrimSpace(pub)) != 1 {
		t.Fatal("duplicate or missing public key")
	}
}

func TestInstallScriptRestoresCommentedKeyAndIgnoresQuotedCommand(t *testing.T) {
	sh := "D:/Program Files/Git/bin/sh.exe"
	if _, err := os.Stat(sh); err != nil {
		sh = "C:/Program Files/Git/bin/sh.exe"
	}
	if _, err := os.Stat(sh); err != nil {
		t.Skip("POSIX shell unavailable")
	}
	_, pub, err := EnsureKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, old := range []string{"# " + string(pub), "command=\"echo " + strings.TrimSpace(string(pub)) + "\" ssh-ed25519 AAAAother comment\n"} {
		home := t.TempDir()
		os.MkdirAll(filepath.Join(home, ".ssh"), 0700)
		path := filepath.Join(home, ".ssh", "authorized_keys")
		os.WriteFile(path, []byte(old), 0600)
		cmd := exec.Command(sh, "-s")
		cmd.Env = append(os.Environ(), "HOME="+filepath.ToSlash(home))
		cmd.Stdin = strings.NewReader(InstallScript(pub))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		if !strings.Contains(string(out), "installed") {
			t.Fatalf("inactive key mistaken for an active key: %s", out)
		}
		data, _ := os.ReadFile(path)
		if !bytes.HasSuffix(data, pub) {
			t.Fatal("missing active key")
		}
	}
}

// A real local SSH protocol fixture exercises host verification and auth,
// without contacting any of the user's servers.
func TestPasswordBootstrapVerifiesKeyAndRejectsWrongPassword(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".ssh"), 0700)
	key, pub, err := EnsureKey(home)
	if err != nil {
		t.Fatal(err)
	}
	allowed, _, _, _, err := ssh.ParseAuthorizedKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(priv)
	var installed atomic.Bool
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if string(p) != "correct-password" {
				return nil, errors.New("denied")
			}
			return nil, nil
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !installed.Load() || !bytes.Equal(key.Marshal(), allowed.Marshal()) {
				return nil, errors.New("key absent")
			}
			return nil, nil
		},
	}
	config.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				s, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer s.Close()
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, requests, err := nc.Accept()
					if err != nil {
						continue
					}
					go func() {
						defer ch.Close()
						for req := range requests {
							if req.Type != "exec" {
								req.Reply(false, nil)
								continue
							}
							req.Reply(true, nil)
							var payload struct{ Command string }
							ssh.Unmarshal(req.Payload, &payload)
							if payload.Command == "sh -s" {
								var b bytes.Buffer
								b.ReadFrom(ch)
								if !strings.Contains(b.String(), "authorized_keys") {
									ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
									return
								}
								installed.Store(true)
								fmt.Fprint(ch, "installed\n")
							} else {
								fmt.Fprint(ch, "__KEYDESK_OK__")
							}
							ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
							return
						}
					}()
				}
			}()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	target := Target{Alias: "fixture", Host: "127.0.0.1", Port: port, User: "deploy"}
	info, err := Inspect(context.Background(), home, target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Known || info.Fingerprint != ssh.FingerprintSHA256(hostSigner.PublicKey()) {
		t.Fatal("wrong probe identity")
	}
	if _, err := Bootstrap(context.Background(), home, target, "wrong", key, pub, info.Fingerprint, true); err == nil {
		t.Fatal("wrong password succeeded")
	}
	if installed.Load() {
		t.Fatal("unauthorized install")
	}
	if _, err := Bootstrap(context.Background(), home, target, "correct-password", key, pub, info.Fingerprint, true); err != nil {
		t.Fatal(err)
	}
	if !installed.Load() {
		t.Fatal("key not installed")
	}
	// Exercise the whole application workflow, including the real OpenSSH
	// process, saved alias, persisted result and exported inventory.
	sshConfig := "UserKnownHostsFile \"" + filepath.ToSlash(filepath.Join(home, ".ssh", "known_hosts")) + "\"\n"
	if err := os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte(sshConfig), 0600); err != nil {
		t.Fatal(err)
	}
	service := NewService(home)
	row, err := service.Install(context.Background(), InstallRequest{Target: target, Password: "correct-password", Fingerprint: info.Fingerprint, Trust: true})
	if err != nil {
		t.Fatal(err)
	}
	if row.State != "key_ready" {
		t.Fatalf("full workflow failed: %+v", row)
	}
	status, _ := os.ReadFile(service.statusPath())
	if bytes.Contains(status, []byte("correct-password")) {
		t.Fatal("password persisted")
	}
	if _, err := service.Export(context.Background()); err != nil {
		t.Fatal(err)
	}
}
