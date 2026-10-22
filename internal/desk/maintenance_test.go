package desk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestDeleteConnectionPreservesSharedIdentityAndOtherAliases(t *testing.T) {
	home := t.TempDir()
	key, _, err := EnsureKey(home)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(key)
	for _, a := range []string{"expired", "other"} {
		if _, err := SaveAlias(home, Target{Alias: a, Host: "example.com", Port: 22, User: "deploy"}, key); err != nil {
			t.Fatal(err)
		}
	}
	s := NewService(home)
	plan, err := s.PrepareDelete(context.Background(), "expired")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteConnection(context.Background(), plan.Token, false); err == nil {
		t.Fatal("deleted without confirmation")
	}
	result, err := s.DeleteConnection(context.Background(), plan.Token, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.Alias != "expired" || len(result.Backups) == 0 {
		t.Fatal("missing deletion receipt")
	}
	aliases, err := Aliases(home)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(aliases, ",") != "other" {
		t.Fatalf("wrong remaining aliases: %v", aliases)
	}
	after, _ := os.ReadFile(key)
	if !bytes.Equal(before, after) {
		t.Fatal("shared private identity was changed")
	}
	if _, err := s.DeleteConnection(context.Background(), plan.Token, true); err == nil {
		t.Fatal("delete plan reused")
	}
}

func TestDeleteRejectsEditedConfiguration(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".ssh"), 0700)
	path := filepath.Join(home, ".ssh", "config")
	os.WriteFile(path, []byte("Host old\n HostName example.com\n"), 0600)
	s := NewService(home)
	p, err := s.PrepareDelete(context.Background(), "old")
	if err != nil {
		t.Fatal(err)
	}
	changed := []byte("Host old\n HostName changed.example\n")
	os.WriteFile(path, changed, 0600)
	if _, err := s.DeleteConnection(context.Background(), p.Token, true); err == nil {
		t.Fatal("stale delete plan committed")
	}
	data, _ := os.ReadFile(path)
	if !bytes.Equal(data, changed) {
		t.Fatal("concurrent changes overwritten")
	}
}

func recreationFixture(t *testing.T) (*Service, Target, string) {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home with spaces")
	oldKey, oldPub, err := EnsureKey(home)
	if err != nil {
		t.Fatal(err)
	}
	oldPublic, _, _, _, _ := ssh.ParseAuthorizedKey(oldPub)
	allowed := map[string]bool{string(oldPublic.Marshal()): true}
	var mu sync.Mutex
	_, secret, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(secret)
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		if string(p) != "correct" {
			return nil, os.ErrPermission
		}
		return nil, nil
	}, PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		mu.Lock()
		ok := allowed[string(k.Marshal())]
		mu.Unlock()
		if !ok {
			return nil, os.ErrPermission
		}
		return nil, nil
	}}
	cfg.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, e := ln.Accept()
			if e != nil {
				return
			}
			go func() {
				defer conn.Close()
				server, channels, requests, e := ssh.NewServerConn(conn, cfg)
				if e != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for next := range channels {
					ch, reqs, e := next.Accept()
					if e != nil {
						continue
					}
					go func() {
						defer ch.Close()
						for req := range reqs {
							if req.Type != "exec" {
								req.Reply(false, nil)
								continue
							}
							req.Reply(true, nil)
							var cmd struct{ Command string }
							ssh.Unmarshal(req.Payload, &cmd)
							if cmd.Command == "sh -s" {
								script, _ := io.ReadAll(ch)
								for _, line := range strings.Split(string(script), "\n") {
									if strings.HasPrefix(line, "key='ssh-ed25519 ") {
										key, _, _, _, e := ssh.ParseAuthorizedKey([]byte(strings.TrimSuffix(strings.TrimPrefix(line, "key='"), "'")))
										if e == nil {
											mu.Lock()
											allowed[string(key.Marshal())] = true
											mu.Unlock()
										}
									}
								}
								ch.Write([]byte("installed\n"))
							} else {
								ch.Write([]byte("__KEYDESK_OK__"))
							}
							ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
							return
						}
					}()
				}
			}()
		}
	}()
	target := Target{Alias: "expired", Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, User: "deploy"}
	if _, err := SaveAlias(home, target, oldKey); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveAlias(home, Target{Alias: "other", Host: "other.example", Port: 22, User: "deploy"}, oldKey); err != nil {
		t.Fatal(err)
	}
	// Simulate a reinstalled server: old trusted key differs from actual peer.
	_, otherHost, _ := ed25519.GenerateKey(rand.Reader)
	oldHost, _ := ssh.NewSignerFromKey(otherHost)
	if err := HostCallback(home, target, ssh.FingerprintSHA256(oldHost.PublicKey()), true)(hostAddress(target), ln.Addr(), oldHost.PublicKey()); err != nil {
		t.Fatal(err)
	}
	return NewService(home), target, oldKey
}

func TestRecreateUsesFreshKeyAndExplicitlyPinnedChangedHost(t *testing.T) {
	s, target, oldPath := recreationFixture(t)
	old, _ := os.ReadFile(oldPath)
	knownPath := filepath.Join(s.home, ".ssh", "known_hosts")
	knownBefore, _ := os.ReadFile(knownPath)
	p, err := s.PrepareRecreate(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if !p.HostChanged || p.Host.Fingerprint == "" {
		t.Fatal("changed host not disclosed")
	}
	data, _ := json.Marshal(p)
	if bytes.Contains(data, []byte("PRIVATE KEY")) {
		t.Fatal("private key in plan")
	}
	if _, err := s.RecreateConnection(context.Background(), p.Token, "correct", false); err == nil {
		t.Fatal("recreated without host/key confirmation")
	}
	result, err := s.RecreateConnection(context.Background(), p.Token, "correct", true)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != "key_ready" || result.KeyPath == oldPath {
		t.Fatalf("not switched to fresh identity: %+v", result)
	}
	newKey, _ := os.ReadFile(result.KeyPath)
	oldAfter, _ := os.ReadFile(oldPath)
	if bytes.Equal(newKey, old) || !bytes.Equal(old, oldAfter) {
		t.Fatal("shared identity changed or reused")
	}
	knownAfter, _ := os.ReadFile(knownPath)
	if !bytes.Equal(knownBefore, knownAfter) {
		t.Fatal("global host trust was overwritten")
	}
	cfg, err := s.configSnapshot(context.Background(), "other")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(cfg, []byte("keydesk_ed25519")) {
		t.Fatal("other alias lost original key")
	}
	cfg, err = s.configSnapshot(context.Background(), target.Alias)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = s.sourceIdentity(parseResolved(cfg))
	if err != nil {
		t.Fatalf("fresh key cannot be sent to other Windows PCs: %v", err)
	}
}

func TestRecreateWrongPasswordPreservesExistingConfiguration(t *testing.T) {
	s, target, _ := recreationFixture(t)
	config := filepath.Join(s.home, ".ssh", "config")
	before, _ := os.ReadFile(config)
	p, err := s.PrepareRecreate(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecreateConnection(context.Background(), p.Token, "incorrect", true); err == nil {
		t.Fatal("wrong password accepted")
	}
	after, _ := os.ReadFile(config)
	if !bytes.Equal(before, after) {
		t.Fatal("failed installation changed config")
	}
}

func TestRecreateRejectsNewIncludeBeforeCreatingKey(t *testing.T) {
	s, target, _ := recreationFixture(t)
	parts := filepath.Join(s.home, ".ssh", "parts")
	if err := os.Mkdir(parts, 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(s.home, ".ssh", "config")
	before, _ := os.ReadFile(config)
	if err := os.WriteFile(config, append([]byte("Include parts/*.conf\n"), before...), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := s.PrepareRecreate(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parts, "new.conf"), []byte("Host *\n ServerAliveInterval 12\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecreateConnection(context.Background(), p.Token, "correct", true); err == nil {
		t.Fatal("new Include was accepted")
	}
	if _, err := os.Stat(filepath.Join(s.home, ".ssh", "keydesk", "keys")); !os.IsNotExist(err) {
		t.Fatal("stale plan created a new key before rejecting Include change")
	}
}

func TestRecreateRejectsInheritedHostKeyAliasBeforePassword(t *testing.T) {
	s, target, _ := recreationFixture(t)
	config := filepath.Join(s.home, ".ssh", "config")
	before, _ := os.ReadFile(config)
	if err := os.WriteFile(config, append(before, []byte("\nHost *\n HostKeyAlias legacy-pin\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareRecreate(context.Background(), target); err == nil {
		t.Fatal("inherited HostKeyAlias would defeat the new pin file")
	}
}
