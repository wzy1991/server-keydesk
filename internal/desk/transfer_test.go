package desk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ssh"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func transferFixture(t *testing.T) (*Service, string) {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home with spaces")
	key, pub, err := EnsureKey(home)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, _, _, _, _ := ssh.ParseAuthorizedKey(pub)
	_, secret, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(secret)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if !bytes.Equal(k.Marshal(), clientKey.Marshal()) {
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
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				server, channels, requests, e := ssh.NewServerConn(c, cfg)
				if e != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for ch := range channels {
					channel, reqs, e := ch.Accept()
					if e != nil {
						continue
					}
					go func() {
						defer channel.Close()
						for req := range reqs {
							if req.Type != "exec" {
								req.Reply(false, nil)
								continue
							}
							req.Reply(true, nil)
							var command struct{ Command string }
							ssh.Unmarshal(req.Payload, &command)
							if strings.Contains(command.Command, "KEYDESK_C_READY") {
								channel.Write([]byte("KEYDESK_C_READY\n"))
							} else {
								channel.Write([]byte("__KEYDESK_OK__"))
							}
							channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
							return
						}
					}()
				}
			}()
		}
	}()
	target := Target{Alias: "c", Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, User: "deploy"}
	if err := HostCallback(home, target, ssh.FingerprintSHA256(hostSigner.PublicKey()), true)(hostAddress(target), ln.Addr(), hostSigner.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveAlias(home, target, key); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveAlias(home, Target{Alias: "b", Host: "b.example", Port: 22, User: "windowsuser"}, key); err != nil {
		t.Fatal(err)
	}
	return NewService(home), key
}

func TestTransferRequiresConfirmationAndOneUsePlan(t *testing.T) {
	s, key := transferFixture(t)
	sent := 0
	s.remoteRunner = func(ctx context.Context, alias, script string, input []byte) ([]byte, error) {
		if len(input) == 0 {
			return []byte(`KEYDESK_RESULT:{"ok":true,"sid":"S-1-5-21-100-101-102-1000","machine":"PC-B","user":"windowsuser","home":"C:/Users/windowsuser","aliases":[]}`), nil
		}
		sent++
		var payload transferPayload
		if err := json.Unmarshal(input, &payload); err != nil {
			t.Fatal(err)
		}
		original, _ := os.ReadFile(key)
		if !bytes.Equal(original, payload.PrivateKey) {
			t.Fatal("incorrect private identity")
		}
		if payload.Alias != "c-from-a" || payload.ReceiverMachine != "PC-B" || !bytes.Contains(payload.KnownHosts, []byte("ssh-ed25519")) {
			t.Fatal("missing selected profile or pinned identity")
		}
		return []byte(`KEYDESK_RESULT:{"ok":true,"alias":"c-from-a","state":"key_ready","detail":"verified","keyPath":"C:/Users/windowsuser/.ssh/keydesk/imported/key","reused":false}`), nil
	}
	plan, err := s.PrepareTransfer(context.Background(), TransferRequest{SourceAlias: "c", DestinationAlias: "b", RemoteAlias: "c-from-a"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(plan)
	if bytes.Contains(encoded, []byte("PRIVATE KEY")) || bytes.Contains(encoded, []byte("privateKey")) {
		t.Fatal("private key leaked to frontend")
	}
	if _, err := s.SendTransfer(context.Background(), plan.Token, false); err == nil {
		t.Fatal("sent without explicit confirmation")
	}
	if sent != 0 {
		t.Fatal("secret sent before confirmation")
	}
	result, err := s.SendTransfer(context.Background(), plan.Token, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != "key_ready" || sent != 1 {
		t.Fatal("transfer failed")
	}
	if _, err := s.SendTransfer(context.Background(), plan.Token, true); err == nil {
		t.Fatal("plan reused")
	}
}

func TestTransferStopsWhenDestinationConfigChangesOrPlanExpires(t *testing.T) {
	for _, change := range []string{"config", "expired"} {
		t.Run(change, func(t *testing.T) {
			s, _ := transferFixture(t)
			sent := false
			s.remoteRunner = func(ctx context.Context, alias, script string, input []byte) ([]byte, error) {
				if len(input) > 0 {
					sent = true
				}
				return []byte(`KEYDESK_RESULT:{"ok":true,"sid":"S-1-5-21-100-101-102-1000","machine":"PC-B","user":"u","home":"C:/Users/u","aliases":[]}`), nil
			}
			plan, err := s.PrepareTransfer(context.Background(), TransferRequest{SourceAlias: "c", DestinationAlias: "b", RemoteAlias: "c"})
			if err != nil {
				t.Fatal(err)
			}
			if change == "config" {
				path := filepath.Join(s.home, ".ssh", "config")
				data, _ := os.ReadFile(path)
				data = []byte(strings.ReplaceAll(string(data), "b.example", "other.example"))
				os.WriteFile(path, data, 0600)
			} else {
				p := s.transfers[plan.Token]
				p.Expires = time.Now().Add(-time.Minute)
				s.transfers[plan.Token] = p
			}
			if _, err := s.SendTransfer(context.Background(), plan.Token, true); err == nil {
				t.Fatal("stale plan accepted")
			}
			if sent {
				t.Fatal("secret sent after destination changed")
			}
		})
	}
}

func TestTransferRejectsAliasConflictAndCustomIdentity(t *testing.T) {
	s, _ := transferFixture(t)
	s.remoteRunner = func(context.Context, string, string, []byte) ([]byte, error) {
		return []byte(`KEYDESK_RESULT:{"ok":true,"sid":"S-1-5-21-100-101-102-1000","machine":"PC-B","user":"u","home":"C:/Users/u","aliases":["existing"]}`), nil
	}
	if _, err := s.PrepareTransfer(context.Background(), TransferRequest{SourceAlias: "c", DestinationAlias: "b", RemoteAlias: "existing"}); err == nil {
		t.Fatal("remote alias conflict accepted")
	}
	path := filepath.Join(s.home, ".ssh", "config")
	data, _ := os.ReadFile(path)
	data = []byte(strings.ReplaceAll(string(data), "keydesk_ed25519", "personal_key"))
	os.WriteFile(path, data, 0600)
	if _, err := s.PrepareTransfer(context.Background(), TransferRequest{SourceAlias: "c", DestinationAlias: "b", RemoteAlias: "safe"}); err == nil {
		t.Fatal("custom identity exported")
	}
}

func TestRemotePowerShellCommandContainsNoSecretPayload(t *testing.T) {
	command := powerShellCommand(strings.Repeat("Write-Output 'test';", 5000))
	if len(command) > 24000 {
		t.Fatal("remote command exceeds Windows command-line budget")
	}
	if !strings.HasPrefix(command, "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand ") {
		t.Fatal("not a fixed encoded PowerShell receiver")
	}
	if len(powerShellCommand(transferReceiver)) > 30000 {
		t.Fatal("actual receiver exceeds Windows command-line budget")
	}
}

func TestTransferSupportsPinnedKnownHostsPathWithSpaces(t *testing.T) {
	s, _ := transferFixture(t)
	path := filepath.Join(s.home, ".ssh", "config")
	data, _ := os.ReadFile(path)
	data = []byte(strings.Replace(string(data), "Host c\n", "Host c\n    UserKnownHostsFile \""+filepath.ToSlash(filepath.Join(s.home, ".ssh", "known_hosts"))+"\"\n", 1))
	os.WriteFile(path, data, 0600)
	s.remoteRunner = func(context.Context, string, string, []byte) ([]byte, error) {
		return []byte(`KEYDESK_RESULT:{"ok":true,"sid":"S-1-5-21-100-101-102-1000","machine":"PC-B","user":"u","home":"C:/Users/u","aliases":[]}`), nil
	}
	if _, err := s.PrepareTransfer(context.Background(), TransferRequest{SourceAlias: "c", DestinationAlias: "b", RemoteAlias: "copied-c"}); err != nil {
		t.Fatal(err)
	}
}

func TestTransferDoesNotExposePrivateKeyEchoedInReceiverResult(t *testing.T) {
	for _, ok := range []bool{true, false} {
		t.Run(fmt.Sprint(ok), func(t *testing.T) {
			s, _ := transferFixture(t)
			secret := ""
			s.remoteRunner = func(ctx context.Context, alias, script string, input []byte) ([]byte, error) {
				if len(input) == 0 {
					return []byte(`KEYDESK_RESULT:{"ok":true,"sid":"S-1-5-21-100-101-102-1000","machine":"PC-B","user":"u","home":"C:/Users/u","aliases":[]}`), nil
				}
				var payload transferPayload
				json.Unmarshal(input, &payload)
				secret = base64.StdEncoding.EncodeToString(payload.PrivateKey)
				data, _ := json.Marshal(TransferResult{OK: ok, Alias: secret, KeyPath: secret, State: secret, Detail: secret})
				return append([]byte("KEYDESK_RESULT:"), data...), nil
			}
			plan, err := s.PrepareTransfer(context.Background(), TransferRequest{SourceAlias: "c", DestinationAlias: "b", RemoteAlias: "copied-c"})
			if err != nil {
				t.Fatal(err)
			}
			result, err := s.SendTransfer(context.Background(), plan.Token, true)
			data, _ := json.Marshal(result)
			if bytes.Contains(data, []byte(secret)) || (err != nil && strings.Contains(err.Error(), secret)) {
				t.Fatal("receiver echoed private data into a frontend result or error")
			}
		})
	}
}
