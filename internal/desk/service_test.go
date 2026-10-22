package desk

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSpecificAliasOverridesEarlierCatchAllWithoutChangingOtherHosts(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".ssh"), 0700)
	config := filepath.Join(home, ".ssh", "config")
	os.WriteFile(config, []byte("User defaultuser\nHost *\n Port 2222\nHost original\n HostName original.example\n"), 0600)
	_, err := SaveAlias(home, Target{Alias: "specific", Host: "specific.example", Port: 2200, User: "deploy"}, filepath.Join(home, ".ssh", "key"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ssh", "-G", "-F", config, "specific")
	hide(cmd)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ReplaceAll(string(out), "\r", ""), "user deploy\n") || !strings.Contains(strings.ReplaceAll(string(out), "\r", ""), "port 2200\n") {
		t.Fatalf("alias masked by defaults: %s", out)
	}
	cmd = exec.Command("ssh", "-G", "-F", config, "original")
	hide(cmd)
	out, err = cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ReplaceAll(string(out), "\r", ""), "user defaultuser\n") || !strings.Contains(strings.ReplaceAll(string(out), "\r", ""), "port 2222\n") {
		t.Fatal("changed existing host semantics")
	}
}

func TestServiceListsWithoutCreatingKeysOrContactingServers(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".ssh"), 0700)
	os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte("Host offline\n HostName 192.0.2.1\n User deploy\n"), 0600)
	svc := NewService(home)
	overview, err := svc.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(overview.Servers) != 1 || overview.Servers[0].State != "unknown" {
		t.Fatalf("%+v", overview)
	}
	if _, err := os.Stat(filepath.Join(home, ".ssh", "keydesk_ed25519")); !os.IsNotExist(err) {
		t.Fatal("listing generated private key")
	}
}

func TestInventoryContainsNoCredentials(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".ssh"), 0700)
	os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte("Host demo\n HostName example.com\n User deploy\n"), 0600)
	svc := NewService(home)
	path, err := svc.Export(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "ssh demo") || strings.Contains(string(data), "PRIVATE KEY") || strings.Contains(string(data), "password") {
		t.Fatalf("unexpected inventory: %s", data)
	}
}
