package desk

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRejectsConfigAndShellInjection(t *testing.T) {
	good := Target{Alias: "prod-01", Host: "2001:db8::1", Port: 22, User: "ubuntu"}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"::1", "::ffff:192.0.2.1", "fe80::1%eth0"} {
		v := good
		v.Host = host
		if err := v.Validate(); err != nil {
			t.Errorf("valid IPv6 rejected %s: %v", host, err)
		}
	}
	for _, mutate := range []func(*Target){func(v *Target) { v.Alias = "-oProxyCommand=bad" }, func(v *Target) { v.Host = "host\nHost injected" }, func(v *Target) { v.User = "root;id" }, func(v *Target) { v.Port = 65536 }, func(v *Target) { v.Host = "https://host" }} {
		v := good
		mutate(&v)
		if v.Validate() == nil {
			t.Fatalf("accepted invalid target: %+v", v)
		}
	}
}

func TestSaveAliasPreservesOriginalAndRejectsDuplicates(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".ssh")
	os.MkdirAll(dir, 0700)
	original := "# personal config\nHost old\n HostName 10.0.0.1"
	path := filepath.Join(dir, "config")
	os.WriteFile(path, []byte(original), 0600)
	target := Target{Alias: "new", Host: "server.example.com", Port: 2222, User: "deploy"}
	if _, err := SaveAlias(home, target, filepath.Join(dir, "key with space")); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.HasSuffix(string(data), original) {
		t.Fatal("original config changed")
	}
	if !strings.Contains(string(data), "IdentityFile \"") {
		t.Fatal("identity path not quoted")
	}
	if _, err := SaveAlias(home, target, "other"); err == nil {
		t.Fatal("duplicate alias accepted")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(data) {
		t.Fatal("conflict changed config")
	}
	backups, _ := filepath.Glob(path + ".keydesk-*.bak")
	if len(backups) != 1 {
		t.Fatal("missing original backup")
	}
	backup, _ := os.ReadFile(backups[0])
	if string(backup) != original {
		t.Fatal("incorrect backup")
	}
}

func TestAliasesFollowIncludesAndIgnoreWildcards(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".ssh")
	os.MkdirAll(filepath.Join(dir, "parts"), 0700)
	os.WriteFile(filepath.Join(dir, "config"), []byte("Include parts/*.conf\nHost primary secondary *.test !excluded\n HostName example.com\nInclude config\n"), 0600)
	os.WriteFile(filepath.Join(dir, "parts", "one.conf"), []byte("Host included\n HostName 1.2.3.4\n"), 0600)
	aliases, err := Aliases(home)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(aliases, ",") != "included,primary,secondary" {
		t.Fatalf("got %v", aliases)
	}
	if _, err := SaveAlias(home, Target{Alias: "included", Host: "x.example", Port: 22, User: "u"}, "key"); err == nil {
		t.Fatal("included alias overwritten")
	}
}

func TestEnsureKeyReusesSameIdentityAndRepairsPublicFile(t *testing.T) {
	home := t.TempDir()
	path, pub, err := EnsureKey(home)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	os.Remove(path + ".pub")
	path2, pub2, err := EnsureKey(home)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path2)
	if string(before) != string(after) || string(pub) != string(pub2) {
		t.Fatal("identity was replaced")
	}
	repaired, _ := os.ReadFile(path + ".pub")
	if string(repaired) != string(pub) {
		t.Fatal("public key not repaired")
	}
}

func TestCheckClassificationDoesNotTreatOfflineAsMissingKey(t *testing.T) {
	cases := []struct{ output, state string }{{"Permission denied (publickey).", "auth_failed"}, {"ssh: connect to host x port 22: Connection timed out", "unreachable"}, {"Host key verification failed.", "host_untrusted"}, {"REMOTE HOST IDENTIFICATION HAS CHANGED!", "host_changed"}, {"proxy command failed", "error"}}
	for _, c := range cases {
		if got := Classify(c.output); got != c.state {
			t.Errorf("%q: %s", c.output, got)
		}
	}
}
