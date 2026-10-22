package desk

import (
	"bytes"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func configFixture(t *testing.T, main string) (string, string) {
	t.Helper()
	home := t.TempDir()
	path := filepath.Join(home, ".ssh", "config")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(main), 0600); err != nil {
		t.Fatal(err)
	}
	return home, path
}
func configAfter(t *testing.T, edits []ConfigEdit, path string) string {
	t.Helper()
	for _, e := range edits {
		if e.Path == path {
			return string(e.After)
		}
	}
	t.Fatalf("missing snapshot %s", path)
	return ""
}
func TestConfigRemovalPreservesOtherAliasesAndCRLF(t *testing.T) {
	before := "# global\r\nServerAliveInterval 15\r\n# Added by Server Keydesk\r\nHost Old keep # shared\r\n  HostName 192.0.2.9\r\n  User alice\r\n\r\n# next\r\nHost next\r\n  HostName 192.0.2.10\r\n"
	home, path := configFixture(t, before)
	edits, err := PlanAliasRemoval(home, "old")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(before, "Host Old keep # shared", "Host keep # shared", 1)
	if got := configAfter(t, edits, path); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if got, _ := os.ReadFile(path); string(got) != before {
		t.Fatal("planning wrote config")
	}
	backups, err := CommitConfigEdits(home, edits)
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 1 {
		t.Fatalf("backups=%v", backups)
	}
	backup, _ := os.ReadFile(backups[0])
	if string(backup) != before {
		t.Fatal("backup differs")
	}
}
func TestConfigRemovalMarkersAndMatch(t *testing.T) {
	for _, marker := range []string{"# Added by Server Keydesk", "# BEGIN KEYDESK IMPORT old deadbeef", "# BEGIN KEYDESK CONNECTION old"} {
		t.Run(marker, func(t *testing.T) {
			end := ""
			if strings.Contains(marker, "BEGIN") {
				end = strings.Replace(strings.Fields(marker)[3], "IMPORT", "IMPORT", 1)
				end = "# END KEYDESK " + end + " old\n"
			}
			before := "# preamble\n" + marker + "\nHost old\n  HostName 192.0.2.1\n" + end + "Host *\n  ServerAliveInterval 12\n# retained\nMatch host next\n  User bob\n"
			home, path := configFixture(t, before)
			edits, err := PlanAliasRemoval(home, "old")
			if err != nil {
				t.Fatal(err)
			}
			want := "# preamble\nHost *\n  ServerAliveInterval 12\n# retained\nMatch host next\n  User bob\n"
			if got := configAfter(t, edits, path); got != want {
				t.Fatalf("got %q want %q", got, want)
			}
		})
	}
}
func TestConfigIncludesSnapshotAndFreshRecreation(t *testing.T) {
	home, path := configFixture(t, "Include parts/*.conf\nHost next\n  HostName 192.0.2.2\n")
	dir := filepath.Join(home, ".ssh", "parts")
	os.Mkdir(dir, 0700)
	inc := filepath.Join(dir, "one.conf")
	os.WriteFile(inc, []byte("Host old\n  HostName 192.0.2.1\n"), 0600)
	edits, err := PlanAliasRemoval(home, "old")
	if err != nil {
		t.Fatal(err)
	}
	if configAfter(t, edits, path) != "Include parts/*.conf\nHost next\n  HostName 192.0.2.2\n" {
		t.Fatal("main changed")
	}
	if configAfter(t, edits, inc) != "" {
		t.Fatal("include alias retained")
	}
	for i := range edits {
		if edits[i].Path == path {
			edits[i].After = append([]byte("Host old\n  HostName 192.0.2.8\nHost *\n"), edits[i].After...)
		}
	}
	if _, err = CommitConfigEdits(home, edits); err != nil {
		t.Fatal(err)
	}
}
func TestConfigStaleSnapshotsAndNewIncludePreventAllWrites(t *testing.T) {
	for _, kind := range []string{"content", "new-include", "same-bytes-replacement", "mode"} {
		t.Run(kind, func(t *testing.T) {
			home, path := configFixture(t, "Include parts/*.conf\nHost old\n  HostName 192.0.2.1\n")
			dir := filepath.Join(home, ".ssh", "parts")
			os.Mkdir(dir, 0700)
			inc := filepath.Join(dir, "one.conf")
			os.WriteFile(inc, []byte("Host safe\n  User bob\n"), 0600)
			defer os.Chmod(inc, 0600)
			edits, err := PlanAliasRemoval(home, "old")
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "content":
				os.WriteFile(inc, []byte("Host changed\n"), 0600)
			case "new-include":
				os.WriteFile(filepath.Join(dir, "new.conf"), []byte("Host new\n"), 0600)
			case "same-bytes-replacement":
				os.Remove(inc)
				os.WriteFile(inc, []byte("Host safe\n  User bob\n"), 0600)
			case "mode":
				os.Chmod(inc, 0400)
			}
			if _, err = CommitConfigEdits(home, edits); err == nil {
				t.Fatal("accepted stale plan")
			}
			got, _ := os.ReadFile(path)
			if string(got) != "Include parts/*.conf\nHost old\n  HostName 192.0.2.1\n" {
				t.Fatal("partially committed")
			}
		})
	}
}
func TestConfigRefusesAmbiguousScopesAndCycles(t *testing.T) {
	for _, body := range []string{"Host old !blocked\n User a\n", "Host old\n Include extra\n", "Match all\n Include extra\nHost old\n User a\n", "Host old\n User a\n# BEGIN KEYDESK IMPORT old bad\n", "Include config\nHost old\n User a\n"} {
		t.Run(body, func(t *testing.T) {
			home, _ := configFixture(t, body)
			if _, err := PlanAliasRemoval(home, "old"); err == nil {
				t.Fatal("accepted ambiguous config")
			}
		})
	}
}
func TestConfigUnchangedSnapshotNotBackedUp(t *testing.T) {
	home, path := configFixture(t, "Include parts.conf\nHost next\n User b\n")
	inc := filepath.Join(home, ".ssh", "parts.conf")
	os.WriteFile(inc, []byte("Host old\n User a\n"), 0600)
	edits, err := PlanAliasRemoval(home, "old")
	if err != nil {
		t.Fatal(err)
	}
	backups, err := CommitConfigEdits(home, edits)
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 1 || !strings.HasPrefix(backups[0], filepath.Join(home, ".ssh", "keydesk", "config-backups")+string(filepath.Separator)) {
		t.Fatalf("backups=%v main=%s", backups, path)
	}
}
func TestConfigRemovalOpenSSHPreservesUnrelatedResolution(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("OpenSSH unavailable")
	}
	home, path := configFixture(t, "Host old keep\n HostName 192.0.2.9\n User testuser\n Port 2202\nHost next\n HostName 192.0.2.10\nHost *\n ServerAliveInterval 14\n")
	run := func(alias string) []byte {
		t.Helper()
		out, err := exec.Command("ssh", "-G", "-F", path, alias).Output()
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	keep, next := run("keep"), run("next")
	edits, err := PlanAliasRemoval(home, "old")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = CommitConfigEdits(home, edits); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keep, run("keep")) || !bytes.Equal(next, run("next")) {
		t.Fatal("unrelated OpenSSH resolution changed")
	}
	if bytes.Contains(run("old"), []byte("hostname 192.0.2.9")) {
		t.Fatal("old alias still resolves to removed profile")
	}
}
func TestConfigRejectsMarkerWithGlobalPreambleInside(t *testing.T) {
	home, _ := configFixture(t, "# BEGIN KEYDESK CONNECTION old\n User global\nHost old\n HostName 192.0.2.1\n# END KEYDESK CONNECTION old\n")
	if _, err := PlanAliasRemoval(home, "old"); err == nil {
		t.Fatal("accepted marker that would delete global directives")
	}
}
func TestConfigRemovalMarkerWithBlankBeforeHost(t *testing.T) {
	home, path := configFixture(t, "# preamble\n# BEGIN KEYDESK CONNECTION old\n\nHost old\n HostName 192.0.2.1\n# END KEYDESK CONNECTION old\nHost keep\n User b\n")
	edits, err := PlanAliasRemoval(home, "old")
	if err != nil {
		t.Fatal(err)
	}
	if got := configAfter(t, edits, path); got != "# preamble\nHost keep\n User b\n" {
		t.Fatalf("orphan marker: %q", got)
	}
}
func TestConfigRefusesSymlinkTargetAndParent(t *testing.T) {
	for _, parent := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "parent"}[parent], func(t *testing.T) {
			home, path := configFixture(t, "Host old\n User a\n")
			other := t.TempDir()
			if parent {
				os.Remove(path)
				os.Remove(filepath.Dir(path))
				if err := os.WriteFile(filepath.Join(other, "config"), []byte("Host old\n User a\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, filepath.Dir(path)); err != nil {
					t.Skip(err)
				}
			} else {
				dest := filepath.Join(other, "config")
				os.Rename(path, dest)
				if err := os.Symlink(dest, path); err != nil {
					t.Skip(err)
				}
			}
			if _, err := PlanAliasRemoval(home, "old"); err == nil {
				t.Fatal("accepted symlink path")
			}
		})
	}
}
func TestConfigCommitHonorsLockAndRejectsTamperedSnapshots(t *testing.T) {
	for _, kind := range []string{"lock", "before", "path", "missing"} {
		t.Run(kind, func(t *testing.T) {
			home, path := configFixture(t, "Host old\n User a\n")
			edits, err := PlanAliasRemoval(home, "old")
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "lock":
				os.Mkdir(filepath.Join(home, ".ssh", ".keydesk-config.lock"), 0700)
			case "before":
				edits[0].Before = []byte("other")
			case "path":
				edits[0].Path = filepath.Join(home, "unrelated")
			case "missing":
				edits = nil
			}
			if _, err := CommitConfigEdits(home, edits); err == nil {
				t.Fatal("unsafe commit accepted")
			}
			got, _ := os.ReadFile(path)
			if string(got) != "Host old\n User a\n" {
				t.Fatal("config changed")
			}
		})
	}
}
func TestConfigCommitRollsBackEarlierFileOnWriteFailure(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows read-only rename failure")
	}
	home, path := configFixture(t, "Include part.conf\nHost old\n User a\n")
	inc := filepath.Join(home, ".ssh", "part.conf")
	before := []byte("Host old\n User b\nHost *\n")
	if err := os.WriteFile(inc, before, 0400); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(inc, 0600)
	edits, err := PlanAliasRemoval(home, "old")
	if err != nil {
		t.Fatal(err)
	}
	backups, err := CommitConfigEdits(home, edits)
	if err == nil {
		t.Fatal("expected read-only target write failure")
	}
	if len(backups) != 2 {
		t.Fatalf("backup count=%d", len(backups))
	}
	got, _ := os.ReadFile(path)
	if string(got) != "Include part.conf\nHost old\n User a\n" {
		t.Fatalf("main not rolled back: %q", got)
	}
	got, _ = os.ReadFile(inc)
	if !bytes.Equal(got, before) {
		t.Fatal("read-only include changed")
	}
}
func TestConfigCommitKeepsBackupsOutsideBroadInclude(t *testing.T) {
	home, path := configFixture(t, "Include parts/*\nHost next\n User b\n")
	dir := filepath.Join(home, ".ssh", "parts")
	os.Mkdir(dir, 0700)
	inc := filepath.Join(dir, "one")
	os.WriteFile(inc, []byte("Host old\n User a\n"), 0600)
	edits, err := PlanAliasRemoval(home, "old")
	if err != nil {
		t.Fatal(err)
	}
	backups, err := CommitConfigEdits(home, edits)
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 1 {
		t.Fatalf("backups=%v", backups)
	}
	saved, _ := os.ReadFile(backups[0])
	if string(saved) != "Host old\n User a\n" {
		t.Fatal("missing exact backup")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatal("backup entered included directory")
	}
	got, _ := os.ReadFile(path)
	if string(got) != "Include parts/*\nHost next\n User b\n" {
		t.Fatal("changed main")
	}
}
func TestConfigCommitRefusesSymlinkBackupDirectory(t *testing.T) {
	home, path := configFixture(t, "Host old\n User a\n")
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(home, ".ssh", "keydesk")); err != nil {
		t.Skip(err)
	}
	edits, err := PlanAliasRemoval(home, "old")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = CommitConfigEdits(home, edits); err == nil {
		t.Fatal("wrote backups through symlink")
	}
	got, _ := os.ReadFile(path)
	if string(got) != "Host old\n User a\n" {
		t.Fatal("changed config")
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Fatal("wrote outside backup root")
	}
}
func TestConfigRefusesMalformedOptionSeparator(t *testing.T) {
	for _, header := range []string{"=Host old", "Host==old"} {
		t.Run(header, func(t *testing.T) {
			home, _ := configFixture(t, header+"\n User a\n")
			if _, err := PlanAliasRemoval(home, "old"); err == nil {
				t.Fatal("accepted malformed Host separator")
			}
		})
	}
}
func TestConfigRefusesIncompleteKeydeskMarker(t *testing.T) {
	home, _ := configFixture(t, "# BEGIN KEYDESK CONNECTION\nHost old\n User a\n")
	if _, err := PlanAliasRemoval(home, "old"); err == nil {
		t.Fatal("accepted incomplete marker")
	}
}
func TestConfigPreservesQuotedHeaderAndEquals(t *testing.T) {
	home, path := configFixture(t, "Host = \"old\" \"keep\" # note\r\n User a\r\n")
	edits, err := PlanAliasRemoval(home, "old")
	if err != nil {
		t.Fatal(err)
	}
	if got := configAfter(t, edits, path); got != "Host = \"keep\" # note\r\n User a\r\n" {
		t.Fatalf("unexpected header rewrite: %q", got)
	}
}
func TestConfigRemovalOpenSSHIncludeAndMatch(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("OpenSSH unavailable")
	}
	home, path := configFixture(t, "")
	inc := filepath.Join(home, ".ssh", "part.conf")
	if runtime.GOOS == "windows" {
		u, err := user.Current()
		if err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("icacls.exe", filepath.Dir(path), "/inheritance:r", "/grant:r", "*"+u.Uid+":(OI)(CI)(F)").CombinedOutput()
		if err != nil {
			t.Fatalf("isolated SSH directory ACL: %v %s", err, out)
		}
	}
	body := "# BEGIN KEYDESK IMPORT old keyid\nHost old\n HostName 192.0.2.1\n User olduser\n# END KEYDESK IMPORT old\nHost *\n ServerAliveInterval 17\n"
	os.WriteFile(inc, []byte(body), 0600)
	main := "Include \"" + filepath.ToSlash(inc) + "\"\nMatch host keep\n HostName 192.0.2.2\n User keeper\nHost next\n HostName 192.0.2.3\n"
	os.WriteFile(path, []byte(main), 0600)
	run := func(alias string) []byte {
		t.Helper()
		out, err := exec.Command("ssh", "-G", "-F", path, alias).Output()
		if err != nil {
			if e, ok := err.(*exec.ExitError); ok {
				t.Fatalf("ssh -G: %v: %s", err, e.Stderr)
			}
			t.Fatal(err)
		}
		return out
	}
	keep, next := run("keep"), run("next")
	edits, err := PlanAliasRemoval(home, "old")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = CommitConfigEdits(home, edits); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keep, run("keep")) || !bytes.Equal(next, run("next")) {
		t.Fatal("unrelated Include/Match resolution changed")
	}
	if bytes.Contains(run("old"), []byte("hostname 192.0.2.1")) {
		t.Fatal("old include profile remains")
	}
}
func TestConfigCommitPreservesIncludedFileACL(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows DACL preservation")
	}
	home, path := configFixture(t, "")
	inc := filepath.Join(home, ".ssh", "part.conf")
	if err := os.WriteFile(inc, []byte("Host old keep\n HostName 192.0.2.1\n User keeper\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := securePrivateFile(inc); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("Include \""+filepath.ToSlash(inc)+"\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	run := func() []byte {
		t.Helper()
		out, err := exec.Command("ssh", "-G", "-F", path, "keep").Output()
		if err != nil {
			if e, ok := err.(*exec.ExitError); ok {
				t.Fatalf("ssh -G: %v %s", err, e.Stderr)
			}
			t.Fatal(err)
		}
		return out
	}
	before := run()
	edits, err := PlanAliasRemoval(home, "old")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = CommitConfigEdits(home, edits); err != nil {
		t.Fatal(err)
	}
	if after := run(); !bytes.Equal(before, after) {
		t.Fatal("included profile resolution changed after replacement")
	}
}
