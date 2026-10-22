package desk

import (
	"golang.org/x/sys/windows"
	"os/exec"
	"strings"
	"testing"
)

func TestPrivateKeyRepairRemovesExplicitEveryoneAccess(t *testing.T) {
	path, _, err := EnsureKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("icacls.exe", path, "/grant", "*S-1-1-0:(R)")
	hide(cmd)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if err := securePrivateFile(path); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sd.String(), ";;;WD)") || strings.Contains(sd.String(), ";;;S-1-1-0)") {
		t.Fatalf("Everyone still has private key access: %s", sd.String())
	}
}
