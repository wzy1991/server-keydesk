package desk

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Use the exact production compressed PowerShell command, actual receiver,
// real private key files and native OpenSSH against a local SSH protocol peer.
func TestTransferFullWindowsReceiverAndOpenSSHVerification(t *testing.T) {
	for _, inheritedAlias := range []bool{false, true} {
		t.Run(map[bool]string{false: "verified", true: "inherited host alias rejected"}[inheritedAlias], func(t *testing.T) {
			s, _ := transferFixture(t)
			home := filepath.Join(t.TempDir(), "Windows B home with spaces")
			if err := os.MkdirAll(home, 0700); err != nil {
				t.Fatal(err)
			}
			if inheritedAlias {
				dir := filepath.Join(home, ".ssh")
				os.MkdirAll(dir, 0700)
				os.WriteFile(filepath.Join(dir, "config"), []byte("Host *\n HostKeyAlias another-trusted-name\n"), 0600)
			}
			s.remoteRunner = func(ctx context.Context, alias, script string, input []byte) ([]byte, error) {
				ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
				defer cancel()
				command := powerShellCommand(script)
				const prefix = "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand "
				cmd := exec.CommandContext(ctx, filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", strings.TrimPrefix(command, prefix))
				hide(cmd)
				cmd.Env = append(os.Environ(), "USERPROFILE="+home)
				cmd.Stdin = bytes.NewReader(input)
				out, err := cmd.CombinedOutput()
				if err != nil {
					return nil, errors.New("isolated Windows receiver failed; output omitted")
				}
				return out, nil
			}
			plan, err := s.PrepareTransfer(context.Background(), TransferRequest{SourceAlias: "c", DestinationAlias: "b", RemoteAlias: "copied-c"})
			if err != nil {
				t.Fatal(err)
			}
			result, err := s.SendTransfer(context.Background(), plan.Token, true)
			if err != nil {
				t.Fatal(err)
			}
			if !result.OK {
				t.Fatal("receiver did not store profile")
			}
			if inheritedAlias {
				if result.State == "key_ready" {
					t.Fatal("reported saved alias working despite incompatible inherited HostKeyAlias")
				}
			} else if result.State != "key_ready" {
				cmd := exec.Command("ssh", "-F", filepath.Join(home, ".ssh", "config"), "-o", "BatchMode=yes", "--", "copied-c", "printf 'KEYDESK_C_READY\\n'")
				hide(cmd)
				out, _ := cmd.CombinedOutput()
				t.Fatalf("actual B to C verification failed: %s; isolated SSH diagnostic: %s", result.State, out)
			}
			if _, err := os.Stat(result.KeyPath); err != nil {
				t.Fatal("receipt points to incorrect imported private key path")
			}
		})
	}
}
