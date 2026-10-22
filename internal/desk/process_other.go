//go:build !windows

package desk

import (
	"os"
	"os/exec"
)

func hide(cmd *exec.Cmd)                  {}
func securePrivateFile(path string) error { return os.Chmod(path, 0600) }
