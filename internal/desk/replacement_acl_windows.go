package desk

import (
	"golang.org/x/sys/windows"
	"os"
)

func preserveReplacementACL(original, replacement string) error {
	sd, err := windows.GetNamedSecurityInfo(original, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	// Retain the effective ACL exactly, rather than inheriting a different ACL
	// from the directory that holds a new temporary file.
	return windows.SetNamedSecurityInfo(replacement, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
