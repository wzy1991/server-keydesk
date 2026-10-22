//go:build !windows

package desk

func preserveReplacementACL(original, replacement string) error { return nil }
