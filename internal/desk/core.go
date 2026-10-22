package desk

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Target struct {
	Alias string `json:"alias"`
	Host  string `json:"host"`
	Port  int    `json:"port"`
	User  string `json:"user"`
}

var aliasRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
var hostRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)
var userRE = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.@-]*\$?$`)

func (t Target) Validate() error {
	if !aliasRE.MatchString(t.Alias) {
		return errors.New("别名须为 1–64 位英文字母、数字、点、下划线或短横线，且以字母或数字开头")
	}
	if _, err := netip.ParseAddr(t.Host); err != nil && !hostRE.MatchString(t.Host) {
		return errors.New("请填写 IP 或域名，不含协议、空格或路径；IPv6 无需方括号")
	}
	if !userRE.MatchString(t.User) {
		return errors.New("请填写有效的 Linux 用户名")
	}
	if t.Port < 1 || t.Port > 65535 {
		return errors.New("端口必须在 1–65535 之间")
	}
	return nil
}

// configWords handles OpenSSH quotes, comments and whitespace without treating
// Windows backslashes as shell escapes.
func configWords(line string) []string {
	var out []string
	var b strings.Builder
	var quote rune
	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	for _, r := range line {
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
			continue
		}
		if r == '"' || r == '\'' {
			quote = r
			continue
		}
		if r == '#' {
			break
		}
		if r == ' ' || r == '\t' || r == '\r' {
			flush()
		} else {
			b.WriteRune(r)
		}
	}
	flush()
	return out
}

func Aliases(home string) ([]string, error) {
	seen := map[string]bool{}
	names := map[string]bool{}
	var visit func(string, int) error
	visit = func(path string, depth int) error {
		path = filepath.Clean(path)
		if seen[path] || depth > 16 {
			return nil
		}
		seen[path] = true
		f, err := os.Open(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 4096), 1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if i := strings.IndexAny(line, "= \t"); i >= 0 && line[i] == '=' {
				line = line[:i] + " " + line[i+1:]
			}
			w := configWords(line)
			if len(w) < 2 {
				continue
			}
			key := strings.ToLower(w[0])
			if w[1] == "=" {
				w = append(w[:1], w[2:]...)
			}
			if key == "host" {
				for _, name := range w[1:] {
					if !strings.ContainsAny(name, "*?![]") && !strings.HasPrefix(name, "-") {
						names[name] = true
					}
				}
			}
			if key == "include" {
				for _, pattern := range w[1:] {
					if strings.HasPrefix(pattern, "~/") {
						pattern = filepath.Join(home, pattern[2:])
					} else if !filepath.IsAbs(pattern) {
						pattern = filepath.Join(home, ".ssh", pattern)
					}
					matches, err := filepath.Glob(pattern)
					if err != nil {
						return fmt.Errorf("无效 Include: %w", err)
					}
					for _, match := range matches {
						if err := visit(match, depth+1); err != nil {
							return err
						}
					}
				}
			}
		}
		return scanner.Err()
	}
	if err := visit(filepath.Join(home, ".ssh", "config"), 0); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

func AliasAvailable(home, alias string) error {
	aliases, err := Aliases(home)
	if err != nil {
		return err
	}
	for _, a := range aliases {
		if strings.EqualFold(a, alias) {
			return fmt.Errorf("SSH 别名 %q 已存在，请选择新别名（已有服务器可在列表直接检测）", alias)
		}
	}
	return nil
}

// SaveAlias puts explicit values before catch-all defaults. Host * restores
// the global scope before the user's original bytes, which remain intact.
func SaveAlias(home string, t Target, key string) (string, error) {
	if err := t.Validate(); err != nil {
		return "", err
	}
	if strings.ContainsAny(key, "\r\n\"%\x00") {
		return "", errors.New("密钥路径包含 SSH 配置不支持的字符")
	}
	dir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	lock := filepath.Join(dir, ".keydesk-config.lock")
	if err := os.Mkdir(lock, 0700); err != nil {
		return "", fmt.Errorf("另一进程正在修改 SSH 配置，或配置目录不可写: %w", err)
	}
	defer os.Remove(lock)
	if err := AliasAvailable(home, t.Alias); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "config")
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if info, e := os.Lstat(path); e == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("SSH config 是符号链接，请手动管理该配置")
	}
	backup := ""
	if err == nil {
		backup = path + ".keydesk-" + time.Now().Format("20060102-150405.000000000") + ".bak"
		if err = os.WriteFile(backup, old, 0600); err != nil {
			return "", err
		}
	}
	stanza := fmt.Sprintf("\n# Added by Server Keydesk\nHost %s\n    HostName %s\n    User %s\n    Port %d\n    IdentityFile \"%s\"\n    IdentitiesOnly yes\n", t.Alias, strings.ReplaceAll(t.Host, "%", "%%"), t.User, t.Port, filepath.ToSlash(key))
	stanza += "\nHost *\n"
	data := append([]byte(stanza), old...)
	return backup, atomicWrite(path, data, 0600)
}

func Classify(output string) string {
	s := strings.ToLower(output)
	switch {
	case strings.Contains(s, "identification has changed"), strings.Contains(s, "offending"), strings.Contains(s, "revoked host key"):
		return "host_changed"
	case strings.Contains(s, "host key verification failed"), strings.Contains(s, "no ed25519 host key"), strings.Contains(s, "no ecdsa host key"), strings.Contains(s, "no rsa host key"):
		return "host_untrusted"
	case strings.Contains(s, "permission denied"), strings.Contains(s, "authentication failed"):
		return "auth_failed"
	case strings.Contains(s, "timed out"), strings.Contains(s, "connection refused"), strings.Contains(s, "could not resolve"), strings.Contains(s, "no route to host"), strings.Contains(s, "network is unreachable"):
		return "unreachable"
	default:
		return "error"
	}
}
