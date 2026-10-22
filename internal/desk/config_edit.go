package desk

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
)

// ConfigEdit is an internal, exact-byte snapshot; never send it to the frontend.
type ConfigEdit struct {
	Path   string `json:"-"`
	Before []byte `json:"-"`
	After  []byte `json:"-"`
	plan   *configEditPlan
}

type configFileSnapshot struct {
	path    string
	data    []byte
	info    os.FileInfo
	parents map[string]os.FileInfo
}
type configGlobSnapshot struct {
	pattern string
	paths   []string
}
type configEditPlan struct {
	home  string
	files []configFileSnapshot
	globs []configGlobSnapshot
}
type configLine struct {
	raw   string
	words []string
	spans [][2]int
}
type configScope struct {
	unconditional bool
	target        bool
	origin        string
}

// configLex records token byte positions so deleting one alias does not rewrite
// quotes, indentation, comments or the original line ending.
func configLex(raw string) (configLine, error) {
	line := configLine{raw: raw}
	text := strings.TrimRight(raw, "\r\n")
	separator := false
	for i := 0; i < len(text); {
		if text[i] == ' ' || text[i] == '\t' {
			i++
			continue
		}
		if text[i] == '=' && len(line.words) <= 1 {
			if len(line.words) != 1 || separator {
				return line, errors.New("SSH 配置包含无效等号分隔符")
			}
			separator = true
			i++
			continue
		}
		if text[i] == '#' {
			break
		}
		start := i
		var token strings.Builder
		var quote byte
		for i < len(text) {
			c := text[i]
			if quote != 0 {
				if c == quote {
					quote = 0
				} else {
					token.WriteByte(c)
				}
				i++
				continue
			}
			if c == '\'' || c == '"' {
				quote = c
				i++
				continue
			}
			if c == ' ' || c == '\t' || c == '#' {
				break
			}
			// Only the first token uses '=' as an option separator.
			if c == '=' && len(line.words) == 0 {
				break
			}
			token.WriteByte(c)
			i++
		}
		if quote != 0 {
			return line, errors.New("SSH 配置包含未闭合引号")
		}
		if token.Len() == 0 {
			return line, errors.New("SSH 配置包含空指令或参数")
		}
		line.words = append(line.words, token.String())
		line.spans = append(line.spans, [2]int{start, i})
	}
	return line, nil
}
func configLines(data []byte) ([]configLine, error) {
	if bytes.IndexByte(data, 0) >= 0 {
		return nil, errors.New("SSH 配置包含 NUL")
	}
	parts := strings.SplitAfter(string(data), "\n")
	var lines []configLine
	for _, raw := range parts {
		if raw == "" {
			continue
		}
		line, err := configLex(raw)
		if err != nil {
			return nil, err
		}
		lines = append(lines, line)
	}
	return lines, nil
}
func configKey(line configLine) string {
	if len(line.words) == 0 {
		return ""
	}
	return strings.ToLower(line.words[0])
}
func configMarker(raw string) (kind, side, alias string) {
	f := strings.Fields(strings.TrimSpace(raw))
	if len(f) >= 5 && f[0] == "#" && (f[1] == "BEGIN" || f[1] == "END") && f[2] == "KEYDESK" && (f[3] == "IMPORT" || f[3] == "CONNECTION") {
		return f[3], f[1], f[4]
	}
	return "", "", ""
}

// Lstat every component, including junctions on Windows. FileAttributes is
// inspected without a platform-specific dependency, allowing native Go tests.
func configSafePath(path string) (os.FileInfo, map[string]os.FileInfo, error) {
	return configSafeNode(path, false)
}
func configSafeNode(path string, directory bool) (os.FileInfo, map[string]os.FileInfo, error) {
	var info os.FileInfo
	parents := map[string]os.FileInfo{}
	for p := path; ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err != nil {
			return nil, nil, err
		}
		reparse := fi.Mode()&os.ModeSymlink != 0
		sys := reflect.ValueOf(fi.Sys())
		if sys.IsValid() && sys.Kind() == reflect.Ptr {
			sys = sys.Elem()
		}
		if sys.IsValid() && sys.Kind() == reflect.Struct {
			attrs := sys.FieldByName("FileAttributes")
			if attrs.IsValid() && attrs.CanUint() && attrs.Uint()&0x400 != 0 {
				reparse = true
			}
		}
		if reparse {
			return nil, nil, fmt.Errorf("拒绝修改符号链接或重解析路径: %s", p)
		}
		if p == path {
			if directory && !fi.IsDir() || !directory && !fi.Mode().IsRegular() {
				return nil, nil, fmt.Errorf("配置路径类型不安全: %s", p)
			}
			info = fi
		} else {
			if !fi.IsDir() {
				return nil, nil, fmt.Errorf("配置父路径不是目录: %s", p)
			}
			parents[p] = fi
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return info, parents, nil
}
func configEnsureDir(path string) error {
	if _, err := os.Lstat(path); err == nil {
		_, _, err = configSafeNode(path, true)
		return err
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := configEnsureDir(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	_, _, err := configSafeNode(path, true)
	return err
}

func PlanAliasRemoval(home, alias string) ([]ConfigEdit, error) {
	if !aliasRE.MatchString(alias) {
		return nil, errors.New("无效 SSH 别名")
	}
	home, err := filepath.Abs(home)
	if err != nil {
		return nil, err
	}
	home = filepath.Clean(home)
	plan := &configEditPlan{home: home}
	parsed := map[string][]configLine{}
	seen := map[string]bool{}
	active := map[string]bool{}
	found := false
	var visit func(string, int, configScope) (configScope, error)
	visit = func(path string, depth int, scope configScope) (configScope, error) {
		path, err = filepath.Abs(path)
		if err != nil {
			return scope, err
		}
		path = filepath.Clean(path)
		key := strings.ToLower(path)
		if active[key] {
			return scope, fmt.Errorf("Include 循环: %s", path)
		}
		if seen[key] {
			return scope, fmt.Errorf("重复 Include 文件，无法安全修改: %s", path)
		}
		if depth > 16 || len(plan.files) >= 128 {
			return scope, errors.New("Include 超过安全深度或文件数量限制")
		}
		info, parents, e := configSafePath(path)
		if e != nil {
			return scope, e
		}
		if info.Size() > 4*1024*1024 {
			return scope, errors.New("SSH 配置文件过大")
		}
		data, e := os.ReadFile(path)
		if e != nil {
			return scope, e
		}
		lines, e := configLines(data)
		if e != nil {
			return scope, fmt.Errorf("%s: %w", path, e)
		}
		plan.files = append(plan.files, configFileSnapshot{path, data, info, parents})
		parsed[path] = lines
		seen[key] = true
		active[key] = true
		defer delete(active, key)
		// A marker is removable only when it encloses one Host section. Malformed,
		// nested or cross-section markers require manual editing.
		markerStart := -1
		markerKind := ""
		markerAlias := ""
		markerHosts := 0
		for i, line := range lines {
			kind, side, ma := configMarker(line.raw)
			markerText := strings.TrimSpace(line.raw)
			if side == "" && (strings.HasPrefix(markerText, "# BEGIN KEYDESK") || strings.HasPrefix(markerText, "# END KEYDESK")) {
				return scope, errors.New("不完整或不支持的 Keydesk 标记")
			}
			if side == "BEGIN" {
				if markerStart >= 0 {
					return scope, errors.New("嵌套 Keydesk 标记")
				}
				markerStart = i
				markerKind = kind
				markerAlias = ma
				markerHosts = 0
			}
			if side == "END" {
				if markerStart < 0 || kind != markerKind || ma != markerAlias || markerHosts != 1 {
					return scope, errors.New("Keydesk 标记不匹配或跨越多个配置节")
				}
				markerStart = -1
			}
			if markerStart >= 0 && markerHosts == 0 && len(line.words) > 0 && configKey(line) != "host" {
				return scope, errors.New("Keydesk 标记内的 Host 之前包含全局配置")
			}
			switch configKey(line) {
			case "host", "match":
				if markerStart >= 0 {
					if configKey(line) != "host" {
						return scope, errors.New("Keydesk 标记跨越 Match")
					}
					markerHosts++
					if len(line.words) != 2 || !strings.EqualFold(line.words[1], markerAlias) {
						return scope, errors.New("Keydesk 标记与 Host 不匹配")
					}
				}
				if len(line.words) < 2 {
					return scope, errors.New("Host/Match 缺少参数")
				}
				scope = configScope{origin: path}
				if configKey(line) == "host" {
					scope.unconditional = len(line.words) == 2 && line.words[1] == "*"
					for _, name := range line.words[1:] {
						if strings.EqualFold(name, alias) {
							scope.target = true
							found = true
						}
					}
					if scope.target {
						for _, name := range line.words[1:] {
							if strings.ContainsAny(name, "*?![]=") || strings.HasPrefix(name, "-") {
								return scope, errors.New("目标 Host 混合通配符或排除模式，请手动修改")
							}
						}
					}
				}
			case "include":
				if !scope.unconditional {
					return scope, errors.New("条件 Host/Match 内的 Include 无法安全自动修改")
				}
				if len(line.words) < 2 {
					return scope, errors.New("Include 缺少路径")
				}
				for _, pattern := range line.words[1:] {
					if strings.ContainsAny(pattern, "%$\x00") || strings.HasPrefix(pattern, "~") && !strings.HasPrefix(pattern, "~/") && !strings.HasPrefix(pattern, "~\\") {
						return scope, errors.New("Include 包含不支持的路径展开")
					}
					if strings.HasPrefix(pattern, "~/") || strings.HasPrefix(pattern, "~\\") {
						pattern = filepath.Join(home, pattern[2:])
					} else if !filepath.IsAbs(pattern) {
						pattern = filepath.Join(home, ".ssh", pattern)
					}
					pattern = filepath.Clean(pattern)
					matches, e := filepath.Glob(pattern)
					if e != nil {
						return scope, e
					}
					sort.Strings(matches)
					plan.globs = append(plan.globs, configGlobSnapshot{pattern, append([]string(nil), matches...)})
					for _, match := range matches {
						scope, e = visit(match, depth+1, scope)
						if e != nil {
							return scope, e
						}
					}
				}
			default:
				if len(line.words) > 0 && scope.target && scope.origin != path {
					return scope, errors.New("目标 Host 的配置跨越 Include 文件边界，请手动修改")
				}
			}
		}
		if markerStart >= 0 {
			return scope, errors.New("Keydesk 标记缺少 END")
		}
		return scope, nil
	}
	main := filepath.Join(home, ".ssh", "config")
	if _, err = visit(main, 0, configScope{unconditional: true}); err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("找不到 SSH 别名 %q", alias)
	}
	edits := make([]ConfigEdit, 0, len(plan.files))
	for _, file := range plan.files {
		after, e := configRemoveAlias(parsed[file.path], alias)
		if e != nil {
			return nil, e
		}
		edits = append(edits, ConfigEdit{Path: file.path, Before: append([]byte(nil), file.data...), After: after, plan: plan})
	}
	return edits, nil
}

func configRemoveAlias(lines []configLine, alias string) ([]byte, error) {
	removed := make([]bool, len(lines))
	replacement := map[int]string{}
	for i, line := range lines {
		if configKey(line) != "host" {
			continue
		}
		var targets []int
		for n, name := range line.words[1:] {
			if strings.EqualFold(name, alias) {
				targets = append(targets, n+1)
			}
		}
		if len(targets) == 0 {
			continue
		}
		if len(targets) < len(line.words)-1 {
			raw := line.raw
			for n := len(targets) - 1; n >= 0; n-- {
				span := line.spans[targets[n]]
				start, end := span[0], span[1]
				for end < len(raw) && (raw[end] == ' ' || raw[end] == '\t') {
					end++
				}
				if end == span[1] {
					for start > 0 && (raw[start-1] == ' ' || raw[start-1] == '\t') {
						start--
					}
				}
				raw = raw[:start] + raw[end:]
			}
			replacement[i] = raw
			continue
		}
		start, end := i, len(lines)
		for j := i + 1; j < len(lines); j++ {
			if k := configKey(lines[j]); k == "host" || k == "match" {
				end = j
				break
			}
		}
		// Comments immediately before the next section belong to that section;
		// preserve them, while including this section's own explicit END marker.
		for end > i+1 && len(lines[end-1].words) == 0 {
			_, side, _ := configMarker(lines[end-1].raw)
			if side == "END" {
				break
			}
			end--
		}
		for j := i - 1; j >= 0 && len(lines[j].words) == 0; j-- {
			raw := strings.TrimSpace(lines[j].raw)
			_, side, ma := configMarker(raw)
			if raw == "# Added by Server Keydesk" || side == "BEGIN" && strings.EqualFold(ma, alias) {
				start = j
				break
			}
			if side != "" {
				break
			}
		}
		for j := start; j < end; j++ {
			removed[j] = true
		}
	}
	var out bytes.Buffer
	for i, line := range lines {
		if removed[i] {
			continue
		}
		if raw, ok := replacement[i]; ok {
			out.WriteString(raw)
		} else {
			out.WriteString(line.raw)
		}
	}
	return out.Bytes(), nil
}

func CommitConfigEdits(home string, edits []ConfigEdit) ([]string, error) {
	if len(edits) == 0 || edits[0].plan == nil {
		return nil, errors.New("缺少配置修改计划")
	}
	plan := edits[0].plan
	home, err := filepath.Abs(home)
	if err != nil {
		return nil, err
	}
	if filepath.Clean(home) != plan.home {
		return nil, errors.New("配置计划与 home 不匹配")
	}
	if len(edits) != len(plan.files) {
		return nil, errors.New("配置计划缺少快照")
	}
	dir := filepath.Join(home, ".ssh")
	if _, _, err = configSafePath(filepath.Join(dir, "config")); err != nil {
		return nil, err
	}
	lock := filepath.Join(dir, ".keydesk-config.lock")
	if err = os.Mkdir(lock, 0700); err != nil {
		return nil, fmt.Errorf("另一进程正在修改 SSH 配置，或配置目录不可写: %w", err)
	}
	defer os.Remove(lock)
	for i, e := range edits {
		if e.plan != plan || e.Path != plan.files[i].path || !bytes.Equal(e.Before, plan.files[i].data) {
			return nil, errors.New("配置快照被替换或顺序不匹配")
		}
	}
	if err = configValidatePlan(plan); err != nil {
		return nil, err
	}
	var backups []string
	backupNames := map[int]string{}
	var nonce [8]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	backupRoot := filepath.Join(dir, "keydesk", "config-backups", time.Now().Format("20060102-150405.000000000")+"-"+hex.EncodeToString(nonce[:]))
	// A dedicated directory keeps broad Include conf.d/* from loading backups.
	// Check new directories as well: creating one inside an Include must not
	// change how the existing config is parsed.
	checkInclude := func(path string) error {
		for _, glob := range plan.globs {
			matched, matchErr := filepath.Match(glob.pattern, path)
			if matchErr != nil {
				return matchErr
			}
			if matched {
				return fmt.Errorf("备份路径会被 Include 读取，请先收窄 Include 模式: %s", glob.pattern)
			}
		}
		return nil
	}
	for i, e := range edits {
		if bytes.Equal(e.Before, e.After) {
			continue
		}
		name := filepath.Join(backupRoot, fmt.Sprintf("%03d-%s.bak", i, filepath.Base(e.Path)))
		if err = checkInclude(name); err != nil {
			return nil, err
		}
		backupNames[i] = name
	}
	if len(backupNames) > 0 {
		for p := backupRoot; p != dir; p = filepath.Dir(p) {
			if _, statErr := os.Lstat(p); os.IsNotExist(statErr) {
				if err = checkInclude(p); err != nil {
					return nil, err
				}
			} else if statErr != nil {
				return nil, statErr
			}
		}
		if err = configEnsureDir(filepath.Dir(backupRoot)); err != nil {
			return nil, err
		}
		if err = os.Mkdir(backupRoot, 0700); err != nil {
			return nil, err
		}
		if _, _, err = configSafeNode(backupRoot, true); err != nil {
			return nil, err
		}
	}
	for i, e := range edits {
		if bytes.Equal(e.Before, e.After) {
			continue
		}
		backup := backupNames[i]
		f, openErr := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if openErr != nil {
			return backups, openErr
		}
		if err = securePrivateFile(backup); err != nil {
			f.Close()
			os.Remove(backup)
			return backups, err
		}
		_, writeErr := f.Write(e.Before)
		if writeErr == nil {
			writeErr = f.Sync()
		}
		closeErr := f.Close()
		if writeErr != nil {
			return backups, writeErr
		}
		if closeErr != nil {
			return backups, closeErr
		}
		backups = append(backups, backup)
	}
	// Validate again after creating backups and immediately before each write.
	if err = configValidatePlan(plan); err != nil {
		return backups, err
	}
	var committed []int
	writtenInfo := map[int]os.FileInfo{}
	rollback := func(cause error) error {
		for n := len(committed) - 1; n >= 0; n-- {
			i := committed[n]
			e := edits[i]
			info, parents, pathErr := configSafePath(e.Path)
			current, readErr := os.ReadFile(e.Path)
			saved := writtenInfo[i]
			safe := pathErr == nil && readErr == nil && saved != nil && os.SameFile(info, saved) && info.Mode() == saved.Mode() && info.Size() == saved.Size() && info.ModTime().Equal(saved.ModTime()) && bytes.Equal(current, e.After)
			if safe {
				for p, fi := range plan.files[i].parents {
					if now := parents[p]; now == nil || !os.SameFile(fi, now) {
						safe = false
						break
					}
				}
			}
			if !safe {
				cause = errors.Join(cause, fmt.Errorf("未回滚并发修改的配置，请使用备份恢复: %s", e.Path))
				continue
			}
			if e2 := atomicWrite(e.Path, e.Before, plan.files[i].info.Mode().Perm()); e2 != nil {
				cause = errors.Join(cause, fmt.Errorf("回滚失败 %s: %w", e.Path, e2))
			}
		}
		return cause
	}
	for i, e := range edits {
		if bytes.Equal(e.Before, e.After) {
			continue
		}
		if err = configValidateUnwritten(plan, committed); err != nil {
			return backups, rollback(err)
		}
		if err = atomicWrite(e.Path, e.After, plan.files[i].info.Mode().Perm()); err != nil {
			return backups, rollback(err)
		}
		committed = append(committed, i)
		info, _, statErr := configSafePath(e.Path)
		if statErr != nil {
			return backups, rollback(statErr)
		}
		writtenInfo[i] = info
		current, readErr := os.ReadFile(e.Path)
		if readErr != nil {
			return backups, rollback(readErr)
		}
		if !bytes.Equal(current, e.After) {
			return backups, rollback(fmt.Errorf("写入后配置被其他进程更改: %s", e.Path))
		}
	}
	return backups, nil
}

func configValidatePlan(plan *configEditPlan) error { return configValidateUnwritten(plan, nil) }
func configValidateUnwritten(plan *configEditPlan, committed []int) error {
	written := map[int]bool{}
	for _, i := range committed {
		written[i] = true
	}
	for i, file := range plan.files {
		if written[i] {
			continue
		}
		info, parents, err := configSafePath(file.path)
		if err != nil {
			return err
		}
		if !os.SameFile(info, file.info) || info.Mode() != file.info.Mode() || info.Size() != file.info.Size() || !info.ModTime().Equal(file.info.ModTime()) {
			return fmt.Errorf("配置已更改，请重新预览: %s", file.path)
		}
		for p, fi := range file.parents {
			if now := parents[p]; now == nil || !os.SameFile(fi, now) {
				return fmt.Errorf("配置父目录已更改: %s", p)
			}
		}
		data, err := os.ReadFile(file.path)
		if err != nil {
			return err
		}
		if !bytes.Equal(data, file.data) {
			return fmt.Errorf("配置已更改，请重新预览: %s", file.path)
		}
	}
	for _, glob := range plan.globs {
		paths, err := filepath.Glob(glob.pattern)
		if err != nil {
			return err
		}
		sort.Strings(paths)
		if len(paths) != len(glob.paths) {
			return fmt.Errorf("Include 文件列表已更改: %s", glob.pattern)
		}
		for i := range paths {
			if paths[i] != glob.paths[i] {
				return fmt.Errorf("Include 文件列表已更改: %s", glob.pattern)
			}
		}
	}
	return nil
}
