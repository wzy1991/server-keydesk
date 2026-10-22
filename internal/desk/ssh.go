package desk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type HostInfo struct {
	Fingerprint string `json:"fingerprint"`
	Algorithm   string `json:"algorithm"`
	Known       bool   `json:"known"`
}

func hostAddress(t Target) string { return net.JoinHostPort(t.Host, fmt.Sprint(t.Port)) }
func knownCallback(home string) (ssh.HostKeyCallback, error) {
	path := filepath.Join(home, ".ssh", "known_hosts")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return func(string, net.Addr, ssh.PublicKey) error { return &knownhosts.KeyError{} }, nil
	}
	return knownhosts.New(path)
}

func HostCallback(home string, t Target, expected string, trust bool) ssh.HostKeyCallback {
	return func(addr string, remote net.Addr, key ssh.PublicKey) error {
		actual := ssh.FingerprintSHA256(key)
		if expected != "" && expected != actual {
			return errors.New("服务器指纹与刚才检查的结果不一致，已停止连接")
		}
		cb, err := knownCallback(home)
		if err != nil {
			return err
		}
		err = cb(addr, remote, key)
		if err == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) || len(keyErr.Want) > 0 {
			return fmt.Errorf("服务器主机密钥已变化或被撤销，请核实后在 OpenSSH 中处理；不会自动覆盖: %w", err)
		}
		if !trust || expected == "" {
			return fmt.Errorf("未知服务器，请核对并确认主机指纹 %s", actual)
		}
		dir := filepath.Join(home, ".ssh")
		if err = os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		f, err := os.OpenFile(filepath.Join(dir, "known_hosts"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.WriteString("\n" + knownhosts.Line([]string{knownhosts.Normalize(hostAddress(t))}, key) + "\n")
		return err
	}
}

func connect(ctx context.Context, t Target, auth []ssh.AuthMethod, cb ssh.HostKeyCallback) (*ssh.Client, error) {
	conn, err := (&net.Dialer{Timeout: 8 * time.Second}).DialContext(ctx, "tcp", hostAddress(t))
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(25 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	c, ch, req, err := ssh.NewClientConn(conn, hostAddress(t), &ssh.ClientConfig{User: t.User, Auth: auth, HostKeyCallback: cb, Timeout: 8 * time.Second})
	if err != nil {
		stop()
		conn.Close()
		return nil, err
	}
	// Cancellation callback is removed by the operation's context cancel.
	return ssh.NewClient(c, ch, req), nil
}

func Inspect(ctx context.Context, home string, t Target) (HostInfo, error) {
	if err := t.Validate(); err != nil {
		return HostInfo{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cb, err := knownCallback(home)
	if err != nil {
		return HostInfo{}, err
	}
	info := HostInfo{}
	observed := false
	var trustErr error
	sentinel := errors.New("fingerprint inspected")
	_, err = connect(ctx, t, nil, func(addr string, remote net.Addr, key ssh.PublicKey) error {
		e := cb(addr, remote, key)
		if e != nil {
			var ke *knownhosts.KeyError
			if !errors.As(e, &ke) || len(ke.Want) > 0 {
				trustErr = fmt.Errorf("服务器主机密钥已变化或被撤销: %w", e)
				return trustErr
			}
		}
		info = HostInfo{Fingerprint: ssh.FingerprintSHA256(key), Algorithm: key.Type(), Known: e == nil}
		observed = true
		return sentinel
	})
	if trustErr != nil {
		return HostInfo{}, trustErr
	}
	if !observed {
		return HostInfo{}, fmt.Errorf("读取服务器指纹失败: %w", err)
	}
	return info, nil
}

func InstallScript(pub []byte) string {
	// Only the key type and key blob go into the fixed script, not user inputs.
	fields := strings.Fields(string(pub))
	if len(fields) < 2 {
		return "exit 2\n"
	}
	return `set -eu
umask 077
cd "$HOME"
[ ! -L .ssh ] || { echo 'Refusing symlink .ssh' >&2; exit 3; }
mkdir -p .ssh
chmod 700 .ssh
[ ! -L .ssh/authorized_keys ] || { echo 'Refusing symlink authorized_keys' >&2; exit 3; }
mkdir .ssh/.keydesk-install.lock || { echo 'Another key installation is running' >&2; exit 4; }
trap 'rmdir .ssh/.keydesk-install.lock' 0
touch .ssh/authorized_keys
chmod 600 .ssh/authorized_keys
key='` + fields[0] + ` ` + fields[1] + ` server-keydesk'
blob='` + fields[1] + `'
if awk -v blob="$blob" '
/^[ \t]*#/ { next }
{
  n=0; quoted=0; escaped=0; token=""
  for (i=1;i<=length($0);i++) {
    c=substr($0,i,1)
    if (escaped) { token=token c; escaped=0; continue }
    if (c=="\\" && quoted) { escaped=1; token=token c; continue }
    if (c=="\"") { quoted=!quoted; token=token c; continue }
    if ((c==" " || c=="\t") && !quoted) {
      if (length(token)) { word[++n]=token; token="" }
    } else { token=token c }
  }
  if (length(token)) word[++n]=token
  if ((n>=2 && word[1] ~ /^(ssh-|ecdsa-|sk-)/ && word[2]==blob) ||
      (n>=3 && word[2] ~ /^(ssh-|ecdsa-|sk-)/ && word[3]==blob)) found=1
}
END { exit !found }
' .ssh/authorized_keys; then
  printf 'already_present\n'
else
  if [ -s .ssh/authorized_keys ]; then
    cp -p .ssh/authorized_keys ".ssh/authorized_keys.keydesk-$(date +%Y%m%d%H%M%S).bak"
    printf '\n' >> .ssh/authorized_keys
  fi
  printf '%s\n' "$key" >> .ssh/authorized_keys
  printf 'installed\n'
fi
`
}

func Bootstrap(ctx context.Context, home string, t Target, password, keyPath string, pub []byte, expected string, trust bool) (string, error) {
	if err := t.Validate(); err != nil {
		return "", err
	}
	if expected == "" {
		return "", errors.New("请先检查服务器指纹")
	}
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	callback := HostCallback(home, t, expected, trust)
	return bootstrapWithCallback(ctx, t, password, keyPath, pub, callback)
}

func bootstrapWithCallback(ctx context.Context, t Target, password, keyPath string, pub []byte, callback ssh.HostKeyCallback) (string, error) {
	if err := t.Validate(); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	client, err := connect(ctx, t, []ssh.AuthMethod{ssh.Password(password), ssh.KeyboardInteractive(func(_, _ string, questions []string, echo []bool) ([]string, error) {
		if len(questions) != 1 {
			return nil, errors.New("服务器需要额外认证步骤，暂不支持")
		}
		return []string{password}, nil
	})}, callback)
	if err != nil {
		return "", fmt.Errorf("密码登录失败: %w", err)
	}
	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return "", err
	}
	session.Stdin = strings.NewReader(InstallScript(pub))
	var output bytes.Buffer
	session.Stdout = &output
	session.Stderr = &output
	err = session.Run("sh -s")
	session.Close()
	client.Close()
	if err != nil {
		return "", fmt.Errorf("安装公钥失败: %w；%s", err, output.String())
	}
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return "", err
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return "", err
	}
	verify, err := connect(ctx, t, []ssh.AuthMethod{ssh.PublicKeys(signer)}, callback)
	if err != nil {
		return "", fmt.Errorf("公钥已写入，但密钥登录未通过验证（检查 sshd 配置或目录权限）: %w", err)
	}
	defer verify.Close()
	vs, err := verify.NewSession()
	if err != nil {
		return "", err
	}
	defer vs.Close()
	out, err := vs.Output("printf '__KEYDESK_OK__'")
	if err != nil || !strings.Contains(string(out), "__KEYDESK_OK__") {
		return "", errors.New("公钥已写入，但远程命令验证失败")
	}
	return strings.TrimSpace(output.String()), nil
}
