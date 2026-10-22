package desk

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/ssh"
	"os"
	"path/filepath"
)

func EnsureKey(home string) (string, []byte, error) {
	dir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", nil, err
	}
	path := filepath.Join(dir, "keydesk_ed25519")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		_, priv, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return "", nil, e
		}
		block, e := ssh.MarshalPrivateKey(priv, "server-keydesk")
		if e != nil {
			return "", nil, e
		}
		data = pem.EncodeToMemory(block)
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return "", nil, e
		}
		if e = securePrivateFile(path); e != nil {
			f.Close()
			os.Remove(path)
			return "", nil, e
		}
		_, e = f.Write(data)
		closeErr := f.Close()
		if e != nil {
			os.Remove(path)
			return "", nil, e
		}
		if closeErr != nil {
			return "", nil, closeErr
		}
	} else if err != nil {
		return "", nil, err
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return "", nil, fmt.Errorf("无法读取应用专用密钥（不会覆盖）: %w", err)
	}
	if err = securePrivateFile(path); err != nil {
		return "", nil, err
	}
	pub := append(ssh.MarshalAuthorizedKey(signer.PublicKey())[:len(ssh.MarshalAuthorizedKey(signer.PublicKey()))-1], []byte(" server-keydesk\n")...)
	if err = os.WriteFile(path+".pub", pub, 0644); err != nil {
		return "", nil, err
	}
	return path, pub, nil
}
