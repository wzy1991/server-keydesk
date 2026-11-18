package desk

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (s *Service) useExistingKey(ctx context.Context, r InstallRequest) (Server, error) {
	if r.Fingerprint == "" {
		return Server{}, errors.New("请先检查服务器指纹")
	}
	path := r.PrivateKeyPath
	if strings.HasPrefix(path, "~/") {
		path = filepath.Join(s.home, path[2:])
	}
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "\"\r\n\x00%$") {
		return Server{}, errors.New("请输入私钥绝对路径，路径不能包含引号、换行、% 或 $")
	}
	path = filepath.Clean(path)
	data, err := os.ReadFile(path)
	if err != nil {
		return Server{}, fmt.Errorf("读取私钥失败: %w", err)
	}
	var signer ssh.Signer
	if r.Passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(data, []byte(r.Passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey(data)
	}
	clear(data)
	if err != nil {
		return Server{}, errors.New("无法解析私钥，请检查文件格式和私钥口令")
	}
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	client, err := connect(ctx, r.Target, []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostCallback(s.home, r.Target, r.Fingerprint, r.Trust))
	if err != nil {
		return Server{}, fmt.Errorf("私钥登录失败: %w", err)
	}
	defer client.Close()
	if err := securePrivateFile(path); err != nil {
		return Server{}, fmt.Errorf("私钥认证成功，但无法收紧本机私钥权限: %w", err)
	}
	if _, err = SaveAlias(s.home, r.Target, path); err != nil {
		return Server{}, fmt.Errorf("私钥认证成功，但保存连接失败: %w", err)
	}
	row := Server{Target: r.Target, State: "unknown", CheckedAt: time.Now().Format(time.RFC3339), Detail: "原有私钥认证成功，连接已保存；尚未检测终端命令。带口令私钥需在终端输入口令或使用 ssh-agent。"}
	if err := s.remember(row); err != nil {
		return row, err
	}
	return row, nil
}
