package nativeui

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"server-keydesk/internal/desk"
)

func (f connectionForm) target() (desk.Target, error) {
	port, err := strconv.Atoi(f.Port)
	if err != nil {
		return desk.Target{}, errors.New("SSH 端口必须是 1 到 65535 的整数")
	}
	t := desk.Target{Alias: strings.TrimSpace(f.Alias), Host: strings.TrimSpace(f.Host), User: strings.TrimSpace(f.User), Port: port}
	return t, t.Validate()
}
func (a *App) openAdd() {
	a.openDialog("add", "添加密钥访问")
	a.formStatus = "先核对服务器指纹，再验证登录。"
}
func (a *App) beginInstall() {
	if a.changing {
		return
	}
	target, err := a.add.target()
	if err != nil {
		a.formStatus = err.Error()
		return
	}
	if !a.add.UsePrivateKey && a.add.Password == "" {
		a.formStatus = "请输入服务器密码（不会保存）"
		return
	}
	if a.add.UsePrivateKey && strings.TrimSpace(a.add.PrivateKeyPath) == "" {
		a.formStatus = "请输入私钥文件路径"
		return
	}
	a.changing = true
	a.dialogBusy = true
	a.formStatus = "正在读取服务器指纹，尚未提交登录认证…"
	a.work(func(ctx context.Context) func() {
		host, err := a.backend.Probe(ctx, target)
		return func() {
			a.changing = false
			a.dialogBusy = false
			if err != nil {
				a.add.Passphrase = ""
				a.add.Password = ""
				a.add.ShowPassword = false
				a.formStatus = err.Error()
				a.notify(err.Error())
				return
			}
			a.installTarget = target
			a.host = host
			a.openDialog("trust", "核对服务器身份")
			a.formStatus = "请核对指纹后确认连接。"
		}
	})
}
func (a *App) install() {
	if a.dialogBusy || a.dialog != "trust" || (!a.add.UsePrivateKey && a.add.Password == "") {
		return
	}
	usingKey := a.add.UsePrivateKey
	r := desk.InstallRequest{Target: a.installTarget, Password: a.add.Password, Fingerprint: a.host.Fingerprint, Trust: !a.host.Known}
	if usingKey {
		r.PrivateKeyPath = strings.TrimSpace(a.add.PrivateKeyPath)
		r.Passphrase = a.add.Passphrase
		r.Password = ""
	}
	a.add.Passphrase = ""
	a.add.Password = ""
	a.add.ShowPassword = false
	a.dialogBusy = true
	a.changing = true
	a.dialogStatus = "正在安装公钥并验证密钥连接…"
	if usingKey {
		a.dialogStatus = "正在验证原有私钥并保存连接…"
	}
	a.work(func(ctx context.Context) func() {
		row, err := a.backend.Install(ctx, r)
		r.Password = ""
		r.Passphrase = ""
		return func() {
			a.dialogBusy = false
			a.changing = false
			a.closeDialog()
			if err != nil {
				a.formStatus = err.Error()
				a.notify(err.Error())
				a.record(a.installTarget.Alias + "：" + err.Error())
				a.Refresh()
				return
			}
			a.add = connectionForm{Port: "22"}
			a.formStatus = "安装成功。现在可以使用 ssh " + row.Alias + " 连接。"
			if usingKey {
				a.formStatus = row.Detail
				a.record(row.Alias + "：原有私钥认证成功，连接已保存")
			} else {
				a.record(row.Alias + "：公钥安装成功，SSH 别名已验证")
			}
			a.notify(row.Alias + " 已保存")
			a.Refresh()
		}
	})
}
func (a *App) openDelete(s desk.Server) {
	a.openDialog("delete", "删除本机连接 · "+s.Alias)
	epoch := a.epoch
	a.dialogStatus = "正在检查配置文件…"
	a.work(func(ctx context.Context) func() {
		p, err := a.backend.PrepareDelete(ctx, s.Alias)
		return func() {
			if epoch != a.epoch || !a.dialogOpen {
				return
			}
			if err != nil {
				a.dialogStatus = err.Error()
				return
			}
			a.deletePlan = &p
			a.dialogStatus = "确认后备份并删除本机连接。"
		}
	})
}
func (a *App) deleteConnection() {
	if a.deletePlan == nil || a.dialogBusy {
		return
	}
	p := *a.deletePlan
	a.deletePlan = nil
	a.dialogBusy = true
	a.changing = true
	a.dialogStatus = "正在备份配置并删除本机连接…"
	a.work(func(ctx context.Context) func() {
		r, err := a.backend.DeleteConnection(ctx, p.Token, true)
		return func() {
			a.dialogBusy = false
			a.changing = false
			if err != nil {
				a.dialogStatus = err.Error() + "\n关闭窗口后可重新检查。"
				return
			}
			a.record(r.Alias + "：本机连接已删除")
			a.maintenanceReceipt("连接已删除 · 配置备份", r)
			a.Refresh()
		}
	})
}
func (a *App) openRecreate(s desk.Server) {
	a.openDialog("recreate", "重新创建连接密钥")
	a.recreate = connectionForm{Alias: s.Alias, Host: s.Host, User: s.User, Port: strconv.Itoa(s.Port)}
	if s.Port == 0 {
		a.recreate.Port = "22"
	}
	a.dialogStatus = "检查指纹时不会发送密码。"
}
func (a *App) invalidateRecreate() {
	a.recreatePlan = nil
	a.ack = false
	a.epoch++
	a.dialogStatus = "连接信息已修改，请重新检查指纹。"
}
func (a *App) prepareRecreate() {
	if a.dialogBusy {
		return
	}
	target, err := a.recreate.target()
	if err != nil {
		a.dialogStatus = err.Error()
		return
	}
	a.invalidateRecreate()
	epoch := a.epoch
	a.dialogBusy = true
	a.dialogStatus = "正在读取服务器指纹，尚未提交登录认证…"
	a.work(func(ctx context.Context) func() {
		p, err := a.backend.PrepareRecreate(ctx, target)
		return func() {
			if epoch != a.epoch || !a.dialogOpen {
				return
			}
			a.dialogBusy = false
			if err != nil {
				a.dialogStatus = err.Error()
				return
			}
			a.recreatePlan = &p
			if p.HostChanged {
				a.dialogStatus = "服务器主机指纹已变化，请先通过可信控制台核对。"
			} else {
				a.dialogStatus = "核对指纹后勾选确认，再安装新密钥。"
			}
		}
	})
}
func (a *App) recreateConnection() {
	if a.dialogBusy || a.recreatePlan == nil || !a.ack {
		return
	}
	if a.recreate.Password == "" {
		a.dialogStatus = "请输入服务器当前密码（不会保存）"
		return
	}
	p := *a.recreatePlan
	password := a.recreate.Password
	a.recreate.Password = ""
	a.recreatePlan = nil
	a.ack = false
	a.dialogBusy = true
	a.changing = true
	a.dialogStatus = "正在安装独立新密钥，验证成功后切换配置…"
	a.work(func(ctx context.Context) func() {
		r, err := a.backend.RecreateConnection(ctx, p.Token, password, true)
		password = ""
		return func() {
			a.dialogBusy = false
			a.changing = false
			if err != nil {
				a.dialogStatus = err.Error()
				a.Refresh()
				return
			}
			a.record(r.Alias + "：新密钥已安装，连接配置已切换")
			a.maintenanceReceipt("连接密钥已重新创建", r)
			a.Refresh()
		}
	})
}
func (a *App) maintenanceReceipt(title string, r desk.MaintenanceResult) {
	text := r.Detail
	if r.KeyPath != "" {
		text += "\n\n新密钥路径：" + r.KeyPath
	}
	if len(r.Backups) > 0 {
		text += "\n\n原配置备份：\n" + strings.Join(r.Backups, "\n")
	}
	if len(r.Warnings) > 0 {
		text += "\n\n需要留意：\n" + strings.Join(r.Warnings, "\n")
	}
	a.detail(title, text)
}
func (a *App) openTransfer() {
	if len(a.overview.Servers) < 2 {
		a.notify("至少需要两个本机 SSH 别名：源服务器 C 和接收电脑 B。")
		return
	}
	a.openDialog("transfer", "发送连接到另一台 Windows 电脑")
	a.source = a.overview.Servers[0].Alias
	a.destination = a.overview.Servers[1].Alias
	a.remoteAlias = a.source
	a.dialogStatus = "检查步骤不会向 B 发送私钥。"
}
func (a *App) invalidateTransfer() {
	a.epoch++
	a.transferPlan = nil
	a.ack = false
	a.dialogText = ""
	a.dialogStatus = "连接信息已修改，请重新检查。"
}
func (a *App) prepareTransfer() {
	if a.dialogBusy {
		return
	}
	if a.source == a.destination {
		a.dialogStatus = "请选择不同的源服务器 C 和接收电脑 B。"
		return
	}
	a.invalidateTransfer()
	epoch := a.epoch
	r := desk.TransferRequest{SourceAlias: a.source, DestinationAlias: a.destination, RemoteAlias: strings.TrimSpace(a.remoteAlias)}
	a.dialogBusy = true
	a.dialogStatus = "正在验证 A → C 的指定密钥，并检查 B 的接收环境；尚未发送私钥…"
	a.work(func(ctx context.Context) func() {
		p, err := a.backend.PrepareTransfer(ctx, r)
		return func() {
			if epoch != a.epoch || !a.dialogOpen {
				return
			}
			a.dialogBusy = false
			if err != nil {
				a.dialogStatus = err.Error()
				return
			}
			a.transferPlan = &p
			a.dialogStatus = "检查通过。核对接收账号和密钥权限范围后，可确认发送。"
		}
	})
}
func (a *App) sendTransfer() {
	if a.dialogBusy || a.transferPlan == nil || !a.ack {
		return
	}
	p := *a.transferPlan
	a.transferPlan = nil
	a.ack = false
	a.dialogBusy = true
	a.dialogStatus = "正在通过 SSH 加密连接发送私钥和配置，并从 B 验证连接 C…"
	a.work(func(ctx context.Context) func() {
		r, err := a.backend.SendTransfer(ctx, p.Token, true)
		return func() {
			a.dialogBusy = false
			if err != nil {
				a.dialogStatus = err.Error()
				a.record("发送到 " + p.Destination.Alias + " 未完成：" + err.Error())
				return
			}
			if r.State == "key_ready" {
				a.dialogStatus = fmt.Sprintf("已发送并验证 B → C。\n在 %s 上运行：ssh %s\n密钥保存位置：%s", p.ReceiverMachine, r.Alias, r.KeyPath)
				a.record("已发送 " + p.Source.Alias + " 的连接到 " + p.Destination.Alias + "，并验证 B → C 成功")
			} else {
				a.dialogStatus = "连接和密钥已保存到 B，但 B → C 未通过验证。"
				a.dialogText = r.Detail + "\n请检查 B 的网络和 SSH 策略；无需重复生成密钥。"
				a.record("连接已发送到 " + p.Destination.Alias + "；B → C 检测状态：" + stateLabel(r.State))
			}
		}
	})
}

func (a *App) choosePrivateKey() {
	if a.changing || a.dialogBusy || a.PickPrivateKey == nil {
		return
	}
	a.dialogBusy = true
	a.changing = true
	picker := a.PickPrivateKey
	a.work(func(ctx context.Context) func() {
		path, err := picker()
		return func() {
			a.dialogBusy = false
			a.changing = false
			if err != nil {
				a.formStatus = "选择私钥失败：" + err.Error()
				return
			}
			if path != "" {
				a.add.PrivateKeyPath = path
				a.add.Passphrase = ""
			}
		}
	})
}
