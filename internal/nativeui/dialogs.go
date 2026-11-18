package nativeui

import (
	"fmt"
	"strings"

	"github.com/egoist/mygo/ui"
)

func warning(c *ui.Context, text string) {
	ui.Text(c, text).FontSize(11).TextColor(ui.Hex("#987236")).Padding(11).Radius(5).Background(ui.Hex("#fbf3e5")).Border(1, ui.Hex("#f0e3cb"))
}
func fingerprint(c *ui.Context, algorithm, value string) {
	ui.Column(c).Padding(14).Gap(8).Radius(7).Background(ui.Hex("#f3f6ee")).Border(1, line).Children(func() { caption(c, algorithm); ui.Text(c, value).FontSize(13).Font("monospace").Selectable() })
}
func (a *App) dialogView(c *ui.Context, width, height float32) {
	if !a.dialogOpen {
		return
	}
	kind := a.dialog
	panelHeight := float32(600)
	if kind == "add" {
		panelHeight = 480
	}
	if kind == "trust" {
		panelHeight = 350
	}
	if kind == "delete" || kind == "detail" {
		panelHeight = 440
	}
	panelHeight = min(panelHeight, height-40)
	dialog := ui.DialogBase(c.Key("dialog-"+kind), &a.dialogOpen, func(backdrop, p ui.Element) {
		backdrop.Background(ui.RGBA(16, 43, 38, .42))
		p.Width(min(float32(590), width-48)).Height(panelHeight).Padding(22).Radius(12).Background(white).Border(1, line).Gap(14)
		ui.Text(c, a.dialogTitle).FontSize(19).Bold()
		ui.Scroll(c.Key("dialog-body")).Grow(1).MinHeight(0).Gap(12).Children(func() {
			switch kind {
			case "add":
				a.addFields(c)
			case "detail":
				ui.Text(c, a.dialogText).FontSize(12).Selectable()
			case "trust":
				description := "这是本机尚未信任的主机，确认后会保存主机指纹。"
				if a.host.Known {
					description = "该主机指纹与本机 known_hosts 记录一致。"
				}
				ui.Text(c, description).FontSize(12).TextColor(muted)
				fingerprint(c, a.host.Algorithm, a.host.Fingerprint)
				caption(c, fmt.Sprintf("%s@%s:%d", a.installTarget.User, a.installTarget.Host, a.installTarget.Port))
				if a.add.UsePrivateKey {
					warning(c, "请通过可信渠道核对指纹。确认后使用原有私钥认证并保存连接，不修改服务器授权密钥。")
				} else {
					warning(c, "请与服务器控制台或可信渠道提供的指纹比对。确认后将发送密码并安装公钥。")
				}
			case "delete":
				if a.deletePlan != nil {
					warning(c, a.deletePlan.Warning)
					ui.Text(c, "将修改并备份：\n"+strings.Join(a.deletePlan.Files, "\n")).FontSize(12).Selectable()
				} else {
					warning(c, "只删除此电脑上的 SSH 别名和检测记录，保留密钥文件及服务器上的公钥。")
				}
			case "recreate":
				a.recreateDialog(c)
			case "transfer":
				a.transferDialog(c)
			}
			if a.dialogStatus != "" {
				ui.Text(c, a.dialogStatus).FontSize(11).TextColor(green).Selectable()
			}
			if a.dialogText != "" && kind != "detail" {
				ui.Text(c, a.dialogText).FontSize(11).TextColor(muted).Selectable()
			}
		})
		ui.Row(c).Justify(ui.End).Gap(10).Children(func() {
			label := "取消"
			if kind == "detail" || kind == "transfer" {
				label = "关闭"
			}
			btn(c, label, false).Disabled(a.dialogBusy).OnClick(a.closeDialog)
			switch kind {
			case "add":
				label := "检查指纹并安装公钥"
				if a.add.UsePrivateKey {
					label = "检查服务器指纹"
				}
				btn(c, label, true).Disabled(a.dialogBusy || a.changing).OnClick(a.beginInstall)
			case "trust":
				label := "指纹正确，安装公钥"
				if a.add.UsePrivateKey {
					label = "指纹正确，保存连接"
				}
				btn(c, label, true).Disabled(a.dialogBusy).OnClick(a.install)
			case "delete":
				btn(c, "删除本机连接", true).Background(danger).Disabled(a.dialogBusy || a.deletePlan == nil).OnClick(a.deleteConnection)
			case "recreate":
				btn(c, "安装新密钥并替换连接", true).Disabled(a.dialogBusy || a.recreatePlan == nil || !a.ack).OnClick(a.recreateConnection)
			case "transfer":
				btn(c, "确认并发送私钥与连接", true).Disabled(a.dialogBusy || a.transferPlan == nil || !a.ack).OnClick(a.sendTransfer)
			}
		})
	})
	if dialog.Dismissed() {
		if a.dialogBusy {
			a.dialogOpen = true
		} else {
			a.closeDialog()
		}
	}
}
func (a *App) recreateDialog(c *ui.Context) {
	caption(c, "填写服务器当前地址和登录密码。新密钥验证成功后才替换本机配置。")
	ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
		ui.Text(c, "连接别名：").FontSize(12)
		ui.Text(c, a.recreate.Alias).FontSize(12).Bold().Selectable().MinWidth(0).Shrink(1)
		a.copyAliasButton(c, "复制连接别名 "+a.recreate.Alias, a.recreate.Alias)
	})
	if field(c, "recreate-host", "服务器地址", &a.recreate.Host, a.dialogBusy, false) {
		a.invalidateRecreate()
	}
	ui.Row(c).Gap(12).Children(func() {
		ui.Column(c).Grow(1).Children(func() {
			if field(c, "recreate-user", "用户名", &a.recreate.User, a.dialogBusy, false) {
				a.invalidateRecreate()
			}
		})
		ui.Column(c).Width(84).Children(func() {
			if field(c, "recreate-port", "SSH 端口", &a.recreate.Port, a.dialogBusy, false) {
				a.invalidateRecreate()
			}
		})
	})
	field(c, "recreate-password", "当前登录密码", &a.recreate.Password, a.dialogBusy, true)
	btn(c, "检查服务器指纹", false).Disabled(a.dialogBusy).OnClick(a.prepareRecreate)
	if p := a.recreatePlan; p != nil {
		fingerprint(c, p.Host.Algorithm, p.Host.Fingerprint)
		warning(c, p.Warning)
		ui.Text(c, "相关配置：\n"+strings.Join(p.Files, "\n")).FontSize(10).TextColor(muted).Selectable()
		ui.Checkbox(c, &a.ack, "我已通过可信渠道核对指纹，确认安装新密钥并替换此连接。").FontSize(11).Disabled(a.dialogBusy)
	}
}
func (a *App) transferDialog(c *ui.Context) {
	caption(c, "通过 A 已有的 SSH 连接发送到 B，让 B 复用密钥连接 C。")
	names := []string{}
	for _, s := range a.overview.Servers {
		names = append(names, s.Alias)
	}
	ui.Column(c).Gap(4).Children(func() {
		caption(c, "要发送的服务器连接 C")
		if ui.Select(c.Key("transfer-source"), &a.source, names).Label("源服务器 C").FillWidth().Disabled(a.dialogBusy).Changed() {
			a.remoteAlias = a.source
			a.invalidateTransfer()
		}
	})
	ui.Column(c).Gap(4).Children(func() {
		caption(c, "接收电脑 B 的 SSH 别名")
		if ui.Select(c.Key("transfer-destination"), &a.destination, names).Label("接收电脑 B").FillWidth().Disabled(a.dialogBusy).Changed() {
			a.invalidateTransfer()
		}
	})
	if field(c, "remote-alias", "保存在 B 上的连接别名", &a.remoteAlias, a.dialogBusy, false) {
		a.invalidateTransfer()
	}
	caption(c, "支持本程序管理的无口令密钥及直连连接。B 需提供 Windows PowerShell 和 OpenSSH。")
	btn(c, "检查 A → C 与接收电脑 B", false).Disabled(a.dialogBusy).OnClick(a.prepareTransfer)
	if p := a.transferPlan; p != nil {
		ui.Text(c, fmt.Sprintf("源服务器 C：%s → %s@%s:%d\n接收电脑 B：%s → %s\n接收账号：%s\n接收目录：%s\nB 的连接命令：ssh %s\n密钥指纹：%s", p.Source.Alias, p.Source.User, p.Source.Host, p.Source.Port, p.Destination.Alias, p.ReceiverMachine, p.ReceiverUser, p.ReceiverHome, p.RemoteAlias, p.Fingerprint)).FontSize(11).Selectable()
		warning(c, p.Warning)
		ui.Checkbox(c, &a.ack, "我信任接收电脑 B，确认复制私钥及其访问权限。").FontSize(11).Disabled(a.dialogBusy)
	}
}
