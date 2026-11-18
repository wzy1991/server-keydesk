package nativeui

import (
	"fmt"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"server-keydesk/internal/desk"
)

var (
	green  = ui.Hex("#18755d")
	dark   = ui.Hex("#152c27")
	muted  = ui.Hex("#7b8582")
	line   = ui.Hex("#e6ebe8")
	white  = ui.Hex("#ffffff")
	paper  = ui.Hex("#f5f7f6")
	ink    = ui.Hex("#23302e")
	danger = ui.Hex("#ad584c")
	logo   = ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="15" fill="#2e4c40"/><g fill="none" stroke="#e4edca" stroke-width="4"><circle cx="25" cy="25" r="10"/><path d="m32 32 17 17m-8-8 5-5m-1 9 5-5"/></g></svg>`))
)

func btn(c *ui.Context, text string, primary bool) ui.Element {
	var e ui.Element
	if primary {
		e = ui.PrimaryButton(c, text)
	} else {
		e = ui.Button(c, text).Background(white).Border(1, line).TextColor(ui.Hex("#526659"))
	}
	return e.Height(32).Padding(7, 11).Radius(6).FontSize(11)
}
func panel(c *ui.Context) ui.Element {
	return ui.Column(c).Background(white).Border(1, line).Radius(9).Clip()
}
func caption(c *ui.Context, text string) ui.Element {
	return ui.Text(c, text).FontSize(10).TextColor(muted)
}
func (a *App) copyAliasButton(c *ui.Context, label, alias string) {
	if alias == "" {
		return
	}
	ui.Button(c.Key("copy-"+alias), "复制").Label(label).Height(20).Padding(2, 7).Radius(4).FontSize(9).Border(1, line).Background(ui.Hex("#f7f9f5")).TextColor(ui.Hex("#526659")).Shrink(0).Tooltip("复制主机别名").OnClick(func() {
		c.WriteClipboard(alias)
		a.notify("已复制主机别名：" + alias)
	})
}
func field(c *ui.Context, key, label string, value *string, disabled, password bool) bool {
	changed := false
	ui.Column(c.Key(key)).Gap(4).FillWidth().Children(func() {
		ui.Text(c, label).FontSize(10).TextColor(ui.Hex("#566a59"))
		input := ui.TextInput(c.Key("input"), value).Label(label).Height(30).FontSize(11).Padding(7, 9).Background(ui.Hex("#fdfefb")).Disabled(disabled)
		if password {
			input.Password()
		}
		changed = input.Changed()
	})
	return changed
}

// View is a Go-native immediate-mode tree; it never constructs a WebView.
func (a *App) View(c *ui.Context) {
	a.drain()
	if a.jobs > 0 {
		c.After(30 * time.Millisecond)
	}
	theme := ui.LightTheme()
	theme.Background = paper
	theme.Surface = white
	theme.SurfaceHover = ui.Hex("#f2f6f2")
	theme.Text = ink
	theme.TextMuted = muted
	theme.Border = line
	theme.Accent = green
	theme.AccentHover = ui.Hex("#115b47")
	theme.FontSize = 12
	theme.Spacing = 3
	theme.Radius = 5
	c.SetTheme(theme)
	width, height := c.Size()
	narrow := width < 1100
	sidebar := float32(174)
	if narrow {
		sidebar = 148
	}
	ui.Row(c.Key("shell")).Fill().Gap(0).Children(func() {
		a.sidebar(c, sidebar)
		ui.Column(c.Key("main")).Grow(1).MinWidth(0).FillHeight().Children(func() {
			ui.Row(c).Height(44).Shrink(0).Padding(0, 24).Background(ui.Hex("#fafcfb")).BorderWidth(0, 0, 1, 0).BorderColor(line).Children(func() {
				caption(c, "工作空间   /   "+a.page).Grow(1)
				caption(c, "● 本地运行 · 密码不落盘")
			})
			switch a.page {
			case "操作记录":
				a.activityView(c)
			case "使用说明":
				a.helpView(c)
			default:
				a.serversView(c, width, height, narrow)
			}
		})
	})
	if a.toast != "" {
		ui.Row(c.Key("toast")).Absolute().Left(sidebar+24).Right(24).Bottom(14).Padding(10, 14).Radius(7).Background(dark).Gap(12).Children(func() {
			ui.Text(c, a.toast).FontSize(12).TextColor(white).Grow(1)
			if ui.Button(c, "×").Label("关闭提示").Background(dark).TextColor(white).Clicked() {
				a.toast = ""
			}
		})
	}
	a.dialogView(c, width, height)
}
func (a *App) sidebar(c *ui.Context, width float32) {
	brandSize, logoSize := float32(23), float32(32)
	if width < 170 {
		brandSize = 20
		logoSize = 28
	}
	ui.Column(c).Width(width).FillHeight().Padding(24, 12).Background(dark).TextColor(ui.Hex("#c2cec9")).Children(func() {
		ui.Row(c).Gap(9).Padding(0, 5).Children(func() {
			ui.Image(c, logo).Size(logoSize, 36)
			ui.Column(c).Gap(2).Children(func() {
				ui.Text(c, "Keydesk").FontSize(brandSize).Bold().TextColor(white)
				ui.Text(c, "SERVER ACCESS").FontSize(7).LetterSpacing(1).TextColor(ui.Hex("#8ca397"))
			})
		})
		ui.Text(c, "工作空间").Margin(34, 9, 14).FontSize(10).TextColor(ui.Hex("#7e9a8c"))
		for _, item := range []struct{ icon, name string }{{"▤", "服务器"}, {"◷", "操作记录"}, {"ⓘ", "使用说明"}} {
			item := item
			bg := dark
			if a.page == item.name {
				bg = ui.Hex("#2b493b")
			}
			ui.Button(c.Key(item.name), "").Label(item.name).Height(44).FillWidth().Margin(0, 0, 6).Padding(10, 12).Border(0, line).Radius(7).Background(bg).TextColor(ui.Hex("#edf4e4")).Children(func() {
				ui.Text(c, item.icon).FontSize(17).Width(19)
				ui.Text(c, item.name).FontSize(12).Grow(1)
				if item.name == "服务器" {
					ui.Textf(c, "%d", len(a.overview.Servers)).FontSize(10).Background(ui.Hex("#47634c")).Radius(4).Padding(2, 6)
				}
			}).OnClick(func() { a.page = item.name })
		}
		ui.Spacer(c)
		ui.Text(c, "● 本机 SSH 工作空间").FontSize(10).TextColor(ui.Hex("#b1c1b7"))
		ui.Text(c, "连接由你的电脑直接发起").FontSize(9).Margin(9, 0, 28).TextColor(ui.Hex("#759185"))
		ui.Text(c, "BUILT WITH MYGO / GO").FontSize(7).LetterSpacing(1).TextColor(ui.Hex("#637d70"))
	})
}
func (a *App) serversView(c *ui.Context, width, height float32, narrow bool) {
	padding := float32(24)
	if narrow {
		padding = 18
	}
	ui.Column(c).Grow(1).MinHeight(0).Padding(14, padding, 12).Gap(12).Children(func() {
		ui.Row(c).Height(46).Shrink(0).Gap(12).Children(func() {
			ui.Column(c).Grow(1).MinWidth(0).Gap(3).Children(func() {
				ui.Text(c, "服务器").FontSize(25).Bold()
				caption(c, "配置一次密钥，让下一次连接更简单。")
			})
			btn(c, "添加服务器", true).Disabled(a.changing).OnClick(a.openAdd)
			btn(c, "发送连接到其他电脑", false).Disabled(a.changing).OnClick(a.openTransfer)
			btn(c, "刷新本机配置", false).Disabled(a.loading || a.changing).OnClick(a.Refresh)
		})
		counts := [4]int{len(a.overview.Servers)}
		for _, s := range a.overview.Servers {
			switch s.State {
			case "key_ready":
				counts[1]++
			case "unknown":
				counts[2]++
			default:
				counts[3]++
			}
		}
		panel(c).Height(48).Shrink(0).Children(func() {
			ui.Row(c).Fill().Children(func() {
				for i, label := range []string{"已发现服务器", "● 密钥登录可用", "● 尚未检测", "● 需要处理"} {
					ui.Row(c.Key(label)).Grow(1).Basis(0).Padding(8, 14).Gap(8).Children(func() { caption(c, label).Grow(1).SingleLine(); ui.Textf(c, "%d", counts[i]).FontSize(23) })
					if i < 3 {
						ui.Box(c).Width(1).Height(26).Background(line)
					}
				}
			})
		})
		workspaceHeight := height - 224
		ui.Row(c).Height(workspaceHeight).Shrink(0).AlignItems(ui.Start).Children(func() { a.serverPanel(c, narrow) })
		caption(c, "◇  检测结果表示当前公钥登录是否成功。网络不可达或认证失败，不能证明远程没有安装公钥。").MaxLines(2)
	})
}
func (a *App) serverPanel(c *ui.Context, narrow bool) {
	panel(c).Grow(1).MinWidth(0).FillHeight().Children(func() {
		ui.Row(c).Padding(15, 16, 12).Gap(12).Children(func() {
			ui.Column(c).Grow(1).Gap(4).Children(func() {
				ui.Text(c, "服务器列表").FontSize(13).Bold()
				caption(c, "兼容已有密钥、SSH Agent 和代理配置")
			})
			text := "检测全部"
			if a.batch {
				text = "正在检测…"
			}
			btn(c, text, false).Disabled(a.batch || a.changing || len(a.overview.Servers) == 0).OnClick(a.checkAll)
		})
		ui.Row(c).Padding(0, 14, 12).Gap(8).Children(func() {
			ui.TextInput(c.Key("search"), &a.search).Label("搜索服务器").Placeholder("搜索别名、地址或用户名").Grow(1).MinWidth(0).Height(31).FontSize(11)
			ui.Select(c.Key("filter"), &a.filter, []string{"全部状态", "密钥可用", "尚未检测", "需要处理"}).Label("按状态筛选").Width(103).Height(31).FontSize(11)
		})
		ui.Row(c).Height(29).Padding(0, 14).Gap(8).Background(ui.Hex("#f8faf7")).BorderWidth(1, 0).BorderColor(line).Children(func() {
			caption(c, "服务器 / 连接地址").Grow(1)
			caption(c, "密钥状态").Width(90)
			caption(c, "操作").Width(124)
		})
		ui.Scroll(c.Key("server-list")).Grow(1).MinHeight(0).TrackScroll(&a.listScroll).Children(func() {
			rows := a.visible()
			if len(rows) == 0 {
				msg := "没有匹配的服务器"
				if len(a.overview.Servers) == 0 {
					msg = "还没有服务器。在右侧添加，或刷新已有 SSH 配置。"
				}
				ui.Text(c, msg).FontSize(12).TextColor(muted).Padding(50, 18)
				return
			}
			for _, s := range rows {
				a.serverRow(c, s, narrow)
			}
		})
		ui.Row(c).Padding(12, 14).Gap(8).BorderWidth(1, 0, 0).BorderColor(line).Children(func() {
			caption(c, "仅在你点击检测时连接服务器").Grow(1).SingleLine()
			ui.Button(c, "导出智能体清单 ↗").Label("导出智能体清单").FontSize(9).TextColor(green).Border(0, line).Background(white).Padding(0).Disabled(a.changing).OnClick(a.export)
		})
	})
}
func (a *App) serverRow(c *ui.Context, s desk.Server, narrow bool) {
	ui.Row(c.Key(s.Alias)).Padding(12, 14).Gap(8).BorderWidth(0, 0, 1, 0).BorderColor(ui.Hex("#f0f3ee")).Children(func() {
		ui.Row(c).Grow(1).MinWidth(0).Gap(10).Children(func() {
			if !narrow {
				ui.Text(c, "▤").FontSize(20).TextColor(ui.Hex("#8ea08c")).Padding(7).Radius(6).Background(ui.Hex("#f7f9f5"))
			}
			ui.Column(c).Grow(1).MinWidth(0).Gap(5).Children(func() {
				ui.Row(c).Gap(6).AlignItems(ui.Center).FillWidth().Children(func() {
					ui.Text(c, s.Alias).FontSize(12).Bold().SingleLine().Selectable().MinWidth(0).Shrink(1)
					a.copyAliasButton(c, "复制别名 "+s.Alias, s.Alias)
				})
				ui.Textf(c, "%s@%s:%d", s.User, s.Host, s.Port).FontSize(10).TextColor(muted).SingleLine()
			})
		})
		state := s.State
		if a.checking[s.Alias] {
			state = "checking"
		}
		color, bg := muted, ui.Hex("#f0f3ef")
		if state == "key_ready" {
			color = ui.Hex("#368363")
			bg = ui.Hex("#eaf5ed")
		} else if state == "auth_failed" || state == "host_changed" {
			color = danger
			bg = ui.Hex("#fbefed")
		} else if state != "unknown" && state != "checking" {
			color = ui.Hex("#b08a44")
			bg = ui.Hex("#fbf4e7")
		}
		ui.Button(c, "").Label("查看 "+s.Alias+" 的连接详情").Disabled(a.changing).Width(90).Padding(0).Border(0, line).Background(white).Children(func() {
			ui.Column(c).Gap(4).Children(func() {
				ui.Text(c, "● "+stateLabel(state)).FontSize(9).TextColor(color).Background(bg).Padding(4, 6).Radius(4)
				when := "未检测"
				if t, e := time.Parse(time.RFC3339, s.CheckedAt); e == nil {
					when = t.Local().Format("01-02 15:04")
				}
				caption(c, when).FontSize(8)
			})
		}).OnClick(func() {
			a.detail(s.Alias+" · "+stateLabel(s.State), fmt.Sprintf("%s@%s:%d\n\n%s\n\n连接命令：ssh %s", s.User, s.Host, s.Port, s.Detail, s.Alias))
		})
		ui.Row(c).Width(124).Gap(3).Children(func() {
			for _, action := range []struct {
				text, label string
				fn          func()
			}{{"检测", "检测 " + s.Alias, func() { a.check(s.Alias) }}, {"重建", "重新创建 " + s.Alias, func() { a.openRecreate(s) }}, {"删除", "删除 " + s.Alias, func() { a.openDelete(s) }}} {
				action := action
				button := btn(c.Key(action.label), action.text, false).Label(action.label).Height(28).Padding(5, 6).FontSize(10).Disabled(a.checking[s.Alias] || a.batch || a.changing)
				if action.text == "删除" {
					button.TextColor(danger)
				}
				button.OnClick(action.fn)
			}
		})
	})
}
func (a *App) addFields(c *ui.Context) {
	ui.Column(c).FillWidth().Gap(10).Children(func() {
		caption(c, "核对服务器指纹后验证登录。")
		ui.Checkbox(c, &a.add.UsePrivateKey, "使用已有私钥（不安装新密钥）").Disabled(a.changing)
		field(c, "add-host", "服务器地址", &a.add.Host, a.changing, false)
		ui.Row(c).Gap(10).Children(func() {
			ui.Column(c).Grow(1).MinWidth(0).Children(func() { field(c, "add-user", "用户名", &a.add.User, a.changing, false) })
			ui.Column(c).Width(74).Children(func() { field(c, "add-port", "SSH 端口", &a.add.Port, a.changing, false) })
		})
		if a.add.UsePrivateKey {
			caption(c, "私钥文件")
			ui.Row(c).Gap(8).Children(func() {
				name := a.add.PrivateKeyPath
				if name == "" {
					name = "尚未选择文件"
				}
				ui.Text(c, name).FontSize(11).Grow(1).MinWidth(0).Selectable()
				btn(c, "选择私钥文件", false).Disabled(a.changing).OnClick(a.choosePrivateKey)
			})
			field(c, "add-passphrase", "私钥口令（可选，不保存）", &a.add.Passphrase, a.changing, true)
			caption(c, "保留原文件内容，收紧权限为仅当前用户可访问。口令不保存，可配合 ssh-agent 使用。")
		} else {
			ui.Column(c).Gap(4).Children(func() {
				caption(c, "登录密码")
				ui.Row(c).Gap(4).Children(func() {
					input := ui.TextInput(c.Key("add-password"), &a.add.Password).Label("登录密码").Placeholder("仅用于本次安装").Grow(1).MinWidth(0).Height(30).FontSize(11).Disabled(a.changing)
					if !a.add.ShowPassword {
						input.Password()
					}
					ui.Button(c, "◉").Label("显示或隐藏密码").Height(30).Width(28).FontSize(12).Disabled(a.changing).OnClick(func() { a.add.ShowPassword = !a.add.ShowPassword })
				})
			})
		}
		ui.Column(c).Gap(4).Children(func() {
			field(c, "add-alias", "连接别名", &a.add.Alias, a.changing, false)
			alias := a.add.Alias
			if alias == "" {
				alias = "prod-web"
			}
			caption(c, "以后通过 ssh "+alias+" 连接").FontSize(9)
		})
		if !a.add.UsePrivateKey {
			ui.Text(c, "◇ 使用专用无口令 Ed25519 密钥，权限限当前用户。保留服务器已有公钥。").FontSize(9).TextColor(ui.Hex("#8d987c")).Padding(8).Radius(5).Background(ui.Hex("#f7f9f3"))
		}
		ui.Text(c, a.formStatus).FontSize(9).TextColor(muted).MaxLines(3)
	})
}
func (a *App) activityView(c *ui.Context) {
	ui.Column(c).Grow(1).MinHeight(0).Padding(24).Gap(20).Children(func() {
		ui.Text(c, "操作记录").FontSize(25).Bold()
		caption(c, "本次运行的操作结果，不记录密码或私钥内容。")
		panel(c).Grow(1).MinHeight(0).Children(func() {
			ui.Scroll(c).Grow(1).Children(func() {
				if len(a.log) == 0 {
					ui.Text(c, "还没有操作记录").Padding(40).TextColor(muted)
				}
				for _, item := range a.log {
					ui.Row(c).Padding(16).Gap(20).Children(func() { caption(c, item.Time).Width(65); ui.Text(c, item.Message).FontSize(12).Grow(1).Selectable() })
				}
			})
		})
	})
}
func (a *App) helpView(c *ui.Context) {
	ui.Column(c).Grow(1).MinHeight(0).Padding(24).Gap(18).Children(func() {
		ui.Text(c, "使用说明").FontSize(25).Bold()
		panel(c).Grow(1).MinHeight(0).Children(func() {
			ui.Scroll(c).Grow(1).Padding(24).Gap(12).Selectable().Children(func() {
				for _, p := range []struct{ title, text string }{{"添加服务器", "填写 Linux 服务器地址、用户名、密码、端口和未使用的别名。IPv6 地址不加方括号。"}, {"核对主机指纹", "先通过云服务商控制台或可信渠道核对指纹，确认后才发送密码。首次安装支持直连 Linux 服务器。"}, {"检测已有服务器", "从本机 SSH config 及 Include 文件发现别名。检测使用系统 OpenSSH，兼容已有密钥、SSH Agent 和代理配置。"}, {"让不同智能体使用", "导出智能体清单，把导出路径写进智能体的说明文件。同一 Windows 用户下的工具可共用 SSH 别名。"}, {"发送连接到其他电脑", "选择 C 的连接和已配置密钥登录的 Windows B 别名，检查并确认后复制私钥。B 无需安装 Keydesk。共享私钥的访问范围不限于所选 C。"}, {"删除和重建", "删除只清理本机别名并备份，保留旧密钥和远程授权。重建安装独立新密钥并验证后才切换配置。服务器指纹变化必须先核对。"}, {"文件位置", strings.Join([]string{"SSH 配置：" + a.overview.ConfigPath, "默认专用私钥：" + a.overview.KeyPath, "智能体清单：" + a.overview.InventoryPath}, "\n")}, {"原生界面", "此版本全部界面由 Go 和 mygo/ui 绘制，不创建 WebView，不加载 HTML、CSS 或 JavaScript。"}} {
					ui.Text(c, p.title).FontSize(14).Bold().TextColor(green)
					ui.Text(c, p.text).FontSize(12).TextColor(muted)
				}
			})
		})
	})
}
