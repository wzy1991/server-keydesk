// Package nativeui implements Keydesk's desktop interface entirely in Go.
// No webview, frontend server, HTML or JavaScript is created by this package.
package nativeui

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/egoist/mygo/ui"
	"server-keydesk/internal/desk"
)

type Backend interface {
	List(context.Context) (desk.Overview, error)
	Check(context.Context, string) (desk.Server, error)
	Probe(context.Context, desk.Target) (desk.HostInfo, error)
	Install(context.Context, desk.InstallRequest) (desk.Server, error)
	Export(context.Context) (string, error)
	PrepareDelete(context.Context, string) (desk.DeletePlan, error)
	DeleteConnection(context.Context, string, bool) (desk.MaintenanceResult, error)
	PrepareRecreate(context.Context, desk.Target) (desk.RecreatePlan, error)
	RecreateConnection(context.Context, string, string, bool) (desk.MaintenanceResult, error)
	PrepareTransfer(context.Context, desk.TransferRequest) (desk.TransferPlan, error)
	SendTransfer(context.Context, string, bool) (desk.TransferResult, error)
}
type connectionForm struct {
	Host, User, Port, Alias, Password string
	ShowPassword                      bool
}
type activity struct{ Time, Message string }
type App struct {
	backend                                       Backend
	ctx                                           context.Context
	cancel                                        context.CancelFunc
	execute                                       func(func())
	done                                          chan func()
	jobs                                          int
	overview                                      desk.Overview
	page, search, filter                          string
	checking                                      map[string]bool
	loading, batch, changing                      bool
	refreshAgain                                  bool
	add, recreate                                 connectionForm
	formStatus                                    string
	log                                           []activity
	toast                                         string
	dialog, dialogTitle, dialogText, dialogStatus string
	dialogOpen, dialogBusy, ack                   bool
	epoch                                         uint64
	installTarget                                 desk.Target
	host                                          desk.HostInfo
	deletePlan                                    *desk.DeletePlan
	recreatePlan                                  *desk.RecreatePlan
	transferPlan                                  *desk.TransferPlan
	source, destination, remoteAlias              string
	listScroll                                    ui.ScrollState
}

func New(backend Backend) *App {
	ctx, cancel := context.WithCancel(context.Background())
	return &App{backend: backend, ctx: ctx, cancel: cancel, execute: func(fn func()) { go fn() }, done: make(chan func(), 512), page: "服务器", filter: "全部状态", checking: map[string]bool{}, add: connectionForm{Port: "22"}, formStatus: "先核对服务器指纹，再发送登录密码。"}
}

// Close is also called by the native window lifecycle, cancelling worker IO.
func (a *App) Close() { a.cancel(); a.add.Password = ""; a.recreate.Password = "" }
func (a *App) work(job func(context.Context) func()) {
	a.jobs++
	ctx := a.ctx
	a.execute(func() {
		apply := job(ctx)
		select {
		case a.done <- func() {
			a.jobs--
			if ctx.Err() == nil && apply != nil {
				apply()
			}
		}:
		case <-ctx.Done():
		}
	})
}
func (a *App) drain() {
	for {
		select {
		case fn := <-a.done:
			fn()
		default:
			return
		}
	}
}
func (a *App) record(message string) {
	a.log = append([]activity{{time.Now().Format("15:04:05"), message}}, a.log...)
	if len(a.log) > 120 {
		a.log = a.log[:120]
	}
}
func (a *App) notify(message string) { a.toast = message }
func (a *App) detail(title, text string) {
	a.epoch++
	a.dialog = "detail"
	a.dialogTitle = title
	a.dialogText = text
	a.dialogStatus = ""
	a.dialogOpen = true
	a.dialogBusy = false
}
func (a *App) openDialog(kind, title string) {
	a.epoch++
	a.dialog = kind
	a.dialogTitle = title
	a.dialogText = ""
	a.dialogStatus = ""
	a.dialogOpen = true
	a.dialogBusy = false
	a.ack = false
	a.deletePlan = nil
	a.recreatePlan = nil
	a.transferPlan = nil
}
func (a *App) closeDialog() {
	if a.dialogBusy {
		return
	}
	a.epoch++
	a.dialogOpen = false
	a.add.Password = ""
	a.add.ShowPassword = false
	a.recreate.Password = ""
	a.recreate.ShowPassword = false
	a.deletePlan = nil
	a.recreatePlan = nil
	a.transferPlan = nil
	a.ack = false
}
func (a *App) Refresh() {
	if a.loading {
		a.refreshAgain = true
		return
	}
	a.loading = true
	a.work(func(ctx context.Context) func() {
		result, err := a.backend.List(ctx)
		return func() {
			a.loading = false
			if a.refreshAgain {
				a.refreshAgain = false
				a.Refresh()
				return
			}
			if err != nil {
				a.notify(err.Error())
				a.record("读取配置失败：" + err.Error())
				return
			}
			a.overview = result
		}
	})
}
func (a *App) check(alias string) {
	if a.checking[alias] || a.changing {
		return
	}
	a.checking[alias] = true
	a.work(func(ctx context.Context) func() {
		row, err := a.backend.Check(ctx, alias)
		return func() {
			delete(a.checking, alias)
			if err != nil {
				a.notify(alias + "：" + err.Error())
				a.record(alias + " 检测失败：" + err.Error())
				return
			}
			for i, s := range a.overview.Servers {
				if s.Alias == alias {
					a.overview.Servers[i] = row
				}
			}
			a.record(alias + "：" + stateLabel(row.State))
		}
	})
}
func (a *App) checkAll() {
	if a.batch || a.changing {
		return
	}
	aliases := []string{}
	for _, s := range a.overview.Servers {
		if a.checking[s.Alias] {
			continue
		}
		a.checking[s.Alias] = true
		aliases = append(aliases, s.Alias)
	}
	a.batch = true
	a.work(func(ctx context.Context) func() {
		type result struct {
			alias string
			row   desk.Server
			err   error
		}
		results := make([]result, len(aliases))
		var next int
		var mu sync.Mutex
		var wg sync.WaitGroup
		for range min(3, len(aliases)) {
			wg.Go(func() {
				for {
					mu.Lock()
					i := next
					next++
					mu.Unlock()
					if i >= len(aliases) {
						return
					}
					row, err := a.backend.Check(ctx, aliases[i])
					results[i] = result{aliases[i], row, err}
				}
			})
		}
		wg.Wait()
		return func() {
			a.batch = false
			for _, r := range results {
				delete(a.checking, r.alias)
				if r.err != nil {
					a.record(r.alias + " 检测失败：" + r.err.Error())
					continue
				}
				for i, s := range a.overview.Servers {
					if s.Alias == r.alias {
						a.overview.Servers[i] = r.row
					}
				}
				a.record(r.alias + "：" + stateLabel(r.row.State))
			}
			a.notify("全部检测完成，结果已更新")
		}
	})
}
func (a *App) export() {
	epoch := a.epoch
	a.work(func(ctx context.Context) func() {
		path, err := a.backend.Export(ctx)
		return func() {
			if err != nil {
				a.notify(err.Error())
				return
			}
			if a.dialogOpen || epoch != a.epoch {
				a.record("智能体清单已导出：" + path)
				a.notify("智能体清单已导出：" + path)
				return
			}
			a.detail("智能体清单已导出", fmt.Sprintf("文件：%s\n\n在相应智能体的说明文件中加入：\n执行远程部署前，先读取 %s，使用其中的 SSH 别名连接目标服务器，并重新确认可访问性。\n\n清单不包含密码或私钥。其他电脑或隔离环境需要独立授权。", path, path))
			a.record("已导出智能体服务器清单")
		}
	})
}
func (a *App) visible() []desk.Server {
	rows := []desk.Server{}
	query := strings.ToLower(a.search)
	for _, s := range a.overview.Servers {
		if !strings.Contains(strings.ToLower(s.Alias+" "+s.Host+" "+s.User), query) {
			continue
		}
		if a.filter == "密钥可用" && s.State != "key_ready" || a.filter == "尚未检测" && s.State != "unknown" || a.filter == "需要处理" && (s.State == "unknown" || s.State == "key_ready") {
			continue
		}
		rows = append(rows, s)
	}
	return rows
}
func stateLabel(state string) string {
	switch state {
	case "unknown":
		return "尚未检测"
	case "checking":
		return "正在检测"
	case "key_ready":
		return "密钥可用"
	case "auth_failed":
		return "认证失败"
	case "unreachable":
		return "网络不可达"
	case "host_untrusted":
		return "指纹待确认"
	case "host_changed":
		return "指纹已变化"
	default:
		return "检测异常"
	}
}
