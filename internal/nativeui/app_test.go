package nativeui

import (
	"context"
	"errors"
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"
	"server-keydesk/internal/desk"
)

// The network boundary is substituted; the real native controls, controller,
// confirmation state and worker completion paths run in every test.
type fixtureBackend struct {
	rows                                        []desk.Server
	installed, deleted, recreated, sent, checks int
	fail                                        bool
}

func fixture() *fixtureBackend {
	return &fixtureBackend{rows: []desk.Server{{Target: desk.Target{Alias: "prod-web", Host: "203.0.113.10", User: "ubuntu", Port: 22}, State: "auth_failed"}, {Target: desk.Target{Alias: "office-pc", Host: "192.0.2.20", User: "operator", Port: 22}, State: "key_ready"}}}
}
func (f *fixtureBackend) List(context.Context) (desk.Overview, error) {
	return desk.Overview{Servers: append([]desk.Server(nil), f.rows...), ConfigPath: "C:/Users/You/.ssh/config", KeyPath: "C:/Users/You/.ssh/keydesk_ed25519", InventoryPath: "C:/Users/You/.ssh/keydesk/servers.md"}, nil
}
func (f *fixtureBackend) Check(_ context.Context, a string) (desk.Server, error) {
	f.checks++
	for _, s := range f.rows {
		if s.Alias == a {
			s.State = "key_ready"
			return s, nil
		}
	}
	return desk.Server{}, errors.New("missing alias")
}
func (f *fixtureBackend) Probe(context.Context, desk.Target) (desk.HostInfo, error) {
	return desk.HostInfo{Algorithm: "ssh-ed25519", Fingerprint: "SHA256:ExampleHostFingerprint"}, nil
}
func (f *fixtureBackend) Install(_ context.Context, r desk.InstallRequest) (desk.Server, error) {
	if (r.Password != "fixture-password" && !(r.PrivateKeyPath == "C:/fixture/key" && r.Passphrase == "secret" && r.Password == "")) || r.Fingerprint != "SHA256:ExampleHostFingerprint" {
		return desk.Server{}, errors.New("incorrect credentials or fingerprint")
	}
	f.installed++
	if f.fail {
		return desk.Server{}, errors.New("认证失败")
	}
	return desk.Server{Target: r.Target, State: "key_ready"}, nil
}
func (f *fixtureBackend) Export(context.Context) (string, error) {
	return "C:/Users/You/.ssh/keydesk/servers.md", nil
}
func (f *fixtureBackend) PrepareDelete(_ context.Context, a string) (desk.DeletePlan, error) {
	return desk.DeletePlan{Token: "delete-once", Alias: a, Files: []string{"C:/Users/You/.ssh/config"}, Warning: "仅删除本机连接；保留私钥和远程公钥。"}, nil
}
func (f *fixtureBackend) DeleteConnection(_ context.Context, token string, yes bool) (desk.MaintenanceResult, error) {
	if token != "delete-once" || !yes {
		return desk.MaintenanceResult{}, errors.New("confirmation required")
	}
	f.deleted++
	f.rows = f.rows[:1]
	return desk.MaintenanceResult{Alias: "office-pc", State: "deleted", Detail: "本机连接已删除", Backups: []string{"C:/Users/You/.ssh/keydesk/config-backups/config.bak"}}, nil
}
func (f *fixtureBackend) PrepareRecreate(_ context.Context, t desk.Target) (desk.RecreatePlan, error) {
	return desk.RecreatePlan{Token: "recreate-once", Target: t, Host: desk.HostInfo{Algorithm: "ssh-ed25519", Fingerprint: "SHA256:NewHostFingerprint"}, HostChanged: true, Files: []string{"C:/Users/You/.ssh/config"}, Warning: "主机指纹已变化，核对后创建独立新密钥。旧密钥保留。"}, nil
}
func (f *fixtureBackend) RecreateConnection(_ context.Context, token, password string, yes bool) (desk.MaintenanceResult, error) {
	if token != "recreate-once" || password != "fixture-password" || !yes {
		return desk.MaintenanceResult{}, errors.New("confirmation required")
	}
	f.recreated++
	if f.fail {
		return desk.MaintenanceResult{}, errors.New("密码认证失败，原连接未切换")
	}
	return desk.MaintenanceResult{Alias: "prod-web", State: "key_ready", Detail: "独立新密钥已安装并验证", KeyPath: "C:/Users/You/.ssh/keydesk/keys/example/id_ed25519"}, nil
}
func (f *fixtureBackend) PrepareTransfer(_ context.Context, r desk.TransferRequest) (desk.TransferPlan, error) {
	return desk.TransferPlan{Token: "transfer-once", Source: f.rows[0].Target, Destination: f.rows[1].Target, RemoteAlias: r.RemoteAlias, ReceiverMachine: "OFFICE-PC", ReceiverUser: "operator", ReceiverHome: "C:/Users/operator", Fingerprint: "SHA256:ExampleKeyFingerprint", Warning: "将复制私钥及其对所有已授权服务器的访问权限。"}, nil
}
func (f *fixtureBackend) SendTransfer(_ context.Context, token string, yes bool) (desk.TransferResult, error) {
	if token != "transfer-once" || !yes {
		return desk.TransferResult{}, errors.New("confirmation required")
	}
	f.sent++
	state := "key_ready"
	if f.fail {
		state = "unreachable"
	}
	return desk.TransferResult{OK: true, Alias: "prod-web", State: state, Detail: "连接已保存到 B，但 B 无法连接 C", KeyPath: "C:/Users/operator/.ssh/keydesk/imported/example/id_ed25519"}, nil
}
func testApp(t *testing.T) (*App, *fixtureBackend, *ui.Tester) {
	t.Helper()
	b := fixture()
	a := New(b)
	a.execute = func(fn func()) { fn() }
	t.Cleanup(a.Close)
	a.Refresh()
	tt := ui.NewTester(a.View, 1320, 840)
	return a, b, tt
}
func click(t *testing.T, tt *ui.Tester, label string) {
	t.Helper()
	if err := tt.Click(label); err != nil {
		t.Fatal(err)
	}
}

func TestNativeNavigationSearchFilterAndNoAutomaticConnection(t *testing.T) {
	a, b, tt := testApp(t)
	if b.checks != 0 || !tt.HasText("prod-web") {
		t.Fatal("startup connected or omitted server")
	}
	a.search = "office"
	tt.Frame()
	_, prodShown := tt.Find("prod-web")
	_, officeShown := tt.Find("office-pc")
	if prodShown || !officeShown {
		t.Fatal("search not applied")
	}
	a.search = ""
	a.filter = "需要处理"
	tt.Frame()
	if tt.HasText("office-pc") {
		t.Fatal("status filter not applied")
	}
	click(t, tt, "操作记录")
	if !tt.HasText("还没有操作记录") {
		t.Fatal("missing activity")
	}
	click(t, tt, "使用说明")
	if !tt.HasText("让不同智能体使用") {
		t.Fatal("missing guide")
	}
}
func TestNativeInstallRequiresFingerprintAndClearsPassword(t *testing.T) {
	a, b, tt := testApp(t)
	a.add = connectionForm{Host: "203.0.113.9", User: "ubuntu", Port: "22", Alias: "new-server", Password: "fixture-password"}
	tt.Frame()
	click(t, tt, "添加服务器")
	click(t, tt, "检查指纹并安装公钥")
	if b.installed != 0 || !tt.HasText("SHA256:ExampleHostFingerprint") {
		t.Fatal("password submitted before fingerprint confirmation")
	}
	click(t, tt, "取消")
	if a.add.Password != "" || b.installed != 0 {
		t.Fatal("cancel retained password or installed key")
	}
	a.add.Password = "fixture-password"
	tt.Frame()
	click(t, tt, "添加服务器")
	click(t, tt, "检查指纹并安装公钥")
	click(t, tt, "指纹正确，安装公钥")
	if b.installed != 1 || a.add.Password != "" {
		t.Fatal("installation or secret cleanup failed")
	}
}
func TestNativeDeleteCancelAndBackupReceipt(t *testing.T) {
	_, b, tt := testApp(t)
	click(t, tt, "删除 office-pc")
	click(t, tt, "取消")
	if b.deleted != 0 {
		t.Fatal("cancel deleted")
	}
	click(t, tt, "删除 office-pc")
	click(t, tt, "删除本机连接")
	if b.deleted != 1 || !tt.HasText("连接已删除 · 配置备份") {
		t.Fatal("delete receipt missing")
	}
}
func TestNativeRecreateAcknowledgementEditedTargetAndFailureCleanup(t *testing.T) {
	a, b, tt := testApp(t)
	click(t, tt, "重新创建 prod-web")
	a.recreate.Password = "fixture-password"
	tt.Frame()
	click(t, tt, "检查服务器指纹")
	click(t, tt, "安装新密钥并替换连接")
	if b.recreated != 0 {
		t.Fatal("unconfirmed recreate executed")
	}
	a.ack = true
	tt.Frame()
	a.recreate.Host = "203.0.113.11"
	a.invalidateRecreate()
	tt.Frame()
	click(t, tt, "安装新密钥并替换连接")
	if b.recreated != 0 {
		t.Fatal("edited plan remained valid")
	}
	click(t, tt, "检查服务器指纹")
	a.ack = true
	b.fail = true
	tt.Frame()
	click(t, tt, "安装新密钥并替换连接")
	if a.recreate.Password != "" || a.recreatePlan != nil || !tt.HasText("密码认证失败，原连接未切换") {
		t.Fatal("failed recreate did not clear secret/token")
	}
	click(t, tt, "取消")
	if a.recreate.Password != "" {
		t.Fatal("cancel retained secret")
	}
}
func TestNativeTransferRequiresAcknowledgementAndDistinguishesUnreachable(t *testing.T) {
	a, b, tt := testApp(t)
	click(t, tt, "发送连接到其他电脑")
	click(t, tt, "检查 A → C 与接收电脑 B")
	click(t, tt, "确认并发送私钥与连接")
	if b.sent != 0 {
		t.Fatal("unacknowledged private transfer")
	}
	a.ack = true
	b.fail = true
	tt.Frame()
	click(t, tt, "确认并发送私钥与连接")
	if b.sent != 1 || !tt.HasText("连接和密钥已保存到 B，但 B → C 未通过验证。") {
		t.Fatal("stored/unreachable distinction missing")
	}
}
func TestNativeLatePreviewCannotReopenCancelledDialog(t *testing.T) {
	a, b, tt := testApp(t)
	var work []func()
	a.execute = func(fn func()) { work = append(work, fn) }
	click(t, tt, "删除 office-pc")
	click(t, tt, "取消")
	for _, fn := range work {
		fn()
	}
	tt.Frame()
	if a.dialogOpen || b.deleted != 0 {
		t.Fatal("late preview reopened or committed")
	}
}

func TestNativeRefreshRequestedDuringLoadIsNotLost(t *testing.T) {
	a, _, tt := testApp(t)
	var work []func()
	a.execute = func(fn func()) { work = append(work, fn) }
	a.Refresh()
	a.Refresh()
	work[0]()
	tt.Frame()
	if len(work) != 2 {
		t.Fatal("refresh after a configuration change was lost while an older list was loading")
	}
	work[1]()
	tt.Frame()
	if a.loading {
		t.Fatal("follow-up refresh never completed")
	}
}

func TestNativeLateExportCannotReplaceBusyTransferDialog(t *testing.T) {
	a, _, tt := testApp(t)
	var work []func()
	a.execute = func(fn func()) { work = append(work, fn) }
	a.export()
	a.execute = func(fn func()) { fn() }
	a.openTransfer()
	a.prepareTransfer()
	tt.Frame()
	a.ack = true
	a.execute = func(fn func()) { work = append(work, fn) }
	a.sendTransfer()
	work[0]()
	tt.Frame()
	if a.dialog != "transfer" || !a.dialogBusy || !a.dialogOpen {
		t.Fatal("late export replaced the busy private-key transfer dialog")
	}
}

func TestNativeRecreateSuccessUsingActualConfirmationControl(t *testing.T) {
	a, b, tt := testApp(t)
	click(t, tt, "重新创建 prod-web")
	a.recreate.Password = "fixture-password"
	tt.Frame()
	click(t, tt, "检查服务器指纹")
	click(t, tt, "我已通过可信渠道核对指纹，确认安装新密钥并替换此连接。")
	click(t, tt, "安装新密钥并替换连接")
	if b.recreated != 1 || a.recreate.Password != "" || !tt.HasText("连接密钥已重新创建") {
		t.Fatal("confirmed recreation did not complete or retained password")
	}
}

func TestNativeBusyDeletionCannotBeDismissed(t *testing.T) {
	a, b, tt := testApp(t)
	click(t, tt, "删除 office-pc")
	var work []func()
	a.execute = func(fn func()) { work = append(work, fn) }
	click(t, tt, "删除本机连接")
	tt.Key(0, ui.KeyEscape)
	click(t, tt, "取消")
	if !a.dialogOpen || !a.dialogBusy || b.deleted != 0 {
		t.Fatal("pending deletion dialog was dismissed")
	}
	work[0]()
	tt.Frame()
	if b.deleted != 1 || !tt.HasText("连接已删除 · 配置备份") {
		t.Fatal("busy deletion did not finish")
	}
}

func TestNativeTransferEditedAliasInvalidatesReadyPlan(t *testing.T) {
	a, b, tt := testApp(t)
	click(t, tt, "发送连接到其他电脑")
	click(t, tt, "检查 A → C 与接收电脑 B")
	click(t, tt, "我信任接收电脑 B，确认复制私钥及其访问权限。")
	click(t, tt, "保存在 B 上的连接别名")
	// The visible caption precedes the equally named accessible input. Click
	// inside the field below that caption, as an actual pointer user does.
	r, _ := tt.Find("保存在 B 上的连接别名")
	tt.ClickAt(r.X+40, r.Y+r.H+16)
	tt.Type("-renamed")
	click(t, tt, "确认并发送私钥与连接")
	if a.transferPlan != nil || a.ack || b.sent != 0 {
		t.Fatal("edited native input retained old transfer authority")
	}
}

func TestNativeInstallPreflightCannotBeInterruptedByDetails(t *testing.T) {
	a, b, tt := testApp(t)
	a.add = connectionForm{Host: "203.0.113.9", User: "ubuntu", Port: "22", Alias: "new-server", Password: "fixture-password"}
	var work []func()
	a.execute = func(fn func()) { work = append(work, fn) }
	tt.Frame()
	click(t, tt, "添加服务器")
	click(t, tt, "检查指纹并安装公钥")
	click(t, tt, "查看 prod-web 的连接详情")
	if a.dialog != "add" || !a.dialogBusy {
		t.Fatal("details interrupted the pending password-install preflight")
	}
	work[0]()
	tt.Frame()
	a.execute = func(fn func()) { fn() }
	click(t, tt, "指纹正确，安装公钥")
	if b.installed != 1 {
		t.Fatal("preflight left an unusable trust confirmation")
	}
}

func TestNativeSuccessfulTransferRetryClearsOldFailureReceipt(t *testing.T) {
	a, b, tt := testApp(t)
	click(t, tt, "发送连接到其他电脑")
	click(t, tt, "检查 A → C 与接收电脑 B")
	a.ack = true
	b.fail = true
	tt.Frame()
	click(t, tt, "确认并发送私钥与连接")
	if !tt.HasText("B 无法连接 C") {
		t.Fatal("fixture did not exercise saved-but-unreachable result")
	}
	b.fail = false
	click(t, tt, "检查 A → C 与接收电脑 B")
	a.ack = true
	tt.Frame()
	click(t, tt, "确认并发送私钥与连接")
	if !tt.HasText("已发送并验证 B → C。") || tt.HasText("B 无法连接 C") {
		t.Fatal("successful retry retained stale failure details")
	}
}
func TestNativeCompactLayoutAndLongList(t *testing.T) {
	for _, count := range []int{2, 80} {
		for _, size := range [][2]int{{1000, 720}, {900, 680}, {800, 600}} {
			t.Run(fmt.Sprintf("%d-%dx%d", count, size[0], size[1]), func(t *testing.T) {
				a, _, tt := testApp(t)
				if count == 80 {
					for i := 2; i < count; i++ {
						a.overview.Servers = append(a.overview.Servers, desk.Server{Target: desk.Target{Alias: fmt.Sprintf("server-%d", i), Host: "203.0.113.1", User: "ubuntu", Port: 22}, State: "unknown"})
					}
				}
				tt.SetSize(size[0], size[1])
				tt.Frame()
				for _, label := range []string{"添加服务器", "服务器列表"} {
					r, ok := tt.Find(label)
					if !ok || r.Y < 0 || r.Y+r.H > float32(size[1]) || r.X+r.W > float32(size[0]) {
						t.Fatalf("control outside viewport %s: %+v", label, r)
					}
				}
				if tt.HasText("登录密码") {
					t.Fatal("add form remains fixed on main page")
				}
				if count == 80 && a.listScroll.MaxY <= 0 {
					t.Fatal("long server list does not scroll internally")
				}
				click(t, tt, "添加服务器")
				r, ok := tt.Find("检查指纹并安装公钥")
				if !ok || r.Y+r.H > float32(size[1]) {
					t.Fatal("add dialog outside compact viewport")
				}
			})
		}
	}
}
func TestNativePreview(t *testing.T) {
	dir := os.Getenv("KEYDESK_PREVIEW_DIR")
	if dir == "" {
		t.Skip("preview export only when explicitly requested")
	}
	a, _, tt := testApp(t)
	tt.SetSize(1000, 720)
	os.MkdirAll(dir, 0700)
	save := func(name string) {
		f, e := os.Create(filepath.Join(dir, name))
		if e != nil {
			t.Fatal(e)
		}
		defer f.Close()
		if e = png.Encode(f, tt.Image()); e != nil {
			t.Fatal(e)
		}
	}
	save("preview-native.png")
	click(t, tt, "添加服务器")
	save("preview-native-add.png")
	a.closeDialog()
	tt.Frame()
	click(t, tt, "重新创建 prod-web")
	click(t, tt, "检查服务器指纹")
	save("preview-native-recreate.png")
	a.closeDialog()
	tt.Frame()
	click(t, tt, "发送连接到其他电脑")
	click(t, tt, "检查 A → C 与接收电脑 B")
	save("preview-native-transfer.png")
	if strings.Contains(strings.Join(tt.Texts(), "\n"), "fixture-password") {
		t.Fatal("password in visible text")
	}
}

func TestNativeExistingKeyFlow(t *testing.T) {
	a, b, tt := testApp(t)
	a.add = connectionForm{Host: "203.0.113.9", User: "ubuntu", Port: "22", Alias: "existing", UsePrivateKey: true, PrivateKeyPath: "C:/fixture/key", Passphrase: "secret"}
	tt.Frame()
	click(t, tt, "添加服务器")
	if !tt.HasText("私钥文件") {
		t.Fatal("missing private key field")
	}
	click(t, tt, "检查服务器指纹")
	if b.installed != 0 {
		t.Fatal("authenticated before confirmation")
	}
	click(t, tt, "取消")
	if a.add.Passphrase != "" {
		t.Fatal("cancel retained passphrase")
	}
	a.add.Passphrase = "secret"
	click(t, tt, "添加服务器")
	click(t, tt, "检查服务器指纹")
	click(t, tt, "指纹正确，保存连接")
	if b.installed != 1 || a.add.Passphrase != "" {
		t.Fatal("key request or cleanup failed")
	}
	for _, entry := range a.log {
		if strings.Contains(entry.Message, "公钥安装成功") {
			t.Fatal("incorrect install receipt")
		}
	}
}

func TestPrivateKeyPicker(t *testing.T) {
	a, _, tt := testApp(t)
	a.add.UsePrivateKey = true
	a.PickPrivateKey = func() (string, error) { return "C:/keys/selected.pem", nil }
	click(t, tt, "添加服务器")
	click(t, tt, "选择私钥文件")
	if a.add.PrivateKeyPath != "C:/keys/selected.pem" {
		t.Fatal("selection not applied")
	}
	a.PickPrivateKey = func() (string, error) { return "", nil }
	click(t, tt, "选择私钥文件")
	if a.add.PrivateKeyPath != "C:/keys/selected.pem" || a.dialogBusy {
		t.Fatal("cancel lost selection or left busy")
	}
}

func TestNativeAliasIsCopyable(t *testing.T) {
	a, _, tt := testApp(t)

	// 1. One-click copy button in the server row.
	click(t, tt, "复制别名 prod-web")
	if got := tt.Clipboard(); got != "prod-web" {
		t.Fatalf("copy button clipboard = %q, want %q", got, "prod-web")
	}
	if a.toast != "已复制主机别名：prod-web" {
		t.Fatalf("toast = %q, want copy confirmation", a.toast)
	}

	// 2. Direct text selection and Cmd/Ctrl+C on the alias text.
	tt.SetClipboard("")
	r, ok := tt.Find("office-pc")
	if !ok {
		t.Fatal("missing office-pc alias")
	}
	tt.ClickAt(r.X+r.W/2, r.Y+r.H/2)
	tt.Key(ui.Cmd, ui.KeyA)
	tt.Key(ui.Cmd, ui.KeyC)
	if got := tt.Clipboard(); got != "office-pc" {
		t.Fatalf("selectable alias clipboard = %q, want %q", got, "office-pc")
	}

	// 3. Copy button inside the recreate dialog.
	tt.SetClipboard("")
	click(t, tt, "重新创建 prod-web")
	click(t, tt, "复制连接别名 prod-web")
	if got := tt.Clipboard(); got != "prod-web" {
		t.Fatalf("recreate dialog copy clipboard = %q, want %q", got, "prod-web")
	}
}
