package main

import (
	_ "embed"
	"github.com/egoist/mygo"
	"github.com/egoist/mygo/plugins/terminal"
	"github.com/egoist/mygo/plugins/updater"
	"github.com/egoist/mygo/plugins/updater/native"
	"github.com/egoist/mygo/ui"
	"log"
	"os"
	"server-keydesk/internal/desk"
	"server-keydesk/internal/nativeui"
)

//go:embed resources/icon.png
var appIcon []byte

func main() {
	mygo.Use(native.New(updater.Options{Icon: appIcon}))
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	app := nativeui.New(desk.NewService(home))
	app.Version = mygo.App.Version()
	app.CheckForUpdates = updater.CheckForUpdates
	app.TerminalFactory = func(alias string, command []string, onExit func(int)) (nativeui.TerminalHandle, error) {
		term, err := terminal.New(terminal.Options{
			Command: command,
			Dir:     home,
			OnTitle: func(title string) {},
			OnExit:  onExit,
		})
		if err != nil {
			return nil, err
		}
		return embeddedTerminal{term}, nil
	}
	app.TerminalView = func(c *ui.Context, handle nativeui.TerminalHandle) ui.Element {
		wrapper, _ := handle.(embeddedTerminal)
		if wrapper.term == nil {
			return ui.Text(c, "内嵌终端不可用").FontSize(12)
		}
		return terminal.View(c, wrapper.term).Fill().AutoFocus()
	}
	defer app.Close()
	mygo.App.WhenReady(func() {
		window := mygo.NewWindow(mygo.WindowOptions{Title: "Server Keydesk · SSH 公钥助手", Content: ui.View(app.View), Width: 1000, Height: 760, MinWidth: 820, MinHeight: 640})
		app.PickPrivateKey = func() (string, error) {
			paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: window, Title: "选择 SSH 私钥文件", ShowHiddenFiles: true})
			if err != nil || len(paths) == 0 {
				return "", err
			}
			return paths[0], nil
		}
		window.OnClosed(app.Close)
		if err := window.SetIcon(appIcon); err != nil {
			log.Printf("设置窗口图标失败: %v", err)
		}
		app.Refresh()
	})
	if err := mygo.App.Run(); err != nil {
		log.Fatal(err)
	}
}

type embeddedTerminal struct{ term *terminal.Terminal }

func (t embeddedTerminal) Close() { _ = t.term.Close() }
