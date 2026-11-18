package main

import (
	_ "embed"
	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"log"
	"os"
	"server-keydesk/internal/desk"
	"server-keydesk/internal/nativeui"
)

//go:embed resources/icon.png
var appIcon []byte

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	app := nativeui.New(desk.NewService(home))
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
