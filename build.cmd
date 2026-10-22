@echo off
setlocal
cd /d "%~dp0"
set CGO_ENABLED=0
go test ./...
if errorlevel 1 exit /b 1
go vet ./...
if errorlevel 1 exit /b 1
rem mygo build embeds the Windows icon, version information and DPI manifest.
go run github.com/egoist/mygo/cmd/mygo@v0.5.5 build -platform windows/amd64
if errorlevel 1 exit /b 1
copy /y "dist\windows-amd64\Server-Keydesk.exe" "Server-Keydesk.exe" >nul
if errorlevel 1 exit /b 1
echo Built Server-Keydesk.exe
