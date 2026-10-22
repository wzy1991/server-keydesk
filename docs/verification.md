# Verification and implementation record

## Decisions

- Windows x64 release, because this is the user's current desktop. mygo embedded webview + Go; no frontend build tool at runtime.
- Dedicated unencrypted app identity with current-user-only protected DACL, for noninteractive deployment access. Existing personal keys are preserved.
- Explicit host fingerprint review in the UI; mismatched known host keys block bootstrap.
- Detect successful key authentication instead of claiming to enumerate all machines or infer key absence from network errors.
- Prepend specific host entries and reset Host * before original bytes; appending would let earlier catch-all defaults override the new account/port.
- System OpenSSH default config loading is retained in production, including system ssh_config. Isolated tests use an explicit temporary config.
- First-time password bootstrap requires a direct route. Existing alias checks retain ProxyJump/ProxyCommand behavior.

## Independent review

A fresh read-only reviewer found four important issues; all were addressed:

1. Commented/quoted key text was mistaken for an installed key → quote-aware authorized_keys tokenization and a failing-then-passing shell regression test.
2. Explicit ACL entries survived permission repair → replace the protected Windows DACL with a current-user-only DACL; failing-then-passing Everyone-read regression.
3. Explicit -F suppressed system ssh_config → normal production execution omits -F; isolated test homes still use it.
4. Compressed IPv6 beginning with ':' was rejected → netip address parsing; failing-then-passing validation regression.

## Coverage and limits

13 Go tests, including a real local SSH protocol fixture and system OpenSSH subprocess. Remote installer script executed in temporary homes via POSIX sh. Frontend tests run with an explicit RPC fixture, separately from Go backend tests. Actual mygo Windows window launched and inspected; no real server was contacted by verification.

Checks: go test ./... -count=1; go vet ./...; node --check web/app.js; Windows release build. Tests never create keys in the user's real .ssh. The user may independently operate the running desktop app.

No deferred review findings. Not validated on every Linux distribution or real server policy; first-time proxy/bootstrap and interactive MFA are outside this version.

## Connection transfer update

Added a Windows receiver and explicit desktop transfer flow. A verifies the selected app-managed C identity before preparing a transfer, checks B over its existing SSH alias, then issues an expiring one-use token. No private bytes are returned to the frontend. Sending rechecks frozen source/destination config digests and the key fingerprint. Fixed receiver code travels as a compressed PowerShell command; the private payload travels only on SSH stdin.

Receiver imports into a distinct protected key path, preserves B's native key and original config, detects conflicting aliases/includes, pins C's actual verified host key and checks the saved alias using native OpenSSH. Receipts distinguish stored-but-unreachable from verified. Only state enums and booleans are accepted from a post-transfer receipt; arbitrary remote text cannot echo private data into UI/errors/activity.

Independent review findings addressed: receipt echo leakage; unquoted paths containing spaces; isolated verification incorrectly bypassing saved alias behavior; commented Host/Include directives producing false conflicts. A proposed case-sensitivity finding was withdrawn (PowerShell -replace is already case insensitive); equals/casing tests remain useful regressions.

Additional integration caught OpenSSH 8.1's unsupported KnownHostsCommand. A bounded, network-free option probe now omits that directive on older clients; no IgnoreUnknown directive is persisted. This preserves parsing of unrelated aliases and their own IgnoreUnknown lists. End-to-end test uses the exact production PowerShell bootstrap, temporary Windows B home, real private identity and actual system OpenSSH against a local SSH protocol server; checks successful verification and rejection of an incompatible inherited HostKeyAlias. Unicode and space-containing receiver paths are covered.

All transfer tests use isolated temporary profiles and generated test keys. No user's real private key or real remote host is involved. Known limitation: actual encrypted A→B transport is exercised through system OpenSSH in the application; automated receiver integration substitutes a local process boundary for that hop. Real B's SSH policies/network still need a user-initiated run.

Final update verification: 25 top-level Go tests passed, zero failures and zero skipped; go vet ./... passed; node syntax checks passed; 9 transfer UI scenarios passed; Windows release build passed. Portable and source ZIP archives validated after creation.

## Delete, recreate and compact layout update

Implemented local alias deletion and independent key recreation with five-minute, one-use confirmation plans. Deletion preserves shared private keys and remote authorization. Recreation inspects host identity without sending the password, verifies a new connection-specific identity before switching configuration, and keeps the old identity. Default known_hosts mismatches require explicit new-fingerprint confirmation; custom trust-file history must be compared separately. Revoked default trust records remain blocked.

Configuration editing preserves unrelated bytes, CRLF, multi-alias Host bodies and ordinary global Include/Match behavior. Exact backups are stored outside broad Include directories. Snapshots cover file identity, parent identity, bytes/mode/timestamp and Include match lists. Stale plans are rejected before remote side effects and revalidated during commit. Later write failures trigger guarded rollback. Replacing a Windows config preserves its original effective DACL before writing contents, including included configs under a broadly accessible parent.

Read-only independent review identified two reproducible gaps: newly matched Include files were detected only after remote installation, and inherited HostKeyAlias could break the newly pinned native alias. Failing regressions were added; the full plan is now validated before identity creation, and incompatible HostKeyAlias is rejected during preparation. Password cleanup on dialog cancellation/completion was verified after fixing an asynchronous close-event timing gap.

Latest backend verification: **50 top-level Go tests passed, zero failures/skips**, including actual OpenSSH and Windows PowerShell receiver integration. go vet ./... passed. Four focused recreate tests passed again after final path-safety changes. Frontend: 12 maintenance scenarios and 9 existing transfer scenarios passed. Layout regression covered 2 and 80 sample servers at 1320×840, 1280×720, 940×660 and 1060×660: no page overflow, complete add form visible, long lists scroll internally. Windows release build passed. Native launch succeeded; a fresh native screenshot could not be captured because the Windows automation helper reported no foreground process ID, so latest geometry validation uses the browser rendering of the embedded assets.

## Windows icon fix

Root cause: the previous plain `go build` path did not emit Windows icon resources, and main.go did not set a native window icon. The HTML favicon does not configure the EXE or native titlebar/taskbar. A resource-level regression reproduced the absence of RT_GROUP_ICON type14/id1 in the old EXE.

Added a 1024px PNG rendered from the existing SVG key logo, an explicit native window SetIcon call, and mygo.json. Release builds now use the pinned official mygo CLI, which emits the Windows resources and manifest. The packaged EXE passes the same regression: icon group1 contains valid 32-bit PNG payloads at 16/24/32/48/64/128/256px, and the DPI manifest is present. main package compile and vet passed. SSH backend code is unchanged. Source archives retain the required embedded PNG; release packaging rechecks the actual EXE icon before generating archives.

## Pure Go native UI, version 0.2.0

Replaced the entire release UI with mygo/ui: main.go uses Content: ui.View and embeds only the PNG window icon. It does not call SetFrontend, BindAs or provide a window URL. Typed native actions reuse desk.Service directly; background workers return completion closures to the main-thread view. Closing the window cancels the shared IO context. No backend SSH configuration/key format changed.

Latest user amendment implemented: add-key access opens as a modal from “添加服务器”. The main page is a full-width server list; default window is 1000×760 (minimum 820×640). Native tests cover 2/80 servers in 1000×720, 900×680 and 800×600 content areas, verifying visible main actions, no fixed password form, a scrolling long list, and accessible add-modal action geometry. Fixture PNGs are produced directly by the native renderer.

Independent read-only review found three issues. Regression tests reproduced and fixed each: delayed export completion overriding a busy transfer dialog; status-detail navigation interrupting password-install preflight; successful transfer retries retaining prior failure detail. A separate async regression fixes a refresh request lost while a previous list load was running. Native input/checkbox tests verify confirmation, target edits invalidating plans, password cleanup, busy Escape/cancel behavior and saved-but-unreachable receipts. No review findings remain deferred.

Verification: full Go suite **65 top-level tests passed, zero failures/skips**, including 15 native interaction/layout/preview tests and the existing 50 backend tests; go vet ./... passed. Native tests passed again after final visual adjustments. Official mygo Windows build succeeded. A real native Windows window and native UI Automation control tree were inspected; the running process had no WebView/browser descendants. Only local configuration was listed in that window; no server checks, credential entry or server changes were performed. Release/source archives exclude the retired web UI and browser test artifacts; required icon source is retained.
