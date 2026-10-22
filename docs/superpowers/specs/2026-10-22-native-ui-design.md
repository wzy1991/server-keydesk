# Native Go UI migration

User-approved direction: use pure Go native UI and retain the current appearance. Keep mygo v0.5.5 and the existing desk.Service backend, SSH files, identities, confirmation boundaries and receipt wording.

Use mygo/ui Content rather than a URL/SetFrontend/RPC binding. Preserve the dark green sidebar, compact header/statistics, left server list, right add form, activity/help pages and green buttons. All controls, scrolling and modal dialogs are built in Go. Preserve the executable and native window icons. Do not load HTML, JavaScript or a WebView in the release path.

Latest user amendment: move the add-key form into a modal opened by “添加服务器”, use the full main pane for the server list, and reduce the main window width. This supersedes the right-column form above. Default native window 1000×760, minimum 820×640; render checks at 1000×720, 900×680, 800×600 content sizes. Keep the same colors, typography and interaction boundaries.

The existing backend remains authoritative. A native controller calls its typed methods on workers, returning results to the UI thread through a completion queue. Cancellation is tied to the window/app lifetime; no worker directly modifies view state. Fingerprint inspection happens before password submission; secret fields are cleared on cancellation, failure and completion. Delete/recreate/transfer retain one-use backend tokens and explicit acknowledgement, with plans invalidated on edited inputs. Busy destructive operations keep their dialog open. Closing a pending preview prevents a late result reopening it.

Match the current compact layout at 1320×840, 1280×720 and 940×660 content sizes. Routine server tasks and the complete add form remain visible. Only long server lists, help/activity and oversized dialog contents scroll. Text uses Windows font shaping and Chinese input support.

Alternatives: retaining HTML contradicts the explicit migration request; mixing native controls with web dialogs leaves a web dependency and splits the interface. Therefore the selected implementation is wholly mygo/ui with the existing Go backend.

Verification: native headless ui.Tester tests for navigation/search/filter, inspection before credentials, cancel/cleanup, delete/recreate/transfer confirmation, edited/stale previews, busy async results and small-window geometry. Render native preview PNGs with fixture data. Run existing backend tests unchanged, go vet and official mygo Windows packaging, verify icon resources and inspect the actual native window where the desktop helper permits. All tests use temporary profiles or fixture backend objects; no real SSH credentials or hosts.
