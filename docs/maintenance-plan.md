# Delete and recreate SSH connections

User intent: remove obsolete connections and recreate invalid SSH authentication without disrupting other connections or Windows machines sharing an identity.

## Behavior

- Delete is a local configuration action: explicit confirmation removes the selected alias from main/Include files and clears its status/inventory entry. Preserve private keys and remote authorized_keys because they may be shared. Back up edited files before writing. Show exact affected paths. Imported per-alias metadata is archived to permit future import under the same name.
- Recreate takes an existing alias plus address/user/port/password. Before sending credentials, inspect and show the actual host fingerprint, including a clearly marked changed fingerprint. After confirmation, generate a fresh, connection-specific Ed25519 key, pin that inspected host identity, install using password, verify the new key, then replace only that alias. Do not rotate the common default identity or revoke old remote keys. Changed host identities use the selected connection's dedicated pin file rather than overwriting the user's global known_hosts.
- Stop on stale plans, configuration edits, symlinks/reparse paths, unsupported ambiguous blocks or include cycles/limits. Secrets stay out of RPC responses and logs. New identities must remain compatible with Send Connection.

## Config editor interface

ConfigEdit {Path string; Before []byte; After []byte}; unexported/private bytes, never frontend.
PlanAliasRemoval(home,alias string) ([]ConfigEdit,error): discover main config and recursive user Include files; remove exact explicit alias from all matching Host sections. A multi-alias Host keeps other aliases and body; a single-alias block is removed to next Host/Match. Preserve unrelated bytes/line endings. Recognize old/new Keydesk marker comments. Never edit through symlinks/reparse points. Return main edit even if it is unchanged when main has no matching header, so recreation can prepend there. Read-only planning. Refuse removal when scope/Include semantics cannot be preserved safely.
CommitConfigEdits(home string,edits []ConfigEdit) ([]string,error): same .ssh/.keydesk-config.lock, validate all snapshots before edits, create exact-byte backups, atomic writes, roll back committed edits on a later failure only if untouched by others. Return backup paths. Parent main config always exists for an existing alias. Do not contact remote servers or delete key files.

## Tasks

1. Config editor and meaningful temp-file/OpenSSH -G regression tests.
2. Maintenance service: expiring one-use plans, fresh identities, changed-host explicit pinning, verify-before-switch, metadata/archive/status handling, concurrency checks.
3. Row action buttons and confirmation/recreation dialogs; correct password cleanup and accurately describe local deletion vs revocation.
4. Full Go suite, native PowerShell regressions, browser scenarios, independent review, release rebuild and archives.
