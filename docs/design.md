# Server Keydesk

Windows desktop application built with egoist/mygo, embedded HTML/CSS/JavaScript, and Go SSH backend.

## Scope

- Enter address, port (default 22), username, password, and a unique SSH alias.
- Show the SSH host fingerprint before credentials are sent; require explicit trust for an unknown host; reject changed host keys.
- Generate one dedicated Ed25519 key in ~/.ssh/keydesk_ed25519, with private key permissions restricted to the current user.
- Install its public key into the remote user's authorized_keys without replacing existing entries; verify a new public-key-only connection.
- Back up and prepend a concrete host entry to ~/.ssh/config, restore global scope with Host *, and retain all original bytes. Existing aliases are never overwritten.
- Discover concrete aliases, including Include files, and resolve them through ssh -G. Probe with the system OpenSSH client, so existing agents, keys, jump hosts, and ProxyCommand routes continue to work.
- Show verified key login, authentication failure, unknown/changed host key, unreachable, or unknown status. A failed connection cannot prove that a public key is absent.
- Export an agent-readable inventory; no password is persisted or logged. No automatic edits to agent-wide instruction files.

## Approach

Use mygo's embedded web frontend instead of native UI for a compact, accessible Chinese interface. Use Go SSH for first-time password bootstrap; use existing system OpenSSH for checking aliases. The app key is unencrypted to permit unattended use; its protected Windows DACL permits only the current user. Remote code is a fixed POSIX shell script with an internally generated public key. No extra service is exposed.

## Validation

Unit tests for input validation, config preservation/conflicts, key generation and file permissions, nested Include discovery, and status classification. Local SSH fixture tests for fingerprint trust, changed-key rejection, password bootstrap, public-key verification, and failures. Run the installation script in a temporary Linux-style home using Git's sh to verify idempotency, existing entries, and a missing trailing newline. Build a Windows GUI executable and inspect its rendered frontend.
