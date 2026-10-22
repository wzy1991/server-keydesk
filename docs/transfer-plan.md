# Windows-to-Windows connection transfer

Goal: A already has SSH aliases for Windows B and Linux C. Transfer the application-managed private identity and selected direct C profile to B through A's authenticated SSH connection to B. B must not generate another key or require another password login to C.

Implementation choices: dedicated imported-key filename on B; do not overwrite B's own app key. Transfer only on explicit UI confirmation; inform user that a shared private identity grants access to every server authorizing that key. Receiver requires Windows PowerShell 5.1 and OpenSSH, not an installed Keydesk app. C must be an app-managed direct SSH connection; proxy/certificate/custom identities are rejected with a useful message. Linux receivers are outside this change.

## Wire contract

Remote PowerShell preflight receives no input and returns one line prefixed KEYDESK_RESULT: followed by JSON with ok, home, user, sid, machine and aliases (string array). Go validates alias conflicts locally, then sends compact JSON to the receive script's stdin over SSH. Secrets never appear in command arguments, frontend RPC responses, exported inventory or logs.

Payload JSON: version=1; alias; host; port; user; keyId (64 lowercase hex SHA256 of public key wire bytes); fingerprint (OpenSSH SHA256 public fingerprint); privateKey (base64 OpenSSH private PEM bytes); publicKey (base64 authorized key line bytes); knownHosts (base64 UTF8 exact host-key pin for C); receiverSid; receiverMachine.

Receiver result JSON: ok; alias; keyPath; state (key_ready or a non-success state); detail; reused. Receiver rejects a different SID/machine, reparse paths, alias conflicts or different existing key bytes; protects private key DACL for the current SID before writing. Keys live in USERPROFILE/.ssh/keydesk/imported/<keyId>/id_ed25519, pins in known_hosts_<alias>. Only selected alias is installed, and original config is backed up and preserved. Use a .ssh config lock directory. An existing identical imported profile is idempotent; different aliases/configs are never overwritten. Test B→C using native OpenSSH with StrictHostKeyChecking and publickey-only auth; report configuration success separately from connection failure (B might lack network access to C).

## Tasks

1. [x] Implement/test fixed PowerShell preflight and receive scripts (isolated files and test home; no real servers).
2. [x] Implement/test Go transfer orchestration: source validation, exact source-key authentication to C and capture its validated host key, destination preflight, expiring one-use plan token, source/destination config digest checks, secret-only stdin transfer, bounded output and timeout.
3. [x] Add desktop transfer dialog with source C, destination B, destination alias, preparation preview, private-key scope acknowledgement, explicit send, accurate success/failure details. Existing operations remain available.
4. [x] Run regression suite, isolated receiver tests and browser tests; independent review, release build and repackaging.
