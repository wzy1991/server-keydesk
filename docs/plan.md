# Server Keydesk Implementation Plan

> For agentic workers: execute inline using superpowers:executing-plans; complete with a fresh review.

**Goal:** Install Linux SSH public keys and identify servers with working key authentication from a Windows mygo desktop app.

**Architecture:** Embedded frontend → bound Go service → SSH/key/config modules. Files and remote sessions stay in Go; passwords never enter persistent state.

**Tech stack:** Go 1.27.1, egoist/mygo pinned commit, golang.org/x/crypto/ssh, Windows OpenSSH.

**Spec:** design.md

## Global constraints

- Preserve existing local SSH configuration and remote authorized_keys.
- No unknown host accepted silently; no password persistence.
- Only explicit user actions contact servers.

## Review focus

- Duplicate aliases, including included config files, must not install a key before conflict detection.
- Stale/changed host keys must block password authentication.
- Installation can succeed remotely while local config writing fails: expose a recoverable error.
- Offline and proxy failures must not claim a missing key.
- Paths with spaces and missing newlines must preserve data.

## Tasks

1. [x] Write failing core tests; implement validation, key management, config import/write, and status classification; run go test.
2. [x] Write failing SSH fixture/script tests; implement fingerprint inspection, bootstrap and verification; run full suite.
3. [x] Implement Chinese embedded frontend and mygo binding; build GUI executable; inspect UI and exercise state transitions.
4. [x] Run go test, go vet, frontend checks and fresh code review; package executable, source, and usage notes.
