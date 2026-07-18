# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

Changes since `e1f26d9` (First commit).

### Added

- **Named stores**
  - Stores under `~/.secrets/stores/<label>` (default label: `default`)
  - `setup [label] [path]` — init a store; optional explicit path registered in `~/.secrets/labels`
  - Global `-s` / `--store LABEL` and `SIMPLESEC_STORE`
  - Legacy fallback: existing `~/.secrets/pass` used as `default` when `~/.secrets/stores/default` is absent
  - All `pass` operations set `PASSWORD_STORE_DIR` to the resolved store

- **Template → temp credential files**
  - `templates/` directory with starter `aws` and `openvpn` templates
  - `{{secret/path}}` placeholders filled from the selected store (first line of each `pass` entry)
  - `file <template> [--ttl SECONDS]` — render to a `0600` tempfile, print path, delete after TTL
  - Template-name shorthand: `simplesec aws` ≡ `simplesec file aws`
  - Default tempfile TTL `120` (`SIMPLESEC_TTL`); per-call `--ttl`
  - `with <template> [--ttl SECONDS] -- <cmd> …` — substitute `{}` with the temp path, trap cleanup on exit; sets `SIMPLESEC_FILE` if no `{}`

- **Git sync wrappers**
  - `pull [git-args…]` / `push [git-args…]` in the resolved store
  - Clear errors when the store is missing, not a git repo, or has no remote
  - Clone still manual (out of scope)

- **Fail-closed security preflight** (decrypt paths: `get`, `clip`, `file`, `with`)
  - YubiKey present (card + YubiKey identity / `ykman`)
  - Decrypt private key on card for every ID in `.gpg-id`
  - `gpg-agent` `default-cache-ttl` / `max-cache-ttl` ≤ `SIMPLESEC_REQUIRE_CACHE_TTL` (default `0`)
  - Encrypt/decrypt touch policy enabled (`ykman`)
  - Optional `scd disconnect` before decrypt (`SIMPLESEC_LOCK_BEFORE_DECRYPT`, default on)
  - Unset security env vars mean **enforced**; opt out only via explicit `=0` or `SIMPLESEC_ALLOW_INSECURE=1`
  - `doctor` command to print PASS/FAIL for each check
  - Safe `.env` loader (KEY=VALUE only; process env wins)

### Changed

- Rewrote `simplesec.sh` CLI surface and usage help around the new commands and globals
- Rewrote `README.md` for stores, templates, git sync, and YubiKey / cache-TTL setup
- Rewrote `.env.example` around `SIMPLESEC_*` security and TTL settings (replaced unused draft GPG helper vars)

### Fixed

- Heredoc `EOF` delimiter in usage help (indented closer previously caused “delimited by end-of-file” / broken `case`)
