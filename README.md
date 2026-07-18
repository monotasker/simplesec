# Simplesec

Secure secret management via `pass` + GPG, with named stores and
template-rendered temporary credential files.

Secrets live in **separate** git-backed password stores (not in this
tool repo). This project holds the wrapper script and templates only.

## Dependencies

```bash
# macOS
brew install pass gnupg yubikey-manager

# Fedora/RHEL
sudo dnf install pass gnupg yubikey-manager wl-copy xclip xsel git -y

# Ubuntu/Debian
sudo apt install pass gnupg yubikey-manager wl-clipboard xclip xsel git -y
```

Clipboard helpers: macOS `pbcopy`, or Linux `wl-copy` / `xclip` / `xsel`.

Decrypt paths require a **YubiKey** (OpenPGP applet), `gpg`/`gpgconf`, and
`ykman` for touch-policy verification.

## Install

```bash
chmod +x ~/.local/bin/simplesec/simplesec.sh
ln -sf ~/.local/bin/simplesec/simplesec.sh ~/.local/bin/simplesec
# ensure ~/.local/bin is on PATH
cp ~/.local/bin/simplesec/.env.example ~/.local/bin/simplesec/.env
# leave security defaults as-is for team machines
```

## Stores

Stores are labeled. By default they live under `~/.secrets/stores/<label>`.

```bash
simplesec setup                          # ~/.secrets/stores/default
simplesec setup work                     # ~/.secrets/stores/work
simplesec setup vault /Volumes/vault/sec # store at path; label vault
```

Select a store with `-s` / `--store` or `SIMPLESEC_STORE`:

```bash
simplesec -s work add aws/access_key_id
simplesec -s work get aws/access_key_id
simplesec -s work list
```

If `~/.secrets/pass` already exists and `~/.secrets/stores/default` does
not, the legacy path is used as the `default` store.

### Shared team stores

Clone a shared password-store repo yourself, then either use that path
directly or register it:

```bash
git clone git@example.com:team/secrets.git ~/team-secrets
simplesec setup team ~/team-secrets
```

Sync later with:

```bash
simplesec -s team pull
simplesec -s team push
# extra args are forwarded to git:
simplesec -s team pull --rebase
```

`simplesec clone` is not provided yet.

## Secrets CRUD

```bash
simplesec add aws/access_key_id
simplesec get aws/access_key_id
simplesec clip aws/secret_access_key
simplesec list
```

## Templates → temp files

Templates live in `templates/` beside this script. Placeholders use
`{{secret/path}}` and are filled from the **selected store** (first line
of each `pass` entry).

Shipped examples:

- `templates/aws` — AWS credentials file fragment
- `templates/openvpn` — two-line OpenVPN auth file

### Command substitution + TTL

```bash
openvpn --auth-user-pass "$(simplesec openvpn)"
aws --profile default something  # after pointing at:
#   --authfile=$(simplesec aws)
#   --authfile=$(simplesec file aws --ttl 600)
#   --authfile=$(simplesec -s work file aws --ttl 300)
```

Default TTL is `120` seconds (`SIMPLESEC_TTL` to change globally). The
file is deleted after the TTL; choose a value that outlasts the consumer.
For long-running tools, prefer `with`.

### Exec wrapper (trap cleanup)

```bash
simplesec with openvpn -- openvpn --auth-user-pass {}
simplesec -s work with aws --ttl 30 -- some-cmd --authfile={}
```

Every `{}` in the command args is replaced with the temp path. If no
`{}` is present, `SIMPLESEC_FILE` is set instead. The file is removed on
exit (INT/TERM/EXIT). Optional `--ttl` is a safety net if the process is
hard-killed.

## Security (fail-closed by default)

Before any decrypt (`get`, `clip`, `file`, `with`), simplesec verifies:

1. **YubiKey present** (OpenPGP card + YubiKey identity / `ykman`)
2. **Decrypt key on card** for every ID in the store’s `.gpg-id`
3. **gpg-agent cache TTL ≤ 0** (`default-cache-ttl` and `max-cache-ttl`)
4. **Encrypt/decrypt touch policy** enabled on the YubiKey (`ykman`)
5. Optionally **disconnects the card** before decrypt so PIN cache is cleared

Unset config means **enforced**. Opt out only with explicit env / `.env`
values (do not ship opt-outs to teammates).

```bash
simplesec doctor   # print PASS/FAIL for each check
```

### Required machine setup

```bash
# ~/.gnupg/gpg-agent.conf
default-cache-ttl 0
max-cache-ttl 0
```

```bash
gpgconf --kill gpg-agent
ykman openpgp keys set-touch enc on   # admin PIN; may be `dec` on some firmwares
```

Private keys must live on the YubiKey (card stubs only on disk). See
[drduh/YubiKey-Guide](https://github.com/drduh/YubiKey-Guide).

### Escape hatch (local debugging only)

```bash
SIMPLESEC_ALLOW_INSECURE=1 simplesec get aws/access_key_id
```

Or set individual `SIMPLESEC_REQUIRE_*=0` in a personal `.env` — never in a
shared team store.

### Other notes

- Secrets are GPG-encrypted; only granted keys can decrypt.
- Temp files are mode `0600` under `$TMPDIR` (separate from GPG unlock TTL).
- Never commit GPG private keys; only encrypted `.gpg` secret files in
  store repos.
- Unplug the YubiKey when idle; card PIN caching is not fully controlled by
  gpg-agent TTL alone.
