#!/bin/bash
# simplesec.sh - Secure secret management via pass + GPG
# Usage: simplesec [-s store] <command> [args...]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE_DIR="${SCRIPT_DIR}/templates"
STORES_ROOT="${HOME}/.secrets/stores"
LABELS_FILE="${HOME}/.secrets/labels"
LEGACY_STORE="${HOME}/.secrets/pass"

die() {
  echo "simplesec: $*" >&2
  exit 1
}

env_is_true() {
  case "${1:-}" in
  1 | true | TRUE | yes | YES | on | ON) return 0 ;;
  *) return 1 ;;
  esac
}

# Load KEY=VALUE from .env without executing shell. Process env wins over file.
load_env_file() {
  local f="$1" line key val
  [[ -f "$f" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${line//[[:space:]]/}" ]] && continue
    if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      key="${BASH_REMATCH[1]}"
      val="${BASH_REMATCH[2]}"
      val="${val#"${val%%[![:space:]]*}"}"
      val="${val%"${val##*[![:space:]]}"}"
      if [[ "$val" =~ ^\".*\"$ ]]; then
        val="${val:1:${#val}-2}"
      elif [[ "$val" =~ ^\'.*\'$ ]]; then
        val="${val:1:${#val}-2}"
      fi
      if [[ -z "${!key+x}" ]]; then
        export "${key}=${val}"
      fi
    fi
  done <"$f"
}

load_env_file "${SCRIPT_DIR}/.env"

# Secure-by-default: unset means enforced. Opt out explicitly.
: "${SIMPLESEC_REQUIRE_YUBIKEY:=1}"
: "${SIMPLESEC_REQUIRE_CACHE_TTL:=0}"
: "${SIMPLESEC_REQUIRE_KEY_ON_CARD:=1}"
: "${SIMPLESEC_REQUIRE_TOUCH:=1}"
: "${SIMPLESEC_LOCK_BEFORE_DECRYPT:=1}"
: "${SIMPLESEC_ALLOW_INSECURE:=0}"
DEFAULT_TTL="${SIMPLESEC_TTL:-120}"
STORE_LABEL="${SIMPLESEC_STORE:-default}"

usage() {
  cat <<'EOF'
Usage: simplesec [-s store|--store store] <command> [args...]

Commands:
  setup [label] [path]   Initialize a store (default label: default)
  add <name>             Store a secret interactively
  get <name>             Retrieve secret (prints to stdout)
  clip <name>            Copy secret to clipboard
  list                   List secrets in the selected store
  file <template> [--ttl SECONDS]
                         Render template to a temp file; print path; delete after TTL
  with <template> [--ttl SECONDS] -- <cmd> [args...]
                         Render template, run cmd (replace {} with path), clean up on exit
  pull [git-args...]     git pull in the selected store
  push [git-args...]     git push in the selected store
  doctor                 Verify YubiKey + GPG security requirements

Globals:
  -s, --store LABEL      Select store (default: default, or SIMPLESEC_STORE)
  SIMPLESEC_TTL          Default TTL seconds for file mode (default: 120)

Security (fail-closed by default; set in environment or simplesec/.env):
  SIMPLESEC_REQUIRE_YUBIKEY=1       YubiKey must be present (default)
  SIMPLESEC_REQUIRE_CACHE_TTL=0     Max allowed gpg-agent cache TTL (default 0)
  SIMPLESEC_REQUIRE_KEY_ON_CARD=1   Decrypt key must be on the card (default)
  SIMPLESEC_REQUIRE_TOUCH=1         Encrypt/decrypt touch policy On (default)
  SIMPLESEC_LOCK_BEFORE_DECRYPT=1   Disconnect card before decrypt (default)
  SIMPLESEC_ALLOW_INSECURE=1        Bypass all checks (escape hatch; loud warning)

Template shorthand:
  simplesec <template> [--ttl SECONDS]
                         Same as: simplesec file <template> [--ttl SECONDS]

Notes:
  - Stores live under ~/.secrets/stores/<label>, or at an explicit path
    registered via: setup <label> <path>
  - Legacy ~/.secrets/pass is used as default if present and no
    ~/.secrets/stores/default exists yet.
  - Templates live in the simplesec project templates/ directory.
  - Placeholders use {{secret/path}} (first line of the pass entry).
  - For $(simplesec tmpl), TTL must outlast the consumer; prefer
    'with' for long-running commands.
EOF
}

# --- store resolution -------------------------------------------------------

resolve_store() {
  local label="${1:-$STORE_LABEL}"
  local mapped=""

  if [[ -f "$LABELS_FILE" ]]; then
    mapped="$(grep -E "^${label}=" "$LABELS_FILE" 2>/dev/null | head -n1 | cut -d= -f2- || true)"
    if [[ -n "$mapped" ]]; then
      printf '%s\n' "$mapped"
      return 0
    fi
  fi

  if [[ "$label" == "default" && -d "$LEGACY_STORE" && ! -d "${STORES_ROOT}/default" ]]; then
    printf '%s\n' "$LEGACY_STORE"
    return 0
  fi

  printf '%s\n' "${STORES_ROOT}/${label}"
}

register_label() {
  local label="$1"
  local path="$2"
  mkdir -p "$(dirname "$LABELS_FILE")"
  if [[ -f "$LABELS_FILE" ]]; then
    grep -v -E "^${label}=" "$LABELS_FILE" >"${LABELS_FILE}.tmp" || true
    mv "${LABELS_FILE}.tmp" "$LABELS_FILE"
  fi
  printf '%s=%s\n' "$label" "$path" >>"$LABELS_FILE"
}

require_store_dir() {
  local store
  store="$(resolve_store)"
  if [[ ! -d "$store" ]]; then
    echo "simplesec: store not found: $store (run: simplesec setup${STORE_LABEL:+ $STORE_LABEL})" >&2
    return 1
  fi
  printf '%s\n' "$store"
}

require_git_store() {
  local store
  store="$(require_store_dir)" || return 1
  if [[ ! -d "${store}/.git" ]]; then
    echo "simplesec: not a git repository: $store" >&2
    return 1
  fi
  printf '%s\n' "$store"
}

# --- security preflight (fail-closed) ---------------------------------------

gpg_agent_option() {
  local name="$1"
  if ! command -v gpgconf >/dev/null 2>&1; then
    return 1
  fi
  gpgconf --list-options gpg-agent 2>/dev/null |
    awk -F: -v n="$name" '$1 == n { print $10; exit }'
}

check_gpg_available() {
  if ! command -v gpg >/dev/null 2>&1; then
    echo "simplesec: gpg not found on PATH (install gnupg)." >&2
    return 1
  fi
  if ! command -v gpgconf >/dev/null 2>&1; then
    echo "simplesec: gpgconf not found on PATH (install gnupg)." >&2
    return 1
  fi
  return 0
}

check_cache_ttl() {
  local required="${SIMPLESEC_REQUIRE_CACHE_TTL:-0}"
  local def max
  if ! [[ "$required" =~ ^[0-9]+$ ]]; then
    echo "simplesec: SIMPLESEC_REQUIRE_CACHE_TTL must be an integer (got: $required)" >&2
    return 1
  fi
  def="$(gpg_agent_option default-cache-ttl || true)"
  max="$(gpg_agent_option max-cache-ttl || true)"
  # Unconfigured agent defaults are not zero.
  def="${def:-600}"
  max="${max:-7200}"
  if ! [[ "$def" =~ ^[0-9]+$ && "$max" =~ ^[0-9]+$ ]]; then
    echo "simplesec: could not parse gpg-agent cache TTL values (default='$def' max='$max')" >&2
    return 1
  fi
  if ((def > required)) || ((max > required)); then
    echo "simplesec: GPG agent cache TTL too high (default-cache-ttl=$def max-cache-ttl=$max; required<=$required)." >&2
    echo "  Fix — add to ~/.gnupg/gpg-agent.conf:" >&2
    echo "    default-cache-ttl $required" >&2
    echo "    max-cache-ttl $required" >&2
    echo "  Then run: gpgconf --kill gpg-agent" >&2
    echo "  Note: YubiKey may still cache PIN until unplug/disconnect; see LOCK_BEFORE_DECRYPT." >&2
    return 1
  fi
  return 0
}

check_yubikey_present() {
  local status
  if ! status="$(gpg --card-status 2>/dev/null)"; then
    echo "simplesec: no OpenPGP smartcard detected. Insert your YubiKey and retry." >&2
    return 1
  fi
  if echo "$status" | grep -qiE 'Yubi[Kk]ey|Yubico'; then
    return 0
  fi
  if command -v ykman >/dev/null 2>&1; then
    if ykman info >/dev/null 2>&1; then
      return 0
    fi
    echo "simplesec: OpenPGP card present, but ykman cannot see a YubiKey." >&2
    return 1
  fi
  echo "simplesec: smartcard present but not identified as a YubiKey." >&2
  echo "  Install yubikey-manager (brew install yubikey-manager) or use a YubiKey." >&2
  return 1
}

check_key_on_card() {
  local store gpg_id listing colon
  store="$(resolve_store)"
  if [[ ! -f "${store}/.gpg-id" ]]; then
    echo "simplesec: missing ${store}/.gpg-id (run setup / init pass)." >&2
    return 1
  fi
  while IFS= read -r gpg_id || [[ -n "$gpg_id" ]]; do
    [[ -z "${gpg_id//[[:space:]]/}" ]] && continue
    [[ "$gpg_id" =~ ^# ]] && continue
    listing="$(gpg --list-secret-keys --keyid-format long "$gpg_id" 2>/dev/null || true)"
    if [[ -z "$listing" ]]; then
      echo "simplesec: no secret key found for '$gpg_id' (from .gpg-id)." >&2
      echo "  Import card stubs / insert YubiKey, then: gpg --card-status" >&2
      return 1
    fi
    if echo "$listing" | grep -qE '^(sec|ssb)>|[[:space:]]card-no:'; then
      continue
    fi
    colon="$(gpg --list-secret-keys --with-colons "$gpg_id" 2>/dev/null || true)"
    # Field 15 on sec/ssb is the smartcard serial when the key lives on a token.
    if echo "$colon" | awk -F: '
      $1 == "sec" || $1 == "ssb" {
        if ($15 != "") found = 1
      }
      END { exit !found }
    '; then
      continue
    fi
    echo "simplesec: secret key for '$gpg_id' looks like a software key on disk." >&2
    echo "  Move the private key onto your YubiKey (see README security section)." >&2
    return 1
  done <"${store}/.gpg-id"
  return 0
}

check_touch_policy() {
  local info enc_line
  if ! command -v ykman >/dev/null 2>&1; then
    echo "simplesec: ykman not installed (required to verify encrypt/decrypt touch policy)." >&2
    echo "  Install: brew install yubikey-manager" >&2
    return 1
  fi
  if ! info="$(ykman openpgp info 2>/dev/null)"; then
    echo "simplesec: cannot read OpenPGP info from YubiKey (is it inserted?)." >&2
    return 1
  fi
  enc_line="$(echo "$info" | grep -iE 'Encryption key|Decryption key|ENC' | head -n1 || true)"
  if echo "$info" | grep -qiE 'Encryption key[[:space:].:]*Off'; then
    echo "simplesec: YubiKey encryption-key touch policy is Off." >&2
    echo "  Fix: ykman openpgp keys set-touch enc on" >&2
    echo "  (admin PIN required; some firmwares use: set-touch dec on)" >&2
    return 1
  fi
  if echo "$info" | grep -qiE 'Encryption key[[:space:].:]*(On|Fixed|Always|Cached|Once)'; then
    return 0
  fi
  # Newer ykman: try direct get-touch if present
  if ykman openpgp keys get-touch enc >/dev/null 2>&1; then
    local policy
    policy="$(ykman openpgp keys get-touch enc 2>/dev/null | tr '[:upper:]' '[:lower:]')"
    case "$policy" in
    *off*)
      echo "simplesec: YubiKey enc touch policy is off ($policy)." >&2
      echo "  Fix: ykman openpgp keys set-touch enc on" >&2
      return 1
      ;;
    *on* | *fixed* | *cached* | *always*)
      return 0
      ;;
    esac
  fi
  echo "simplesec: could not confirm encrypt/decrypt touch policy is enabled." >&2
  echo "  ykman openpgp info reported:" >&2
  echo "$info" | sed 's/^/    /' >&2
  echo "  Expected Encryption key touch On/Fixed/Cached. Set with:" >&2
  echo "    ykman openpgp keys set-touch enc on" >&2
  return 1
}

lock_card_pin_cache() {
  if command -v gpg-connect-agent >/dev/null 2>&1; then
    gpg-connect-agent "scd disconnect" /bye >/dev/null 2>&1 || true
  fi
}

# Returns 0 if OK. With report=1, prints ok/fail lines for doctor.
run_security_checks() {
  local report="${1:-0}"
  local failed=0

  ok() {
    if [[ "$report" == "1" ]]; then
      echo "  OK  $1"
    fi
  }
  bad() {
    failed=1
    if [[ "$report" == "1" ]]; then
      echo "  FAIL  $1"
    fi
  }

  if env_is_true "${SIMPLESEC_ALLOW_INSECURE}"; then
    echo "simplesec: WARNING: SIMPLESEC_ALLOW_INSECURE=1 — security checks bypassed." >&2
    if [[ "$report" == "1" ]]; then
      echo "  SKIP  all checks (ALLOW_INSECURE=1)"
    fi
    return 0
  fi

  if ! check_gpg_available; then
    bad "gpg/gpgconf available"
    [[ "$report" == "1" ]] || return 1
  else
    ok "gpg/gpgconf available"
  fi

  if env_is_true "${SIMPLESEC_REQUIRE_YUBIKEY}"; then
    if check_yubikey_present; then
      ok "YubiKey present"
    else
      bad "YubiKey present"
      [[ "$report" == "1" ]] || return 1
    fi
  else
    ok "YubiKey check disabled (SIMPLESEC_REQUIRE_YUBIKEY=0)"
  fi

  if env_is_true "${SIMPLESEC_REQUIRE_KEY_ON_CARD}"; then
    if check_key_on_card; then
      ok "decrypt key on card (.gpg-id)"
    else
      bad "decrypt key on card (.gpg-id)"
      [[ "$report" == "1" ]] || return 1
    fi
  else
    ok "key-on-card check disabled (SIMPLESEC_REQUIRE_KEY_ON_CARD=0)"
  fi

  # Cache TTL: enforced whenever REQUIRE is set as integer (always, including 0)
  if [[ -n "${SIMPLESEC_REQUIRE_CACHE_TTL+x}" ]]; then
    if check_cache_ttl; then
      ok "gpg-agent cache TTL <= ${SIMPLESEC_REQUIRE_CACHE_TTL}"
    else
      bad "gpg-agent cache TTL <= ${SIMPLESEC_REQUIRE_CACHE_TTL}"
      [[ "$report" == "1" ]] || return 1
    fi
  fi

  if env_is_true "${SIMPLESEC_REQUIRE_TOUCH}"; then
    if check_touch_policy; then
      ok "encrypt/decrypt touch policy enabled"
    else
      bad "encrypt/decrypt touch policy enabled"
      [[ "$report" == "1" ]] || return 1
    fi
  else
    ok "touch policy check disabled (SIMPLESEC_REQUIRE_TOUCH=0)"
  fi

  if [[ "$report" == "1" ]]; then
    if env_is_true "${SIMPLESEC_LOCK_BEFORE_DECRYPT}"; then
      echo "  INFO  LOCK_BEFORE_DECRYPT=1 (card PIN cache cleared before each decrypt)"
    else
      echo "  INFO  LOCK_BEFORE_DECRYPT=0"
    fi
  fi

  return "$failed"
}

require_secure_decrypt() {
  run_security_checks 0 || return 1
  if env_is_true "${SIMPLESEC_LOCK_BEFORE_DECRYPT}" && ! env_is_true "${SIMPLESEC_ALLOW_INSECURE}"; then
    lock_card_pin_cache
  fi
  return 0
}

doctor_report() {
  echo "simplesec doctor (store=$(resolve_store))"
  echo "config:"
  echo "  REQUIRE_YUBIKEY=${SIMPLESEC_REQUIRE_YUBIKEY}"
  echo "  REQUIRE_CACHE_TTL=${SIMPLESEC_REQUIRE_CACHE_TTL}"
  echo "  REQUIRE_KEY_ON_CARD=${SIMPLESEC_REQUIRE_KEY_ON_CARD}"
  echo "  REQUIRE_TOUCH=${SIMPLESEC_REQUIRE_TOUCH}"
  echo "  LOCK_BEFORE_DECRYPT=${SIMPLESEC_LOCK_BEFORE_DECRYPT}"
  echo "  ALLOW_INSECURE=${SIMPLESEC_ALLOW_INSECURE}"
  echo "checks:"
  if run_security_checks 1; then
    echo "result: PASS"
    return 0
  fi
  echo "result: FAIL"
  return 1
}

# --- clipboard --------------------------------------------------------------

portable_clip() {
  if command -v pbcopy >/dev/null 2>&1; then
    pbcopy
  elif command -v wl-copy >/dev/null 2>&1; then
    wl-copy
  elif command -v xclip >/dev/null 2>&1; then
    xclip -sel clip
  elif command -v xsel >/dev/null 2>&1; then
    xsel --clipboard --input
  else
    echo "No clipboard tool found. Install one:" >&2
    echo "  macOS:   brew install pbcopy" >&2
    echo "  Linux:   sudo dnf install wl-copy xclip xsel" >&2
    exit 1
  fi
  echo "Copied to clipboard" >&2
}

# --- templates --------------------------------------------------------------

find_template() {
  local name="$1"
  if [[ -f "${TEMPLATE_DIR}/${name}" ]]; then
    printf '%s\n' "${TEMPLATE_DIR}/${name}"
    return 0
  fi
  if [[ -f "${TEMPLATE_DIR}/${name}.tmpl" ]]; then
    printf '%s\n' "${TEMPLATE_DIR}/${name}.tmpl"
    return 0
  fi
  return 1
}

pass_first_line() {
  local key="$1"
  local store
  store="$(resolve_store)"
  PASSWORD_STORE_DIR="$store" pass show "$key" | head -n1
}

render_template_to() {
  local tmpl_file="$1"
  local out_file="$2"
  local content key val

  content="$(<"$tmpl_file")"
  while [[ "$content" =~ \{\{([^}]+)\}\} ]]; do
    key="${BASH_REMATCH[1]}"
    if ! val="$(pass_first_line "$key")"; then
      echo "simplesec: failed to read secret: $key" >&2
      return 1
    fi
    content="${content//\{\{$key\}\}/$val}"
  done
  printf '%s\n' "$content" >"$out_file"
  chmod 600 "$out_file"
}

make_secret_temp() {
  local tmpl_name="$1"
  local tmpl_file tmp

  if ! tmpl_file="$(find_template "$tmpl_name")"; then
    echo "simplesec: template not found: $tmpl_name (looked in $TEMPLATE_DIR)" >&2
    return 1
  fi
  tmp="$(mktemp "${TMPDIR:-/tmp}/simplesec.${tmpl_name}.XXXXXX")"
  if ! render_template_to "$tmpl_file" "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  printf '%s\n' "$tmp"
}

schedule_ttl_rm() {
  local path="$1"
  local ttl="$2"
  (
    sleep "$ttl"
    rm -f "$path"
  ) >/dev/null 2>&1 &
  disown 2>/dev/null || true
}

parse_ttl_flag() {
  # Sets TTL from remaining args; strips --ttl N from ARGS array named by caller via globals
  TTL="$DEFAULT_TTL"
  local out=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
    --ttl)
      [[ $# -ge 2 ]] || die "--ttl requires a value"
      TTL="$2"
      shift 2
      ;;
    --ttl=*)
      TTL="${1#--ttl=}"
      shift
      ;;
    *)
      out+=("$1")
      shift
      ;;
    esac
  done
  PARSED_ARGS=("${out[@]+"${out[@]}"}")
}

# --- argument globals -------------------------------------------------------

while [[ $# -gt 0 ]]; do
  case "$1" in
  -s | --store)
    [[ $# -ge 2 ]] || die "$1 requires a store label"
    STORE_LABEL="$2"
    shift 2
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    break
    ;;
  esac
done

COMMAND="${1:-}"
if [[ -n "$COMMAND" ]]; then
  shift
fi

is_builtin() {
  case "$1" in
  setup | add | get | clip | list | file | with | pull | push | doctor | help) return 0 ;;
  *) return 1 ;;
  esac
}

# Template shorthand: first arg matches a template and is not a builtin
if [[ -n "$COMMAND" ]] && ! is_builtin "$COMMAND" && find_template "$COMMAND" >/dev/null; then
  set -- "$COMMAND" "$@"
  COMMAND="file"
fi

case "$COMMAND" in
setup)
  label="${1:-default}"
  explicit_path="${2:-}"
  if [[ -n "$explicit_path" ]]; then
    if [[ "$explicit_path" != /* ]]; then
      explicit_path="$(pwd)/${explicit_path}"
    fi
    mkdir -p "$explicit_path"
    store_path="$(cd "$explicit_path" && pwd)"
    register_label "$label" "$store_path"
  else
    store_path="${STORES_ROOT}/${label}"
    mkdir -p "$store_path"
  fi

  cd "$store_path" || die "cannot enter $store_path"
  if ! gpg --list-keys >/dev/null 2>&1; then
    echo "Install GPG first (e.g. brew install gnupg / sudo dnf install gnupg)" >&2
  fi
  read -r -p "Enter your email for GPG key: " EMAIL
  [[ -n "$EMAIL" ]] || die "email required"
  printf '%s\n' "$EMAIL" >.gpg-id
  PASSWORD_STORE_DIR="$store_path" pass init "$EMAIL"
  if [[ ! -d .git ]]; then
    git init
  fi
  git add .gpg-id
  git commit -m "Initial setup" || true
  echo "Setup complete for store '$label' at $store_path"
  echo "Share .gpg-id with teammates (and grant their GPG keys access)."
  ;;

add)
  name="${1:-}"
  [[ -n "$name" ]] || die "Usage: simplesec add <name>"
  store="$(require_store_dir)" || exit 1
  PASSWORD_STORE_DIR="$store" pass insert --echo "$name"
  (
    cd "$store" || exit 1
    if [[ -f "${name}.gpg" ]]; then
      git add "${name}.gpg"
      git commit -m "Add $name" || true
      git push origin HEAD 2>/dev/null ||
        echo "No remote set or push failed. Run: simplesec -s $STORE_LABEL push" >&2
    fi
  )
  ;;

get)
  name="${1:-}"
  [[ -n "$name" ]] || die "Usage: simplesec get <name>"
  store="$(require_store_dir)" || exit 1
  require_secure_decrypt || exit 1
  PASSWORD_STORE_DIR="$store" pass show "$name"
  ;;

clip)
  name="${1:-}"
  [[ -n "$name" ]] || die "Usage: simplesec clip <name>"
  store="$(require_store_dir)" || exit 1
  require_secure_decrypt || exit 1
  PASSWORD_STORE_DIR="$store" pass show "$name" | portable_clip
  ;;

list)
  store="$(require_store_dir)" || exit 1
  find "$store" -name '*.gpg' -not -path '*/.git/*' |
    sed "s|^${store}/||; s|\.gpg$||" |
    sort
  ;;

file)
  parse_ttl_flag "$@"
  tmpl_name="${PARSED_ARGS[0]:-}"
  [[ -n "$tmpl_name" ]] || die "Usage: simplesec file <template> [--ttl SECONDS]"
  [[ "$TTL" =~ ^[0-9]+$ ]] || die "TTL must be a non-negative integer"
  require_secure_decrypt || exit 1
  tmp="$(make_secret_temp "$tmpl_name")" || exit 1
  schedule_ttl_rm "$tmp" "$TTL"
  printf '%s\n' "$tmp"
  ;;

with)
  TTL_SET=0
  TTL="$DEFAULT_TTL"
  tmpl_name=""
  cmd_args=()
  seen_sep=0
  while [[ $# -gt 0 ]]; do
    if [[ $seen_sep -eq 1 ]]; then
      cmd_args+=("$1")
      shift
      continue
    fi
    case "$1" in
    --)
      seen_sep=1
      shift
      ;;
    --ttl)
      [[ $# -ge 2 ]] || die "--ttl requires a value"
      TTL="$2"
      TTL_SET=1
      shift 2
      ;;
    --ttl=*)
      TTL="${1#--ttl=}"
      TTL_SET=1
      shift
      ;;
    *)
      if [[ -z "$tmpl_name" ]]; then
        tmpl_name="$1"
        shift
      else
        die "unexpected argument before --: $1 (use: simplesec with <template> [--ttl N] -- <cmd>...)"
      fi
      ;;
    esac
  done
  [[ -n "$tmpl_name" ]] || die "Usage: simplesec with <template> [--ttl SECONDS] -- <cmd> [args...]"
  [[ $seen_sep -eq 1 ]] || die "missing -- before command"
  [[ ${#cmd_args[@]} -gt 0 ]] || die "missing command after --"
  [[ "$TTL" =~ ^[0-9]+$ ]] || die "TTL must be a non-negative integer"

  require_secure_decrypt || exit 1
  tmp="$(make_secret_temp "$tmpl_name")" || exit 1
  cleanup() { rm -f "$tmp"; }
  trap cleanup EXIT INT TERM
  if [[ $TTL_SET -eq 1 ]]; then
    schedule_ttl_rm "$tmp" "$TTL"
  fi

  replaced=()
  saw_placeholder=0
  for arg in "${cmd_args[@]}"; do
    if [[ "$arg" == *'{}'* ]]; then
      saw_placeholder=1
      replaced+=("${arg//\{\}/$tmp}")
    else
      replaced+=("$arg")
    fi
  done
  if [[ $saw_placeholder -eq 0 ]]; then
    export SIMPLESEC_FILE="$tmp"
  fi

  "${replaced[@]}"
  status=$?
  trap - EXIT INT TERM
  cleanup
  exit "$status"
  ;;

pull)
  store="$(require_git_store)" || exit 1
  cd "$store" || die "cannot enter $store"
  git pull "$@"
  ;;

push)
  store="$(require_git_store)" || exit 1
  cd "$store" || die "cannot enter $store"
  if ! git remote | grep -q .; then
    die "no git remote configured in $store"
  fi
  git push "$@"
  ;;

doctor)
  doctor_report
  ;;

help | "")
  usage
  ;;

*)
  die "unknown command: $COMMAND (try: simplesec help)"
  ;;
esac
