# Simplesec

## Overview

Uses `pass` (GPG-encrypted password store) to securely manage credentials for
CLI tools like `aws`, `gh`, etc. Secrets never appear in command line history or
logs.

## Installation

### 1. Install dependencies

```bash
sudo dnf install pass gnupg xclip git -y
```

### 2. Initialize GPG key (if not done)

```bash
gpg --gen-key
# Follow prompts — use real name/email, strong passphrase
```

### 3. Initialize password store

```bash
pass init "your-email@example.com"
```

### 4. Clone secrets repo (team only)

```bash
mkdir -p ~/.password-store
cd ~/.password-store
git clone ssh://user@server:/path/to/your/password-store.git .
git config --local user.name "Your Name"
git config --local user.email "your-email@example.com"
```

### 5. Install the wrapper script

```bash
mkdir -p ~/.local/bin/secure-secrets
cp ~/.local/bin/secure-secrets/secrets.sh ~/.local/bin/secure-secrets/
chmod +x ~/.local/bin/secure-secrets/secrets.sh
export PATH="$HOME/.local/bin/secure-secrets:$PATH"  # Add to ~/.bashrc or ~/.zshrc
```

## Usage

### Retrieve a secret (outputs to terminal)

```bash
secrets get aws/access-key
```

### Copy to clipboard (auto-clears after 45s)

```bash
secrets get -c aws/secret-key
```

### Store a new secret

```bash
pass insert aws/access-key
```

## Security Features

- Secrets encrypted with GPG — only you can decrypt them
- No plaintext ever on command line or logs
- Clipboard auto-clears after 45 seconds
- Team secrets stored in Git repo — versioned, auditable, shareable via SSH

## For New Team Members

1. Import your GPG key: `gpg --recv-keys YOUR_GPG_KEY_ID`
2. Clone the repo:
   `git clone ssh://user@server:/path/to/password-store.git ~/.password-store`
3. Run: `pass init "your-email@example.com"` (uses same GPG key)
4. Install script as above

## Notes

- Use `gpg --list-secret-keys` to find your key ID
- Never commit the GPG private key to Git — only encrypted secrets
- The `secrets.sh` wrapper ensures safe, consistent access
