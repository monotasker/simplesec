 #!/bin/bash
 # simplesec.sh - Secure secret management via pass + GPG
 # Usage: ./simplesec.sh [setup|add|get|list] [name]

 # Secure secrets store in ~/.secrets/pass (isolated from system pass)
 SECRET_ROOT="$HOME/.secrets/pass"

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
   echo "Copied to clipboard"
 }

 case "$1" in
   setup)
     mkdir -p "$SECRET_ROOT"
     cd "$SECRET_ROOT"
     gpg --list-keys > /dev/null || echo "Install GPG first: sudo dnf install gnupg"
     read -p "Enter your email for GPG key: " EMAIL
     echo "$EMAIL" > .gpg-id
     pass init "$EMAIL"
     git init && git add .gpg-id && git commit -m "Initial setup"
     echo "Setup complete. Share .gpg-id with teammates."
     ;;
   add)
     [ -z "$2" ] && echo "Usage: ./simplesec.sh add <name>" && exit 1
     pass insert --echo "$2"
     git add "$SECRET_ROOT/$2.gpg" && git commit -m "Add $2"
     git push origin main 2>/dev/null || echo "No remote set. Run: git remote add origin
<repo>"
     ;;
   get)
     [ -z "$2" ] && echo "Usage: ./simplesec.sh get <name>" && exit 1
     pass "$2" # prints to stdout (for scripting)
     ;;
   clip) pass $2 | portable_clip
     ;;
   list)
     find "$SECRET_ROOT" -name "*.gpg" | sed 's/.*\///; s/\.gpg$//'
     ;;
   *)
     cat <<EOF
       Usage: ./simplesec.sh [command] [name]

       Commands:
         setup     Initialize secrets store (run once)
         add <name>   Store a secret interactively
         get <name>   Retrieve secret (prints to stdout)
         clip <name>  Copy secret to clipboard (no stdout output)
         list        List all stored secrets

       Notes:
       - Secrets are GPG-encrypted and stored in Git.
       - Share .gpg-id with teammates so they can decrypt.

       Installation:

       - set up clip program

       # macOS:
       brew install pbcopy

       # Fedora/RHEL (Wayland/X11):
       sudo dnf install wl-copy xclip xsel

       # Ubuntu/Debian:
       sudo apt install wl-copy xclip xsel



       EOF
     ;;
 esac
