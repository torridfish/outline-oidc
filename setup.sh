#!/usr/bin/env bash
# Usage: ./setup.sh docs.example.com
# Writes .env (with fresh secrets) and the allowlist file. Refuses to overwrite an existing .env.
set -euo pipefail
cd "$(dirname "$0")"

DOMAIN="${1:-}"
if [ -z "$DOMAIN" ]; then
  echo "usage: $0 <domain>   e.g. $0 docs.example.com" >&2
  exit 1
fi
if [ -e .env ]; then
  echo ".env already exists; refusing to overwrite it" >&2
  exit 1
fi
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }

SECRET_KEY=$(openssl rand -hex 32)
UTILS_SECRET=$(openssl rand -hex 32)
POSTGRES_PASSWORD=$(openssl rand -hex 24)
OIDC_CLIENT_SECRET=$(openssl rand -hex 24)
SIGNING_KEY=$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -outform PEM 2>/dev/null | base64 | tr -d '\n')

umask 077
: > .env
while IFS= read -r line || [ -n "$line" ]; do
  line=${line//__DOMAIN__/$DOMAIN}
  line=${line//__SECRET_KEY__/$SECRET_KEY}
  line=${line//__UTILS_SECRET__/$UTILS_SECRET}
  line=${line//__POSTGRES_PASSWORD__/$POSTGRES_PASSWORD}
  line=${line//__OIDC_CLIENT_SECRET__/$OIDC_CLIENT_SECRET}
  line=${line//__SIGNING_KEY__/$SIGNING_KEY}
  printf '%s\n' "$line" >> .env
done < .env.example
umask 022

[ -e allowlist/allowed-emails.txt ] || cp allowlist/allowed-emails.example.txt allowlist/allowed-emails.txt
mkdir -p .cloudflared && chmod 777 .cloudflared

echo "Wrote .env for $DOMAIN. Next: add a login provider to .env, edit allowlist/allowed-emails.txt, set up the tunnel (see README)."
