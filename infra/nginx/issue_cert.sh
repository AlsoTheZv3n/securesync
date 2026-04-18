#!/usr/bin/env bash
# Issue a fresh Let's Encrypt cert for a verified custom tenant domain.
#
# Usage:
#   ./infra/nginx/issue_cert.sh <domain> [--staging]
#
# Pre-reqs:
#   * Tenant's custom_domain already points at our nginx host (A/CNAME).
#   * Our nginx already serves the HTTP-01 webroot at
#     /var/www/certbot/.well-known/acme-challenge/ (see tenant-vhost.conf.template).
#   * certbot is installed on the nginx host or inside a sidecar container.
#
# Re-running against an already-issued domain is fine — certbot will NOOP if
# the cert isn't near expiry. Add --staging while testing to avoid LE's
# 50-certs-per-week rate limit.

set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <domain> [--staging]" >&2
  exit 2
fi

DOMAIN="$1"
shift || true
EXTRA_ARGS=("$@")

ADMIN_EMAIL="${LETSENCRYPT_EMAIL:-ops@nexo-ai.ch}"

certbot certonly \
  --webroot \
  --webroot-path /var/www/certbot \
  --email "$ADMIN_EMAIL" \
  --agree-tos \
  --non-interactive \
  --no-eff-email \
  -d "$DOMAIN" \
  "${EXTRA_ARGS[@]}"

echo "✓ cert issued for $DOMAIN — now run:"
echo "    python -m infra.nginx.generate_vhosts --apply"
