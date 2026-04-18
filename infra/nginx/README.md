# Nginx + Certbot — Operator Playbook

Production flow for white-label tenant domains. All scripts here run on the
host / in the nginx container, NOT through the platform API — dynamic DNS
plumbing is an explicit operator action, not a side-effect of tenant edits.

## The 3-step tenant onboarding

1. **Tenant admin sets `custom_domain`** on their Tenant via the API.
2. **Tenant admin verifies ownership** via `POST /tenants/{id}/verify-domain`
   → adds the returned TXT record at their DNS provider → `POST /verify-domain/confirm`.
3. **Operator provisions the vhost + cert**:

```bash
# 1. Issue an initial Let's Encrypt cert via HTTP-01 (requires tenant's
#    A/CNAME already pointing at our nginx host).
./infra/nginx/issue_cert.sh customer.acme-corp.ch

# 2. Regenerate tenant vhosts from DB (only verified tenants are included).
cd platform
python -m infra.nginx.generate_vhosts --apply
```

`generate_vhosts.py --apply` writes `/etc/nginx/conf.d/tenant-<slug>.conf`
for every verified tenant, removes stale files, and reloads nginx.

## Automated renewal

The `nginx` container's crontab should run:

```cron
0 3 * * * certbot renew --webroot -w /var/www/certbot --deploy-hook "nginx -s reload"
```

Let's Encrypt renews at 30 days left (60-day-old certs), so daily is fine.

## Wildcards vs. per-customer certs

This setup uses **one cert per custom_domain**. For MSPs that want
`*.<msp-domain>` wildcards, use certbot with DNS-01 and a provider plugin.
That's a later upgrade — wildcards require MSP-side DNS-API credentials
and aren't needed for the customer-brings-their-own-domain case.

## Rate limits

Let's Encrypt has tight limits:
- 50 new certs per registered domain per week
- 5 duplicate certs per week
- 300 new orders per account per 3 hours

Don't run `issue_cert.sh` in a loop during testing — use `--staging` first.
