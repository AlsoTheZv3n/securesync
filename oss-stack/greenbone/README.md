# Greenbone Community Edition (OpenVAS) — SecureSync OSS Stack

This stack runs Greenbone Community Edition and exposes the GMP protocol on
TCP port `9390` (TLS) so the SecureSync platform can drive scans.

## Prerequisites

The stack joins an external Docker network named `securesync_scanner-net`,
which is created by the platform's main compose. Bring up the platform first:

```bash
cd ../../          # repo root
docker compose -f docker-compose.dev.yml up -d
```

## First boot (slow — ~30–60 minutes)

```bash
cd oss-stack/greenbone
docker compose up -d

# Watch the gvmd log until you see "Scanner has been added" and "feed sync done".
docker compose logs -f gvmd
```

The first boot downloads ~1 GB of NVT definitions (Network Vulnerability Tests,
~120 000 of them). Scans cannot start before the feed sync completes.

## Connecting from SecureSync

In your project root `.env`:

```env
GREENBONE_HOST=127.0.0.1     # if platform runs on host
# GREENBONE_HOST=gvmd        # if platform runs in compose, use service name
GREENBONE_USERNAME=admin
GREENBONE_PASSWORD=admin
```

For Docker-internal connections (production), the platform reaches `gvmd:9390`
inside the `scanner-net` network.

## Verifying

```bash
# From inside the platform container or with python-gvm installed locally:
python -c "
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
with Gmp(TLSConnection(hostname='127.0.0.1', port=9390)) as gmp:
    gmp.authenticate('admin', 'admin')
    print(gmp.get_version().decode())
"
```

## Production hardening

Before exposing this stack to anything beyond a development laptop:

1. **Change the admin password** — set `GREENBONE_PASSWORD` to a strong secret.
2. **Remove the host port mapping** for `gvmd` (`ports: ["9390:9390"]` block).
   Production platform should reach gvmd over the internal Docker network.
3. **Pin image tags** — `:stable` floats. Replace with explicit version tags
   that match the GMP version your `python-gvm` client expects.
4. **Resource limits** — gvmd + ospd-openvas can use 4–8 GB RAM during a large
   scan. Add `deploy.resources.limits.memory` accordingly.

## Cleanup

```bash
docker compose down -v   # drops all volumes — re-syncs feed on next boot
```
