"""Render per-tenant nginx vhosts from the DB.

Usage:
    cd platform
    python -m infra.nginx.generate_vhosts              # dry-run to stdout
    python -m infra.nginx.generate_vhosts --apply      # write + reload nginx

Policy:
  * Only tenants with `custom_domain_verified = true` get a vhost.
  * One file per tenant: /etc/nginx/conf.d/tenant-<slug>.conf
  * Existing tenant-*.conf files whose tenant is now unverified / deleted
    are removed.

This intentionally stays a standalone operator tool — not an API endpoint.
Dynamic nginx reloads driven by every tenant edit are a great way to
accidentally brick production; operators should run this explicitly.
"""

from __future__ import annotations

import argparse
import asyncio
import shutil
import subprocess
import sys
from pathlib import Path

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import structlog
from sqlalchemy import select

from app.core.database import AsyncSessionLocal, engine
from app.core.logging import configure_logging
from app.models.tenant import Tenant

configure_logging()
logger = structlog.get_logger()

_TEMPLATE_PATH = Path(__file__).resolve().parents[2] / "nginx" / "conf.d" / "tenant-vhost.conf.template"
_DEFAULT_CONF_D = Path("/etc/nginx/conf.d")
_LETSENCRYPT_LIVE = Path("/etc/letsencrypt/live")


def _render(tenant: Tenant) -> str:
    template = _TEMPLATE_PATH.read_text(encoding="utf-8")
    cert_path = _LETSENCRYPT_LIVE / tenant.custom_domain / "fullchain.pem"
    key_path = _LETSENCRYPT_LIVE / tenant.custom_domain / "privkey.pem"
    return (
        template
        .replace("{{TENANT_DOMAIN}}", tenant.custom_domain or "")
        .replace("{{TENANT_SLUG}}", tenant.slug)
        .replace("{{CERT_PATH}}", str(cert_path))
        .replace("{{KEY_PATH}}", str(key_path))
    )


def _tenant_vhost_path(conf_d: Path, slug: str) -> Path:
    return conf_d / f"tenant-{slug}.conf"


async def _list_verified_tenants() -> list[Tenant]:
    async with AsyncSessionLocal() as session:
        stmt = select(Tenant).where(
            Tenant.custom_domain_verified.is_(True),
            Tenant.deleted_at.is_(None),
            Tenant.custom_domain.is_not(None),
        )
        return list((await session.execute(stmt)).scalars().all())


def _reload_nginx() -> None:
    """Run `nginx -t && nginx -s reload` — expects we're on the host or in a
    container that can exec nginx. Skips gracefully when nginx isn't on PATH
    (dev machine)."""
    if shutil.which("nginx") is None:
        logger.warning("nginx_not_found_on_path_skipping_reload")
        return
    subprocess.run(["nginx", "-t"], check=True)
    subprocess.run(["nginx", "-s", "reload"], check=True)


async def _main(apply: bool, conf_d: Path) -> int:
    tenants = await _list_verified_tenants()
    await engine.dispose()

    wanted: dict[Path, str] = {}
    for t in tenants:
        wanted[_tenant_vhost_path(conf_d, t.slug)] = _render(t)

    # Find existing tenant-*.conf files no longer in `wanted`.
    stale: list[Path] = []
    if conf_d.exists():
        for existing in conf_d.glob("tenant-*.conf"):
            if existing not in wanted:
                stale.append(existing)

    if not apply:
        print(f"# Would write {len(wanted)} vhost(s) and drop {len(stale)} stale file(s):")
        for path, content in wanted.items():
            print(f"# --- {path} ---")
            print(content)
        for path in stale:
            print(f"# --- would remove: {path} ---")
        return 0

    conf_d.mkdir(parents=True, exist_ok=True)
    for path, content in wanted.items():
        path.write_text(content, encoding="utf-8")
        logger.info("vhost_written", path=str(path))
    for path in stale:
        path.unlink()
        logger.info("vhost_removed", path=str(path))

    _reload_nginx()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="Write files and reload nginx")
    parser.add_argument(
        "--conf-d",
        default=str(_DEFAULT_CONF_D),
        help="Target directory for generated vhosts",
    )
    args = parser.parse_args()
    return asyncio.run(_main(apply=args.apply, conf_d=Path(args.conf_d)))


if __name__ == "__main__":
    sys.exit(main())
