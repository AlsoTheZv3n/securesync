# Mocks & Stubs Registry

This file lists **every** test mock, stub, eager-mode hack, and "for-test-only"
shortcut in the codebase. When a real implementation lands, find the entry,
swap it, and delete the row.

> **Convention:** every mock must (1) carry an inline `# MOCK — <reason>` header
> at the call site and (2) appear in this table.

---

## Active mocks

| # | What is mocked | Where | Why | How to swap to production |
|---|---|---|---|---|
| 1 | `NucleiClient.scan()` subprocess call | [tests/integration/test_scan_task.py](../platform/tests/integration/test_scan_task.py) — `mock_nuclei_findings` fixture | Tests must run without the `nuclei` Go binary installed and without network egress | Install `nuclei` on the worker host, drop the `monkeypatch.setattr(NucleiClient, "scan", ...)` block. The subprocess invocation already exists in [app/integrations/nuclei.py](../platform/app/integrations/nuclei.py) — no production code change needed. |
| 2 | Celery task `.delay()` dispatch (Nuclei + OpenVAS) | [tests/integration/test_scans_api.py](../platform/tests/integration/test_scans_api.py) — `dispatch_calls` fixture | API tests assert "task was enqueued with the right args" without spinning up a Celery worker. Going through a real broker would require Redis + worker process per test run. Each new scanner must be added to the same monkeypatch block. | Once a Celery worker runs alongside the test suite (CI: `docker compose -f docker-compose.dev.yml up -d redis` + spawn worker), remove the `monkeypatch.setattr(...)` lines. Add `CELERY_TASK_ALWAYS_EAGER=True` env var in CI for synchronous in-process execution. |
| 3 | Test-DB schema bootstrap via `Base.metadata.create_all` | [tests/conftest.py](../platform/tests/conftest.py) — `engine_fixture` | Faster than running Alembic for every test session, and avoids drift if migrations and models disagree (model definitions are the source of truth in tests) | When migration coverage matters (Phase 2), replace with `alembic upgrade head` against the test DB — see https://alembic.sqlalchemy.org/en/latest/cookbook.html#test-current-database-revision-is-at-head |
| 4 | Greenbone GMP XML fixtures (parser tests) | [tests/unit/test_openvas_parser.py](../platform/tests/unit/test_openvas_parser.py) — `SAMPLE_REPORT_XML` constants | Parser is a pure function over `gmp.get_report(...)` XML output. Tests run without the gvmd container (~1 GB feed download, 30+ min first boot). | Optional: also add an integration test that boots [oss-stack/greenbone/docker-compose.yml](../oss-stack/greenbone/docker-compose.yml), waits for feed sync, and runs an end-to-end scan against a known-vulnerable target VM. Gate behind a `--with-greenbone` pytest marker. |
| 5 | OWASP ZAP alert dict fixtures (parser tests) | [tests/unit/test_zap_parser.py](../platform/tests/unit/test_zap_parser.py) — `SAMPLE_ALERTS` constant | Parser is a pure function over `zap.alert.alerts(baseurl=...)` output. Tests run without the ZAP daemon (Java/JVM, ~500 MB image, ~30 s startup). The risk→severity mapping and CWE→raw_data passthrough are the parser's contract. | The ZAP daemon is already declared in [docker-compose.yml](../docker-compose.yml). For an end-to-end test, spin up a deliberately vulnerable target (DVWA, juice-shop) and run the real `ZAPClient.scan()`. Gate behind `--with-zap` pytest marker. |
| 6 | DefectDojo REST API (`httpx` calls) | [tests/unit/test_defectdojo_client.py](../platform/tests/unit/test_defectdojo_client.py) — `respx` intercepts | The client talks to `DEFECTDOJO_URL/api/v2/...`. Tests use `respx.mock(base_url=...)` to assert request bodies (JSON + multipart), response parsing, and tenacity retry on `TransportError`. Never hits a real DefectDojo. | When CI runs DefectDojo in a container, drop the `respx.mock(...)` block and point `DEFECTDOJO_URL` + `DEFECTDOJO_API_KEY` at the running instance. Gate behind `--with-defectdojo` pytest marker. |
| 7 | DefectDojo sync hooks (`provision_product_for_tenant`, `push_scan_to_defectdojo`) | [tests/integration/test_defectdojo_hooks.py](../platform/tests/integration/test_defectdojo_hooks.py) — `monkeypatch.setattr(...)` | Integration tests verify the *wiring* (hook is invoked from the API and from the scan task) without actually touching HTTP. Combined with row #6, this covers the whole DefectDojo path in layers. | Once a live DefectDojo is part of CI, remove the `monkeypatch.setattr(...)` lines — the real service functions will already make the calls through to row #6's real HTTP client. |
| 8 | Wazuh REST API (`httpx` calls) + JSON fixtures | [tests/unit/test_wazuh_client.py](../platform/tests/unit/test_wazuh_client.py), [tests/unit/test_wazuh_parser.py](../platform/tests/unit/test_wazuh_parser.py) | Wazuh Manager stack is 3+ containers (~2 GB RAM, OpenSearch in Java), too heavy for unit tests. `respx` mocks all HTTP, including the auth round-trip (JWT caching is covered), group creation (incl. "already exists" tolerance), and the vulnerability endpoint. | Bring up [oss-stack/wazuh/docker-compose.yml](../oss-stack/wazuh/docker-compose.yml), wait for manager readiness, point `WAZUH_API_URL` at it, drop the `respx.mock(...)` blocks. Gate behind `--with-wazuh` pytest marker. |
| 9 | Wazuh tenant sync hook (`provision_agent_group_for_tenant`) | [tests/integration/test_wazuh_hooks.py](../platform/tests/integration/test_wazuh_hooks.py) — `monkeypatch.setattr(...)` | Same pattern as row #7: verify the hook is invoked from tenant create without hitting HTTP. | Remove the monkeypatch when Wazuh runs in CI. |
| 10 | EPSS HTTP (`api.first.org/data/v1/epss`) | [tests/unit/test_epss_client.py](../platform/tests/unit/test_epss_client.py), [tests/integration/test_enrichment.py](../platform/tests/integration/test_enrichment.py) | `respx.mock(base_url=EPSS_API_URL)` — tests must never hit the public EPSS endpoint (rate-limited, flaky for CI). Each test FLUSHes the Redis `epss:*` cache first so prior runs don't mask misses. | EPSS is public + free; to run a single "canary" test against live EPSS, drop the `respx.mock(...)` block. Still want `TEST_REDIS_URL` set so the cache layer gets real coverage. |
| 11 | HIBP HTTP (`haveibeenpwned.com/api/v3`) | [tests/unit/test_hibp_client.py](../platform/tests/unit/test_hibp_client.py) | `respx.mock(base_url=...)` plus a **shortened `min_interval_seconds`** in the fixture so rate-limit tests complete in ~600 ms instead of 4.5 s. Real HIBP requires a paid API key and enforces 1 req / 1500 ms. | Set `HIBP_API_KEY` in CI secrets and drop the `respx.mock(...)` blocks. Keep the rate limiter tuned to 1.6 s (free tier) or 0.5 s (Pwned 1 tier). |
| 12 | WeasyPrint `render_pdf()` | [tests/integration/test_reports_api.py](../platform/tests/integration/test_reports_api.py) — `_mock_weasyprint` autouse fixture | WeasyPrint needs Cairo / Pango / gdk-pixbuf native libs. The Dockerfile installs them on Linux but they fail to load on Windows dev. The mock returns a valid minimal PDF (`%PDF-1.4...%%EOF`) plus a marker embedding the rendered-HTML length, so we can still assert the HTML pipeline ran. Template rendering is fully covered by [tests/unit/test_report_generator.py](../platform/tests/unit/test_report_generator.py) (Jinja-only). | In CI on Linux (matches our Dockerfile), remove the `_mock_weasyprint` fixture. Real WeasyPrint produces ~80–300 KB PDFs in under a second — update size assertions accordingly. |
| 13 | NinjaOne RMM API (`app.ninjarmm.com`) — OAuth + tickets | [tests/unit/test_ninjaone_client.py](../platform/tests/unit/test_ninjaone_client.py), [tests/integration/test_ninjaone_hooks.py](../platform/tests/integration/test_ninjaone_hooks.py) | `respx.mock(base_url=NINJAONE_API_URL)` intercepts OAuth + ticket creation. Unit tests cover token caching, both response shapes (bare list vs. `{"items": [...]}`) and both id fields (`id` vs. `ticketId`). Integration test uses `monkeypatch.setattr(...)` at the service level to verify only Critical+High severities are ticketed. | Provide a valid `NINJAONE_CLIENT_ID` + `_SECRET` in CI secrets, drop the respx + monkeypatch blocks. The real API rate-limits aggressively — keep tests under `--with-ninjaone` marker to avoid accidental CI fan-out. |

---

## Future planned stubs

These will be needed in upcoming phases — listed here so we don't forget to register them:

*(All upcoming-phase stubs are now fielded — list is empty until Phase 5 work begins.)*

---

## How to add a new mock

1. Add the inline header at the call site:
   ```python
   # MOCK — <one-line why> — see docs/mocks.md row #N
   monkeypatch.setattr(...)
   ```
2. Append a row to the **Active mocks** table above.
3. If the mock simulates an external API, store any response fixtures under `platform/tests/fixtures/<service>/`.

## How to remove a mock

1. Implement the real thing (or verify CI dependencies are present).
2. Delete the inline `# MOCK — …` block.
3. Strike the row from this table (don't just delete it — line through it for one release so reviewers see what changed):
   ```
   | ~~1~~ | ~~NucleiClient.scan()~~ | ~~tests/...~~ | ~~Replaced by real subprocess in CI on 2026-MM-DD~~ |
   ```
