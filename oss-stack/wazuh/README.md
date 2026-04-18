# Wazuh Single-Node — SecureSync OSS Stack

Runs the Wazuh Manager, Indexer (OpenSearch), and Dashboard. The SecureSync
platform polls the Manager's REST API on TCP 55000. Agents in customer
networks connect to the Manager on 1514/1515.

Based on the official `wazuh-docker` single-node compose — see
https://github.com/wazuh/wazuh-docker/tree/v4.8.0/single-node for the full
production setup including cert generation scripts.

## Prerequisites

The compose joins the external network `securesync_scanner-net`, created by
the main dev stack. Bring the platform up first:

```bash
cd ../../          # repo root
docker compose -f docker-compose.dev.yml up -d
```

## First boot

```bash
cd oss-stack/wazuh
docker compose up -d
docker compose logs -f wazuh.manager    # wait for "Wazuh API listening on port 55000"
```

Note: this is a **simplified** compose without pre-generated SSL certs. For
production, follow the Wazuh docs to generate certs with `wazuh-certs-tool.sh`
and mount them into the containers.

## Connecting SecureSync

In the project root `.env`:

```env
WAZUH_API_URL=https://127.0.0.1:55000
WAZUH_USERNAME=wazuh-wui
WAZUH_PASSWORD=MyS3cr37P450r.*-
# Default certs are self-signed — dev only:
WAZUH_VERIFY_SSL=false
```

For platform-in-Docker reach the manager over the internal network:

```env
WAZUH_API_URL=https://wazuh.manager:55000
```

## Enrolling a test agent

```bash
# From a Linux VM or container, connecting to your manager host:
curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.8.0-1_amd64.deb
sudo WAZUH_MANAGER="<your-manager-host>" dpkg -i wazuh-agent_4.8.0-1_amd64.deb
sudo systemctl enable --now wazuh-agent
```

Within a minute the agent should appear in `GET /agents` (via SecureSync) and
start reporting software inventory + vulnerabilities.

## Grouping by tenant

SecureSync derives a Wazuh agent group name per tenant as
`ss-<tenant-slug>` (see `app/integrations/wazuh.py:tenant_group_name`). The
group is created automatically when a tenant is registered; you still need
to **assign each agent** to the right group manually (or via a GPO /
Ansible on agent rollout):

```bash
# On the Wazuh Manager host:
/var/ossec/bin/agent_groups -a -i 001 -g ss-acme -q
```

## Production hardening

1. Generate proper certs with `wazuh-certs-tool.sh`.
2. Bind API port 55000 to `127.0.0.1` only — SecureSync reaches it via the
   internal Docker network.
3. Rotate `WAZUH_PASSWORD` / `WAZUH_INDEXER_PASSWORD` / `WAZUH_DASHBOARD_PASSWORD`.
4. Pin image tags explicitly (not `:latest`).
5. Tune `OPENSEARCH_JAVA_OPTS` for your workload (1GB heap is enough for a
   few hundred agents; bump to 4GB+ for larger deployments).

## Cleanup

```bash
docker compose down -v   # removes all volumes including agent data
```
