# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Certbot hook for DNS-01 challenge authentication using dnsmasq. Creates temporary ACME challenge TXT records in dnsmasq, enabling wildcard certificates or certificates for non-HTTP-accessible servers.

## Architecture

Python package (`certbot_hook_dnsmasq`) with two subcommands:

- **`cli.py`** -- argparse entry point, dispatches to subcommands
- **`flatten.py`** -- flattens dnsmasq config by following all includes; extracts config values (auth-server, auth-sec-servers, listen-address)
- **`hook.py`** -- auth-hook orchestration: writes ACME challenge config, restarts dnsmasq, verifies local DNS, notifies secondaries, waits for sync
- **`external.py`** -- thin subprocess wrappers for dig, ldns-notify, systemctl, dnsmasq

Workflow (auth-hook subcommand):
1. Flattens dnsmasq config and extracts auth-server, secondaries, and public IP
2. Writes dnsmasq config with TXT record to `<conf-dir>/dnsmasq.acme.<domain>.conf`
3. Validates and restarts dnsmasq via systemd
4. Verifies local DNS has correct record
5. Sends NOTIFY to secondary DNS servers via `ldns-notify`
6. Polls secondaries until they sync (max 120s)

## Usage

```bash
certbot certonly \
    --manual \
    --preferred-challenges dns \
    --manual-auth-hook "certbot-hook-dnsmasq auth-hook" \
    -d example.com
```

Flatten dnsmasq config (for debugging):

```bash
certbot-hook-dnsmasq flatten-config [/etc/dnsmasq.conf]
```

## Running Tests

```bash
uv run pytest tests/ -v
```

## Dependencies

- Python 3.11+
- dnsmasq (configured as DNS server)
- dig (dnsutils/bind-utils)
- ldns-notify (ldnsutils)
- systemd (systemctl)

## Configuration

Auth-hook options (CLI flags override environment variables, which override defaults):

| CLI Flag | Environment Variable | Default |
|---|---|---|
| `--conf-dir` | `DNSMASQ_CONF_DIR` | `/etc/dnsmasq.d` |
| `--conf` | `DNSMASQ_CONF` | `/etc/dnsmasq.conf` |
| `--service` | `DNSMASQ_SERVICE` | `dnsmasq` |

## Environment Variables (from certbot)

- `CERTBOT_DOMAIN` -- Domain being validated
- `CERTBOT_VALIDATION` -- ACME challenge token value
