# certbot-hook-dnsmasq

> **Warning:** This project has been vibe coded using [Claude Code](https://claude.ai/claude-code). Review carefully before using in production.

Certbot hook for DNS-01 challenge authentication using a dnsmasq server.

## Overview

This tool creates temporary TXT records in dnsmasq for ACME DNS-01 challenges, allowing certbot to obtain wildcard certificates or certificates for servers that aren't publicly accessible via HTTP.

It auto-discovers your DNS setup from the dnsmasq config (`auth-server`, `auth-sec-servers`, and either `listen-address` or the bound `interface`) so there is minimal configuration needed.

## Requirements

- Python 3.11+ (no runtime Python dependencies)
- dnsmasq configured as an authoritative DNS server
- `dig` command (from `dnsutils` or `bind-utils`)
- `ldns-notify` (from `ldnsutils`) for notifying secondary DNS servers
- systemd (for restarting dnsmasq via `systemctl`)

## Installation

```bash
pip install .
```

Or with [uv](https://docs.astral.sh/uv/):

```bash
uv pip install .
```

Verify the installation:

```bash
certbot-hook-dnsmasq --version
```

## Usage

### Auth Hook (certbot DNS-01 challenge)

Use as a certbot manual auth hook:

```bash
certbot certonly \
    --manual \
    --preferred-challenges dns \
    --manual-auth-hook "certbot-hook-dnsmasq auth-hook" \
    -d example.com
```

You can also specify custom paths:

```bash
certbot certonly \
    --manual \
    --preferred-challenges dns \
    --manual-auth-hook "certbot-hook-dnsmasq auth-hook --conf-dir /custom/dir --conf /custom/dnsmasq.conf --service dnsmasq-custom" \
    -d example.com
```

### Flatten Config (debugging tool)

Flatten a dnsmasq config by following all `conf-file=` and `conf-dir=` includes, useful for debugging:

```bash
certbot-hook-dnsmasq flatten-config [/etc/dnsmasq.conf]
```

### Running as a Python module

The tool can also be run as a Python module:

```bash
python -m certbot_hook_dnsmasq --version
python -m certbot_hook_dnsmasq auth-hook
python -m certbot_hook_dnsmasq flatten-config
```

## How it works

The `auth-hook` subcommand uses two-phase execution for efficient multi-domain certificates:

**Phase 1 -- Write only** (when more challenges are coming):
- Creates a dnsmasq config file with the ACME challenge TXT record and a CAA record for Let's Encrypt
- Returns immediately so certbot can send the next challenge

**Phase 2 -- Write + finalize** (on the last challenge):
1. Writes the final challenge config file
2. Flattens the dnsmasq config (recursively following all includes) and auto-discovers the auth-server zone, secondary servers, and public IP
3. Validates the dnsmasq configuration (`dnsmasq --test`)
4. Restarts dnsmasq to load all new records
5. Verifies ALL TXT records are present on the local DNS server
6. Sends a single DNS NOTIFY to secondary servers via `ldns-notify`
7. Polls secondary servers round-robin until all expected TXT records are present on all servers (up to 120 seconds)

This means a certificate with 10 domains causes only one dnsmasq restart and one propagation wait, not 10.

### Multi-domain and wildcard support

When requesting both a domain and its wildcard (e.g. `-d example.com -d *.example.com`), certbot generates two challenges for `_acme-challenge.example.com` with different tokens. The hook handles this correctly by writing each challenge to a separate file (`dnsmasq.acme.{domain}.{hash}.conf`) and verifying that all expected tokens are present during the finalize phase.

## Configuration

The auth-hook auto-discovers your DNS setup from the dnsmasq config. You can override paths and service name via CLI flags or environment variables:

| CLI Flag | Environment Variable | Default | Description |
|---|---|---|---|
| `--conf-dir` | `DNSMASQ_CONF_DIR` | `/etc/dnsmasq.d` | Directory for ACME challenge config files |
| `--conf` | `DNSMASQ_CONF` | `/etc/dnsmasq.conf` | Main dnsmasq config file path |
| `--service` | `DNSMASQ_SERVICE` | `dnsmasq` | systemd service name |

CLI flags take priority over environment variables, which take priority over defaults.

Certbot sets the following environment variables automatically:

- `CERTBOT_DOMAIN` -- the domain being validated
- `CERTBOT_VALIDATION` -- the ACME challenge token value
- `CERTBOT_REMAINING_CHALLENGES` -- number of challenges remaining after this one (used for batching; available since certbot 1.4.0)

### What gets auto-discovered

From the dnsmasq config (after flattening all includes):

- **`auth-server=`** -- the authoritative zone name (last value wins, takes the zone name before any comma)
- **`auth-sec-servers=`** -- secondary DNS servers to notify (all values collected)
- **public IPv4** -- used as the source IP for `dig` queries and `ldns-notify`, discovered in priority order:
  1. the first public `listen-address=`, or
  2. if the server binds via `bind-dynamic`/`bind-interfaces` (no `listen-address=`), the first public (globally-routable) IPv4 on the bound `interface=`, looked up with `ip -4 addr`.

## Development

```bash
uv pip install -e .           # Install in development mode
uv run pytest tests/ -v       # Run all tests
uv run pytest tests/test_hook.py -v  # Run specific test module
```

All tests use mocked subprocess calls and filesystem interactions -- no external tools or network access needed.

## License

Apache License 2.0 -- see [LICENSE](LICENSE)
