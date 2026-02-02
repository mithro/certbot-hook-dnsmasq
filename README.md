# certbot-hook-dnsmasq

Certbot hook for DNS-01 challenge authentication using a dnsmasq server.

## Overview

This tool creates temporary TXT records in dnsmasq for ACME DNS-01 challenges, allowing certbot to obtain wildcard certificates or certificates for servers that aren't publicly accessible via HTTP.

It auto-discovers your DNS setup from the dnsmasq config (`auth-server`, `auth-sec-servers`, `listen-address`) so there is minimal configuration needed.

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

The `auth-hook` subcommand performs the following steps:

1. Flattens the dnsmasq config (recursively following all includes) and auto-discovers the auth-server zone, secondary servers, and public IP from `auth-server=`, `auth-sec-servers=`, and `listen-address=` directives
2. Creates a dnsmasq config file with the ACME challenge TXT record and a CAA record for Let's Encrypt
3. Validates the dnsmasq configuration (`dnsmasq --test`)
4. Restarts dnsmasq to load the new record
5. Verifies the local DNS server has the correct TXT record
6. Sends DNS NOTIFY to secondary servers via `ldns-notify` to trigger zone transfers
7. Polls secondary servers round-robin until they sync (up to 120 seconds)

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

### What gets auto-discovered

From the dnsmasq config (after flattening all includes):

- **`auth-server=`** -- the authoritative zone name (last value wins, takes the zone name before any comma)
- **`auth-sec-servers=`** -- secondary DNS servers to notify (all values collected)
- **`listen-address=`** -- the first public IPv4 address found (used as source IP for dig queries and ldns-notify)

## Development

```bash
uv pip install -e .           # Install in development mode
uv run pytest tests/ -v       # Run all tests
uv run pytest tests/test_hook.py -v  # Run specific test module
```

All tests use mocked subprocess calls and filesystem interactions -- no external tools or network access needed.

## License

Apache License 2.0 -- see [LICENSE](LICENSE)
