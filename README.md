# certbot-hook-dnsmasq

Hook for certbot that allows using DNS-01 challenge authentication with a dnsmasq server.

## Overview

This tool creates temporary TXT records in dnsmasq for ACME DNS-01 challenges, allowing certbot to obtain wildcard certificates or certificates for servers that aren't publicly accessible via HTTP.

## Requirements

- Python 3.11+
- dnsmasq configured as a DNS server
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

### Flatten Config (debugging tool)

Flatten a dnsmasq config by following all includes, useful for debugging:

```bash
certbot-hook-dnsmasq flatten-config [/etc/dnsmasq.conf]
```

## How it works

1. Flattens the dnsmasq config and auto-discovers auth-server zone, secondary servers, and public IP
2. Creates a dnsmasq config file with the ACME challenge TXT record
3. Validates the dnsmasq configuration (`dnsmasq --test`)
4. Restarts dnsmasq to load the new record
5. Verifies the local DNS server has the correct record
6. Sends NOTIFY to secondary DNS servers to trigger zone transfer
7. Waits for secondary servers to sync (up to 120 seconds)

## Configuration

The auth-hook auto-discovers your DNS setup from the dnsmasq config (auth-server, auth-sec-servers, listen-address). You can override defaults via CLI flags or environment variables:

| CLI Flag | Environment Variable | Default |
|---|---|---|
| `--conf-dir` | `DNSMASQ_CONF_DIR` | `/etc/dnsmasq.d` |
| `--conf` | `DNSMASQ_CONF` | `/etc/dnsmasq.conf` |
| `--service` | `DNSMASQ_SERVICE` | `dnsmasq` |

CLI flags take priority over environment variables, which take priority over defaults.

Certbot sets the following environment variables automatically:

- `CERTBOT_DOMAIN` -- the domain being validated
- `CERTBOT_VALIDATION` -- the ACME challenge token value

## License

Apache License 2.0 - see [LICENSE](LICENSE)
