# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Certbot hook for DNS-01 challenge authentication using dnsmasq. Creates temporary ACME challenge TXT records in dnsmasq, enabling wildcard certificates or certificates for non-HTTP-accessible servers. Distributed as a Python package with a `certbot-hook-dnsmasq` CLI entry point.

## Project Structure

```
certbot_hook_dnsmasq/        # Python package
    __init__.py              # Package init, exports __version__
    __main__.py              # Enables `python -m certbot_hook_dnsmasq`
    cli.py                   # argparse entry point, dispatches to subcommands
    flatten.py               # Flattens dnsmasq config; extracts config values
    hook.py                  # Auth-hook orchestration logic
    external.py              # Thin subprocess wrappers for external tools
tests/
    test_cli.py              # CLI argument parsing and subcommand dispatch
    test_flatten.py          # Config flattening and value extraction
    test_hook.py             # Auth-hook workflow and helpers
    test_external.py         # Subprocess wrapper behaviour
pyproject.toml               # Package metadata and build config
TODO.md                      # Planned future work
```

## Architecture

Python package (`certbot_hook_dnsmasq`) with two subcommands (`auth-hook` and `flatten-config`):

- **`cli.py`** -- argparse entry point with `--version` flag. Config resolution order: CLI flags > environment variables > defaults. Uses typed `_resolve_path` / `_resolve_str` helpers.
- **`flatten.py`** -- flattens dnsmasq config by recursively following `conf-file=` and `conf-dir=` includes (with cycle detection). `DnsmasqConfigValues` dataclass holds extracted values (auth-zone, auth-sec-servers, public IPv4 via `ipaddress.IPv4Address.is_global`).
- **`hook.py`** -- auth-hook orchestration: writes ACME challenge TXT + CAA records, restarts dnsmasq, verifies local DNS, notifies secondaries, polls secondaries round-robin until synced. All subprocess failures are caught and reported cleanly (no raw tracebacks).
- **`external.py`** -- thin subprocess wrappers for `dig`, `ldns-notify`, `systemctl`, `dnsmasq --test`. These are the only modules that call `subprocess.run`.

### Auth-hook workflow

1. Flattens dnsmasq config and extracts auth-server zone, secondary servers, and public IP
2. Writes `<conf-dir>/dnsmasq.acme.<domain>.conf` with TXT and CAA records
3. Validates config (`dnsmasq --test`) and restarts dnsmasq via systemd
4. Verifies local DNS has the correct TXT record
5. Sends DNS NOTIFY to secondary servers via `ldns-notify`
6. Polls secondaries round-robin until they sync (max 120s, configurable)

## Development

```bash
uv pip install -e .           # Install in development mode
uv run pytest tests/ -v       # Run all tests
uv run pytest tests/test_flatten.py -v  # Run specific test module
```

The package can also be run as a module:

```bash
uv run python -m certbot_hook_dnsmasq --version
uv run python -m certbot_hook_dnsmasq auth-hook
uv run python -m certbot_hook_dnsmasq flatten-config /etc/dnsmasq.conf
```

### Test structure

All tests use `unittest.mock.patch` to mock subprocess calls and filesystem interactions. No external tools or network access needed. Tests are organised by module: `test_flatten.py`, `test_external.py`, `test_hook.py`, `test_cli.py`.

## Dependencies

### Python
- Python 3.11+
- No runtime Python dependencies (stdlib only)

### External tools (called via subprocess)
- `dnsmasq` -- DNS server, used for `--test` config validation
- `dig` -- TXT record queries (from `dnsutils` / `bind-utils`)
- `ldns-notify` -- DNS NOTIFY to secondaries (from `ldnsutils`)
- `systemctl` -- service restart/status (systemd)

## Configuration

Auth-hook options (CLI flags override environment variables, which override defaults):

| CLI Flag | Environment Variable | Default |
|---|---|---|
| `--conf-dir` | `DNSMASQ_CONF_DIR` | `/etc/dnsmasq.d` |
| `--conf` | `DNSMASQ_CONF` | `/etc/dnsmasq.conf` |
| `--service` | `DNSMASQ_SERVICE` | `dnsmasq` |

### Environment variables (set by certbot)

- `CERTBOT_DOMAIN` -- Domain being validated (required for `auth-hook`)
- `CERTBOT_VALIDATION` -- ACME challenge token value (required for `auth-hook`)

### Auto-discovered from dnsmasq config

The `auth-hook` reads the dnsmasq config to discover:
- `auth-server=` -- the authoritative zone name (last value wins)
- `auth-sec-servers=` -- secondary DNS servers to notify
- `listen-address=` -- first public IPv4 address (used as source IP for queries and NOTIFY)
