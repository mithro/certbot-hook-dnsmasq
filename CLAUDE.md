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
    hook.py                  # Auth-hook and cleanup-hook orchestration logic
    external.py              # Thin subprocess wrappers for external tools
tests/
    test_cli.py              # CLI argument parsing and subcommand dispatch
    test_flatten.py          # Config flattening and value extraction
    test_hook.py             # Auth-hook and cleanup-hook workflow and helpers
    test_external.py         # Subprocess wrapper behaviour
pyproject.toml               # Package metadata and build config
```

## Architecture

Python package (`certbot_hook_dnsmasq`) with three subcommands (`auth-hook`, `cleanup-hook`, and `flatten-config`):

- **`cli.py`** -- argparse entry point with `--version` flag. Config resolution order: CLI flags > environment variables > defaults. Uses typed `_resolve_path` / `_resolve_str` helpers.
- **`flatten.py`** -- flattens dnsmasq config by recursively following `conf-file=` and `conf-dir=` includes (with cycle detection). `DnsmasqConfigValues` dataclass holds extracted values (auth-zone, auth-sec-servers, public IPv4 via `is_public_ipv4`/`ipaddress.IPv4Address.is_global`, and the bound `interface`). `is_public_ipv4` is a shared helper (also used by `hook.py`).
- **`hook.py`** -- auth-hook and cleanup-hook orchestration, both with two-phase execution. Auth-hook writes per-challenge config files (hash-based filenames), then on the final invocation restarts dnsmasq, verifies all TXT records locally and on secondaries, sends one NOTIFY, waits for propagation. Cleanup-hook removes the config files, then on the final invocation tests config and restarts dnsmasq. All subprocess failures are caught and reported cleanly (no raw tracebacks).
- **`external.py`** -- thin subprocess wrappers for `dig` (`query_all_txt_records`), `ldns-notify`, `systemctl`, `dnsmasq --test`. This is the only module that calls `subprocess.run`.

### Auth-hook workflow (batch-aware)

The hook uses `CERTBOT_REMAINING_CHALLENGES` for two-phase execution:

**Phase 1 (remaining > 0):** Write config file only, return immediately.

**Phase 2 (remaining == 0):** Write config file, then finalize:
1. Flattens dnsmasq config and extracts auth-server zone, secondary servers, and public IP
2. Validates config (`dnsmasq --test`) and restarts dnsmasq via systemd
3. Scans `conf_dir` for all `dnsmasq.acme.*.conf` files to discover pending challenges
4. Verifies ALL TXT records on local DNS (grouped by domain, subset check)
5. Sends a single DNS NOTIFY to secondary servers via `ldns-notify`
6. Polls secondaries round-robin until all expected TXT records are present (max 120s)
7. Returns 1 (failure) if secondaries do not sync within the timeout

Config files use hash-based naming: `dnsmasq.acme.{domain}.{sha256(token)[:8]}.conf`. This ensures wildcard + base domain challenges (same domain, different tokens) get separate files.

### Cleanup-hook workflow (batch-aware)

The cleanup hook also uses `CERTBOT_REMAINING_CHALLENGES` for two-phase execution:

**Phase 1 (remaining > 0):** Remove config file only, return immediately.

**Phase 2 (remaining == 0):** Remove config file, then finalize:
1. Validates config (`dnsmasq --test`) and restarts dnsmasq via systemd
2. Returns 1 (failure) if config test or restart fails

The cleanup hook does not need DNS verification, NOTIFY, or sync waiting -- removed records will propagate on the next zone refresh.

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
uv run python -m certbot_hook_dnsmasq cleanup-hook
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

Auth-hook and cleanup-hook options (CLI flags override environment variables, which override defaults):

| CLI Flag | Environment Variable | Default |
|---|---|---|
| `--conf-dir` | `DNSMASQ_CONF_DIR` | `/etc/dnsmasq.d` |
| `--conf` | `DNSMASQ_CONF` | `/etc/dnsmasq.conf` |
| `--service` | `DNSMASQ_SERVICE` | `dnsmasq` |

### Environment variables (set by certbot)

- `CERTBOT_DOMAIN` -- Domain being validated (required for `auth-hook` and `cleanup-hook`)
- `CERTBOT_VALIDATION` -- ACME challenge token value (required for `auth-hook` and `cleanup-hook`)
- `CERTBOT_REMAINING_CHALLENGES` -- Number of challenges remaining after this one (0 = last). Used for batch mode: when > 0, the hook writes/removes the config file and returns immediately. When 0 or missing, the hook finalizes. Available since certbot 1.4.0.

### Auto-discovered from dnsmasq config

The `auth-hook` reads the dnsmasq config to discover:
- `auth-server=` -- the authoritative zone name (last value wins)
- `auth-sec-servers=` -- secondary DNS servers to notify
- public IPv4 (source IP for `dig` queries and NOTIFY), in priority order:
  1. the first public `listen-address=`, or
  2. if the server binds via `bind-dynamic`/`bind-interfaces` (no `listen-address=`), the first public IPv4 on the bound `interface=`, looked up with `ip -4 addr` (`external.interface_ipv4_addresses` → `hook.resolve_interface_public_ipv4`)
