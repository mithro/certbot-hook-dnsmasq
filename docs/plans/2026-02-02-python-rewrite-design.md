# Design: Rewrite certbot-hook-dnsmasq in Python

## Goal

Replace the bash script `dnsmasq-hook.sh` with a proper Python CLI tool, merging
`dnsmasq_flatten_config.py` into a single package with subcommands.

## CLI Interface

Tool name: `certbot-hook-dnsmasq` (matches repo name).

### Subcommands

**`certbot-hook-dnsmasq auth-hook`** — certbot `--manual-auth-hook` replacement.

Flags (with env var fallbacks):
- `--conf-dir` / `DNSMASQ_CONF_DIR` (default: `/etc/dnsmasq.d`)
- `--conf` / `DNSMASQ_CONF` (default: `/etc/dnsmasq.conf`)
- `--service` / `DNSMASQ_SERVICE` (default: `dnsmasq`)

Reads from environment (required, set by certbot):
- `CERTBOT_DOMAIN`
- `CERTBOT_VALIDATION`

**`certbot-hook-dnsmasq flatten-config`** — standalone config flattener.

Arguments:
- Positional `config_path` (default: `/etc/dnsmasq.conf`)

Prints flattened config to stdout.

## Package Structure

```
certbot_hook_dnsmasq/
    __init__.py          # version, package metadata
    __main__.py          # entry point: python -m certbot_hook_dnsmasq
    cli.py               # argparse subcommand dispatch
    flatten.py           # dnsmasq config flattening (from dnsmasq_flatten_config.py)
    hook.py              # auth-hook logic (from dnsmasq-hook.sh)
    external.py          # thin subprocess wrappers for dig, ldns-notify, systemctl, dnsmasq
tests/
    __init__.py
    test_flatten.py      # moved from test_dnsmasq_flatten_config.py
    test_hook.py         # tests for auth-hook logic
    test_cli.py          # CLI integration tests
    test_external.py     # tests for subprocess wrappers
pyproject.toml           # packaging, console_scripts entry point
TODO.md                  # tracked future work
```

Console entry point in `pyproject.toml`:
```toml
[project.scripts]
certbot-hook-dnsmasq = "certbot_hook_dnsmasq.cli:main"
```

Runnable as `certbot-hook-dnsmasq auth-hook` or `uv run python -m certbot_hook_dnsmasq auth-hook`.

## Module Responsibilities

### `cli.py` — Subcommand dispatch

- Parses arguments with `argparse`
- `auth-hook` subcommand: resolves CLI flags vs env vars, calls `hook.run_auth_hook()`
- `flatten-config` subcommand: calls flatten logic, prints to stdout

### `flatten.py` — Config flattening

Direct port of `dnsmasq_flatten_config.py`:
- `parse_defaults(defaults_path)` — parses `/etc/default/dnsmasq`
- `should_exclude(filename, patterns)` — checks exclusion patterns
- `parse_config(config_path, exclude_patterns, visited)` — recursive config parser

New addition:
- `extract_config_values(lines)` — extracts `auth_zone`, `auth_sec_servers`, and
  `public_ipv4` from flattened config lines (replaces the grep/cut/sed pipeline in
  the bash script)

### `hook.py` — Auth-hook workflow

- `write_acme_challenge(conf_dir, domain, validation)` — writes dnsmasq ACME config
- `verify_local_dns(public_ipv4, domain, validation)` — checks local TXT record
- `notify_secondaries(public_ipv4, auth_zone, servers)` — sends NOTIFY via ldns-notify
- `wait_for_sync(servers, domain, validation, max_wait, interval)` — polls secondaries
  with round-robin checking and response tracking
- `run_auth_hook(conf_dir, conf, service, domain, validation)` — orchestrates the full flow

### `external.py` — Subprocess wrappers

- `query_txt_record(server, domain)` — shared DNS query function used by both
  `verify_local_dns()` and `wait_for_sync()`
- `run_ldns_notify(source_ip, zone, servers)` — sends NOTIFY
- `run_systemctl(action, service)` — restart/status
- `run_dnsmasq_test(conf)` — `dnsmasq --test -C`

## DNS Sync Polling

`wait_for_sync()` uses round-robin polling with a response dictionary:

```python
responses = {}  # server -> last seen TXT value
while elapsed < max_wait:
    for server in servers:
        if responses.get(server) == validation:
            continue  # already synced
        responses[server] = query_txt_record(server, domain)

    # Log current state
    for server, value in responses.items():
        synced = value == validation
        print(f"  {server}: {value!r} ({'synced' if synced else 'waiting'})")

    if all(v == validation for v in responses.values()):
        print("All secondaries synced!")
        return

    sleep(interval)
```

This provides full visibility into what each server returns at each poll cycle.

## Dependencies

No new Python dependencies beyond stdlib. External tools called via subprocess:
- `dig` (dnsutils/bind-utils)
- `ldns-notify` (ldnsutils)
- `systemctl` (systemd)
- `dnsmasq` (for `--test`)

See TODO.md for plan to replace external tools with native Python.

## Configuration Resolution Order

For `auth-hook` options:
1. CLI flag (highest priority)
2. Environment variable
3. Default value
