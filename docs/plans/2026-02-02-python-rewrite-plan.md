# Python Rewrite Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Rewrite `dnsmasq-hook.sh` and `dnsmasq_flatten_config.py` into a single Python package `certbot_hook_dnsmasq` with `auth-hook` and `flatten-config` subcommands.

**Architecture:** Python package with `cli.py` (argparse dispatch), `flatten.py` (config flattening, ported from existing code), `hook.py` (auth-hook orchestration), `external.py` (subprocess wrappers for dig/ldns-notify/systemctl/dnsmasq). External tools called via subprocess; no new dependencies beyond stdlib.

**Tech Stack:** Python 3.11+ stdlib only (argparse, subprocess, pathlib, dataclasses, ipaddress, re). pytest for testing. uv for running.

---

### Task 1: Create pyproject.toml and package skeleton

**Files:**
- Create: `pyproject.toml`
- Create: `certbot_hook_dnsmasq/__init__.py`
- Create: `certbot_hook_dnsmasq/__main__.py`
- Create: `tests/__init__.py`

**Step 1: Create pyproject.toml**

```toml
[build-system]
requires = ["setuptools>=64"]
build-backend = "setuptools.backends._legacy:_Backend"

[project]
name = "certbot-hook-dnsmasq"
version = "0.1.0"
description = "Certbot DNS-01 hook for dnsmasq"
requires-python = ">=3.11"
license = "Apache-2.0"

[project.scripts]
certbot-hook-dnsmasq = "certbot_hook_dnsmasq.cli:main"

[tool.pytest.ini_options]
testpaths = ["tests"]
```

**Step 2: Create `certbot_hook_dnsmasq/__init__.py`**

```python
"""Certbot DNS-01 hook for dnsmasq."""

__version__ = "0.1.0"
```

**Step 3: Create `certbot_hook_dnsmasq/__main__.py`**

```python
"""Allow running as: python -m certbot_hook_dnsmasq"""

from certbot_hook_dnsmasq.cli import main

main()
```

**Step 4: Create `tests/__init__.py`**

Empty file.

**Step 5: Verify the package installs**

Run: `uv pip install -e .`
Expected: installs successfully

**Step 6: Commit**

```bash
git add pyproject.toml certbot_hook_dnsmasq/__init__.py certbot_hook_dnsmasq/__main__.py tests/__init__.py
git commit -m "Add package skeleton with pyproject.toml"
```

---

### Task 2: Port flatten module with existing tests

**Files:**
- Create: `certbot_hook_dnsmasq/flatten.py`
- Create: `tests/test_flatten.py`

**Step 1: Create `certbot_hook_dnsmasq/flatten.py`**

Copy the contents of `dnsmasq_flatten_config.py` into `certbot_hook_dnsmasq/flatten.py`. Keep all three functions (`parse_defaults`, `should_exclude`, `parse_config`) and the `flatten_config` orchestrator (renamed from `main`). Remove the `if __name__ == '__main__'` block and the `sys.argv` handling — that moves to `cli.py` later.

```python
"""Flatten dnsmasq config by following all includes."""

import re
from pathlib import Path


def parse_defaults(defaults_path: Path | None = None) -> tuple[Path | None, list[str]]:
    """Parse /etc/default/dnsmasq to get CONFIG_DIR and exclusion patterns."""
    if defaults_path is None:
        defaults_path = Path('/etc/default/dnsmasq')

    if not defaults_path.is_file():
        return None, []

    for line in defaults_path.read_text().splitlines():
        line = line.strip()
        if line.startswith('#') or not line:
            continue

        match = re.match(r'^CONFIG_DIR=(.+)$', line)
        if match:
            parts = match.group(1).split(',')
            conf_dir = Path(parts[0])
            exclude_patterns = parts[1:] if len(parts) > 1 else []
            return conf_dir, exclude_patterns

    return None, []


def should_exclude(filename: str, exclude_patterns: list[str]) -> bool:
    """Check if a file should be excluded based on patterns."""
    for pattern in exclude_patterns:
        if filename.endswith(pattern):
            return True
    return False


def parse_config(
    config_path: Path,
    exclude_patterns: list[str],
    visited: set[Path] | None = None
) -> list[str]:
    """Parse a dnsmasq config file, following includes recursively."""
    if visited is None:
        visited = set()

    config_path = config_path.resolve()
    if config_path in visited:
        return []
    visited.add(config_path)

    if not config_path.is_file():
        return []

    lines = []
    for line in config_path.read_text().splitlines():
        stripped = line.strip()

        if not stripped or stripped.startswith('#'):
            continue

        if stripped.startswith('conf-file='):
            include_path = Path(stripped.split('=', 1)[1])
            if not should_exclude(include_path.name, exclude_patterns):
                lines.extend(parse_config(include_path, exclude_patterns, visited))
            continue

        if stripped.startswith('conf-dir='):
            value = stripped.split('=', 1)[1]
            parts = value.split(',')
            dir_path = Path(parts[0])
            local_exclude = []
            local_include = []
            for ext in parts[1:]:
                if ext.startswith('*'):
                    local_include.append(ext[1:])
                else:
                    local_exclude.append(ext)

            if dir_path.is_dir():
                for f in sorted(dir_path.iterdir()):
                    if not f.is_file():
                        continue
                    if should_exclude(f.name, exclude_patterns):
                        continue
                    if should_exclude(f.name, local_exclude):
                        continue
                    if local_include:
                        if not any(f.name.endswith(ext) for ext in local_include):
                            continue
                    lines.extend(parse_config(f, exclude_patterns, visited))
            continue

        lines.append(stripped)

    return lines


def flatten_config(
    config_path: Path,
    defaults_path: Path | None = None,
) -> list[str]:
    """Flatten a dnsmasq config file, resolving all includes.

    This is the main entry point. It reads /etc/default/dnsmasq for
    CONFIG_DIR and exclusion patterns, then recursively parses the config.
    """
    default_conf_dir, exclude_patterns = parse_defaults(defaults_path)

    visited: set[Path] = set()
    lines = parse_config(config_path, exclude_patterns, visited)

    if default_conf_dir and default_conf_dir.is_dir():
        for f in sorted(default_conf_dir.iterdir()):
            if not f.is_file():
                continue
            if should_exclude(f.name, exclude_patterns):
                continue
            lines.extend(parse_config(f, exclude_patterns, visited))

    return lines
```

**Step 2: Create `tests/test_flatten.py`**

Port tests from `test_dnsmasq_flatten_config.py`, updating imports to use the new package path. Add a test for the new `flatten_config` orchestrator.

```python
"""Tests for certbot_hook_dnsmasq.flatten"""

from pathlib import Path

import pytest

from certbot_hook_dnsmasq.flatten import (
    flatten_config,
    parse_config,
    parse_defaults,
    should_exclude,
)


class TestShouldExclude:
    def test_matches_suffix(self):
        assert should_exclude("foo.dpkg-dist", [".dpkg-dist"]) is True
        assert should_exclude("foo.dpkg-old", [".dpkg-old"]) is True

    def test_no_match(self):
        assert should_exclude("foo.conf", [".dpkg-dist"]) is False
        assert should_exclude("foo", [".dpkg-dist"]) is False

    def test_multiple_patterns(self):
        patterns = [".dpkg-dist", ".dpkg-old", ".dpkg-new"]
        assert should_exclude("foo.dpkg-dist", patterns) is True
        assert should_exclude("foo.dpkg-old", patterns) is True
        assert should_exclude("foo.dpkg-new", patterns) is True
        assert should_exclude("foo.conf", patterns) is False

    def test_empty_patterns(self):
        assert should_exclude("foo.conf", []) is False


class TestParseConfig:
    def test_simple_config(self, tmp_path):
        config = tmp_path / "dnsmasq.conf"
        config.write_text("auth-server=example.com\nlisten-address=1.2.3.4\n")

        lines = parse_config(config, [])
        assert lines == ["auth-server=example.com", "listen-address=1.2.3.4"]

    def test_skips_comments(self, tmp_path):
        config = tmp_path / "dnsmasq.conf"
        config.write_text("# comment\nauth-server=example.com\n  # indented comment\n")

        lines = parse_config(config, [])
        assert lines == ["auth-server=example.com"]

    def test_skips_empty_lines(self, tmp_path):
        config = tmp_path / "dnsmasq.conf"
        config.write_text("auth-server=example.com\n\n\nlisten-address=1.2.3.4\n")

        lines = parse_config(config, [])
        assert lines == ["auth-server=example.com", "listen-address=1.2.3.4"]

    def test_follows_conf_file(self, tmp_path):
        main_conf = tmp_path / "dnsmasq.conf"
        include_conf = tmp_path / "extra.conf"

        include_conf.write_text("listen-address=5.6.7.8\n")
        main_conf.write_text(f"auth-server=example.com\nconf-file={include_conf}\n")

        lines = parse_config(main_conf, [])
        assert lines == ["auth-server=example.com", "listen-address=5.6.7.8"]

    def test_follows_conf_dir(self, tmp_path):
        main_conf = tmp_path / "dnsmasq.conf"
        conf_dir = tmp_path / "dnsmasq.d"
        conf_dir.mkdir()

        (conf_dir / "01-first.conf").write_text("server=8.8.8.8\n")
        (conf_dir / "02-second.conf").write_text("server=8.8.4.4\n")
        main_conf.write_text(f"conf-dir={conf_dir}\n")

        lines = parse_config(main_conf, [])
        assert lines == ["server=8.8.8.8", "server=8.8.4.4"]

    def test_conf_dir_excludes_patterns(self, tmp_path):
        main_conf = tmp_path / "dnsmasq.conf"
        conf_dir = tmp_path / "dnsmasq.d"
        conf_dir.mkdir()

        (conf_dir / "good.conf").write_text("server=8.8.8.8\n")
        (conf_dir / "bad.conf.dpkg-dist").write_text("server=BAD\n")
        main_conf.write_text(f"conf-dir={conf_dir}\n")

        lines = parse_config(main_conf, [".dpkg-dist"])
        assert lines == ["server=8.8.8.8"]
        assert "server=BAD" not in lines

    def test_conf_dir_with_local_exclude(self, tmp_path):
        main_conf = tmp_path / "dnsmasq.conf"
        conf_dir = tmp_path / "dnsmasq.d"
        conf_dir.mkdir()

        (conf_dir / "good.conf").write_text("server=8.8.8.8\n")
        (conf_dir / "backup.bak").write_text("server=BAD\n")
        main_conf.write_text(f"conf-dir={conf_dir},.bak\n")

        lines = parse_config(main_conf, [])
        assert lines == ["server=8.8.8.8"]

    def test_conf_dir_with_include_filter(self, tmp_path):
        main_conf = tmp_path / "dnsmasq.conf"
        conf_dir = tmp_path / "dnsmasq.d"
        conf_dir.mkdir()

        (conf_dir / "good.conf").write_text("server=8.8.8.8\n")
        (conf_dir / "other.txt").write_text("server=BAD\n")
        main_conf.write_text(f"conf-dir={conf_dir},*.conf\n")

        lines = parse_config(main_conf, [])
        assert lines == ["server=8.8.8.8"]

    def test_prevents_circular_includes(self, tmp_path):
        conf_a = tmp_path / "a.conf"
        conf_b = tmp_path / "b.conf"

        conf_a.write_text(f"server=A\nconf-file={conf_b}\n")
        conf_b.write_text(f"server=B\nconf-file={conf_a}\n")

        lines = parse_config(conf_a, [])
        assert lines == ["server=A", "server=B"]

    def test_nonexistent_file_returns_empty(self, tmp_path):
        nonexistent = tmp_path / "nope.conf"
        lines = parse_config(nonexistent, [])
        assert lines == []

    def test_nonexistent_conf_dir_skipped(self, tmp_path):
        main_conf = tmp_path / "dnsmasq.conf"
        main_conf.write_text("auth-server=example.com\nconf-dir=/nonexistent\n")

        lines = parse_config(main_conf, [])
        assert lines == ["auth-server=example.com"]


class TestParseDefaults:
    def test_parses_config_dir(self, tmp_path):
        defaults = tmp_path / "dnsmasq"
        defaults.write_text("CONFIG_DIR=/etc/dnsmasq.d,.dpkg-dist,.dpkg-old,.dpkg-new\n")

        conf_dir, exclude = parse_defaults(defaults)
        assert str(conf_dir) == '/etc/dnsmasq.d'
        assert exclude == ['.dpkg-dist', '.dpkg-old', '.dpkg-new']

    def test_skips_comments(self, tmp_path):
        defaults = tmp_path / "dnsmasq"
        defaults.write_text("# CONFIG_DIR=/commented/out\nCONFIG_DIR=/etc/dnsmasq.d\n")

        conf_dir, exclude = parse_defaults(defaults)
        assert str(conf_dir) == '/etc/dnsmasq.d'
        assert exclude == []

    def test_no_config_dir(self, tmp_path):
        defaults = tmp_path / "dnsmasq"
        defaults.write_text("# just a comment\n")

        conf_dir, exclude = parse_defaults(defaults)
        assert conf_dir is None
        assert exclude == []

    def test_nonexistent_file(self, tmp_path):
        nonexistent = tmp_path / "nope"

        conf_dir, exclude = parse_defaults(nonexistent)
        assert conf_dir is None
        assert exclude == []

    def test_config_dir_without_excludes(self, tmp_path):
        defaults = tmp_path / "dnsmasq"
        defaults.write_text("CONFIG_DIR=/etc/dnsmasq.d\n")

        conf_dir, exclude = parse_defaults(defaults)
        assert str(conf_dir) == '/etc/dnsmasq.d'
        assert exclude == []


class TestFlattenConfig:
    def test_flattens_with_conf_dir(self, tmp_path):
        """flatten_config follows conf-dir includes."""
        conf_dir = tmp_path / "dnsmasq.d"
        conf_dir.mkdir()
        (conf_dir / "extra.conf").write_text("server=8.8.8.8\n")

        main_conf = tmp_path / "dnsmasq.conf"
        main_conf.write_text(f"auth-server=example.com\nconf-dir={conf_dir}\n")

        # No defaults file — pass nonexistent path
        lines = flatten_config(main_conf, defaults_path=tmp_path / "no-defaults")
        assert lines == ["auth-server=example.com", "server=8.8.8.8"]

    def test_flattens_with_defaults_config_dir(self, tmp_path):
        """flatten_config reads CONFIG_DIR from defaults file."""
        conf_dir = tmp_path / "dnsmasq.d"
        conf_dir.mkdir()
        (conf_dir / "extra.conf").write_text("server=8.8.8.8\n")

        defaults = tmp_path / "defaults"
        defaults.write_text(f"CONFIG_DIR={conf_dir}\n")

        main_conf = tmp_path / "dnsmasq.conf"
        main_conf.write_text("auth-server=example.com\n")

        lines = flatten_config(main_conf, defaults_path=defaults)
        assert lines == ["auth-server=example.com", "server=8.8.8.8"]
```

**Step 3: Run tests to verify they pass**

Run: `uv run pytest tests/test_flatten.py -v`
Expected: all tests PASS

**Step 4: Commit**

```bash
git add certbot_hook_dnsmasq/flatten.py tests/test_flatten.py
git commit -m "Port flatten module from dnsmasq_flatten_config.py"
```

---

### Task 3: Add extract_config_values to flatten module

**Files:**
- Modify: `certbot_hook_dnsmasq/flatten.py`
- Modify: `tests/test_flatten.py`

**Step 1: Write the failing tests**

Add to `tests/test_flatten.py`:

```python
from certbot_hook_dnsmasq.flatten import extract_config_values


class TestExtractConfigValues:
    def test_extracts_auth_zone(self):
        lines = ["auth-server=example.com,ns1.example.com"]
        values = extract_config_values(lines)
        assert values.auth_zone == "example.com"

    def test_auth_zone_last_wins(self):
        lines = [
            "auth-server=first.com",
            "auth-server=second.com,ns1.second.com",
        ]
        values = extract_config_values(lines)
        assert values.auth_zone == "second.com"

    def test_auth_zone_without_comma(self):
        lines = ["auth-server=example.com"]
        values = extract_config_values(lines)
        assert values.auth_zone == "example.com"

    def test_extracts_auth_sec_servers(self):
        lines = ["auth-sec-servers=ns2.example.com,ns3.example.com"]
        values = extract_config_values(lines)
        assert values.auth_sec_servers == ["ns2.example.com", "ns3.example.com"]

    def test_multiple_auth_sec_servers_lines(self):
        lines = [
            "auth-sec-servers=ns2.example.com",
            "auth-sec-servers=ns3.example.com",
        ]
        values = extract_config_values(lines)
        assert values.auth_sec_servers == ["ns2.example.com", "ns3.example.com"]

    def test_extracts_public_ipv4(self):
        lines = [
            "listen-address=127.0.0.1",
            "listen-address=203.0.113.1",
        ]
        values = extract_config_values(lines)
        assert values.public_ipv4 == "203.0.113.1"

    def test_skips_private_ipv4(self):
        lines = [
            "listen-address=10.0.0.1",
            "listen-address=172.16.0.1",
            "listen-address=192.168.1.1",
            "listen-address=203.0.113.1",
        ]
        values = extract_config_values(lines)
        assert values.public_ipv4 == "203.0.113.1"

    def test_skips_ipv6(self):
        lines = [
            "listen-address=::1",
            "listen-address=203.0.113.1",
        ]
        values = extract_config_values(lines)
        assert values.public_ipv4 == "203.0.113.1"

    def test_missing_auth_zone_returns_none(self):
        lines = ["listen-address=1.2.3.4"]
        values = extract_config_values(lines)
        assert values.auth_zone is None

    def test_missing_sec_servers_returns_empty(self):
        lines = ["auth-server=example.com"]
        values = extract_config_values(lines)
        assert values.auth_sec_servers == []

    def test_missing_public_ipv4_returns_none(self):
        lines = ["listen-address=127.0.0.1"]
        values = extract_config_values(lines)
        assert values.public_ipv4 is None

    def test_full_config(self):
        lines = [
            "auth-server=example.com,ns1.example.com",
            "auth-sec-servers=ns2.example.com,ns3.example.com",
            "listen-address=127.0.0.1",
            "listen-address=203.0.113.1",
            "server=8.8.8.8",
        ]
        values = extract_config_values(lines)
        assert values.auth_zone == "example.com"
        assert values.auth_sec_servers == ["ns2.example.com", "ns3.example.com"]
        assert values.public_ipv4 == "203.0.113.1"
```

**Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_flatten.py::TestExtractConfigValues -v`
Expected: FAIL — `ImportError: cannot import name 'extract_config_values'`

**Step 3: Implement extract_config_values**

Add to `certbot_hook_dnsmasq/flatten.py`:

```python
import ipaddress
from dataclasses import dataclass, field


@dataclass
class DnsmasqConfigValues:
    """Values extracted from a flattened dnsmasq config."""
    auth_zone: str | None = None
    auth_sec_servers: list[str] = field(default_factory=list)
    public_ipv4: str | None = None


def _is_public_ipv4(addr_str: str) -> bool:
    """Check if a string is a public (non-private, non-loopback) IPv4 address."""
    try:
        addr = ipaddress.IPv4Address(addr_str)
    except (ipaddress.AddressValueError, ValueError):
        return False
    return addr.is_global


def extract_config_values(lines: list[str]) -> DnsmasqConfigValues:
    """Extract auth-server, auth-sec-servers, and public listen-address from config lines.

    Replicates the grep/cut/sed extraction from the original bash script:
    - auth-server: last value wins, take zone name before any comma
    - auth-sec-servers: all values collected, comma-separated within each line
    - listen-address: first public IPv4 address found
    """
    values = DnsmasqConfigValues()

    for line in lines:
        if line.startswith('auth-server='):
            # Last wins; take zone name before any comma
            raw = line.split('=', 1)[1]
            values.auth_zone = raw.split(',')[0]

        elif line.startswith('auth-sec-servers='):
            raw = line.split('=', 1)[1]
            values.auth_sec_servers.extend(
                s.strip() for s in raw.split(',') if s.strip()
            )

        elif line.startswith('listen-address='):
            if values.public_ipv4 is None:
                addr = line.split('=', 1)[1]
                if _is_public_ipv4(addr):
                    values.public_ipv4 = addr

    return values
```

**Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_flatten.py::TestExtractConfigValues -v`
Expected: all PASS

**Step 5: Run all flatten tests to check for regressions**

Run: `uv run pytest tests/test_flatten.py -v`
Expected: all PASS

**Step 6: Commit**

```bash
git add certbot_hook_dnsmasq/flatten.py tests/test_flatten.py
git commit -m "Add extract_config_values to parse auth-server, secondaries, and public IP"
```

---

### Task 4: Create external.py subprocess wrappers

**Files:**
- Create: `certbot_hook_dnsmasq/external.py`
- Create: `tests/test_external.py`

**Step 1: Write the failing tests**

Create `tests/test_external.py`:

```python
"""Tests for certbot_hook_dnsmasq.external"""

from unittest.mock import patch, MagicMock
import subprocess

import pytest

from certbot_hook_dnsmasq.external import (
    query_txt_record,
    run_dnsmasq_test,
    run_ldns_notify,
    run_systemctl,
)


class TestQueryTxtRecord:
    @patch("certbot_hook_dnsmasq.external.subprocess.run")
    def test_returns_txt_value(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout='"test-validation-token"\n',
            returncode=0,
        )
        result = query_txt_record("8.8.8.8", "_acme-challenge.example.com")
        assert result == "test-validation-token"
        mock_run.assert_called_once_with(
            ["dig", "@8.8.8.8", "TXT", "_acme-challenge.example.com", "+short"],
            capture_output=True,
            text=True,
            check=False,
        )

    @patch("certbot_hook_dnsmasq.external.subprocess.run")
    def test_returns_none_on_empty(self, mock_run):
        mock_run.return_value = MagicMock(stdout="\n", returncode=0)
        result = query_txt_record("8.8.8.8", "_acme-challenge.example.com")
        assert result is None

    @patch("certbot_hook_dnsmasq.external.subprocess.run")
    def test_returns_none_on_failure(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=9)
        result = query_txt_record("8.8.8.8", "_acme-challenge.example.com")
        assert result is None


class TestRunDnsmasqTest:
    @patch("certbot_hook_dnsmasq.external.subprocess.run")
    def test_calls_dnsmasq_test(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        run_dnsmasq_test("/etc/dnsmasq.conf")
        mock_run.assert_called_once_with(
            ["dnsmasq", "--test", "-C", "/etc/dnsmasq.conf"],
            capture_output=True,
            text=True,
            check=True,
        )

    @patch("certbot_hook_dnsmasq.external.subprocess.run")
    def test_raises_on_failure(self, mock_run):
        mock_run.side_effect = subprocess.CalledProcessError(1, "dnsmasq")
        with pytest.raises(subprocess.CalledProcessError):
            run_dnsmasq_test("/etc/dnsmasq.conf")


class TestRunSystemctl:
    @patch("certbot_hook_dnsmasq.external.subprocess.run")
    def test_calls_systemctl(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        run_systemctl("restart", "dnsmasq")
        mock_run.assert_called_once_with(
            ["systemctl", "restart", "dnsmasq"],
            check=True,
        )


class TestRunLdnsNotify:
    @patch("certbot_hook_dnsmasq.external.subprocess.run")
    def test_calls_ldns_notify(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        run_ldns_notify("203.0.113.1", "example.com", ["ns2.example.com", "ns3.example.com"])
        mock_run.assert_called_once_with(
            ["ldns-notify", "-I", "203.0.113.1", "-z", "example.com",
             "ns2.example.com", "ns3.example.com"],
            check=True,
        )
```

**Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_external.py -v`
Expected: FAIL — `ModuleNotFoundError`

**Step 3: Implement external.py**

Create `certbot_hook_dnsmasq/external.py`:

```python
"""Thin subprocess wrappers for external tools (dig, ldns-notify, systemctl, dnsmasq)."""

import subprocess


def query_txt_record(server: str, domain: str) -> str | None:
    """Query a DNS server for a TXT record. Returns the value or None."""
    result = subprocess.run(
        ["dig", f"@{server}", "TXT", domain, "+short"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    value = result.stdout.strip().strip('"')
    return value if value else None


def run_dnsmasq_test(conf: str) -> None:
    """Run dnsmasq --test to validate configuration. Raises on failure."""
    subprocess.run(
        ["dnsmasq", "--test", "-C", conf],
        capture_output=True,
        text=True,
        check=True,
    )


def run_systemctl(action: str, service: str) -> None:
    """Run a systemctl action (restart, status, etc.) on a service."""
    subprocess.run(
        ["systemctl", action, service],
        check=True,
    )


def run_ldns_notify(source_ip: str, zone: str, servers: list[str]) -> None:
    """Send DNS NOTIFY to secondary servers via ldns-notify."""
    subprocess.run(
        ["ldns-notify", "-I", source_ip, "-z", zone, *servers],
        check=True,
    )
```

**Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_external.py -v`
Expected: all PASS

**Step 5: Commit**

```bash
git add certbot_hook_dnsmasq/external.py tests/test_external.py
git commit -m "Add external.py subprocess wrappers for dig, ldns-notify, systemctl"
```

---

### Task 5: Create hook.py auth-hook logic

**Files:**
- Create: `certbot_hook_dnsmasq/hook.py`
- Create: `tests/test_hook.py`

**Step 1: Write failing tests for write_acme_challenge**

Create `tests/test_hook.py`:

```python
"""Tests for certbot_hook_dnsmasq.hook"""

from pathlib import Path
from unittest.mock import patch, call

import pytest

from certbot_hook_dnsmasq.hook import write_acme_challenge


class TestWriteAcmeChallenge:
    def test_creates_config_file(self, tmp_path):
        write_acme_challenge(tmp_path, "example.com", "test-token-123")

        config_file = tmp_path / "dnsmasq.acme.example.com.conf"
        assert config_file.exists()
        content = config_file.read_text()
        assert "txt-record=_acme-challenge.example.com.,test-token-123" in content
        assert "dns-rr=example.com.,257," in content

    def test_overwrites_existing(self, tmp_path):
        config_file = tmp_path / "dnsmasq.acme.example.com.conf"
        config_file.write_text("old content")

        write_acme_challenge(tmp_path, "example.com", "new-token")

        content = config_file.read_text()
        assert "old content" not in content
        assert "new-token" in content
```

**Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_hook.py::TestWriteAcmeChallenge -v`
Expected: FAIL — `ImportError`

**Step 3: Implement write_acme_challenge**

Create `certbot_hook_dnsmasq/hook.py`:

```python
"""Auth-hook logic for certbot DNS-01 challenges with dnsmasq."""

import sys
import time
from pathlib import Path

from certbot_hook_dnsmasq.external import (
    query_txt_record,
    run_dnsmasq_test,
    run_ldns_notify,
    run_systemctl,
)
from certbot_hook_dnsmasq.flatten import (
    DnsmasqConfigValues,
    extract_config_values,
    flatten_config,
)

# CAA record: hex-encoded "issuelet'sencrypt.org" with tag byte
_CAA_HEX = "000569737375656C657473656E63727970742E6F7267"


def write_acme_challenge(conf_dir: Path, domain: str, validation: str) -> Path:
    """Write dnsmasq config file with ACME challenge TXT record.

    Returns the path to the created config file.
    """
    config_file = conf_dir / f"dnsmasq.acme.{domain}.conf"
    config_file.write_text(
        f"dns-rr={domain}.,257,{_CAA_HEX}\n"
        f"txt-record=_acme-challenge.{domain}.,{validation}\n"
    )
    return config_file
```

**Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_hook.py::TestWriteAcmeChallenge -v`
Expected: PASS

**Step 5: Commit**

```bash
git add certbot_hook_dnsmasq/hook.py tests/test_hook.py
git commit -m "Add write_acme_challenge to hook module"
```

---

### Task 6: Add verify_local_dns and wait_for_sync to hook.py

**Files:**
- Modify: `certbot_hook_dnsmasq/hook.py`
- Modify: `tests/test_hook.py`

**Step 1: Write failing tests for verify_local_dns**

Add to `tests/test_hook.py`:

```python
from certbot_hook_dnsmasq.hook import verify_local_dns


class TestVerifyLocalDns:
    @patch("certbot_hook_dnsmasq.hook.query_txt_record")
    def test_returns_true_when_matches(self, mock_query):
        mock_query.return_value = "test-token"
        result = verify_local_dns("203.0.113.1", "example.com", "test-token")
        assert result is True
        mock_query.assert_called_once_with("203.0.113.1", "_acme-challenge.example.com")

    @patch("certbot_hook_dnsmasq.hook.query_txt_record")
    def test_returns_false_when_mismatch(self, mock_query):
        mock_query.return_value = "wrong-token"
        result = verify_local_dns("203.0.113.1", "example.com", "test-token")
        assert result is False

    @patch("certbot_hook_dnsmasq.hook.query_txt_record")
    def test_returns_false_when_none(self, mock_query):
        mock_query.return_value = None
        result = verify_local_dns("203.0.113.1", "example.com", "test-token")
        assert result is False
```

**Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_hook.py::TestVerifyLocalDns -v`
Expected: FAIL — `ImportError`

**Step 3: Implement verify_local_dns**

Add to `certbot_hook_dnsmasq/hook.py`:

```python
def verify_local_dns(public_ipv4: str, domain: str, validation: str) -> bool:
    """Verify the local DNS server has the correct ACME challenge TXT record."""
    record = f"_acme-challenge.{domain}"
    value = query_txt_record(public_ipv4, record)
    if value != validation:
        print(f"ERROR: Local DNS does not have correct TXT record", file=sys.stderr)
        print(f"  Expected: {validation}", file=sys.stderr)
        print(f"  Got: {value!r}", file=sys.stderr)
        return False
    return True
```

**Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_hook.py::TestVerifyLocalDns -v`
Expected: PASS

**Step 5: Write failing tests for wait_for_sync**

Add to `tests/test_hook.py`:

```python
from certbot_hook_dnsmasq.hook import wait_for_sync


class TestWaitForSync:
    @patch("certbot_hook_dnsmasq.hook.time.sleep")
    @patch("certbot_hook_dnsmasq.hook.query_txt_record")
    def test_returns_true_when_all_synced(self, mock_query, mock_sleep):
        mock_query.return_value = "test-token"
        responses = wait_for_sync(
            ["ns2.example.com", "ns3.example.com"],
            "example.com",
            "test-token",
            max_wait=120,
            interval=5,
        )
        assert responses == {
            "ns2.example.com": "test-token",
            "ns3.example.com": "test-token",
        }
        # Should not sleep if synced on first check
        mock_sleep.assert_not_called()

    @patch("certbot_hook_dnsmasq.hook.time.sleep")
    @patch("certbot_hook_dnsmasq.hook.query_txt_record")
    def test_polls_until_synced(self, mock_query, mock_sleep):
        # First round: ns2 not synced, ns3 synced
        # Second round: ns2 synced
        mock_query.side_effect = [
            None, "test-token",       # round 1: ns2=None, ns3=token
            "test-token",             # round 2: ns2=token (ns3 skipped)
        ]
        responses = wait_for_sync(
            ["ns2.example.com", "ns3.example.com"],
            "example.com",
            "test-token",
            max_wait=120,
            interval=5,
        )
        assert responses == {
            "ns2.example.com": "test-token",
            "ns3.example.com": "test-token",
        }
        mock_sleep.assert_called_once_with(5)

    @patch("certbot_hook_dnsmasq.hook.time.sleep")
    @patch("certbot_hook_dnsmasq.hook.query_txt_record")
    def test_returns_partial_on_timeout(self, mock_query, mock_sleep):
        mock_query.return_value = None
        responses = wait_for_sync(
            ["ns2.example.com"],
            "example.com",
            "test-token",
            max_wait=10,
            interval=5,
        )
        assert responses == {"ns2.example.com": None}
        # Should have slept twice (0+5=5, 5+5=10, then timeout)
        assert mock_sleep.call_count == 2

    @patch("certbot_hook_dnsmasq.hook.time.sleep")
    @patch("certbot_hook_dnsmasq.hook.query_txt_record")
    def test_tracks_actual_responses(self, mock_query, mock_sleep):
        """Responses dict tracks the actual value from each server."""
        mock_query.side_effect = [
            "wrong-token", "test-token",  # round 1
            "test-token",                 # round 2
        ]
        responses = wait_for_sync(
            ["ns2.example.com", "ns3.example.com"],
            "example.com",
            "test-token",
            max_wait=120,
            interval=5,
        )
        assert responses["ns2.example.com"] == "test-token"
        assert responses["ns3.example.com"] == "test-token"
```

**Step 6: Run tests to verify they fail**

Run: `uv run pytest tests/test_hook.py::TestWaitForSync -v`
Expected: FAIL — `ImportError`

**Step 7: Implement wait_for_sync**

Add to `certbot_hook_dnsmasq/hook.py`:

```python
def wait_for_sync(
    servers: list[str],
    domain: str,
    validation: str,
    max_wait: int = 120,
    interval: int = 5,
) -> dict[str, str | None]:
    """Poll secondary DNS servers until they have the correct TXT record.

    Returns a dict mapping server -> last observed TXT value.
    """
    record = f"_acme-challenge.{domain}"
    responses: dict[str, str | None] = {}
    elapsed = 0

    while True:
        for server in servers:
            if responses.get(server) == validation:
                continue
            responses[server] = query_txt_record(server, record)

        # Log current state
        for server in servers:
            value = responses.get(server)
            status = "synced" if value == validation else "waiting"
            print(f"  {server}: {value!r} ({status})")

        if all(responses.get(s) == validation for s in servers):
            print("All secondaries synced!")
            return responses

        elapsed += interval
        if elapsed > max_wait:
            print(f"WARNING: Secondaries may not have synced within {max_wait}s")
            return responses

        time.sleep(interval)
```

**Step 8: Run tests to verify they pass**

Run: `uv run pytest tests/test_hook.py -v`
Expected: all PASS

**Step 9: Commit**

```bash
git add certbot_hook_dnsmasq/hook.py tests/test_hook.py
git commit -m "Add verify_local_dns and wait_for_sync to hook module"
```

---

### Task 7: Add run_auth_hook orchestrator to hook.py

**Files:**
- Modify: `certbot_hook_dnsmasq/hook.py`
- Modify: `tests/test_hook.py`

**Step 1: Write failing test for run_auth_hook**

Add to `tests/test_hook.py`:

```python
from certbot_hook_dnsmasq.hook import run_auth_hook
from certbot_hook_dnsmasq.flatten import DnsmasqConfigValues


class TestRunAuthHook:
    @patch("certbot_hook_dnsmasq.hook.wait_for_sync")
    @patch("certbot_hook_dnsmasq.hook.run_ldns_notify")
    @patch("certbot_hook_dnsmasq.hook.verify_local_dns")
    @patch("certbot_hook_dnsmasq.hook.run_systemctl")
    @patch("certbot_hook_dnsmasq.hook.run_dnsmasq_test")
    @patch("certbot_hook_dnsmasq.hook.write_acme_challenge")
    @patch("certbot_hook_dnsmasq.hook.extract_config_values")
    @patch("certbot_hook_dnsmasq.hook.flatten_config")
    def test_orchestrates_full_flow(
        self, mock_flatten, mock_extract, mock_write,
        mock_test, mock_systemctl, mock_verify, mock_notify, mock_wait,
        tmp_path,
    ):
        mock_flatten.return_value = ["auth-server=example.com"]
        mock_extract.return_value = DnsmasqConfigValues(
            auth_zone="example.com",
            auth_sec_servers=["ns2.example.com"],
            public_ipv4="203.0.113.1",
        )
        mock_write.return_value = tmp_path / "dnsmasq.acme.example.com.conf"
        mock_verify.return_value = True
        mock_wait.return_value = {"ns2.example.com": "test-token"}

        result = run_auth_hook(
            conf_dir=tmp_path,
            conf=Path("/etc/dnsmasq.conf"),
            service="dnsmasq",
            domain="example.com",
            validation="test-token",
        )

        assert result == 0
        mock_flatten.assert_called_once_with(Path("/etc/dnsmasq.conf"))
        mock_extract.assert_called_once()
        mock_write.assert_called_once_with(tmp_path, "example.com", "test-token")
        mock_test.assert_called_once_with(str(Path("/etc/dnsmasq.conf")))
        assert mock_systemctl.call_count == 2  # restart + status
        mock_verify.assert_called_once_with("203.0.113.1", "example.com", "test-token")
        mock_notify.assert_called_once_with("203.0.113.1", "example.com", ["ns2.example.com"])
        mock_wait.assert_called_once()

    @patch("certbot_hook_dnsmasq.hook.extract_config_values")
    @patch("certbot_hook_dnsmasq.hook.flatten_config")
    def test_exits_on_missing_auth_zone(self, mock_flatten, mock_extract, tmp_path):
        mock_flatten.return_value = []
        mock_extract.return_value = DnsmasqConfigValues(
            auth_zone=None,
            auth_sec_servers=[],
            public_ipv4=None,
        )

        result = run_auth_hook(
            conf_dir=tmp_path,
            conf=Path("/etc/dnsmasq.conf"),
            service="dnsmasq",
            domain="example.com",
            validation="test-token",
        )
        assert result == 1

    @patch("certbot_hook_dnsmasq.hook.run_dnsmasq_test")
    @patch("certbot_hook_dnsmasq.hook.write_acme_challenge")
    @patch("certbot_hook_dnsmasq.hook.extract_config_values")
    @patch("certbot_hook_dnsmasq.hook.flatten_config")
    def test_exits_on_verify_failure(
        self, mock_flatten, mock_extract, mock_write, mock_test, tmp_path,
    ):
        mock_flatten.return_value = ["auth-server=example.com"]
        mock_extract.return_value = DnsmasqConfigValues(
            auth_zone="example.com",
            auth_sec_servers=["ns2.example.com"],
            public_ipv4="203.0.113.1",
        )
        mock_write.return_value = tmp_path / "test.conf"

        with patch("certbot_hook_dnsmasq.hook.run_systemctl"):
            with patch("certbot_hook_dnsmasq.hook.verify_local_dns", return_value=False):
                result = run_auth_hook(
                    conf_dir=tmp_path,
                    conf=Path("/etc/dnsmasq.conf"),
                    service="dnsmasq",
                    domain="example.com",
                    validation="test-token",
                )
        assert result == 1
```

**Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_hook.py::TestRunAuthHook -v`
Expected: FAIL — `ImportError`

**Step 3: Implement run_auth_hook**

Add to `certbot_hook_dnsmasq/hook.py`:

```python
def run_auth_hook(
    conf_dir: Path,
    conf: Path,
    service: str,
    domain: str,
    validation: str,
) -> int:
    """Run the full auth-hook workflow. Returns 0 on success, 1 on failure."""
    # Flatten config and extract values
    lines = flatten_config(conf)
    values = extract_config_values(lines)

    # Validate required values
    if not values.auth_zone:
        print("ERROR: No auth-server found in dnsmasq config", file=sys.stderr)
        return 1
    if not values.auth_sec_servers:
        print("ERROR: No auth-sec-servers found in dnsmasq config", file=sys.stderr)
        return 1
    if not values.public_ipv4:
        print("ERROR: No public IPv4 listen-address found in dnsmasq config", file=sys.stderr)
        return 1

    print("Discovered dnsmasq config:")
    print(f"  Zone: {values.auth_zone}")
    print(f"  Secondary servers: {' '.join(values.auth_sec_servers)}")
    print(f"  Public IPv4: {values.public_ipv4}")

    # Write ACME challenge config
    write_acme_challenge(conf_dir, domain, validation)

    # Test and restart dnsmasq
    run_dnsmasq_test(str(conf))
    run_systemctl("restart", service)
    run_systemctl("status", service)

    # Verify local DNS
    if not verify_local_dns(values.public_ipv4, domain, validation):
        return 1

    # Notify secondaries and wait for sync
    print("Sending NOTIFY to secondaries...")
    run_ldns_notify(values.public_ipv4, values.auth_zone, values.auth_sec_servers)

    print("Waiting for secondaries to sync (max 120s)...")
    wait_for_sync(values.auth_sec_servers, domain, validation)

    return 0
```

**Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_hook.py -v`
Expected: all PASS

**Step 5: Commit**

```bash
git add certbot_hook_dnsmasq/hook.py tests/test_hook.py
git commit -m "Add run_auth_hook orchestrator"
```

---

### Task 8: Create cli.py with subcommands

**Files:**
- Create: `certbot_hook_dnsmasq/cli.py`
- Create: `tests/test_cli.py`

**Step 1: Write failing tests**

Create `tests/test_cli.py`:

```python
"""Tests for certbot_hook_dnsmasq.cli"""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from certbot_hook_dnsmasq.cli import main, build_parser


class TestBuildParser:
    def test_auth_hook_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["auth-hook"])
        assert args.subcommand == "auth-hook"

    def test_flatten_config_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["flatten-config", "/etc/dnsmasq.conf"])
        assert args.subcommand == "flatten-config"
        assert args.config_path == Path("/etc/dnsmasq.conf")

    def test_flatten_config_default_path(self):
        parser = build_parser()
        args = parser.parse_args(["flatten-config"])
        assert args.config_path == Path("/etc/dnsmasq.conf")

    def test_auth_hook_flags(self):
        parser = build_parser()
        args = parser.parse_args([
            "auth-hook",
            "--conf-dir", "/custom/dir",
            "--conf", "/custom/dnsmasq.conf",
            "--service", "dnsmasq-custom",
        ])
        assert args.conf_dir == Path("/custom/dir")
        assert args.conf == Path("/custom/dnsmasq.conf")
        assert args.service == "dnsmasq-custom"


class TestMainFlattenConfig:
    @patch("certbot_hook_dnsmasq.cli.flatten_config")
    def test_prints_flattened_lines(self, mock_flatten, capsys):
        mock_flatten.return_value = ["auth-server=example.com", "server=8.8.8.8"]
        with patch("sys.argv", ["certbot-hook-dnsmasq", "flatten-config", "/test/conf"]):
            result = main()
        assert result == 0
        output = capsys.readouterr().out
        assert "auth-server=example.com\n" in output
        assert "server=8.8.8.8\n" in output


class TestMainAuthHook:
    @patch("certbot_hook_dnsmasq.cli.run_auth_hook")
    def test_reads_certbot_env_vars(self, mock_hook):
        mock_hook.return_value = 0
        env = {
            "CERTBOT_DOMAIN": "example.com",
            "CERTBOT_VALIDATION": "test-token",
        }
        with patch.dict(os.environ, env, clear=False):
            with patch("sys.argv", ["certbot-hook-dnsmasq", "auth-hook"]):
                result = main()
        assert result == 0
        mock_hook.assert_called_once()
        call_kwargs = mock_hook.call_args
        assert call_kwargs[1]["domain"] == "example.com"
        assert call_kwargs[1]["validation"] == "test-token"

    def test_fails_without_certbot_domain(self, capsys):
        env_without = {k: v for k, v in os.environ.items()
                       if k not in ("CERTBOT_DOMAIN", "CERTBOT_VALIDATION")}
        with patch.dict(os.environ, env_without, clear=True):
            with patch("sys.argv", ["certbot-hook-dnsmasq", "auth-hook"]):
                result = main()
        assert result == 1
        assert "CERTBOT_DOMAIN" in capsys.readouterr().err

    @patch("certbot_hook_dnsmasq.cli.run_auth_hook")
    def test_cli_flags_override_env(self, mock_hook):
        mock_hook.return_value = 0
        env = {
            "CERTBOT_DOMAIN": "example.com",
            "CERTBOT_VALIDATION": "test-token",
            "DNSMASQ_CONF_DIR": "/env/dir",
        }
        with patch.dict(os.environ, env, clear=False):
            with patch("sys.argv", [
                "certbot-hook-dnsmasq", "auth-hook",
                "--conf-dir", "/cli/dir",
            ]):
                result = main()
        assert result == 0
        call_kwargs = mock_hook.call_args[1]
        assert call_kwargs["conf_dir"] == Path("/cli/dir")

    @patch("certbot_hook_dnsmasq.cli.run_auth_hook")
    def test_env_var_fallback(self, mock_hook):
        mock_hook.return_value = 0
        env = {
            "CERTBOT_DOMAIN": "example.com",
            "CERTBOT_VALIDATION": "test-token",
            "DNSMASQ_CONF_DIR": "/env/dir",
            "DNSMASQ_CONF": "/env/dnsmasq.conf",
            "DNSMASQ_SERVICE": "dnsmasq-env",
        }
        with patch.dict(os.environ, env, clear=False):
            with patch("sys.argv", ["certbot-hook-dnsmasq", "auth-hook"]):
                result = main()
        assert result == 0
        call_kwargs = mock_hook.call_args[1]
        assert call_kwargs["conf_dir"] == Path("/env/dir")
        assert call_kwargs["conf"] == Path("/env/dnsmasq.conf")
        assert call_kwargs["service"] == "dnsmasq-env"
```

**Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_cli.py -v`
Expected: FAIL — `ModuleNotFoundError`

**Step 3: Implement cli.py**

Create `certbot_hook_dnsmasq/cli.py`:

```python
"""CLI entry point with subcommands for certbot-hook-dnsmasq."""

import argparse
import os
import sys
from pathlib import Path

from certbot_hook_dnsmasq.flatten import flatten_config
from certbot_hook_dnsmasq.hook import run_auth_hook


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="certbot-hook-dnsmasq",
        description="Certbot DNS-01 hook for dnsmasq",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # auth-hook subcommand
    auth = subparsers.add_parser(
        "auth-hook",
        help="Certbot manual auth hook for DNS-01 challenges",
    )
    auth.add_argument(
        "--conf-dir",
        type=Path,
        default=None,
        help="Directory for dnsmasq ACME configs (default: /etc/dnsmasq.d, env: DNSMASQ_CONF_DIR)",
    )
    auth.add_argument(
        "--conf",
        type=Path,
        default=None,
        help="dnsmasq config file (default: /etc/dnsmasq.conf, env: DNSMASQ_CONF)",
    )
    auth.add_argument(
        "--service",
        default=None,
        help="systemd service name (default: dnsmasq, env: DNSMASQ_SERVICE)",
    )

    # flatten-config subcommand
    flat = subparsers.add_parser(
        "flatten-config",
        help="Flatten dnsmasq config by following all includes",
    )
    flat.add_argument(
        "config_path",
        type=Path,
        nargs="?",
        default=Path("/etc/dnsmasq.conf"),
        help="Path to dnsmasq config file (default: /etc/dnsmasq.conf)",
    )

    return parser


def _resolve(cli_value, env_var: str, default):
    """Resolve a config value: CLI flag > env var > default."""
    if cli_value is not None:
        return cli_value
    env = os.environ.get(env_var)
    if env is not None:
        return type(default)(env) if not isinstance(default, str) else env
    return default


def main() -> int:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args()

    if args.subcommand == "flatten-config":
        lines = flatten_config(args.config_path)
        for line in lines:
            print(line)
        return 0

    if args.subcommand == "auth-hook":
        domain = os.environ.get("CERTBOT_DOMAIN")
        validation = os.environ.get("CERTBOT_VALIDATION")

        if not domain:
            print("ERROR: CERTBOT_DOMAIN environment variable not set", file=sys.stderr)
            return 1
        if not validation:
            print("ERROR: CERTBOT_VALIDATION environment variable not set", file=sys.stderr)
            return 1

        conf_dir = _resolve(args.conf_dir, "DNSMASQ_CONF_DIR", Path("/etc/dnsmasq.d"))
        conf = _resolve(args.conf, "DNSMASQ_CONF", Path("/etc/dnsmasq.conf"))
        service = _resolve(args.service, "DNSMASQ_SERVICE", "dnsmasq")

        # Ensure Path types
        if isinstance(conf_dir, str):
            conf_dir = Path(conf_dir)
        if isinstance(conf, str):
            conf = Path(conf)

        return run_auth_hook(
            conf_dir=conf_dir,
            conf=conf,
            service=service,
            domain=domain,
            validation=validation,
        )

    return 1
```

**Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cli.py -v`
Expected: all PASS

**Step 5: Run all tests**

Run: `uv run pytest tests/ -v`
Expected: all PASS

**Step 6: Commit**

```bash
git add certbot_hook_dnsmasq/cli.py tests/test_cli.py
git commit -m "Add CLI with auth-hook and flatten-config subcommands"
```

---

### Task 9: Update __main__.py, verify end-to-end, update .gitignore

**Files:**
- Modify: `certbot_hook_dnsmasq/__main__.py`
- Modify: `.gitignore`

**Step 1: Update __main__.py to use sys.exit**

```python
"""Allow running as: python -m certbot_hook_dnsmasq"""

import sys

from certbot_hook_dnsmasq.cli import main

sys.exit(main())
```

**Step 2: Verify the module runs**

Run: `uv run python -m certbot_hook_dnsmasq --help`
Expected: shows help with `auth-hook` and `flatten-config` subcommands

Run: `uv run python -m certbot_hook_dnsmasq flatten-config --help`
Expected: shows help for flatten-config

Run: `uv run python -m certbot_hook_dnsmasq auth-hook --help`
Expected: shows help for auth-hook

**Step 3: Update .gitignore**

Add `*.egg-info/` to `.gitignore` (created by `pip install -e .`):

```
.claude/
.tmp.*
__pycache__/
*.pyc
.pytest_cache/
*.egg-info/
```

**Step 4: Run all tests one final time**

Run: `uv run pytest tests/ -v`
Expected: all PASS

**Step 5: Commit**

```bash
git add certbot_hook_dnsmasq/__main__.py .gitignore
git commit -m "Wire up __main__.py with sys.exit and update .gitignore"
```

---

### Task 10: Remove old files and update CLAUDE.md

**Files:**
- Delete: `dnsmasq-hook.sh`
- Delete: `dnsmasq_flatten_config.py`
- Delete: `test_dnsmasq_flatten_config.py`
- Modify: `CLAUDE.md`
- Modify: `README.md`

**Step 1: Delete old files**

```bash
git rm dnsmasq-hook.sh dnsmasq_flatten_config.py test_dnsmasq_flatten_config.py
```

**Step 2: Update CLAUDE.md**

Replace the Architecture section to reflect the new package structure. Update usage example to use the Python CLI. Update Dependencies to note it's a Python package.

Key changes:
- Architecture: describe it as a Python package with modules
- Usage: `certbot-hook-dnsmasq auth-hook` instead of `/path/to/dnsmasq-hook.sh`
- Dependencies: add Python 3.11+

**Step 3: Update README.md**

Update usage instructions to show the new CLI. Update "How it works" section. Update requirements to include Python 3.11+.

Key changes:
- Usage example: `certbot --manual-auth-hook "certbot-hook-dnsmasq auth-hook"`
- Add installation section: `uv pip install .` or `pip install .`
- Document `flatten-config` subcommand
- Document CLI flags and env var fallbacks

**Step 4: Run all tests one final time**

Run: `uv run pytest tests/ -v`
Expected: all PASS

**Step 5: Commit**

```bash
git add -A
git commit -m "Remove old bash/Python files, update docs for Python package"
```
