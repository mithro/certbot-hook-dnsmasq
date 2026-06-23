"""Flatten dnsmasq config by following all includes."""

import ipaddress
import re
from dataclasses import dataclass, field
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


@dataclass
class DnsmasqConfigValues:
    """Values extracted from a flattened dnsmasq config."""
    auth_zone: str | None = None
    auth_sec_servers: list[str] = field(default_factory=list)
    public_ipv4: str | None = None
    interface: str | None = None


def is_public_ipv4(addr_str: str) -> bool:
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
    - interface: first bound interface (bind-dynamic/bind-interfaces setups name
      the interface here instead of a listen-address)
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
                if is_public_ipv4(addr):
                    values.public_ipv4 = addr

        elif line.startswith('interface='):
            # Bare interface= only; except-interface=/no-dhcp-interface= don't match.
            if values.interface is None:
                values.interface = line.split('=', 1)[1]

    return values
