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
