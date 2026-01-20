#!/usr/bin/env python3
"""Flatten dnsmasq config by following all includes."""

import re
import sys
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
            # Remaining parts are exclusion patterns (e.g., .dpkg-dist)
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

        # Skip comments and empty lines
        if not stripped or stripped.startswith('#'):
            continue

        # Handle conf-file=/path
        if stripped.startswith('conf-file='):
            include_path = Path(stripped.split('=', 1)[1])
            if not should_exclude(include_path.name, exclude_patterns):
                lines.extend(parse_config(include_path, exclude_patterns, visited))
            continue

        # Handle conf-dir=/path or conf-dir=/path,ext1,ext2
        if stripped.startswith('conf-dir='):
            value = stripped.split('=', 1)[1]
            parts = value.split(',')
            dir_path = Path(parts[0])
            # Additional patterns from this conf-dir line
            # Leading dot = exclude, leading * = include-only
            local_exclude = []
            local_include = []
            for ext in parts[1:]:
                if ext.startswith('*'):
                    local_include.append(ext[1:])  # Remove *
                else:
                    local_exclude.append(ext)

            if dir_path.is_dir():
                # Process files in alphabetical order
                for f in sorted(dir_path.iterdir()):
                    if not f.is_file():
                        continue
                    # Check global exclude patterns
                    if should_exclude(f.name, exclude_patterns):
                        continue
                    # Check local exclude patterns
                    if should_exclude(f.name, local_exclude):
                        continue
                    # Check local include patterns (if specified, only those match)
                    if local_include:
                        if not any(f.name.endswith(ext) for ext in local_include):
                            continue
                    lines.extend(parse_config(f, exclude_patterns, visited))
            continue

        # Regular config line
        lines.append(stripped)

    return lines


def main():
    # Get CONFIG_DIR and exclusion patterns from /etc/default/dnsmasq
    default_conf_dir, exclude_patterns = parse_defaults()

    # Start with master config
    master_config = Path('/etc/dnsmasq.conf')
    if len(sys.argv) > 1:
        master_config = Path(sys.argv[1])

    lines = parse_config(master_config, exclude_patterns)

    # If CONFIG_DIR is set and wasn't already processed via conf-dir in config
    # (this handles the -7 command line option)
    if default_conf_dir and default_conf_dir.is_dir():
        for f in sorted(default_conf_dir.iterdir()):
            if not f.is_file():
                continue
            if should_exclude(f.name, exclude_patterns):
                continue
            lines.extend(parse_config(f, exclude_patterns, set()))

    for line in lines:
        print(line)


if __name__ == '__main__':
    main()
