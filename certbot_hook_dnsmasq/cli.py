"""CLI entry point with subcommands for certbot-hook-dnsmasq."""

import argparse
import os
import sys
from pathlib import Path

from certbot_hook_dnsmasq import __version__
from certbot_hook_dnsmasq.flatten import flatten_config
from certbot_hook_dnsmasq.hook import run_auth_hook, run_cleanup_hook


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="certbot-hook-dnsmasq",
        description="Certbot DNS-01 hook for dnsmasq",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
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

    # cleanup-hook subcommand
    cleanup = subparsers.add_parser(
        "cleanup-hook",
        help="Certbot manual cleanup hook for DNS-01 challenges",
    )
    cleanup.add_argument(
        "--conf-dir",
        type=Path,
        default=None,
        help="Directory for dnsmasq ACME configs (default: /etc/dnsmasq.d, env: DNSMASQ_CONF_DIR)",
    )
    cleanup.add_argument(
        "--conf",
        type=Path,
        default=None,
        help="dnsmasq config file (default: /etc/dnsmasq.conf, env: DNSMASQ_CONF)",
    )
    cleanup.add_argument(
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


def _resolve_path(cli_value: Path | None, env_var: str, default: Path) -> Path:
    """Resolve a Path config value: CLI flag > env var > default."""
    if cli_value is not None:
        return cli_value
    env = os.environ.get(env_var)
    if env is not None:
        return Path(env)
    return default


def _resolve_str(cli_value: str | None, env_var: str, default: str) -> str:
    """Resolve a string config value: CLI flag > env var > default."""
    if cli_value is not None:
        return cli_value
    env = os.environ.get(env_var)
    if env is not None:
        return env
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

        remaining_str = os.environ.get("CERTBOT_REMAINING_CHALLENGES", "0")
        try:
            remaining_challenges = int(remaining_str)
        except ValueError:
            remaining_challenges = 0

        conf_dir = _resolve_path(args.conf_dir, "DNSMASQ_CONF_DIR", Path("/etc/dnsmasq.d"))
        conf = _resolve_path(args.conf, "DNSMASQ_CONF", Path("/etc/dnsmasq.conf"))
        service = _resolve_str(args.service, "DNSMASQ_SERVICE", "dnsmasq")

        return run_auth_hook(
            conf_dir=conf_dir,
            conf=conf,
            service=service,
            domain=domain,
            validation=validation,
            remaining_challenges=remaining_challenges,
        )

    if args.subcommand == "cleanup-hook":
        domain = os.environ.get("CERTBOT_DOMAIN")
        validation = os.environ.get("CERTBOT_VALIDATION")

        if not domain:
            print("ERROR: CERTBOT_DOMAIN environment variable not set", file=sys.stderr)
            return 1
        if not validation:
            print("ERROR: CERTBOT_VALIDATION environment variable not set", file=sys.stderr)
            return 1

        remaining_str = os.environ.get("CERTBOT_REMAINING_CHALLENGES", "0")
        try:
            remaining_challenges = int(remaining_str)
        except ValueError:
            remaining_challenges = 0

        conf_dir = _resolve_path(args.conf_dir, "DNSMASQ_CONF_DIR", Path("/etc/dnsmasq.d"))
        conf = _resolve_path(args.conf, "DNSMASQ_CONF", Path("/etc/dnsmasq.conf"))
        service = _resolve_str(args.service, "DNSMASQ_SERVICE", "dnsmasq")

        return run_cleanup_hook(
            conf_dir=conf_dir,
            conf=conf,
            service=service,
            domain=domain,
            validation=validation,
            remaining_challenges=remaining_challenges,
        )

    return 1
