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
