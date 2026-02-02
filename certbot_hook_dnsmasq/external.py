"""Thin subprocess wrappers for external tools (dig, ldns-notify, systemctl, dnsmasq)."""

import subprocess


def query_all_txt_records(server: str, domain: str) -> set[str]:
    """Query a DNS server for all TXT records at a name. Returns a set of values."""
    result = subprocess.run(
        ["dig", f"@{server}", "TXT", domain, "+short"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return set()
    values = set()
    for line in result.stdout.strip().split('\n'):
        value = line.strip('"')
        if value:
            values.add(value)
    return values


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
