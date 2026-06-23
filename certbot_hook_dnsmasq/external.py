"""Thin subprocess wrappers for external tools (dig, ldns-notify, systemctl, dnsmasq, ip)."""

import json
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


def interface_ipv4_addresses(interface: str) -> list[str]:
    """Return the IPv4 addresses configured on a network interface, in order.

    Uses `ip -j -4 addr show dev <interface>` and extracts the `local` value of
    each inet entry. Returns an empty list on any failure (command error or
    unparseable output).
    """
    result = subprocess.run(
        ["ip", "-j", "-4", "addr", "show", "dev", interface],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return []
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    addresses = []
    for link in data:
        for addr in link.get("addr_info", []):
            if addr.get("family") == "inet" and "local" in addr:
                addresses.append(addr["local"])
    return addresses
