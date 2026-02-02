"""Auth-hook logic for certbot DNS-01 challenges with dnsmasq."""

import hashlib
import subprocess
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
    extract_config_values,
    flatten_config,
)

# CAA record wire format: flags=0, tag="issue", value="letsencrypt.org"
_CAA_HEX = "000569737375656C657473656E63727970742E6F7267"


def write_acme_challenge(conf_dir: Path, domain: str, validation: str) -> Path:
    """Write dnsmasq config file with ACME challenge TXT record.

    Uses a hash of the validation token in the filename so that multiple
    challenges for the same domain (e.g. wildcard + base) get separate files.

    Returns the path to the created config file.
    """
    token_hash = hashlib.sha256(validation.encode()).hexdigest()[:8]
    config_file = conf_dir / f"dnsmasq.acme.{domain}.{token_hash}.conf"
    config_file.write_text(
        f"dns-rr={domain}.,257,{_CAA_HEX}\n"
        f"txt-record=_acme-challenge.{domain}.,{validation}\n"
    )
    return config_file


def read_pending_challenges(conf_dir: Path) -> dict[str, set[str]]:
    """Scan conf_dir for ACME challenge config files and extract (domain, token) pairs.

    Returns a dict mapping domain -> set of validation tokens.
    """
    challenges: dict[str, set[str]] = {}
    for path in conf_dir.glob("dnsmasq.acme.*.conf"):
        for line in path.read_text().splitlines():
            if line.startswith("txt-record=_acme-challenge."):
                # txt-record=_acme-challenge.example.com.,token-value
                after_prefix = line[len("txt-record=_acme-challenge."):]
                domain_with_dot, token = after_prefix.split(",", 1)
                domain = domain_with_dot.rstrip(".")
                challenges.setdefault(domain, set()).add(token)
    return challenges


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


def run_auth_hook(
    conf_dir: Path,
    conf: Path,
    service: str,
    domain: str,
    validation: str,
    max_wait: int = 120,
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
    try:
        run_dnsmasq_test(str(conf))
        run_systemctl("restart", service)
        run_systemctl("status", service)
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Command failed: {e.cmd}", file=sys.stderr)
        return 1

    # Verify local DNS
    if not verify_local_dns(values.public_ipv4, domain, validation):
        return 1

    # Notify secondaries and wait for sync
    print("Sending NOTIFY to secondaries...")
    try:
        run_ldns_notify(values.public_ipv4, values.auth_zone, values.auth_sec_servers)
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Command failed: {e.cmd}", file=sys.stderr)
        return 1

    print(f"Waiting for secondaries to sync (max {max_wait}s)...")
    wait_for_sync(values.auth_sec_servers, domain, validation, max_wait=max_wait)

    return 0
