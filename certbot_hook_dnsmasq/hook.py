"""Auth-hook logic for certbot DNS-01 challenges with dnsmasq."""

import hashlib
import subprocess
import sys
import time
from pathlib import Path

from certbot_hook_dnsmasq.external import (
    query_all_txt_records,
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


def verify_local_dns(public_ipv4: str, challenges: dict[str, set[str]]) -> bool:
    """Verify the local DNS server has all expected ACME challenge TXT records.

    challenges is a dict mapping domain -> set of expected validation tokens.
    Returns True only if all expected tokens are present for all domains.
    """
    all_ok = True
    for domain in sorted(challenges):
        expected = challenges[domain]
        record = f"_acme-challenge.{domain}"
        actual = query_all_txt_records(public_ipv4, record)
        missing = expected - actual
        if missing:
            print(f"ERROR: Local DNS missing TXT records for {record}", file=sys.stderr)
            print(f"  Expected: {sorted(expected)}", file=sys.stderr)
            print(f"  Got: {sorted(actual)}", file=sys.stderr)
            print(f"  Missing: {sorted(missing)}", file=sys.stderr)
            all_ok = False
    return all_ok


def wait_for_sync(
    servers: list[str],
    challenges: dict[str, set[str]],
    max_wait: int = 120,
    interval: int = 5,
) -> bool:
    """Poll secondary DNS servers until they have all expected TXT records.

    challenges is a dict mapping domain -> set of expected validation tokens.
    Returns True if all servers synced, False on timeout.
    """
    # Track which (server, domain) pairs are synced
    synced_pairs: set[tuple[str, str]] = set()
    all_pairs = {
        (server, domain)
        for server in servers
        for domain in challenges
    }
    elapsed = 0

    while True:
        for server in servers:
            for domain in sorted(challenges):
                if (server, domain) in synced_pairs:
                    continue
                record = f"_acme-challenge.{domain}"
                actual = query_all_txt_records(server, record)
                expected = challenges[domain]
                if expected <= actual:
                    synced_pairs.add((server, domain))
                    print(f"  {server}: {domain} synced")
                else:
                    missing = expected - actual
                    print(f"  {server}: {domain} waiting (missing {len(missing)} record(s))")

        if synced_pairs == all_pairs:
            print("All secondaries synced!")
            return True

        elapsed += interval
        if elapsed > max_wait:
            print(f"ERROR: Secondaries did not sync within {max_wait}s", file=sys.stderr)
            for server, domain in sorted(all_pairs - synced_pairs):
                print(f"  {server}: {domain} NOT synced", file=sys.stderr)
            return False

        time.sleep(interval)


def run_auth_hook(
    conf_dir: Path,
    conf: Path,
    service: str,
    domain: str,
    validation: str,
    remaining_challenges: int = 0,
    max_wait: int = 120,
) -> int:
    """Run the auth-hook workflow. Returns 0 on success, 1 on failure.

    When remaining_challenges > 0, only writes the config file and returns.
    When remaining_challenges == 0, writes the config file then finalizes:
    restart dnsmasq, verify all pending challenges, notify and wait for sync.
    """
    # Always write the config file for this challenge
    print(f"Writing ACME challenge for {domain}")
    write_acme_challenge(conf_dir, domain, validation)

    if remaining_challenges > 0:
        print(f"  {remaining_challenges} challenge(s) remaining, deferring restart")
        return 0

    # Final invocation: flatten config and extract values
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

    # Test and restart dnsmasq
    try:
        run_dnsmasq_test(str(conf))
        run_systemctl("restart", service)
        run_systemctl("status", service)
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Command failed: {e.cmd}", file=sys.stderr)
        return 1

    # Discover all pending challenges and verify local DNS
    challenges = read_pending_challenges(conf_dir)
    print(f"Verifying {sum(len(t) for t in challenges.values())} TXT record(s) across {len(challenges)} domain(s)")
    if not verify_local_dns(values.public_ipv4, challenges):
        return 1

    # Notify secondaries and wait for sync
    print("Sending NOTIFY to secondaries...")
    try:
        run_ldns_notify(values.public_ipv4, values.auth_zone, values.auth_sec_servers)
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Command failed: {e.cmd}", file=sys.stderr)
        return 1

    print(f"Waiting for secondaries to sync (max {max_wait}s)...")
    if not wait_for_sync(values.auth_sec_servers, challenges, max_wait=max_wait):
        return 1

    return 0
