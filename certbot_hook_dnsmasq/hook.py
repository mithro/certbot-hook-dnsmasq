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
