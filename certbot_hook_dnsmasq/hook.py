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
