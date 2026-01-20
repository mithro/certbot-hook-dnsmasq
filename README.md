# certbot-hook-dnsmasq

Hook for certbot that allows using DNS-01 challenge authentication with a dnsmasq server.

## Overview

This script creates temporary TXT records in dnsmasq for ACME DNS-01 challenges, allowing certbot to obtain wildcard certificates or certificates for servers that aren't publicly accessible via HTTP.

## Requirements

- dnsmasq configured as a DNS server
- `dig` command (from `dnsutils` or `bind-utils`)
- `ldns-notify` (from `ldnsutils`) for notifying secondary DNS servers
- systemd (for restarting dnsmasq)

## Usage

Use as a certbot manual auth hook:

```bash
certbot certonly \
    --manual \
    --preferred-challenges dns \
    --manual-auth-hook /path/to/dnsmasq-hook.sh \
    -d example.com
```

## How it works

1. Creates a dnsmasq config file with the ACME challenge TXT record
2. Validates the dnsmasq configuration
3. Restarts dnsmasq to load the new record
4. Verifies the local DNS server has the correct record
5. Sends NOTIFY to secondary DNS servers to trigger zone transfer
6. Waits for secondary servers to sync (up to 120 seconds)

## Configuration

The script is currently configured for a specific DNS setup. You may need to modify:

- The IP address used for NOTIFY (`-I` flag in `ldns-notify`)
- The zone name (`-z` flag)
- The secondary DNS server hostnames

## License

Apache License 2.0 - see [LICENSE](LICENSE)
