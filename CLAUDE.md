# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Certbot hook script for DNS-01 challenge authentication using dnsmasq. Creates temporary ACME challenge TXT records in dnsmasq, enabling wildcard certificates or certificates for non-HTTP-accessible servers.

## Architecture

Single bash script (`dnsmasq-hook.sh`) that:
1. Writes dnsmasq config with TXT record to `/etc/dnsmasq.d/dnsmasq.acme.$CERTBOT_DOMAIN.conf`
2. Validates and restarts dnsmasq via systemd
3. Verifies local DNS has correct record
4. Sends NOTIFY to secondary DNS servers via `ldns-notify`
5. Polls secondaries until they sync (max 120s)

## Usage

```bash
certbot certonly \
    --manual \
    --preferred-challenges dns \
    --manual-auth-hook /path/to/dnsmasq-hook.sh \
    -d example.com
```

## Dependencies

- dnsmasq (configured as DNS server)
- dig (dnsutils/bind-utils)
- ldns-notify (ldnsutils)
- systemd

## Environment Variables (from certbot)

- `CERTBOT_DOMAIN` - Domain being validated
- `CERTBOT_VALIDATION` - ACME challenge token value
