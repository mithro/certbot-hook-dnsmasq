# TODO

## Future Subcommands

- [x] **cleanup-hook**: Add `certbot-hook-dnsmasq cleanup-hook` subcommand for certbot
  `--manual-cleanup-hook`. Removes the `dnsmasq.acme.*.conf` file created by
  `auth-hook`, tests the config, and restarts dnsmasq. Supports batch mode via
  `CERTBOT_REMAINING_CHALLENGES` (defers restart until last cleanup call).

## Replace External Tools with Native Python

Currently the tool shells out to `dig`, `ldns-notify`, `systemctl`, and `dnsmasq`.
Plan to replace these with Python-native implementations:

- [ ] **Replace `dig` with `dnspython`**: Use the `dnspython` library for TXT record
  lookups instead of shelling out to `dig`. Removes the dnsutils dependency and gives
  better error handling.

- [ ] **Replace `ldns-notify` with native DNS NOTIFY**: Implement RFC 1996 DNS NOTIFY
  messages directly using `dnspython` or raw sockets. Removes the ldnsutils dependency.

- [ ] **Replace `systemctl` with D-Bus**: Use `dbus-python` or `dasbus` to communicate
  with systemd directly for service restart/status. Removes the systemctl dependency.

- [ ] **Replace `dnsmasq --test` with config validation**: Validate the dnsmasq config
  syntax in Python rather than shelling out to `dnsmasq --test`.

## Configuration

- [ ] **Config file support**: Add support for a configuration file (e.g.
  `/etc/certbot-hook-dnsmasq.conf` or `~/.config/certbot-hook-dnsmasq/config.toml`)
  as an additional source in the configuration resolution order
  (CLI flag > env var > config file > default).

## Optimisations

- [x] **Batch multiple DNS records**: Two-phase execution using
  `CERTBOT_REMAINING_CHALLENGES`. Each invocation writes a per-challenge config file
  (`dnsmasq.acme.{domain}.{hash}.conf`). The final invocation restarts dnsmasq once,
  verifies all TXT records, sends one NOTIFY, and waits for all secondaries to sync.
  Supports wildcard + base domain (multiple tokens for the same domain).

- [ ] **Skip update if identical**: Before writing the ACME challenge config, check if
  the existing config file already has identical content. If so, skip the write,
  dnsmasq restart, and NOTIFY to avoid unnecessary service disruption.
