# TODO

## Future Subcommands

- [ ] **cleanup-hook**: Add `certbot-hook-dnsmasq cleanup-hook` subcommand for certbot
  `--manual-cleanup-hook`. Should remove the `dnsmasq.acme.*.conf` file created by
  `auth-hook`, test the config, and restart dnsmasq. Currently stale ACME challenge
  configs accumulate in the conf directory.

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

- [ ] **Batch multiple DNS records**: Allow the hook to process multiple ACME challenge
  records at once (e.g. when certbot is validating multiple domains in a single run),
  writing all TXT records before doing a single dnsmasq restart and NOTIFY cycle
  instead of restarting per-domain.

- [ ] **Skip update if identical**: Before writing the ACME challenge config, check if
  the existing config file already has identical content. If so, skip the write,
  dnsmasq restart, and NOTIFY to avoid unnecessary service disruption.
