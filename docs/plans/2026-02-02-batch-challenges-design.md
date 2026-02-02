# Batch ACME Challenge Support Design

**Goal:** Support certbot multi-domain certificates by batching DNS record writes and deferring restart/notify/wait until the final challenge.

**Problem:** Certbot calls the auth hook once per challenge, sequentially. Currently we restart dnsmasq, verify DNS, send NOTIFY, and poll secondaries on every invocation. For N domains, this means N restarts and N propagation waits. Additionally, wildcard + base domain certificates produce two challenges for the same domain name with different tokens, and the current code overwrites the first token's config file with the second.

## Two-phase execution

The hook uses `CERTBOT_REMAINING_CHALLENGES` (available since certbot 1.4.0) to split into two phases:

**Phase 1 (remaining > 0): Write only**
- Write a config file with the TXT and CAA records
- Return 0 immediately

**Phase 2 (remaining == 0): Write + finalize**
- Write the config file
- Flatten dnsmasq config, extract values
- Validate and restart dnsmasq (once)
- Scan conf_dir for all pending challenge files, verify ALL TXT records on local DNS
- Send a single NOTIFY to secondaries
- Poll secondaries until ALL expected TXT records are present on ALL servers
- Return 1 if secondaries fail to sync within the timeout

When `CERTBOT_REMAINING_CHALLENGES` is missing (certbot < 1.4.0 or manual invocation), defaults to 0 -- same behaviour as before.

## Config file naming

Each challenge writes to `dnsmasq.acme.{domain}.{sha256(token)[:8]}.conf`. The hash suffix ensures uniqueness when the same domain has multiple challenges (wildcard + base). The token hash is deterministic, which supports future skip-if-identical optimisation.

File content is unchanged:
```
txt-record=_acme-challenge.example.com.,token-value
dns-rr=example.com.,257,000569737375656C657473656E63727970742E6F7267
```

## Multi-value TXT verification

When a domain has multiple challenges, multiple TXT records exist at the same name. `dig +short` returns all values on separate lines.

New function `query_all_txt_records(server, domain) -> set[str]` replaces the single-value `query_txt_record` for verification and sync-waiting.

Challenges are grouped by domain: `{"example.com": {"token_A", "token_B"}, "www.example.com": {"token_C"}}`.

Verification checks that the expected token set is a **subset** of actual records (stale records from previous runs are harmless).

Sync-waiting tracks `(server, domain)` pairs. A pair is synced when all expected tokens for that domain are present on that server. Polling is round-robin across all unsatisfied pairs.

## Module changes

**`external.py`:**
- Add `query_all_txt_records(server, domain) -> set[str]`
- Keep `query_txt_record` if still needed, or remove if fully replaced

**`hook.py`:**
- `write_acme_challenge`: filename gains `{sha256(token)[:8]}` suffix
- New `read_pending_challenges(conf_dir) -> dict[str, set[str]]`: globs `dnsmasq.acme.*.conf`, parses `txt-record=` lines, returns `{domain: {tokens}}`
- `verify_local_dns`: takes `dict[str, set[str]]`, checks all domains/tokens against local DNS
- `wait_for_sync`: takes `dict[str, set[str]]`, tracks `(server, domain)` pairs
- `run_auth_hook`: gains `remaining_challenges: int` parameter; writes config then either returns (phase 1) or finalizes (phase 2). Returns 1 if secondaries fail to sync.

**`cli.py`:**
- Reads `CERTBOT_REMAINING_CHALLENGES` from environment, parses as int (default 0), passes to `run_auth_hook`

**`flatten.py`:** No changes.

## Error handling

- **Failed write on early invocation**: returns non-zero, certbot aborts
- **Missing `CERTBOT_REMAINING_CHALLENGES`**: defaults to 0 (backward compatible)
- **Single domain certificates**: one invocation with remaining=0, same as current behaviour
- **Stale config files**: harmless -- subset check means extra records don't cause false failures
- **Verification failure**: returns 1, certbot does not submit any challenges
- **Secondary sync timeout**: returns 1 (hard failure, not a warning)
