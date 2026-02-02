# Batch ACME Challenge Support Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Support certbot multi-domain certificates by writing DNS records per-invocation and deferring restart/notify/wait until the final challenge.

**Architecture:** Two-phase hook execution using `CERTBOT_REMAINING_CHALLENGES`. Each invocation writes a per-challenge config file (`dnsmasq.acme.{domain}.{hash}.conf`). The final invocation (remaining=0) restarts dnsmasq, verifies all TXT records locally and on secondaries, sends one NOTIFY, and waits for propagation. Verification uses multi-value TXT lookups grouped by domain.

**Tech Stack:** Python 3.11+, hashlib (stdlib), pytest with unittest.mock

**Design doc:** `docs/plans/2026-02-02-batch-challenges-design.md`

---

### Task 1: Add `query_all_txt_records` to external.py

**Files:**
- Modify: `certbot_hook_dnsmasq/external.py:1-19`
- Test: `tests/test_external.py`

**Step 1: Write the failing tests**

Add to `tests/test_external.py`:

```python
from certbot_hook_dnsmasq.external import (
    query_all_txt_records,
    query_txt_record,
    run_dnsmasq_test,
    run_ldns_notify,
    run_systemctl,
)


class TestQueryAllTxtRecords:
    @patch("certbot_hook_dnsmasq.external.subprocess.run")
    def test_returns_set_of_values(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout='"token-A"\n"token-B"\n',
            returncode=0,
        )
        result = query_all_txt_records("8.8.8.8", "_acme-challenge.example.com")
        assert result == {"token-A", "token-B"}
        mock_run.assert_called_once_with(
            ["dig", "@8.8.8.8", "TXT", "_acme-challenge.example.com", "+short"],
            capture_output=True,
            text=True,
            check=False,
        )

    @patch("certbot_hook_dnsmasq.external.subprocess.run")
    def test_returns_single_value_set(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout='"only-token"\n',
            returncode=0,
        )
        result = query_all_txt_records("8.8.8.8", "_acme-challenge.example.com")
        assert result == {"only-token"}

    @patch("certbot_hook_dnsmasq.external.subprocess.run")
    def test_returns_empty_set_on_empty(self, mock_run):
        mock_run.return_value = MagicMock(stdout="\n", returncode=0)
        result = query_all_txt_records("8.8.8.8", "_acme-challenge.example.com")
        assert result == set()

    @patch("certbot_hook_dnsmasq.external.subprocess.run")
    def test_returns_empty_set_on_failure(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=9)
        result = query_all_txt_records("8.8.8.8", "_acme-challenge.example.com")
        assert result == set()
```

**Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_external.py -v`
Expected: FAIL with ImportError (query_all_txt_records not found)

**Step 3: Write the implementation**

Add to `certbot_hook_dnsmasq/external.py` after the existing `query_txt_record` function:

```python
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
```

**Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_external.py -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add certbot_hook_dnsmasq/external.py tests/test_external.py
git commit -m "Add query_all_txt_records for multi-value TXT lookups"
```

---

### Task 2: Change `write_acme_challenge` to use hash-based filenames

**Files:**
- Modify: `certbot_hook_dnsmasq/hook.py:1-33`
- Test: `tests/test_hook.py`

**Step 1: Update existing tests and add new ones**

In `tests/test_hook.py`, update the import to include `hashlib` and update TestWriteAcmeChallenge:

```python
import hashlib

class TestWriteAcmeChallenge:
    def test_creates_config_file_with_hash(self, tmp_path):
        path = write_acme_challenge(tmp_path, "example.com", "test-token-123")

        token_hash = hashlib.sha256("test-token-123".encode()).hexdigest()[:8]
        expected_name = f"dnsmasq.acme.example.com.{token_hash}.conf"
        assert path.name == expected_name
        assert path.exists()
        content = path.read_text()
        assert "txt-record=_acme-challenge.example.com.,test-token-123" in content
        assert "dns-rr=example.com.,257," in content

    def test_different_tokens_create_different_files(self, tmp_path):
        path1 = write_acme_challenge(tmp_path, "example.com", "token-A")
        path2 = write_acme_challenge(tmp_path, "example.com", "token-B")

        assert path1.name != path2.name
        assert path1.exists()
        assert path2.exists()

    def test_same_token_overwrites_same_file(self, tmp_path):
        path1 = write_acme_challenge(tmp_path, "example.com", "same-token")
        path2 = write_acme_challenge(tmp_path, "example.com", "same-token")

        assert path1 == path2
        # Only one file for this token
        matching = list(tmp_path.glob("dnsmasq.acme.example.com.*.conf"))
        assert len(matching) == 1
```

**Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_hook.py::TestWriteAcmeChallenge -v`
Expected: FAIL (old filename format doesn't have hash)

**Step 3: Update the implementation**

In `certbot_hook_dnsmasq/hook.py`, add `import hashlib` to the imports and update `write_acme_challenge`:

```python
import hashlib

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
```

**Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_hook.py::TestWriteAcmeChallenge -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add certbot_hook_dnsmasq/hook.py tests/test_hook.py
git commit -m "Use hash-based filenames for per-challenge config files"
```

---

### Task 3: Add `read_pending_challenges`

**Files:**
- Modify: `certbot_hook_dnsmasq/hook.py`
- Test: `tests/test_hook.py`

**Step 1: Write the failing tests**

Add to `tests/test_hook.py`:

```python
from certbot_hook_dnsmasq.hook import run_auth_hook, write_acme_challenge, verify_local_dns, wait_for_sync, read_pending_challenges


class TestReadPendingChallenges:
    def test_reads_single_challenge(self, tmp_path):
        write_acme_challenge(tmp_path, "example.com", "token-A")
        challenges = read_pending_challenges(tmp_path)
        assert challenges == {"example.com": {"token-A"}}

    def test_reads_multiple_domains(self, tmp_path):
        write_acme_challenge(tmp_path, "example.com", "token-A")
        write_acme_challenge(tmp_path, "www.example.com", "token-B")
        challenges = read_pending_challenges(tmp_path)
        assert challenges == {
            "example.com": {"token-A"},
            "www.example.com": {"token-B"},
        }

    def test_reads_multiple_tokens_same_domain(self, tmp_path):
        write_acme_challenge(tmp_path, "example.com", "token-A")
        write_acme_challenge(tmp_path, "example.com", "token-B")
        challenges = read_pending_challenges(tmp_path)
        assert challenges == {"example.com": {"token-A", "token-B"}}

    def test_ignores_non_acme_files(self, tmp_path):
        write_acme_challenge(tmp_path, "example.com", "token-A")
        (tmp_path / "other.conf").write_text("server=8.8.8.8\n")
        challenges = read_pending_challenges(tmp_path)
        assert challenges == {"example.com": {"token-A"}}

    def test_empty_directory(self, tmp_path):
        challenges = read_pending_challenges(tmp_path)
        assert challenges == {}
```

**Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_hook.py::TestReadPendingChallenges -v`
Expected: FAIL with ImportError (read_pending_challenges not found)

**Step 3: Write the implementation**

Add to `certbot_hook_dnsmasq/hook.py`:

```python
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
```

**Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_hook.py::TestReadPendingChallenges -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add certbot_hook_dnsmasq/hook.py tests/test_hook.py
git commit -m "Add read_pending_challenges to scan config dir for pending tokens"
```

---

### Task 4: Rewrite `verify_local_dns` for multi-domain multi-token verification

**Files:**
- Modify: `certbot_hook_dnsmasq/hook.py:36-45`
- Modify: `certbot_hook_dnsmasq/hook.py:8-13` (imports)
- Test: `tests/test_hook.py`

**Step 1: Write the failing tests**

Replace `TestVerifyLocalDns` in `tests/test_hook.py`:

```python
class TestVerifyLocalDns:
    @patch("certbot_hook_dnsmasq.hook.query_all_txt_records")
    def test_returns_true_when_all_present(self, mock_query):
        mock_query.return_value = {"token-A", "token-B"}
        challenges = {"example.com": {"token-A", "token-B"}}
        result = verify_local_dns("203.0.113.1", challenges)
        assert result is True
        mock_query.assert_called_once_with("203.0.113.1", "_acme-challenge.example.com")

    @patch("certbot_hook_dnsmasq.hook.query_all_txt_records")
    def test_returns_true_with_extra_records(self, mock_query):
        """Stale records from previous runs don't cause failure."""
        mock_query.return_value = {"token-A", "old-stale-token"}
        challenges = {"example.com": {"token-A"}}
        result = verify_local_dns("203.0.113.1", challenges)
        assert result is True

    @patch("certbot_hook_dnsmasq.hook.query_all_txt_records")
    def test_returns_false_when_missing(self, mock_query):
        mock_query.return_value = {"token-A"}
        challenges = {"example.com": {"token-A", "token-B"}}
        result = verify_local_dns("203.0.113.1", challenges)
        assert result is False

    @patch("certbot_hook_dnsmasq.hook.query_all_txt_records")
    def test_returns_false_when_empty(self, mock_query):
        mock_query.return_value = set()
        challenges = {"example.com": {"token-A"}}
        result = verify_local_dns("203.0.113.1", challenges)
        assert result is False

    @patch("certbot_hook_dnsmasq.hook.query_all_txt_records")
    def test_checks_multiple_domains(self, mock_query):
        mock_query.side_effect = [
            {"token-A"},  # example.com
            {"token-B"},  # www.example.com
        ]
        challenges = {
            "example.com": {"token-A"},
            "www.example.com": {"token-B"},
        }
        result = verify_local_dns("203.0.113.1", challenges)
        assert result is True
        assert mock_query.call_count == 2

    @patch("certbot_hook_dnsmasq.hook.query_all_txt_records")
    def test_fails_if_any_domain_missing(self, mock_query):
        mock_query.side_effect = [
            {"token-A"},  # example.com OK
            set(),        # www.example.com missing
        ]
        challenges = {
            "example.com": {"token-A"},
            "www.example.com": {"token-B"},
        }
        result = verify_local_dns("203.0.113.1", challenges)
        assert result is False
```

**Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_hook.py::TestVerifyLocalDns -v`
Expected: FAIL (wrong signature)

**Step 3: Update the implementation**

In `certbot_hook_dnsmasq/hook.py`, update the import to include `query_all_txt_records`:

```python
from certbot_hook_dnsmasq.external import (
    query_all_txt_records,
    query_txt_record,
    run_dnsmasq_test,
    run_ldns_notify,
    run_systemctl,
)
```

Replace `verify_local_dns`:

```python
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
```

**Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_hook.py::TestVerifyLocalDns -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add certbot_hook_dnsmasq/hook.py tests/test_hook.py
git commit -m "Rewrite verify_local_dns for multi-domain multi-token verification"
```

---

### Task 5: Rewrite `wait_for_sync` for multi-domain multi-token sync

**Files:**
- Modify: `certbot_hook_dnsmasq/hook.py:48-84`
- Test: `tests/test_hook.py`

**Step 1: Write the failing tests**

Replace `TestWaitForSync` in `tests/test_hook.py`:

```python
class TestWaitForSync:
    @patch("certbot_hook_dnsmasq.hook.time.sleep")
    @patch("certbot_hook_dnsmasq.hook.query_all_txt_records")
    def test_returns_true_when_all_synced(self, mock_query, mock_sleep):
        mock_query.return_value = {"test-token"}
        challenges = {"example.com": {"test-token"}}
        synced = wait_for_sync(
            ["ns2.example.com", "ns3.example.com"],
            challenges,
            max_wait=120,
            interval=5,
        )
        assert synced is True
        mock_sleep.assert_not_called()

    @patch("certbot_hook_dnsmasq.hook.time.sleep")
    @patch("certbot_hook_dnsmasq.hook.query_all_txt_records")
    def test_polls_until_synced(self, mock_query, mock_sleep):
        # Round 1: ns2 has nothing for example.com, ns3 has it
        # Round 2: ns2 now has it
        mock_query.side_effect = [
            set(), {"test-token"},       # round 1: ns2=empty, ns3=ok
            {"test-token"},              # round 2: ns2=ok (ns3 skipped)
        ]
        challenges = {"example.com": {"test-token"}}
        synced = wait_for_sync(
            ["ns2.example.com", "ns3.example.com"],
            challenges,
            max_wait=120,
            interval=5,
        )
        assert synced is True
        mock_sleep.assert_called_once_with(5)

    @patch("certbot_hook_dnsmasq.hook.time.sleep")
    @patch("certbot_hook_dnsmasq.hook.query_all_txt_records")
    def test_returns_false_on_timeout(self, mock_query, mock_sleep):
        mock_query.return_value = set()
        challenges = {"example.com": {"test-token"}}
        synced = wait_for_sync(
            ["ns2.example.com"],
            challenges,
            max_wait=10,
            interval=5,
        )
        assert synced is False
        assert mock_sleep.call_count == 2

    @patch("certbot_hook_dnsmasq.hook.time.sleep")
    @patch("certbot_hook_dnsmasq.hook.query_all_txt_records")
    def test_multi_domain_multi_token(self, mock_query, mock_sleep):
        """Two domains with two tokens each, all on one server."""
        mock_query.side_effect = [
            {"token-A", "token-B"},  # ns2: example.com
            {"token-C"},             # ns2: www.example.com
        ]
        challenges = {
            "example.com": {"token-A", "token-B"},
            "www.example.com": {"token-C"},
        }
        synced = wait_for_sync(
            ["ns2.example.com"],
            challenges,
            max_wait=120,
            interval=5,
        )
        assert synced is True
        mock_sleep.assert_not_called()

    @patch("certbot_hook_dnsmasq.hook.time.sleep")
    @patch("certbot_hook_dnsmasq.hook.query_all_txt_records")
    def test_partial_token_set_not_synced(self, mock_query, mock_sleep):
        """Server has one of two expected tokens -- not synced yet."""
        mock_query.side_effect = [
            {"token-A"},               # round 1: only 1 of 2
            {"token-A", "token-B"},    # round 2: both present
        ]
        challenges = {"example.com": {"token-A", "token-B"}}
        synced = wait_for_sync(
            ["ns2.example.com"],
            challenges,
            max_wait=120,
            interval=5,
        )
        assert synced is True
        mock_sleep.assert_called_once_with(5)
```

**Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_hook.py::TestWaitForSync -v`
Expected: FAIL (wrong signature)

**Step 3: Update the implementation**

Replace `wait_for_sync` in `certbot_hook_dnsmasq/hook.py`:

```python
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
```

**Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_hook.py::TestWaitForSync -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add certbot_hook_dnsmasq/hook.py tests/test_hook.py
git commit -m "Rewrite wait_for_sync for multi-domain multi-token sync checking"
```

---

### Task 6: Rewrite `run_auth_hook` with two-phase execution

**Files:**
- Modify: `certbot_hook_dnsmasq/hook.py:87-143`
- Test: `tests/test_hook.py`

**Step 1: Write the failing tests**

Replace `TestRunAuthHook` in `tests/test_hook.py`. Note: `run_auth_hook` now takes `remaining_challenges` parameter.

```python
class TestRunAuthHook:
    @patch("certbot_hook_dnsmasq.hook.wait_for_sync")
    @patch("certbot_hook_dnsmasq.hook.run_ldns_notify")
    @patch("certbot_hook_dnsmasq.hook.verify_local_dns")
    @patch("certbot_hook_dnsmasq.hook.read_pending_challenges")
    @patch("certbot_hook_dnsmasq.hook.run_systemctl")
    @patch("certbot_hook_dnsmasq.hook.run_dnsmasq_test")
    @patch("certbot_hook_dnsmasq.hook.write_acme_challenge")
    @patch("certbot_hook_dnsmasq.hook.extract_config_values")
    @patch("certbot_hook_dnsmasq.hook.flatten_config")
    def test_full_flow_remaining_zero(
        self, mock_flatten, mock_extract, mock_write,
        mock_test, mock_systemctl, mock_read_pending,
        mock_verify, mock_notify, mock_wait,
        tmp_path,
    ):
        mock_flatten.return_value = ["auth-server=example.com"]
        mock_extract.return_value = DnsmasqConfigValues(
            auth_zone="example.com",
            auth_sec_servers=["ns2.example.com"],
            public_ipv4="203.0.113.1",
        )
        mock_write.return_value = tmp_path / "dnsmasq.acme.example.com.abcd1234.conf"
        mock_read_pending.return_value = {"example.com": {"test-token"}}
        mock_verify.return_value = True
        mock_wait.return_value = True

        result = run_auth_hook(
            conf_dir=tmp_path,
            conf=Path("/etc/dnsmasq.conf"),
            service="dnsmasq",
            domain="example.com",
            validation="test-token",
            remaining_challenges=0,
        )

        assert result == 0
        mock_write.assert_called_once_with(tmp_path, "example.com", "test-token")
        mock_flatten.assert_called_once()
        mock_test.assert_called_once()
        assert mock_systemctl.call_count == 2
        mock_read_pending.assert_called_once_with(tmp_path)
        mock_verify.assert_called_once_with("203.0.113.1", {"example.com": {"test-token"}})
        mock_notify.assert_called_once()
        mock_wait.assert_called_once()

    @patch("certbot_hook_dnsmasq.hook.write_acme_challenge")
    def test_write_only_when_remaining_positive(self, mock_write, tmp_path):
        mock_write.return_value = tmp_path / "test.conf"

        result = run_auth_hook(
            conf_dir=tmp_path,
            conf=Path("/etc/dnsmasq.conf"),
            service="dnsmasq",
            domain="example.com",
            validation="test-token",
            remaining_challenges=2,
        )

        assert result == 0
        mock_write.assert_called_once_with(tmp_path, "example.com", "test-token")

    @patch("certbot_hook_dnsmasq.hook.write_acme_challenge")
    def test_no_restart_when_remaining_positive(self, mock_write, tmp_path):
        mock_write.return_value = tmp_path / "test.conf"

        with patch("certbot_hook_dnsmasq.hook.flatten_config") as mock_flatten:
            result = run_auth_hook(
                conf_dir=tmp_path,
                conf=Path("/etc/dnsmasq.conf"),
                service="dnsmasq",
                domain="example.com",
                validation="test-token",
                remaining_challenges=3,
            )

        assert result == 0
        mock_flatten.assert_not_called()

    @patch("certbot_hook_dnsmasq.hook.read_pending_challenges")
    @patch("certbot_hook_dnsmasq.hook.run_systemctl")
    @patch("certbot_hook_dnsmasq.hook.run_dnsmasq_test")
    @patch("certbot_hook_dnsmasq.hook.write_acme_challenge")
    @patch("certbot_hook_dnsmasq.hook.extract_config_values")
    @patch("certbot_hook_dnsmasq.hook.flatten_config")
    def test_exits_on_missing_auth_zone(
        self, mock_flatten, mock_extract, mock_write,
        mock_test, mock_systemctl, mock_read_pending,
        tmp_path,
    ):
        mock_flatten.return_value = []
        mock_extract.return_value = DnsmasqConfigValues(
            auth_zone=None, auth_sec_servers=[], public_ipv4=None,
        )
        mock_write.return_value = tmp_path / "test.conf"

        result = run_auth_hook(
            conf_dir=tmp_path,
            conf=Path("/etc/dnsmasq.conf"),
            service="dnsmasq",
            domain="example.com",
            validation="test-token",
            remaining_challenges=0,
        )
        assert result == 1

    @patch("certbot_hook_dnsmasq.hook.read_pending_challenges")
    @patch("certbot_hook_dnsmasq.hook.run_systemctl")
    @patch("certbot_hook_dnsmasq.hook.run_dnsmasq_test")
    @patch("certbot_hook_dnsmasq.hook.write_acme_challenge")
    @patch("certbot_hook_dnsmasq.hook.extract_config_values")
    @patch("certbot_hook_dnsmasq.hook.flatten_config")
    def test_exits_on_missing_sec_servers(
        self, mock_flatten, mock_extract, mock_write,
        mock_test, mock_systemctl, mock_read_pending,
        tmp_path,
    ):
        mock_flatten.return_value = ["auth-server=example.com"]
        mock_extract.return_value = DnsmasqConfigValues(
            auth_zone="example.com", auth_sec_servers=[], public_ipv4="203.0.113.1",
        )
        mock_write.return_value = tmp_path / "test.conf"

        result = run_auth_hook(
            conf_dir=tmp_path,
            conf=Path("/etc/dnsmasq.conf"),
            service="dnsmasq",
            domain="example.com",
            validation="test-token",
            remaining_challenges=0,
        )
        assert result == 1

    @patch("certbot_hook_dnsmasq.hook.read_pending_challenges")
    @patch("certbot_hook_dnsmasq.hook.run_systemctl")
    @patch("certbot_hook_dnsmasq.hook.run_dnsmasq_test")
    @patch("certbot_hook_dnsmasq.hook.write_acme_challenge")
    @patch("certbot_hook_dnsmasq.hook.extract_config_values")
    @patch("certbot_hook_dnsmasq.hook.flatten_config")
    def test_exits_on_missing_public_ipv4(
        self, mock_flatten, mock_extract, mock_write,
        mock_test, mock_systemctl, mock_read_pending,
        tmp_path,
    ):
        mock_flatten.return_value = ["auth-server=example.com"]
        mock_extract.return_value = DnsmasqConfigValues(
            auth_zone="example.com", auth_sec_servers=["ns2.example.com"], public_ipv4=None,
        )
        mock_write.return_value = tmp_path / "test.conf"

        result = run_auth_hook(
            conf_dir=tmp_path,
            conf=Path("/etc/dnsmasq.conf"),
            service="dnsmasq",
            domain="example.com",
            validation="test-token",
            remaining_challenges=0,
        )
        assert result == 1

    @patch("certbot_hook_dnsmasq.hook.read_pending_challenges")
    @patch("certbot_hook_dnsmasq.hook.write_acme_challenge")
    @patch("certbot_hook_dnsmasq.hook.extract_config_values")
    @patch("certbot_hook_dnsmasq.hook.flatten_config")
    def test_exits_on_dnsmasq_test_failure(
        self, mock_flatten, mock_extract, mock_write,
        mock_read_pending, tmp_path,
    ):
        mock_flatten.return_value = ["auth-server=example.com"]
        mock_extract.return_value = DnsmasqConfigValues(
            auth_zone="example.com",
            auth_sec_servers=["ns2.example.com"],
            public_ipv4="203.0.113.1",
        )
        mock_write.return_value = tmp_path / "test.conf"

        with patch("certbot_hook_dnsmasq.hook.run_dnsmasq_test",
                    side_effect=subprocess.CalledProcessError(1, ["dnsmasq", "--test"])):
            result = run_auth_hook(
                conf_dir=tmp_path,
                conf=Path("/etc/dnsmasq.conf"),
                service="dnsmasq",
                domain="example.com",
                validation="test-token",
                remaining_challenges=0,
            )
        assert result == 1

    @patch("certbot_hook_dnsmasq.hook.read_pending_challenges")
    @patch("certbot_hook_dnsmasq.hook.verify_local_dns")
    @patch("certbot_hook_dnsmasq.hook.run_systemctl")
    @patch("certbot_hook_dnsmasq.hook.run_dnsmasq_test")
    @patch("certbot_hook_dnsmasq.hook.write_acme_challenge")
    @patch("certbot_hook_dnsmasq.hook.extract_config_values")
    @patch("certbot_hook_dnsmasq.hook.flatten_config")
    def test_exits_on_ldns_notify_failure(
        self, mock_flatten, mock_extract, mock_write, mock_test,
        mock_systemctl, mock_verify, mock_read_pending, tmp_path,
    ):
        mock_flatten.return_value = ["auth-server=example.com"]
        mock_extract.return_value = DnsmasqConfigValues(
            auth_zone="example.com",
            auth_sec_servers=["ns2.example.com"],
            public_ipv4="203.0.113.1",
        )
        mock_write.return_value = tmp_path / "test.conf"
        mock_read_pending.return_value = {"example.com": {"test-token"}}
        mock_verify.return_value = True

        with patch("certbot_hook_dnsmasq.hook.run_ldns_notify",
                    side_effect=subprocess.CalledProcessError(1, ["ldns-notify"])):
            result = run_auth_hook(
                conf_dir=tmp_path,
                conf=Path("/etc/dnsmasq.conf"),
                service="dnsmasq",
                domain="example.com",
                validation="test-token",
                remaining_challenges=0,
            )
        assert result == 1

    @patch("certbot_hook_dnsmasq.hook.read_pending_challenges")
    @patch("certbot_hook_dnsmasq.hook.run_dnsmasq_test")
    @patch("certbot_hook_dnsmasq.hook.write_acme_challenge")
    @patch("certbot_hook_dnsmasq.hook.extract_config_values")
    @patch("certbot_hook_dnsmasq.hook.flatten_config")
    def test_exits_on_verify_failure(
        self, mock_flatten, mock_extract, mock_write, mock_test,
        mock_read_pending, tmp_path,
    ):
        mock_flatten.return_value = ["auth-server=example.com"]
        mock_extract.return_value = DnsmasqConfigValues(
            auth_zone="example.com",
            auth_sec_servers=["ns2.example.com"],
            public_ipv4="203.0.113.1",
        )
        mock_write.return_value = tmp_path / "test.conf"
        mock_read_pending.return_value = {"example.com": {"test-token"}}

        with patch("certbot_hook_dnsmasq.hook.run_systemctl"):
            with patch("certbot_hook_dnsmasq.hook.verify_local_dns", return_value=False):
                result = run_auth_hook(
                    conf_dir=tmp_path,
                    conf=Path("/etc/dnsmasq.conf"),
                    service="dnsmasq",
                    domain="example.com",
                    validation="test-token",
                    remaining_challenges=0,
                )
        assert result == 1

    @patch("certbot_hook_dnsmasq.hook.wait_for_sync")
    @patch("certbot_hook_dnsmasq.hook.run_ldns_notify")
    @patch("certbot_hook_dnsmasq.hook.verify_local_dns")
    @patch("certbot_hook_dnsmasq.hook.read_pending_challenges")
    @patch("certbot_hook_dnsmasq.hook.run_systemctl")
    @patch("certbot_hook_dnsmasq.hook.run_dnsmasq_test")
    @patch("certbot_hook_dnsmasq.hook.write_acme_challenge")
    @patch("certbot_hook_dnsmasq.hook.extract_config_values")
    @patch("certbot_hook_dnsmasq.hook.flatten_config")
    def test_exits_on_sync_timeout(
        self, mock_flatten, mock_extract, mock_write,
        mock_test, mock_systemctl, mock_read_pending,
        mock_verify, mock_notify, mock_wait,
        tmp_path,
    ):
        mock_flatten.return_value = ["auth-server=example.com"]
        mock_extract.return_value = DnsmasqConfigValues(
            auth_zone="example.com",
            auth_sec_servers=["ns2.example.com"],
            public_ipv4="203.0.113.1",
        )
        mock_write.return_value = tmp_path / "test.conf"
        mock_read_pending.return_value = {"example.com": {"test-token"}}
        mock_verify.return_value = True
        mock_wait.return_value = False  # sync timed out

        result = run_auth_hook(
            conf_dir=tmp_path,
            conf=Path("/etc/dnsmasq.conf"),
            service="dnsmasq",
            domain="example.com",
            validation="test-token",
            remaining_challenges=0,
        )
        assert result == 1
```

**Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_hook.py::TestRunAuthHook -v`
Expected: FAIL (missing remaining_challenges parameter)

**Step 3: Update the implementation**

Replace `run_auth_hook` in `certbot_hook_dnsmasq/hook.py`:

```python
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
```

**Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_hook.py -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add certbot_hook_dnsmasq/hook.py tests/test_hook.py
git commit -m "Rewrite run_auth_hook with two-phase execution for batch challenges"
```

---

### Task 7: Update CLI to pass `remaining_challenges`

**Files:**
- Modify: `certbot_hook_dnsmasq/cli.py:94-115`
- Test: `tests/test_cli.py`

**Step 1: Write the failing tests**

Add to `tests/test_cli.py` in `TestMainAuthHook`:

```python
    @patch("certbot_hook_dnsmasq.cli.run_auth_hook")
    def test_passes_remaining_challenges(self, mock_hook):
        mock_hook.return_value = 0
        env = {
            "CERTBOT_DOMAIN": "example.com",
            "CERTBOT_VALIDATION": "test-token",
            "CERTBOT_REMAINING_CHALLENGES": "3",
        }
        with patch.dict(os.environ, env, clear=False):
            with patch("sys.argv", ["certbot-hook-dnsmasq", "auth-hook"]):
                result = main()
        assert result == 0
        call_kwargs = mock_hook.call_args[1]
        assert call_kwargs["remaining_challenges"] == 3

    @patch("certbot_hook_dnsmasq.cli.run_auth_hook")
    def test_defaults_remaining_challenges_to_zero(self, mock_hook):
        mock_hook.return_value = 0
        env = {
            "CERTBOT_DOMAIN": "example.com",
            "CERTBOT_VALIDATION": "test-token",
        }
        # Ensure CERTBOT_REMAINING_CHALLENGES is NOT set
        env_clean = {k: v for k, v in os.environ.items()
                     if k != "CERTBOT_REMAINING_CHALLENGES"}
        env_clean.update(env)
        with patch.dict(os.environ, env_clean, clear=True):
            with patch("sys.argv", ["certbot-hook-dnsmasq", "auth-hook"]):
                result = main()
        assert result == 0
        call_kwargs = mock_hook.call_args[1]
        assert call_kwargs["remaining_challenges"] == 0
```

**Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_cli.py::TestMainAuthHook::test_passes_remaining_challenges tests/test_cli.py::TestMainAuthHook::test_defaults_remaining_challenges_to_zero -v`
Expected: FAIL (remaining_challenges not passed)

**Step 3: Update the implementation**

In `certbot_hook_dnsmasq/cli.py`, update the auth-hook section of `main()`:

```python
    if args.subcommand == "auth-hook":
        domain = os.environ.get("CERTBOT_DOMAIN")
        validation = os.environ.get("CERTBOT_VALIDATION")

        if not domain:
            print("ERROR: CERTBOT_DOMAIN environment variable not set", file=sys.stderr)
            return 1
        if not validation:
            print("ERROR: CERTBOT_VALIDATION environment variable not set", file=sys.stderr)
            return 1

        remaining_str = os.environ.get("CERTBOT_REMAINING_CHALLENGES", "0")
        try:
            remaining_challenges = int(remaining_str)
        except ValueError:
            remaining_challenges = 0

        conf_dir = _resolve_path(args.conf_dir, "DNSMASQ_CONF_DIR", Path("/etc/dnsmasq.d"))
        conf = _resolve_path(args.conf, "DNSMASQ_CONF", Path("/etc/dnsmasq.conf"))
        service = _resolve_str(args.service, "DNSMASQ_SERVICE", "dnsmasq")

        return run_auth_hook(
            conf_dir=conf_dir,
            conf=conf,
            service=service,
            domain=domain,
            validation=validation,
            remaining_challenges=remaining_challenges,
        )
```

**Step 4: Run ALL tests to verify everything passes**

Run: `uv run pytest tests/ -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add certbot_hook_dnsmasq/cli.py tests/test_cli.py
git commit -m "Pass CERTBOT_REMAINING_CHALLENGES from env to run_auth_hook"
```

---

### Task 8: Update documentation and TODO.md

**Files:**
- Modify: `CLAUDE.md`
- Modify: `README.md`
- Modify: `TODO.md`

**Step 1: Update CLAUDE.md**

Update the auth-hook workflow section to describe the two-phase execution and the `CERTBOT_REMAINING_CHALLENGES` environment variable. Update the configuration section to list `CERTBOT_REMAINING_CHALLENGES`. Note the config file naming now includes a hash.

**Step 2: Update README.md**

Add a "Multi-domain certificates" section explaining that the hook automatically batches when certbot provides `CERTBOT_REMAINING_CHALLENGES`. Mention the wildcard + base domain support. Update the "How it works" section.

**Step 3: Update TODO.md**

Mark "Batch multiple DNS records" as complete. The "Skip update if identical" item remains.

**Step 4: Run tests one final time**

Run: `uv run pytest tests/ -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add CLAUDE.md README.md TODO.md
git commit -m "Update documentation for batch ACME challenge support"
```
