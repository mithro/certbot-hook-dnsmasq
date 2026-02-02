"""Tests for certbot_hook_dnsmasq.hook"""

import hashlib
import subprocess
from pathlib import Path
from unittest.mock import patch, call

import pytest

from certbot_hook_dnsmasq.flatten import DnsmasqConfigValues
from certbot_hook_dnsmasq.hook import run_auth_hook, write_acme_challenge, verify_local_dns, wait_for_sync, read_pending_challenges


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


class TestRunAuthHook:
    @patch("certbot_hook_dnsmasq.hook.wait_for_sync")
    @patch("certbot_hook_dnsmasq.hook.run_ldns_notify")
    @patch("certbot_hook_dnsmasq.hook.verify_local_dns")
    @patch("certbot_hook_dnsmasq.hook.run_systemctl")
    @patch("certbot_hook_dnsmasq.hook.run_dnsmasq_test")
    @patch("certbot_hook_dnsmasq.hook.write_acme_challenge")
    @patch("certbot_hook_dnsmasq.hook.extract_config_values")
    @patch("certbot_hook_dnsmasq.hook.flatten_config")
    def test_orchestrates_full_flow(
        self, mock_flatten, mock_extract, mock_write,
        mock_test, mock_systemctl, mock_verify, mock_notify, mock_wait,
        tmp_path,
    ):
        mock_flatten.return_value = ["auth-server=example.com"]
        mock_extract.return_value = DnsmasqConfigValues(
            auth_zone="example.com",
            auth_sec_servers=["ns2.example.com"],
            public_ipv4="203.0.113.1",
        )
        mock_write.return_value = tmp_path / "dnsmasq.acme.example.com.conf"
        mock_verify.return_value = True
        mock_wait.return_value = {"ns2.example.com": "test-token"}

        result = run_auth_hook(
            conf_dir=tmp_path,
            conf=Path("/etc/dnsmasq.conf"),
            service="dnsmasq",
            domain="example.com",
            validation="test-token",
        )

        assert result == 0
        mock_flatten.assert_called_once_with(Path("/etc/dnsmasq.conf"))
        mock_extract.assert_called_once()
        mock_write.assert_called_once_with(tmp_path, "example.com", "test-token")
        mock_test.assert_called_once_with(str(Path("/etc/dnsmasq.conf")))
        assert mock_systemctl.call_count == 2  # restart + status
        mock_verify.assert_called_once_with("203.0.113.1", "example.com", "test-token")
        mock_notify.assert_called_once_with("203.0.113.1", "example.com", ["ns2.example.com"])
        mock_wait.assert_called_once()

    @patch("certbot_hook_dnsmasq.hook.extract_config_values")
    @patch("certbot_hook_dnsmasq.hook.flatten_config")
    def test_exits_on_missing_auth_zone(self, mock_flatten, mock_extract, tmp_path):
        mock_flatten.return_value = []
        mock_extract.return_value = DnsmasqConfigValues(
            auth_zone=None,
            auth_sec_servers=[],
            public_ipv4=None,
        )

        result = run_auth_hook(
            conf_dir=tmp_path,
            conf=Path("/etc/dnsmasq.conf"),
            service="dnsmasq",
            domain="example.com",
            validation="test-token",
        )
        assert result == 1

    @patch("certbot_hook_dnsmasq.hook.extract_config_values")
    @patch("certbot_hook_dnsmasq.hook.flatten_config")
    def test_exits_on_missing_sec_servers(self, mock_flatten, mock_extract, tmp_path):
        mock_flatten.return_value = ["auth-server=example.com"]
        mock_extract.return_value = DnsmasqConfigValues(
            auth_zone="example.com",
            auth_sec_servers=[],
            public_ipv4="203.0.113.1",
        )

        result = run_auth_hook(
            conf_dir=tmp_path,
            conf=Path("/etc/dnsmasq.conf"),
            service="dnsmasq",
            domain="example.com",
            validation="test-token",
        )
        assert result == 1

    @patch("certbot_hook_dnsmasq.hook.extract_config_values")
    @patch("certbot_hook_dnsmasq.hook.flatten_config")
    def test_exits_on_missing_public_ipv4(self, mock_flatten, mock_extract, tmp_path):
        mock_flatten.return_value = ["auth-server=example.com"]
        mock_extract.return_value = DnsmasqConfigValues(
            auth_zone="example.com",
            auth_sec_servers=["ns2.example.com"],
            public_ipv4=None,
        )

        result = run_auth_hook(
            conf_dir=tmp_path,
            conf=Path("/etc/dnsmasq.conf"),
            service="dnsmasq",
            domain="example.com",
            validation="test-token",
        )
        assert result == 1

    @patch("certbot_hook_dnsmasq.hook.write_acme_challenge")
    @patch("certbot_hook_dnsmasq.hook.extract_config_values")
    @patch("certbot_hook_dnsmasq.hook.flatten_config")
    def test_exits_on_dnsmasq_test_failure(
        self, mock_flatten, mock_extract, mock_write, tmp_path,
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
            )
        assert result == 1

    @patch("certbot_hook_dnsmasq.hook.verify_local_dns")
    @patch("certbot_hook_dnsmasq.hook.run_systemctl")
    @patch("certbot_hook_dnsmasq.hook.run_dnsmasq_test")
    @patch("certbot_hook_dnsmasq.hook.write_acme_challenge")
    @patch("certbot_hook_dnsmasq.hook.extract_config_values")
    @patch("certbot_hook_dnsmasq.hook.flatten_config")
    def test_exits_on_ldns_notify_failure(
        self, mock_flatten, mock_extract, mock_write, mock_test,
        mock_systemctl, mock_verify, tmp_path,
    ):
        mock_flatten.return_value = ["auth-server=example.com"]
        mock_extract.return_value = DnsmasqConfigValues(
            auth_zone="example.com",
            auth_sec_servers=["ns2.example.com"],
            public_ipv4="203.0.113.1",
        )
        mock_write.return_value = tmp_path / "test.conf"
        mock_verify.return_value = True

        with patch("certbot_hook_dnsmasq.hook.run_ldns_notify",
                    side_effect=subprocess.CalledProcessError(1, ["ldns-notify"])):
            result = run_auth_hook(
                conf_dir=tmp_path,
                conf=Path("/etc/dnsmasq.conf"),
                service="dnsmasq",
                domain="example.com",
                validation="test-token",
            )
        assert result == 1

    @patch("certbot_hook_dnsmasq.hook.run_dnsmasq_test")
    @patch("certbot_hook_dnsmasq.hook.write_acme_challenge")
    @patch("certbot_hook_dnsmasq.hook.extract_config_values")
    @patch("certbot_hook_dnsmasq.hook.flatten_config")
    def test_exits_on_verify_failure(
        self, mock_flatten, mock_extract, mock_write, mock_test, tmp_path,
    ):
        mock_flatten.return_value = ["auth-server=example.com"]
        mock_extract.return_value = DnsmasqConfigValues(
            auth_zone="example.com",
            auth_sec_servers=["ns2.example.com"],
            public_ipv4="203.0.113.1",
        )
        mock_write.return_value = tmp_path / "test.conf"

        with patch("certbot_hook_dnsmasq.hook.run_systemctl"):
            with patch("certbot_hook_dnsmasq.hook.verify_local_dns", return_value=False):
                result = run_auth_hook(
                    conf_dir=tmp_path,
                    conf=Path("/etc/dnsmasq.conf"),
                    service="dnsmasq",
                    domain="example.com",
                    validation="test-token",
                )
        assert result == 1
