"""Tests for certbot_hook_dnsmasq.hook"""

import subprocess
from pathlib import Path
from unittest.mock import patch, call

import pytest

from certbot_hook_dnsmasq.flatten import DnsmasqConfigValues
from certbot_hook_dnsmasq.hook import run_auth_hook, write_acme_challenge, verify_local_dns, wait_for_sync


class TestWriteAcmeChallenge:
    def test_creates_config_file(self, tmp_path):
        write_acme_challenge(tmp_path, "example.com", "test-token-123")

        config_file = tmp_path / "dnsmasq.acme.example.com.conf"
        assert config_file.exists()
        content = config_file.read_text()
        assert "txt-record=_acme-challenge.example.com.,test-token-123" in content
        assert "dns-rr=example.com.,257," in content

    def test_overwrites_existing(self, tmp_path):
        config_file = tmp_path / "dnsmasq.acme.example.com.conf"
        config_file.write_text("old content")

        write_acme_challenge(tmp_path, "example.com", "new-token")

        content = config_file.read_text()
        assert "old content" not in content
        assert "new-token" in content


class TestVerifyLocalDns:
    @patch("certbot_hook_dnsmasq.hook.query_txt_record")
    def test_returns_true_when_matches(self, mock_query):
        mock_query.return_value = "test-token"
        result = verify_local_dns("203.0.113.1", "example.com", "test-token")
        assert result is True
        mock_query.assert_called_once_with("203.0.113.1", "_acme-challenge.example.com")

    @patch("certbot_hook_dnsmasq.hook.query_txt_record")
    def test_returns_false_when_mismatch(self, mock_query):
        mock_query.return_value = "wrong-token"
        result = verify_local_dns("203.0.113.1", "example.com", "test-token")
        assert result is False

    @patch("certbot_hook_dnsmasq.hook.query_txt_record")
    def test_returns_false_when_none(self, mock_query):
        mock_query.return_value = None
        result = verify_local_dns("203.0.113.1", "example.com", "test-token")
        assert result is False


class TestWaitForSync:
    @patch("certbot_hook_dnsmasq.hook.time.sleep")
    @patch("certbot_hook_dnsmasq.hook.query_txt_record")
    def test_returns_true_when_all_synced(self, mock_query, mock_sleep):
        mock_query.return_value = "test-token"
        responses = wait_for_sync(
            ["ns2.example.com", "ns3.example.com"],
            "example.com",
            "test-token",
            max_wait=120,
            interval=5,
        )
        assert responses == {
            "ns2.example.com": "test-token",
            "ns3.example.com": "test-token",
        }
        # Should not sleep if synced on first check
        mock_sleep.assert_not_called()

    @patch("certbot_hook_dnsmasq.hook.time.sleep")
    @patch("certbot_hook_dnsmasq.hook.query_txt_record")
    def test_polls_until_synced(self, mock_query, mock_sleep):
        # First round: ns2 not synced, ns3 synced
        # Second round: ns2 synced
        mock_query.side_effect = [
            None, "test-token",       # round 1: ns2=None, ns3=token
            "test-token",             # round 2: ns2=token (ns3 skipped)
        ]
        responses = wait_for_sync(
            ["ns2.example.com", "ns3.example.com"],
            "example.com",
            "test-token",
            max_wait=120,
            interval=5,
        )
        assert responses == {
            "ns2.example.com": "test-token",
            "ns3.example.com": "test-token",
        }
        mock_sleep.assert_called_once_with(5)

    @patch("certbot_hook_dnsmasq.hook.time.sleep")
    @patch("certbot_hook_dnsmasq.hook.query_txt_record")
    def test_returns_partial_on_timeout(self, mock_query, mock_sleep):
        mock_query.return_value = None
        responses = wait_for_sync(
            ["ns2.example.com"],
            "example.com",
            "test-token",
            max_wait=10,
            interval=5,
        )
        assert responses == {"ns2.example.com": None}
        # Should have slept twice (0+5=5, 5+5=10, then timeout)
        assert mock_sleep.call_count == 2

    @patch("certbot_hook_dnsmasq.hook.time.sleep")
    @patch("certbot_hook_dnsmasq.hook.query_txt_record")
    def test_tracks_actual_responses(self, mock_query, mock_sleep):
        """Responses dict tracks the actual value from each server."""
        mock_query.side_effect = [
            "wrong-token", "test-token",  # round 1
            "test-token",                 # round 2
        ]
        responses = wait_for_sync(
            ["ns2.example.com", "ns3.example.com"],
            "example.com",
            "test-token",
            max_wait=120,
            interval=5,
        )
        assert responses["ns2.example.com"] == "test-token"
        assert responses["ns3.example.com"] == "test-token"


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
