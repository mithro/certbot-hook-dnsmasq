"""Tests for certbot_hook_dnsmasq.external"""

from unittest.mock import patch, MagicMock
import subprocess

import pytest

from certbot_hook_dnsmasq.external import (
    interface_ipv4_addresses,
    query_all_txt_records,
    run_dnsmasq_test,
    run_ldns_notify,
    run_systemctl,
)


class TestRunDnsmasqTest:
    @patch("certbot_hook_dnsmasq.external.subprocess.run")
    def test_calls_dnsmasq_test(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        run_dnsmasq_test("/etc/dnsmasq.conf")
        mock_run.assert_called_once_with(
            ["dnsmasq", "--test", "-C", "/etc/dnsmasq.conf"],
            capture_output=True,
            text=True,
            check=True,
        )

    @patch("certbot_hook_dnsmasq.external.subprocess.run")
    def test_raises_on_failure(self, mock_run):
        mock_run.side_effect = subprocess.CalledProcessError(1, "dnsmasq")
        with pytest.raises(subprocess.CalledProcessError):
            run_dnsmasq_test("/etc/dnsmasq.conf")


class TestRunSystemctl:
    @patch("certbot_hook_dnsmasq.external.subprocess.run")
    def test_calls_systemctl(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        run_systemctl("restart", "dnsmasq")
        mock_run.assert_called_once_with(
            ["systemctl", "restart", "dnsmasq"],
            check=True,
        )


class TestRunLdnsNotify:
    @patch("certbot_hook_dnsmasq.external.subprocess.run")
    def test_calls_ldns_notify(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        run_ldns_notify("203.0.113.1", "example.com", ["ns2.example.com", "ns3.example.com"])
        mock_run.assert_called_once_with(
            ["ldns-notify", "-I", "203.0.113.1", "-z", "example.com",
             "ns2.example.com", "ns3.example.com"],
            check=True,
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


class TestInterfaceIpv4Addresses:
    @patch("certbot_hook_dnsmasq.external.subprocess.run")
    def test_returns_addresses_from_json(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout='[{"ifname":"eth0","addr_info":'
                   '[{"family":"inet","local":"87.121.95.37","scope":"global"}]}]',
            returncode=0,
        )
        result = interface_ipv4_addresses("eth0")
        assert result == ["87.121.95.37"]
        mock_run.assert_called_once_with(
            ["ip", "-j", "-4", "addr", "show", "dev", "eth0"],
            capture_output=True,
            text=True,
            check=False,
        )

    @patch("certbot_hook_dnsmasq.external.subprocess.run")
    def test_returns_addresses_in_order(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout='[{"addr_info":[{"family":"inet","local":"203.0.113.1"},'
                   '{"family":"inet","local":"10.0.0.1"}]}]',
            returncode=0,
        )
        result = interface_ipv4_addresses("eth0")
        assert result == ["203.0.113.1", "10.0.0.1"]

    @patch("certbot_hook_dnsmasq.external.subprocess.run")
    def test_returns_empty_on_failure(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=1)
        result = interface_ipv4_addresses("eth0")
        assert result == []

    @patch("certbot_hook_dnsmasq.external.subprocess.run")
    def test_returns_empty_on_invalid_json(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        result = interface_ipv4_addresses("eth0")
        assert result == []

    @patch("certbot_hook_dnsmasq.external.subprocess.run")
    def test_returns_empty_when_no_addresses(self, mock_run):
        mock_run.return_value = MagicMock(stdout='[{"ifname":"eth0"}]', returncode=0)
        result = interface_ipv4_addresses("eth0")
        assert result == []
