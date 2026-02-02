"""Tests for certbot_hook_dnsmasq.external"""

from unittest.mock import patch, MagicMock
import subprocess

import pytest

from certbot_hook_dnsmasq.external import (
    query_txt_record,
    run_dnsmasq_test,
    run_ldns_notify,
    run_systemctl,
)


class TestQueryTxtRecord:
    @patch("certbot_hook_dnsmasq.external.subprocess.run")
    def test_returns_txt_value(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout='"test-validation-token"\n',
            returncode=0,
        )
        result = query_txt_record("8.8.8.8", "_acme-challenge.example.com")
        assert result == "test-validation-token"
        mock_run.assert_called_once_with(
            ["dig", "@8.8.8.8", "TXT", "_acme-challenge.example.com", "+short"],
            capture_output=True,
            text=True,
            check=False,
        )

    @patch("certbot_hook_dnsmasq.external.subprocess.run")
    def test_returns_first_line_on_multiline(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout='"first-value"\n"second-value"\n',
            returncode=0,
        )
        result = query_txt_record("8.8.8.8", "_acme-challenge.example.com")
        assert result == "first-value"

    @patch("certbot_hook_dnsmasq.external.subprocess.run")
    def test_returns_none_on_empty(self, mock_run):
        mock_run.return_value = MagicMock(stdout="\n", returncode=0)
        result = query_txt_record("8.8.8.8", "_acme-challenge.example.com")
        assert result is None

    @patch("certbot_hook_dnsmasq.external.subprocess.run")
    def test_returns_none_on_failure(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=9)
        result = query_txt_record("8.8.8.8", "_acme-challenge.example.com")
        assert result is None


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
