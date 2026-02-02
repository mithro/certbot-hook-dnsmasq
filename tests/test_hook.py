"""Tests for certbot_hook_dnsmasq.hook"""

from pathlib import Path
from unittest.mock import patch, call

import pytest

from certbot_hook_dnsmasq.hook import write_acme_challenge


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
