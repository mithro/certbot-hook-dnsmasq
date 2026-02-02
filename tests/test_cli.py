"""Tests for certbot_hook_dnsmasq.cli"""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from certbot_hook_dnsmasq import __version__
from certbot_hook_dnsmasq.cli import main, build_parser


class TestBuildParser:
    def test_version_flag(self, capsys):
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--version"])
        assert exc_info.value.code == 0
        assert __version__ in capsys.readouterr().out

    def test_auth_hook_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["auth-hook"])
        assert args.subcommand == "auth-hook"

    def test_flatten_config_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["flatten-config", "/etc/dnsmasq.conf"])
        assert args.subcommand == "flatten-config"
        assert args.config_path == Path("/etc/dnsmasq.conf")

    def test_flatten_config_default_path(self):
        parser = build_parser()
        args = parser.parse_args(["flatten-config"])
        assert args.config_path == Path("/etc/dnsmasq.conf")

    def test_auth_hook_flags(self):
        parser = build_parser()
        args = parser.parse_args([
            "auth-hook",
            "--conf-dir", "/custom/dir",
            "--conf", "/custom/dnsmasq.conf",
            "--service", "dnsmasq-custom",
        ])
        assert args.conf_dir == Path("/custom/dir")
        assert args.conf == Path("/custom/dnsmasq.conf")
        assert args.service == "dnsmasq-custom"


class TestMainFlattenConfig:
    @patch("certbot_hook_dnsmasq.cli.flatten_config")
    def test_prints_flattened_lines(self, mock_flatten, capsys):
        mock_flatten.return_value = ["auth-server=example.com", "server=8.8.8.8"]
        with patch("sys.argv", ["certbot-hook-dnsmasq", "flatten-config", "/test/conf"]):
            result = main()
        assert result == 0
        output = capsys.readouterr().out
        assert "auth-server=example.com\n" in output
        assert "server=8.8.8.8\n" in output


class TestMainAuthHook:
    @patch("certbot_hook_dnsmasq.cli.run_auth_hook")
    def test_reads_certbot_env_vars(self, mock_hook):
        mock_hook.return_value = 0
        env = {
            "CERTBOT_DOMAIN": "example.com",
            "CERTBOT_VALIDATION": "test-token",
        }
        with patch.dict(os.environ, env, clear=False):
            with patch("sys.argv", ["certbot-hook-dnsmasq", "auth-hook"]):
                result = main()
        assert result == 0
        mock_hook.assert_called_once()
        call_kwargs = mock_hook.call_args
        assert call_kwargs[1]["domain"] == "example.com"
        assert call_kwargs[1]["validation"] == "test-token"

    def test_fails_without_certbot_domain(self, capsys):
        env_without = {k: v for k, v in os.environ.items()
                       if k not in ("CERTBOT_DOMAIN", "CERTBOT_VALIDATION")}
        with patch.dict(os.environ, env_without, clear=True):
            with patch("sys.argv", ["certbot-hook-dnsmasq", "auth-hook"]):
                result = main()
        assert result == 1
        assert "CERTBOT_DOMAIN" in capsys.readouterr().err

    def test_fails_without_certbot_validation(self, capsys):
        env_with_domain_only = {k: v for k, v in os.environ.items()
                                if k not in ("CERTBOT_DOMAIN", "CERTBOT_VALIDATION")}
        env_with_domain_only["CERTBOT_DOMAIN"] = "example.com"
        with patch.dict(os.environ, env_with_domain_only, clear=True):
            with patch("sys.argv", ["certbot-hook-dnsmasq", "auth-hook"]):
                result = main()
        assert result == 1
        assert "CERTBOT_VALIDATION" in capsys.readouterr().err

    @patch("certbot_hook_dnsmasq.cli.run_auth_hook")
    def test_cli_flags_override_env(self, mock_hook):
        mock_hook.return_value = 0
        env = {
            "CERTBOT_DOMAIN": "example.com",
            "CERTBOT_VALIDATION": "test-token",
            "DNSMASQ_CONF_DIR": "/env/dir",
        }
        with patch.dict(os.environ, env, clear=False):
            with patch("sys.argv", [
                "certbot-hook-dnsmasq", "auth-hook",
                "--conf-dir", "/cli/dir",
            ]):
                result = main()
        assert result == 0
        call_kwargs = mock_hook.call_args[1]
        assert call_kwargs["conf_dir"] == Path("/cli/dir")

    @patch("certbot_hook_dnsmasq.cli.run_auth_hook")
    def test_env_var_fallback(self, mock_hook):
        mock_hook.return_value = 0
        env = {
            "CERTBOT_DOMAIN": "example.com",
            "CERTBOT_VALIDATION": "test-token",
            "DNSMASQ_CONF_DIR": "/env/dir",
            "DNSMASQ_CONF": "/env/dnsmasq.conf",
            "DNSMASQ_SERVICE": "dnsmasq-env",
        }
        with patch.dict(os.environ, env, clear=False):
            with patch("sys.argv", ["certbot-hook-dnsmasq", "auth-hook"]):
                result = main()
        assert result == 0
        call_kwargs = mock_hook.call_args[1]
        assert call_kwargs["conf_dir"] == Path("/env/dir")
        assert call_kwargs["conf"] == Path("/env/dnsmasq.conf")
        assert call_kwargs["service"] == "dnsmasq-env"
