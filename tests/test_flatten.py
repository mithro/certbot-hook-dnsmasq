"""Tests for certbot_hook_dnsmasq.flatten"""

from pathlib import Path

import pytest

from certbot_hook_dnsmasq.flatten import (
    flatten_config,
    parse_config,
    parse_defaults,
    should_exclude,
)


class TestShouldExclude:
    def test_matches_suffix(self):
        assert should_exclude("foo.dpkg-dist", [".dpkg-dist"]) is True
        assert should_exclude("foo.dpkg-old", [".dpkg-old"]) is True

    def test_no_match(self):
        assert should_exclude("foo.conf", [".dpkg-dist"]) is False
        assert should_exclude("foo", [".dpkg-dist"]) is False

    def test_multiple_patterns(self):
        patterns = [".dpkg-dist", ".dpkg-old", ".dpkg-new"]
        assert should_exclude("foo.dpkg-dist", patterns) is True
        assert should_exclude("foo.dpkg-old", patterns) is True
        assert should_exclude("foo.dpkg-new", patterns) is True
        assert should_exclude("foo.conf", patterns) is False

    def test_empty_patterns(self):
        assert should_exclude("foo.conf", []) is False


class TestParseConfig:
    def test_simple_config(self, tmp_path):
        config = tmp_path / "dnsmasq.conf"
        config.write_text("auth-server=example.com\nlisten-address=1.2.3.4\n")

        lines = parse_config(config, [])
        assert lines == ["auth-server=example.com", "listen-address=1.2.3.4"]

    def test_skips_comments(self, tmp_path):
        config = tmp_path / "dnsmasq.conf"
        config.write_text("# comment\nauth-server=example.com\n  # indented comment\n")

        lines = parse_config(config, [])
        assert lines == ["auth-server=example.com"]

    def test_skips_empty_lines(self, tmp_path):
        config = tmp_path / "dnsmasq.conf"
        config.write_text("auth-server=example.com\n\n\nlisten-address=1.2.3.4\n")

        lines = parse_config(config, [])
        assert lines == ["auth-server=example.com", "listen-address=1.2.3.4"]

    def test_follows_conf_file(self, tmp_path):
        main_conf = tmp_path / "dnsmasq.conf"
        include_conf = tmp_path / "extra.conf"

        include_conf.write_text("listen-address=5.6.7.8\n")
        main_conf.write_text(f"auth-server=example.com\nconf-file={include_conf}\n")

        lines = parse_config(main_conf, [])
        assert lines == ["auth-server=example.com", "listen-address=5.6.7.8"]

    def test_follows_conf_dir(self, tmp_path):
        main_conf = tmp_path / "dnsmasq.conf"
        conf_dir = tmp_path / "dnsmasq.d"
        conf_dir.mkdir()

        (conf_dir / "01-first.conf").write_text("server=8.8.8.8\n")
        (conf_dir / "02-second.conf").write_text("server=8.8.4.4\n")
        main_conf.write_text(f"conf-dir={conf_dir}\n")

        lines = parse_config(main_conf, [])
        assert lines == ["server=8.8.8.8", "server=8.8.4.4"]

    def test_conf_dir_excludes_patterns(self, tmp_path):
        main_conf = tmp_path / "dnsmasq.conf"
        conf_dir = tmp_path / "dnsmasq.d"
        conf_dir.mkdir()

        (conf_dir / "good.conf").write_text("server=8.8.8.8\n")
        (conf_dir / "bad.conf.dpkg-dist").write_text("server=BAD\n")
        main_conf.write_text(f"conf-dir={conf_dir}\n")

        lines = parse_config(main_conf, [".dpkg-dist"])
        assert lines == ["server=8.8.8.8"]
        assert "server=BAD" not in lines

    def test_conf_dir_with_local_exclude(self, tmp_path):
        main_conf = tmp_path / "dnsmasq.conf"
        conf_dir = tmp_path / "dnsmasq.d"
        conf_dir.mkdir()

        (conf_dir / "good.conf").write_text("server=8.8.8.8\n")
        (conf_dir / "backup.bak").write_text("server=BAD\n")
        main_conf.write_text(f"conf-dir={conf_dir},.bak\n")

        lines = parse_config(main_conf, [])
        assert lines == ["server=8.8.8.8"]

    def test_conf_dir_with_include_filter(self, tmp_path):
        main_conf = tmp_path / "dnsmasq.conf"
        conf_dir = tmp_path / "dnsmasq.d"
        conf_dir.mkdir()

        (conf_dir / "good.conf").write_text("server=8.8.8.8\n")
        (conf_dir / "other.txt").write_text("server=BAD\n")
        main_conf.write_text(f"conf-dir={conf_dir},*.conf\n")

        lines = parse_config(main_conf, [])
        assert lines == ["server=8.8.8.8"]

    def test_prevents_circular_includes(self, tmp_path):
        conf_a = tmp_path / "a.conf"
        conf_b = tmp_path / "b.conf"

        conf_a.write_text(f"server=A\nconf-file={conf_b}\n")
        conf_b.write_text(f"server=B\nconf-file={conf_a}\n")

        lines = parse_config(conf_a, [])
        assert lines == ["server=A", "server=B"]

    def test_nonexistent_file_returns_empty(self, tmp_path):
        nonexistent = tmp_path / "nope.conf"
        lines = parse_config(nonexistent, [])
        assert lines == []

    def test_nonexistent_conf_dir_skipped(self, tmp_path):
        main_conf = tmp_path / "dnsmasq.conf"
        main_conf.write_text("auth-server=example.com\nconf-dir=/nonexistent\n")

        lines = parse_config(main_conf, [])
        assert lines == ["auth-server=example.com"]


class TestParseDefaults:
    def test_parses_config_dir(self, tmp_path):
        defaults = tmp_path / "dnsmasq"
        defaults.write_text("CONFIG_DIR=/etc/dnsmasq.d,.dpkg-dist,.dpkg-old,.dpkg-new\n")

        conf_dir, exclude = parse_defaults(defaults)
        assert str(conf_dir) == '/etc/dnsmasq.d'
        assert exclude == ['.dpkg-dist', '.dpkg-old', '.dpkg-new']

    def test_skips_comments(self, tmp_path):
        defaults = tmp_path / "dnsmasq"
        defaults.write_text("# CONFIG_DIR=/commented/out\nCONFIG_DIR=/etc/dnsmasq.d\n")

        conf_dir, exclude = parse_defaults(defaults)
        assert str(conf_dir) == '/etc/dnsmasq.d'
        assert exclude == []

    def test_no_config_dir(self, tmp_path):
        defaults = tmp_path / "dnsmasq"
        defaults.write_text("# just a comment\n")

        conf_dir, exclude = parse_defaults(defaults)
        assert conf_dir is None
        assert exclude == []

    def test_nonexistent_file(self, tmp_path):
        nonexistent = tmp_path / "nope"

        conf_dir, exclude = parse_defaults(nonexistent)
        assert conf_dir is None
        assert exclude == []

    def test_config_dir_without_excludes(self, tmp_path):
        defaults = tmp_path / "dnsmasq"
        defaults.write_text("CONFIG_DIR=/etc/dnsmasq.d\n")

        conf_dir, exclude = parse_defaults(defaults)
        assert str(conf_dir) == '/etc/dnsmasq.d'
        assert exclude == []


class TestFlattenConfig:
    def test_flattens_with_conf_dir(self, tmp_path):
        """flatten_config follows conf-dir includes."""
        conf_dir = tmp_path / "dnsmasq.d"
        conf_dir.mkdir()
        (conf_dir / "extra.conf").write_text("server=8.8.8.8\n")

        main_conf = tmp_path / "dnsmasq.conf"
        main_conf.write_text(f"auth-server=example.com\nconf-dir={conf_dir}\n")

        # No defaults file — pass nonexistent path
        lines = flatten_config(main_conf, defaults_path=tmp_path / "no-defaults")
        assert lines == ["auth-server=example.com", "server=8.8.8.8"]

    def test_flattens_with_defaults_config_dir(self, tmp_path):
        """flatten_config reads CONFIG_DIR from defaults file."""
        conf_dir = tmp_path / "dnsmasq.d"
        conf_dir.mkdir()
        (conf_dir / "extra.conf").write_text("server=8.8.8.8\n")

        defaults = tmp_path / "defaults"
        defaults.write_text(f"CONFIG_DIR={conf_dir}\n")

        main_conf = tmp_path / "dnsmasq.conf"
        main_conf.write_text("auth-server=example.com\n")

        lines = flatten_config(main_conf, defaults_path=defaults)
        assert lines == ["auth-server=example.com", "server=8.8.8.8"]
