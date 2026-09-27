"""Security-related tests."""

import subprocess

import pytest

from ctfcreator.publisher.logging_utils import redact
from ctfcreator.publisher.validation import validate_shell_safe, ValidationError


def test_no_shell_true_in_subprocess():
    """Verify subprocess calls never use shell=True in docker_cli."""
    import inspect
    import ctfcreator.publisher.docker_cli as dc
    source = inspect.getsource(dc.SubprocessRunner.run)
    assert "shell=True" not in source
    assert "shell=False" in source


def test_shell_separator_rejected():
    with pytest.raises(ValidationError):
        validate_shell_safe("foo|bar", "test")


def test_logs_redacted():
    text = "password=supersecret123 token=abc123"
    redacted = redact(text)
    assert "supersecret123" not in redacted
    assert "[REDACTED]" in redacted


def test_private_key_redacted():
    key = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
    redacted = redact(key)
    assert "BEGIN RSA PRIVATE KEY" not in redacted


def test_flag_redacted():
    redacted = redact("flag{real_secret_value_here}")
    assert "real_secret" not in redacted
