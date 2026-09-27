"""Tests unitaires locaux — sans VPS, sans succès simulé d'infrastructure."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "checks"))

from common import (  # noqa: E402
    redact_text,
    require_for_deploy,
    validate_cidr,
    validate_image_ref,
    validate_port,
)
import check_plugins  # noqa: E402


class TestValidation(unittest.TestCase):
    def test_reject_latest(self) -> None:
        self.assertFalse(validate_image_ref("ctfd/ctfd:latest"))
        self.assertTrue(validate_image_ref("ctfd/ctfd:3.8.6"))
        self.assertTrue(
            validate_image_ref(
                "ctfd/ctfd@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )
        )

    def test_port_and_cidr(self) -> None:
        self.assertTrue(validate_port("22"))
        self.assertFalse(validate_port("70000"))
        self.assertTrue(validate_cidr("203.0.113.10/32"))
        self.assertFalse(validate_cidr("not-a-cidr"))

    def test_redact_secrets(self) -> None:
        text = "DB_PASSWORD=supersecretvalue REDIS_URL=redis://:abc@cache:6379"
        out = redact_text(text, extra_secrets=["supersecretvalue", "abc"])
        self.assertNotIn("supersecretvalue", out)
        self.assertIn("***REDACTED***", out)

    def test_require_for_deploy_without_dotenv(self) -> None:
        env = {
            "VPS_PROVIDER": "OVH",
            "TARGET_HOST": "ctfd.cours.example.invalid",
            "ADMIN_SSH_USER": "coursadmin",
            "CTFD_FQDN": "ctfd.cours.example.invalid",
            "SSH_PORT": "22",
            "TARGET_DISTRO": "debian",
            "TARGET_DISTRO_VERSION": "12",
        }
        missing = require_for_deploy(env)
        self.assertTrue(missing)
        self.assertTrue(
            any(
                k in missing
                for k in ("TARGET_HOST", "CTFD_FQDN", "VPS_PROVIDER")
            )
        )
        self.assertNotIn("ADMIN_CIDR", missing)


class TestPluginsCheck(unittest.TestCase):
    def test_degraded_passes(self) -> None:
        from common import build_context

        ctx = build_context()
        ctx.env["DEPLOY_MODE"] = "degraded"
        ctx.env["PLUGIN_SELECTION"] = "none"
        result = check_plugins.run_check(ctx)
        self.assertTrue(result["passed"])

    def test_containers_requires_selection(self) -> None:
        from common import build_context

        ctx = build_context()
        ctx.env["DEPLOY_MODE"] = "containers"
        ctx.env["PLUGIN_SELECTION"] = "none"
        result = check_plugins.run_check(ctx)
        self.assertFalse(result["passed"])

    def test_challenge_containers_accepted(self) -> None:
        from common import build_context

        ctx = build_context()
        ctx.env["DEPLOY_MODE"] = "containers"
        ctx.env["PLUGIN_SELECTION"] = "challenge_containers"
        result = check_plugins.run_check(ctx)
        self.assertTrue(result["passed"], result)


class TestPubkey(unittest.TestCase):
    def test_normalize_pubkey(self) -> None:
        from harden_ssh import normalize_pubkey, pubkey_core

        line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeExampleKeyMaterial00000000000000000000000 me@host"
        self.assertTrue(normalize_pubkey(line).startswith("ssh-ed25519 "))
        self.assertEqual(
            pubkey_core(line),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeExampleKeyMaterial00000000000000000000000",
        )
        with self.assertRaises(RuntimeError):
            normalize_pubkey("not-a-key")

    def test_resolve_requires_pubkey(self) -> None:
        from harden_ssh import resolve_pubkey

        with self.assertRaises(RuntimeError):
            resolve_pubkey(None, None, {})


class TestCliHelp(unittest.TestCase):
    def test_main_help(self) -> None:
        from main import build_parser

        parser = build_parser()
        args = parser.parse_args(["--dry-run", "preflight"])
        self.assertEqual(args.command, "preflight")
        self.assertTrue(args.dry_run)

    def test_harden_ssh_pubkey_args(self) -> None:
        from main import build_parser

        parser = build_parser()
        args = parser.parse_args(
            ["harden-ssh", "--pubkey-file", "/tmp/id.pub", "--identity", "/tmp/id"]
        )
        self.assertEqual(args.pubkey_file, "/tmp/id.pub")
        self.assertEqual(args.identity, "/tmp/id")


if __name__ == "__main__":
    unittest.main()
