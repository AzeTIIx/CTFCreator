"""Tests for tag immutability."""

import pytest

from ctfcreator.publisher.publish import detect_reference_collisions
from ctfcreator.publisher.registry import RegistryClient, check_immutability


class MockRegistry(RegistryClient):
    def __init__(self, digests: dict[str, str]):
        super().__init__("localhost:5000")
        self._digests = digests

    def get_tag_digest(self, repository: str, tag: str) -> str | None:
        return self._digests.get(f"{repository}:{tag}")


def test_reference_collision_detection():
    refs = [
        ("ch-a", "svc1", "localhost:5000/foo:2026.1"),
        ("ch-b", "svc2", "localhost:5000/foo:2026.1"),
    ]
    collisions = detect_reference_collisions(refs)
    assert len(collisions) == 1


def test_no_collision_different_refs():
    refs = [
        ("ch-a", "svc1", "localhost:5000/foo-a:2026.1"),
        ("ch-b", "svc2", "localhost:5000/foo-b:2026.1"),
    ]
    assert detect_reference_collisions(refs) == []


def test_identical_tag_idempotent():
    client = MockRegistry({"web-idor:2026.1": "sha256:same"})
    action, idem, _ = check_immutability(client, "web-idor", "2026.1", "sha256:same")
    assert action == "skip"
    assert idem is True


def test_different_digest_blocked_without_force():
    client = MockRegistry({"web-idor:2026.1": "sha256:remote"})
    action, idem, remote = check_immutability(
        client, "web-idor", "2026.1", "sha256:local", force=False
    )
    assert action == "block"
    assert remote == "sha256:remote"


def test_force_allows_overwrite():
    client = MockRegistry({"web-idor:2026.1": "sha256:remote"})
    action, _, _ = check_immutability(
        client, "web-idor", "2026.1", "sha256:local", force=True
    )
    assert action == "push"
