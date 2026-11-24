"""Shared fixtures: real temporary Git repositories."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

_ENV = {
    **{k: v for k, v in os.environ.items() if not k.startswith("GIT_")},
    "GIT_AUTHOR_NAME": "Tester",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "Tester",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}


class Repo:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.git("init", "-q", "-b", "main")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.autocrlf", "false")

    def git(self, *args: str, input_: bytes | None = None) -> str:
        proc = subprocess.run(
            ["git", "-C", str(self.path), *args],
            capture_output=True,
            check=True,
            env=_ENV,
            input=input_,
        )
        return proc.stdout.decode()

    def write(self, rel: str, data: str | bytes) -> Path:
        target = self.path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data.encode() if isinstance(data, str) else data)
        return target

    def commit(self, message: str = "c") -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD").strip()

    def remove(self, rel: str) -> None:
        self.git("rm", "-q", "-f", rel)

    def dangling_blob(self, content: str) -> str:
        """Write an unreferenced blob straight into the object database."""
        return self.git("hash-object", "-w", "--stdin", input_=content.encode()).strip()


@pytest.fixture
def make_repo(tmp_path: Path) -> Callable[[str], Repo]:
    counter = 0

    def _make(name: str = "repo") -> Repo:
        nonlocal counter
        counter += 1
        root = tmp_path / f"{name}{counter}"
        root.mkdir()
        return Repo(root)

    return _make


@pytest.fixture
def repo(make_repo: Callable[[str], Repo]) -> Repo:
    return make_repo()
