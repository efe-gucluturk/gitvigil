from __future__ import annotations

from pathlib import Path

import pytest

from gitvigil.models import Source
from gitvigil.scanner.git_walker import (
    GitError,
    GitSecurityError,
    GitWalker,
    sanitize_tree_path,
    validate_ref,
    validate_repo_path,
    validate_sha,
)
from gitvigil.util import sanitize

INJECTION_PAYLOADS = [
    "--upload-pack=evil",
    "--upload-pack=touch PWNED",
    "-c core.sshCommand=touch PWNED",
    "-ccore.sshCommand=touch PWNED",
    "--output=PWNED",
    "--exec-path=/tmp/x",
    "-C/tmp",
    "--git-dir=/tmp/x",
    "--help",
    "-",
    "--",
]


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
def test_flag_injection_rejected_as_ref(payload: str, tmp_path: Path, repo):
    repo.write("a.txt", "x")
    repo.commit()
    with pytest.raises(GitSecurityError):
        validate_ref(payload)
    with pytest.raises(GitSecurityError):
        GitWalker(repo.path, rev=payload)
    assert not (Path.cwd() / "PWNED").exists()
    assert not (repo.path / "PWNED").exists()


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
def test_flag_injection_rejected_as_repo_path(payload: str):
    with pytest.raises(GitSecurityError):
        validate_repo_path(payload)
    with pytest.raises(GitSecurityError):
        GitWalker(payload)
    assert not (Path.cwd() / "PWNED").exists()


@pytest.mark.parametrize(
    "ref",
    ["", "a b", "a\nb", "a;rm -rf /", "$(id)", "`id`", "HEAD:secret.txt", "a|b", "x\0y", "feat=1"],
)
def test_weird_refs_rejected(ref: str):
    with pytest.raises(GitSecurityError):
        validate_ref(ref)


@pytest.mark.parametrize("ref", ["main", "feature/x-1", "v1.2.3", "HEAD~2", "HEAD^", "origin/main"])
def test_normal_refs_accepted(ref: str):
    assert validate_ref(ref) == ref


@pytest.mark.parametrize("sha", ["", "abc", "g" * 40, "A" * 40, "a" * 40 + "\n--help", "a" * 41])
def test_invalid_shas_rejected(sha: str):
    with pytest.raises(GitSecurityError):
        validate_sha(sha)


def test_repo_path_validation(tmp_path: Path, repo):
    assert validate_repo_path(repo.path) == repo.path.resolve()
    with pytest.raises(GitSecurityError):
        validate_repo_path(tmp_path / "does-not-exist")
    with pytest.raises(GitSecurityError):
        validate_repo_path(tmp_path)  # exists but is not a repo
    with pytest.raises(GitSecurityError):
        validate_repo_path("a\0b")
    with pytest.raises(GitSecurityError):
        validate_repo_path("")
    repo.write("sub/f.txt", "x")
    repo.commit()
    with pytest.raises(GitSecurityError):  # subdirectory of a repo: scope would be ambiguous
        validate_repo_path(repo.path / "sub")
    with pytest.raises(GitSecurityError):  # traversal that lands outside any repo
        validate_repo_path(repo.path / ".." / "..")
    f = repo.path / "a.txt"
    f.write_text("x")
    with pytest.raises(GitSecurityError):
        validate_repo_path(f)


def test_traversal_that_resolves_to_repo_is_accepted(repo):
    repo.write("sub/x", "x")
    repo.commit()
    assert validate_repo_path(repo.path / "sub" / "..") == repo.path.resolve()


def test_bare_repository_supported(repo, tmp_path: Path):
    repo.write("k.txt", "hello")
    repo.commit()
    bare = tmp_path / "bare.git"
    repo.git("clone", "-q", "--bare", str(repo.path), str(bare))
    assert validate_repo_path(bare) == bare.resolve()
    assert [b.path for b in GitWalker(bare, include_dangling=False).blobs()] == ["k.txt"]


@pytest.mark.parametrize(
    "path,ok",
    [
        ("a/b.txt", True),
        ("../etc/passwd", False),
        ("a/../../b", False),
        ("/abs", False),
        ("C:/x", False),
        ("\\\\server\\share", False),
        (".git/config", False),
        ("a/.GIT/hooks", False),
        ("a//b", False),
        ("a\0b", False),
        ("", False),
    ],
)
def test_tree_path_sanitization(path: str, ok: bool):
    assert (sanitize_tree_path(path) is not None) is ok


def test_sanitize_strips_terminal_escapes():
    evil = "\x1b[2J\x1b]0;pwned\x07 file\u202e.txt"
    clean = sanitize(evil)
    assert "\x1b" not in clean and "\x07" not in clean and "\u202e" not in clean


# --------------------------------------------------------------- history walking


def test_walks_deleted_files_and_all_branches(repo):
    repo.write("config.env", "SECRET=1\n")
    first = repo.commit("add")
    repo.remove("config.env")
    repo.commit("remove")
    repo.git("checkout", "-q", "-b", "side")
    repo.write("side.txt", "only on side\n")
    repo.commit("side")
    repo.git("checkout", "-q", "main")
    walker = GitWalker(repo.path, include_dangling=False)
    blobs = {b.path: b for b in walker.blobs()}
    assert set(blobs) == {"config.env", "side.txt"}
    assert blobs["config.env"].commit == first
    assert blobs["config.env"].source is Source.HISTORY
    assert walker.stats.commits == 3


def test_specific_rev_limits_scope(repo):
    repo.write("a.txt", "a")
    repo.commit()
    repo.git("checkout", "-q", "-b", "other")
    repo.write("b.txt", "b")
    repo.commit()
    repo.git("checkout", "-q", "main")
    assert [b.path for b in GitWalker(repo.path, rev="main", include_dangling=False).blobs()] == [
        "a.txt"
    ]


def test_unknown_rev_raises_git_error(repo):
    repo.write("a.txt", "a")
    repo.commit()
    with pytest.raises(GitError):
        list(GitWalker(repo.path, rev="no-such-branch").blobs())


def test_empty_repository_is_fine(repo):
    assert list(GitWalker(repo.path).blobs()) == []


def test_dangling_blob_found_and_flagged(repo):
    repo.write("a.txt", "a")
    repo.commit()
    sha = repo.dangling_blob("orphaned content\n")
    walker = GitWalker(repo.path)
    dangling = [b for b in walker.blobs() if b.source is Source.DANGLING]
    assert [b.sha for b in dangling] == [sha]
    assert dangling[0].commit is None
    assert walker.stats.blobs_dangling == 1
    assert not [b for b in GitWalker(repo.path, include_dangling=False).blobs() if b.sha == sha]


def test_blob_from_dropped_commit_is_dangling(repo):
    repo.write("a.txt", "a")
    repo.commit()
    repo.write("leak.txt", "leaked in a commit that was later erased\n")
    repo.commit("oops")
    repo.git("reset", "-q", "--hard", "HEAD~1")
    repo.git("reflog", "expire", "--expire=now", "--all")
    contents = [b.content for b in GitWalker(repo.path).blobs() if b.source is Source.DANGLING]
    assert b"leaked in a commit that was later erased\n" in contents


def test_binary_blobs_skipped(repo):
    repo.write("img.bin", b"\x89PNG\r\n\x1a\n\x00\x00\x00data")
    repo.write("ok.txt", "text")
    repo.commit()
    walker = GitWalker(repo.path, include_dangling=False)
    assert [b.path for b in walker.blobs()] == ["ok.txt"]
    assert walker.stats.skipped_binary == 1


def test_oversize_blob_skipped_with_structured_warning(repo):
    repo.write("big.txt", "A" * (3 * 1024 * 1024))
    repo.write("ok.txt", "small")
    sha = repo.commit()
    walker = GitWalker(repo.path, include_dangling=False)
    assert [b.path for b in walker.blobs()] == ["ok.txt"]
    [w] = walker.warnings
    assert (w.code, w.path) == ("blob-too-large", "big.txt")
    assert w.blob_sha and "3145728" in w.message
    assert walker.stats.skipped_oversize == 1
    assert sha  # commit happened


def test_blob_exactly_at_limit_is_scanned(repo):
    repo.write("edge.txt", "B" * (2 * 1024 * 1024))
    repo.commit()
    assert [b.path for b in GitWalker(repo.path, include_dangling=False).blobs()] == ["edge.txt"]


def test_symlinks_are_not_followed(repo, tmp_path: Path):
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("TOP SECRET OUTSIDE THE REPO")
    repo.write("real.txt", "real")
    # Create a symlink *entry* directly in the index (works without OS symlink privileges).
    sha = repo.git("hash-object", "-w", "--stdin", input_=str(outside).encode()).strip()
    repo.git("update-index", "--add", "--cacheinfo", f"120000,{sha},link.txt")
    repo.commit()
    contents = b"".join(b.content for b in GitWalker(repo.path, include_dangling=False).blobs())
    assert b"TOP SECRET" not in contents
    assert str(outside).encode() not in contents


def test_path_filter_skips_reading(repo):
    repo.write("vendor/x.txt", "v")
    repo.write("keep.txt", "k")
    repo.commit()
    walker = GitWalker(
        repo.path, include_dangling=False, path_filter=lambda p: p.startswith("vendor/")
    )
    assert [b.path for b in walker.blobs()] == ["keep.txt"]
    assert walker.stats.skipped_ignored == 1


def test_hostile_repo_config_is_not_executed(repo, tmp_path: Path):
    marker = tmp_path / "executed.txt"
    repo.write("a.txt", "a")
    repo.commit()
    repo.git("config", "core.fsmonitor", f"touch {marker}")
    repo.git("config", "core.pager", f"touch {marker}")
    repo.git("config", "core.sshCommand", f"touch {marker}")
    list(GitWalker(repo.path).blobs())
    assert not marker.exists()
