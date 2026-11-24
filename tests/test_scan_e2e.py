from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from gitvigil.cli import app
from gitvigil.models import Source
from gitvigil.scanner.scan import ScanOptions, scan_repository
from secret_samples import SAMPLES

runner = CliRunner()
GH_TOKEN = SAMPLES["github-pat-classic"]
AWS_KEY = SAMPLES["aws-access-key-id"]


def rule_ids(result) -> set[str]:
    return {f.rule_id for f in result.findings}


def test_secret_committed_then_deleted_is_still_found(repo):
    repo.write("deploy.sh", f"export TOKEN={GH_TOKEN}\n")
    first = repo.commit("add token")
    repo.write("deploy.sh", "export TOKEN=$TOKEN\n")
    repo.commit("remove token")
    repo.remove("deploy.sh")
    repo.commit("delete file")
    result = scan_repository(repo.path)
    [f] = [f for f in result.findings if f.rule_id == "github-pat-classic"]
    assert f.commit == first  # attributed to the commit that introduced it
    assert f.path == "deploy.sh" and f.line == 1
    assert f.source is Source.HISTORY
    assert GH_TOKEN not in result.model_dump_json()


def test_dangling_secret_found(repo):
    repo.write("a.txt", "clean")
    repo.commit()
    repo.dangling_blob(f"leaked = {AWS_KEY}\n")
    result = scan_repository(repo.path)
    [f] = result.findings
    assert (f.rule_id, f.source, f.commit) == ("aws-access-key-id", Source.DANGLING, None)
    assert not scan_repository(repo.path, ScanOptions(include_dangling=False)).findings


def test_binary_and_oversize_files_skipped(repo):
    repo.write("blob.bin", b"\x00\x01" + GH_TOKEN.encode())
    repo.write("huge.txt", GH_TOKEN + "\n" + "x" * (3 * 1024 * 1024))
    repo.write("ok.txt", "nothing here\n")
    repo.commit()
    result = scan_repository(repo.path)
    assert result.findings == []
    assert result.stats.skipped_binary == 1
    assert result.stats.skipped_oversize == 1
    assert [w.code for w in result.warnings] == ["blob-too-large"]


def test_gitvigilignore_paths_and_fingerprints(repo):
    repo.write("src/app.py", f"t = '{GH_TOKEN}'\n")
    repo.write("vendor/lib.py", f"t = '{GH_TOKEN}'\n")
    repo.write("docs/notes.md", f"{AWS_KEY}\n")
    repo.commit()
    assert {f.path for f in scan_repository(repo.path).findings} == {
        "src/app.py", "vendor/lib.py", "docs/notes.md",
    }  # fmt: skip

    repo.write(".gitvigilignore", "vendor/\n*.md\n")
    repo.commit()
    result = scan_repository(repo.path)
    assert {f.path for f in result.findings} == {"src/app.py"}
    assert result.stats.skipped_ignored >= 2

    [finding] = result.findings
    repo.write(".gitvigilignore", f"vendor/\n*.md\nsha256:{finding.fingerprint}\n")
    repo.commit()
    result = scan_repository(repo.path)
    assert result.findings == []
    assert result.stats.suppressed_findings >= 1


def test_ignore_file_symlink_not_followed(repo, tmp_path):
    repo.write("a.py", f"t = '{GH_TOKEN}'\n")
    repo.commit()
    target = tmp_path / "evil-ignore"
    target.write_text("*\n")
    link = repo.path / ".gitvigilignore"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks unavailable")
    assert scan_repository(repo.path).findings  # the symlinked ignore file is not honoured


def test_iac_and_secrets_together_with_history(repo):
    repo.write("Dockerfile", "FROM node:latest\nENV API_TOKEN=" + "a1B2c3D4e5F6g7H8\n")
    repo.commit()
    repo.write("Dockerfile", "FROM node:20@sha256:" + "a" * 64 + "\nUSER node\n")
    repo.commit()
    result = scan_repository(repo.path)
    assert {"GV-DKR-001", "GV-DKR-003", "GV-DKR-004"} <= rule_ids(result)
    assert all(f.cwe and f.remediation for f in result.findings)
    assert result.findings == sorted(
        result.findings, key=lambda f: (-f.severity.rank, f.path, f.line, f.rule_id)
    )


def test_hostile_filenames_are_sanitised_in_table_output(repo):
    repo.write("normal.py", f"t = '{GH_TOKEN}'\n")
    repo.commit()
    out = runner.invoke(app, ["scan", str(repo.path)])
    assert out.exit_code == 1
    assert GH_TOKEN not in out.output
    assert "\x1b" not in out.output


# ------------------------------------------------------------------- CLI


def test_cli_json_redacts_by_default(repo):
    repo.write("a.py", f"t = '{GH_TOKEN}'\n")
    repo.commit()
    res = runner.invoke(app, ["scan", str(repo.path), "--format", "json"])
    assert res.exit_code == 1
    data = json.loads(res.stdout)
    assert GH_TOKEN not in res.stdout
    [f] = data["findings"]
    assert f["redacted_match"] == GH_TOKEN[:4] + "****" + GH_TOKEN[-4:]
    assert "secret" not in f


def test_cli_reveal_secrets_is_opt_in(repo):
    repo.write("a.py", f"t = '{GH_TOKEN}'\n")
    repo.commit()
    res = runner.invoke(app, ["scan", str(repo.path), "--format", "json", "--reveal-secrets"])
    assert json.loads(res.stdout)["findings"][0]["secret"] == GH_TOKEN


def test_cli_exit_codes_and_fail_on(repo):
    repo.write("ok.txt", "clean\n")
    repo.commit()
    assert runner.invoke(app, ["scan", str(repo.path)]).exit_code == 0
    repo.write("Dockerfile", "FROM alpine:3.20\nUSER root\n")  # HIGH
    repo.commit()
    assert runner.invoke(app, ["scan", str(repo.path), "--fail-on", "HIGH"]).exit_code == 1
    assert runner.invoke(app, ["scan", str(repo.path), "--fail-on", "CRITICAL"]).exit_code == 0


@pytest.mark.parametrize(
    "extra",
    [
        ["--rev", "--upload-pack=evil"],
        ["--rev", "-c core.sshCommand=touch PWNED"],
        ["--rev", "HEAD:secret"],
    ],
)
def test_cli_rejects_flag_injection_in_rev(repo, extra):
    repo.write("a.txt", "a")
    repo.commit()
    res = runner.invoke(app, ["scan", str(repo.path), *extra])
    assert res.exit_code == 2
    assert not (repo.path / "PWNED").exists()


@pytest.mark.parametrize("payload", ["--upload-pack=evil", "-c core.sshCommand=x", "-rf"])
def test_cli_rejects_flag_injection_in_path(payload):
    res = runner.invoke(app, ["scan", "--", payload])
    assert res.exit_code == 2
    assert "must not start with '-'" in res.output or "git flag injection" in res.output


def test_cli_non_repo_path_errors_cleanly(tmp_path):
    res = runner.invoke(app, ["scan", str(tmp_path)])
    assert res.exit_code == 2
    assert "Traceback" not in res.output


def test_cli_rules_listing():
    res = runner.invoke(app, ["rules"])
    assert res.exit_code == 0
    assert "secret rules" in res.output and "IaC rules" in res.output
