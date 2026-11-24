from __future__ import annotations

import time
from pathlib import Path

import pytest
import yaml

from gitvigil.engine.common import fingerprint, redact, shannon_entropy
from gitvigil.engine.ignore import IgnoreRules
from gitvigil.engine.regex_safety import UnsafeRegexError, compile_safe
from gitvigil.engine.secrets import RuleLoadError, SecretEngine, load_secret_rules
from gitvigil.models import Source
from secret_samples import SAMPLES, r

RULES = load_secret_rules()


def scan(text: str, path: str = "src/app.py", keep: bool = False):
    engine = SecretEngine(RULES, keep_secret=keep)
    return engine.scan_text(
        text, path=path, blob_sha="a" * 40, commit="b" * 40, source=Source.HISTORY
    )


def test_at_least_forty_rules_with_metadata():
    assert len(RULES) >= 40
    assert all(rule.cwe.startswith("CWE-") and rule.remediation for rule in RULES)


def test_every_rule_has_a_sample():
    assert {r_.id for r_ in RULES} == set(SAMPLES)


@pytest.mark.parametrize("rule_id", sorted(SAMPLES))
def test_rule_detects_its_sample(rule_id: str):
    findings = scan(
        f"value = {SAMPLES[rule_id]}\n"
        if rule_id.startswith("gcp-service")
        else SAMPLES[rule_id] + "\n"
    )
    assert rule_id in {f.rule_id for f in findings}, [f.rule_id for f in findings]


@pytest.mark.parametrize("rule_id", sorted(SAMPLES))
def test_findings_never_contain_raw_secret(rule_id: str):
    sample = SAMPLES[rule_id]
    for f in scan(sample + "\n"):
        dumped = f.model_dump_json()
        assert f.secret is None
        # Longest alphanumeric run of the sample must not appear in any output field.
        core = max(sample.replace("-", " ").replace("_", " ").replace("/", " ").split(), key=len)
        if len(core) >= 20:
            assert core not in dumped


def test_redaction_format():
    token = "gh" + "p_" + "a" * 32 + "9x2a"
    assert redact(token) == "ghp_****9x2a"
    assert redact("short") == "****"
    assert redact(token, "full") == "****"
    assert redact("AK" + "IA" + "A" * 12 + "WXYZ") == "AKIA****WXYZ"


def test_reveal_only_when_requested():
    token = SAMPLES["github-pat-classic"]
    [hidden] = scan(token)
    [shown] = scan(token, keep=True)
    assert hidden.secret is None
    assert shown.secret == token
    assert token not in repr(shown)  # repr=False on the field


def test_aws_documentation_example_is_suppressed():
    assert scan("AK" + "IAIOSFODNN7EXAMPLE\n") == []


@pytest.mark.parametrize(
    "line",
    [
        'password = "changeme-please-now"',
        'api_key = "YOUR_API_KEY_GOES_HERE"',
        'secret = "${SECRET_FROM_ENV_VARIABLE}"',
        'token = "xxxxxxxxxxxxxxxxxxxxxxxx"',
        'client_secret = "aaaaaaaaaaaaaaaaaaaa"',
        'password = "this_is_a_dummy_password_1"',
    ],
)
def test_placeholders_and_low_entropy_are_suppressed(line: str):
    assert scan(line + "\n") == []


def test_database_uri_placeholder_suppressed_real_detected():
    assert scan("postgres://user:password@localhost/db\n") == []
    assert scan("postgres://user:${DB_PASSWORD}@localhost/db\n") == []
    assert scan("postgres://user:" + r(20) + "@localhost/db\n")


def test_inline_ignore_marker():
    assert scan(SAMPLES["github-pat-classic"] + "  # gitvigil:ignore\n") == []


def test_entropy_values():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") == pytest.approx(2.0)


def test_line_numbers_and_stable_fingerprint():
    text = "x = 1\n\n" + SAMPLES["github-pat-classic"] + "\n"
    [f] = scan(text)
    assert f.line == 3
    assert f.fingerprint == fingerprint(
        "github-pat-classic", "src/app.py", SAMPLES["github-pat-classic"]
    )
    [g] = scan(text, path="other.py")
    assert g.fingerprint != f.fingerprint


def test_fingerprint_allowlist_and_path_globs():
    [f] = scan(SAMPLES["github-pat-classic"])
    rules, warnings = IgnoreRules.parse(
        "# comment\nvendor/\n/docs/**/*.md\n*.min.js\n!negation-unsupported\n"
        f"sha256:{f.fingerprint}\n"
    )
    assert len(warnings) == 1  # negation warns, never crashes
    assert rules.is_fingerprint_allowed(f.fingerprint)
    assert rules.is_path_ignored("vendor/a/b.py")
    assert rules.is_path_ignored("pkg/vendor/x.py")
    assert rules.is_path_ignored("docs/a/b/c.md")
    assert not rules.is_path_ignored("src/docs/a.md")  # anchored
    assert rules.is_path_ignored("web/app.min.js")
    assert not rules.is_path_ignored("web/app.js")
    assert not rules.is_path_ignored("vendor")  # dir-only pattern doesn't match a file


# ------------------------------------------------------------ adversarial: rules & ReDoS


@pytest.mark.parametrize(
    "pattern",
    [
        "(a+)+$",
        "(a*)*b",
        "(a|aa)+",
        "a+",
        "a*",
        "a{1,}",
        "(.*a){5}",
        "(a{1,10}){1,10}",
        "(a)\\1",
        "x{1,99999}",
        "(",
        "",
        "a" * 1001,
    ],
)
def test_unsafe_or_invalid_regexes_rejected(pattern: str):
    with pytest.raises(UnsafeRegexError):
        compile_safe(pattern)


def test_safe_regex_accepted():
    assert compile_safe(r"\bghp_[A-Za-z0-9]{36}\b").search("ghp_" + "a" * 36)


def _write_rules(tmp_path: Path, rules: list[dict]) -> Path:
    p = tmp_path / "rules.yaml"
    p.write_text(yaml.safe_dump({"version": 1, "rules": rules}), encoding="utf-8")
    return p


GOOD = {
    "id": "my-rule",
    "description": "d",
    "severity": "HIGH",
    "keywords": ["k"],
    "regex": "k[0-9]{4}",
}


def test_valid_custom_rule_file_loads(tmp_path: Path):
    assert load_secret_rules(_write_rules(tmp_path, [GOOD]))[0].id == "my-rule"


@pytest.mark.parametrize(
    "mutation",
    [
        {"regex": "(a+)+$"},
        {"regex": "a*"},
        {"regex": "(["},
        {"severity": "SEVERE"},
        {"keywords": []},
        {"id": "Bad ID!"},
        {"cwe": "798"},
        {"unexpected": "field"},
        {"secret_group": 3},
        {"entropy_min": 99},
    ],
)
def test_malformed_rules_rejected(tmp_path: Path, mutation: dict):
    with pytest.raises(RuleLoadError):
        load_secret_rules(_write_rules(tmp_path, [{**GOOD, **mutation}]))


def test_duplicate_ids_rejected(tmp_path: Path):
    with pytest.raises(RuleLoadError):
        load_secret_rules(_write_rules(tmp_path, [GOOD, GOOD]))


@pytest.mark.parametrize(
    "content",
    [
        "",
        "- just\n- a list\n",
        "version: 1\nrules: []\n",
        "version: 2\nrules: [{}]\n",
        "version: 1\nrules: [{id: x\n",  # unterminated flow
        "key: [unclosed",
        "!!python/object/apply:os.system ['echo pwned']",
        "a: &a [*a]\n",
        "\x00\x01\x02",
    ],
)
def test_malformed_yaml_rule_files_rejected_without_executing(tmp_path: Path, content: str):
    p = tmp_path / "bad.yaml"
    p.write_text(content, encoding="utf-8", errors="ignore")
    with pytest.raises(RuleLoadError):
        load_secret_rules(p)


def test_oversized_rule_file_rejected(tmp_path: Path):
    p = tmp_path / "huge.yaml"
    p.write_bytes(b"#" * (2 * 1024 * 1024))
    with pytest.raises(RuleLoadError):
        load_secret_rules(p)


def test_missing_rule_file_rejected(tmp_path: Path):
    with pytest.raises(RuleLoadError):
        load_secret_rules(tmp_path / "nope.yaml")


def test_all_shipped_rules_survive_backtracking_inputs():
    payloads = [
        "a" * 200_000 + "!",
        "A" * 200_000,
        "0" * 200_000,
        "password" + " " * 100_000 + "=",
        "password=" + '"' + "a" * 200_000,
        "aws" + "_" * 50_000 + "secret" + "x" * 50_000,
        "eyJ" + "a" * 100_000 + "." + "eyJ" + "a" * 100_000,
        "://" + ":" * 100_000 + "@",
        "https://" + "a:" * 50_000 + "@",
        "sk-" + "a" * 100_000,
        "ghp_" * 40_000,
        "-----BEGIN " * 20_000,
        "xoxb-" + "1" * 100_000,
        ("api_key = '" + "ab" * 50 + "' ") * 3_000,
    ]
    engine = SecretEngine(RULES)
    start = time.perf_counter()
    for payload in payloads:
        engine.scan_text(payload, path="x", blob_sha="a" * 40, commit=None, source=Source.HISTORY)
    elapsed = time.perf_counter() - start
    assert elapsed < 30, f"adversarial inputs took {elapsed:.1f}s"


def test_long_line_secret_found_via_windows():
    token = SAMPLES["github-pat-classic"]
    for pad in (0, 10_000, 30_000):
        findings = scan("x" * pad + " " + token + " " + "y" * pad)
        assert [f.rule_id for f in findings] == ["github-pat-classic"], pad
