"""IaC misconfiguration engine: Dockerfile, docker-compose, Kubernetes manifests, Terraform.

Rule metadata (severity, CWE, remediation) is declarative in ``rules/iac.yaml``; detection
logic lives in the per-format checks below, bound to rules by ID. The loader fails closed if
the two ever drift apart.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterator
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any, Literal, NamedTuple

import yaml
from pydantic import Field, ValidationError, field_validator

from gitvigil.constants import MAX_FINDINGS_PER_BLOB, MAX_RULE_FILE_BYTES, MAX_YAML_DOCUMENTS
from gitvigil.engine.common import fingerprint, looks_like_secret_assignment
from gitvigil.engine.secrets import RuleLoadError
from gitvigil.models import (
    Category,
    Finding,
    ScanWarning,
    Severity,
    Source,
    StrictModel,
    coerce_severity,
)

Target = Literal["dockerfile", "compose", "kubernetes", "terraform"]
_MAX_LINE = 4096


class IacRule(StrictModel):
    id: str = Field(pattern=r"^GV-[A-Z0-9]{2,4}-\d{3}$")
    title: str = Field(min_length=1, max_length=200)
    targets: tuple[Target, ...] = Field(min_length=1)
    severity: Severity
    cwe: str = Field(pattern=r"^CWE-\d{1,4}$")
    description: str = Field(min_length=1, max_length=500)
    remediation: str = Field(min_length=1, max_length=500)

    _sev = field_validator("severity", mode="before")(coerce_severity)

    @field_validator("targets", mode="before")
    @classmethod
    def _targets_tuple(cls, v: Any) -> Any:
        return tuple(v) if isinstance(v, list) else v


class _IacRuleFile(StrictModel):
    version: Literal[1]
    rules: list[IacRule] = Field(min_length=1)


class Hit(NamedTuple):
    rule_id: str
    line: int
    evidence: str


# Rule IDs with an implementation below. Kept in sync with iac.yaml at load time.
IMPLEMENTED_RULES = frozenset(
    {
        "GV-DKR-001", "GV-DKR-002", "GV-DKR-003", "GV-DKR-004",
        "GV-CMP-001", "GV-CMP-002", "GV-CMP-003", "GV-CMP-004", "GV-CMP-005", "GV-CMP-006",
        "GV-CMP-007",
        "GV-K8S-001", "GV-K8S-002", "GV-K8S-003", "GV-K8S-004", "GV-K8S-005", "GV-K8S-006",
        "GV-K8S-007", "GV-K8S-008",
        "GV-TF-001", "GV-TF-002", "GV-TF-003", "GV-TF-004", "GV-TF-005", "GV-TF-006", "GV-TF-007",
    }
)  # fmt: skip


def load_iac_rules(path: Path | None = None) -> list[IacRule]:
    try:
        if path is None:
            raw = resources.files("gitvigil.rules").joinpath("iac.yaml").read_bytes()
        else:
            if path.stat().st_size > MAX_RULE_FILE_BYTES:
                raise RuleLoadError("rule file too large")
            raw = path.read_bytes()
    except OSError as exc:
        raise RuleLoadError(f"cannot read IaC rule file: {exc}") from exc
    if len(raw) > MAX_RULE_FILE_BYTES:
        raise RuleLoadError("rule file too large")
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"invalid YAML in IaC rules: {exc}") from exc
    if not isinstance(data, dict):
        raise RuleLoadError("IaC rules file must be a mapping")
    try:
        parsed = _IacRuleFile.model_validate(data)
    except ValidationError as exc:
        raise RuleLoadError(f"invalid IaC rules: {exc}") from exc
    ids = [r.id for r in parsed.rules]
    if len(ids) != len(set(ids)):
        raise RuleLoadError("duplicate IaC rule id")
    unknown = set(ids) - IMPLEMENTED_RULES
    if unknown:
        raise RuleLoadError(f"IaC rules without implementation: {sorted(unknown)}")
    return parsed.rules


# ============================================================ YAML with line numbers


class _LineDict(dict):
    line: int = 1
    key_lines: dict[Any, int]


class _LineLoader(yaml.SafeLoader):
    """SafeLoader that records source line numbers on mappings (no arbitrary object tags)."""

    def construct_yaml_map(self, node):  # type: ignore[no-untyped-def]
        data = _LineDict()
        data.line = node.start_mark.line + 1
        data.key_lines = {}
        yield data
        data.update(self.construct_mapping(node))
        for key_node, _ in node.value:
            if isinstance(key_node, yaml.ScalarNode):
                data.key_lines[key_node.value] = key_node.start_mark.line + 1


_LineLoader.add_constructor("tag:yaml.org,2002:map", _LineLoader.construct_yaml_map)


def _load_yaml_docs(text: str) -> tuple[list[Any], list[str]]:
    docs: list[Any] = []
    problems: list[str] = []
    try:
        # _LineLoader subclasses SafeLoader: no python/object tags, so this is safe.
        for i, doc in enumerate(yaml.load_all(text, Loader=_LineLoader)):
            if i >= MAX_YAML_DOCUMENTS:
                problems.append(f"more than {MAX_YAML_DOCUMENTS} YAML documents; rest ignored")
                break
            docs.append(doc)
    except yaml.YAMLError as exc:
        problems.append(f"invalid YAML: {type(exc).__name__}")
    except RecursionError:
        problems.append("YAML nesting too deep")
    return docs, problems


def _ln(d: Any, key: str | None = None) -> int:
    if not isinstance(d, _LineDict):
        return 1
    if key is not None and key in d.key_lines:
        return d.key_lines[key]
    return d.line


def _truthy(v: Any) -> bool:
    return v is True or (isinstance(v, str) and v.strip().lower() == "true")


def _image_unpinned(ref: str) -> bool:
    """True for ``name`` (implicit latest) or ``name:latest``; digests/variables are fine."""
    ref = ref.strip()
    if not ref or "@" in ref or "$" in ref or ref == "scratch":
        return False
    last = ref.rsplit("/", 1)[-1]
    if ":" not in last:
        return True
    return last.rsplit(":", 1)[1].lower() == "latest"


# ============================================================ Dockerfile


def _docker_logical_lines(text: str) -> Iterator[tuple[int, str]]:
    buf: list[str] = []
    start = 0
    for lineno, raw in enumerate(text.split("\n"), 1):
        line = raw.rstrip("\r")[:_MAX_LINE]
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if not buf and not stripped:
            continue
        if not buf:
            start = lineno
        if stripped.endswith("\\"):
            buf.append(stripped[:-1])
            continue
        buf.append(stripped)
        yield start, " ".join(buf).strip()
        buf = []
    if buf:
        yield start, " ".join(buf).strip()


def _split_pairs(rest: str) -> list[tuple[str, str]]:
    try:
        tokens = shlex.split(rest)
    except ValueError:
        tokens = rest.split()
    if not tokens:
        return []
    if "=" in tokens[0]:
        return [tuple(t.split("=", 1)) for t in tokens if "=" in t]  # type: ignore[misc]
    return [(tokens[0], " ".join(tokens[1:]))]


@dataclass
class _Stage:
    line: int
    image: str
    users: list[tuple[int, str]] = field(default_factory=list)


def check_dockerfile(text: str) -> list[Hit]:
    hits: list[Hit] = []
    stages: list[_Stage] = []
    aliases: dict[str, int] = {}
    for lineno, line in _docker_logical_lines(text):
        instr, _, rest = line.partition(" ")
        instr = instr.upper()
        if instr == "FROM":
            tokens = [t for t in rest.split() if not t.startswith("--")]
            if not tokens:
                continue
            image = tokens[0]
            inherits = aliases.get(image.lower())
            stage = _Stage(
                lineno, image, list(stages[inherits].users) if inherits is not None else []
            )
            if len(tokens) >= 3 and tokens[1].lower() == "as":
                aliases[tokens[2].lower()] = len(stages)
            stages.append(stage)
            if inherits is None and _image_unpinned(image):
                hits.append(Hit("GV-DKR-003", lineno, f"image={image}"))
        elif instr == "USER" and stages:
            parts = rest.split()
            if parts:
                stages[-1].users.append((lineno, parts[0]))
        elif instr in ("ENV", "ARG"):
            for name, value in _split_pairs(rest):
                if looks_like_secret_assignment(name, value):
                    hits.append(Hit("GV-DKR-004", lineno, f"{instr}:{name}"))
    if stages:
        final = stages[-1]
        if final.image.lower() != "scratch":
            if not final.users:
                hits.append(Hit("GV-DKR-001", final.line, f"stage-image={final.image}"))
            else:
                uline, user = final.users[-1]
                if user.split(":")[0].lower() in ("root", "0"):
                    hits.append(Hit("GV-DKR-002", uline, f"user={user}"))
    return hits


# ============================================================ docker-compose


def _env_pairs(env: Any) -> list[tuple[str, str]]:
    if isinstance(env, dict):
        return [(str(k), "" if v is None else str(v)) for k, v in env.items()]
    if isinstance(env, list):
        return [tuple(e.split("=", 1)) for e in env if isinstance(e, str) and "=" in e]  # type: ignore[misc]
    return []


def check_compose(docs: list[Any]) -> list[Hit]:
    hits: list[Hit] = []
    for doc in docs:
        if not isinstance(doc, dict) or not isinstance(doc.get("services"), dict):
            continue
        for name, svc in doc["services"].items():
            if not isinstance(svc, dict):
                continue
            ev = f"service={name}"
            if _truthy(svc.get("privileged")):
                hits.append(Hit("GV-CMP-001", _ln(svc, "privileged"), ev))
            if str(svc.get("network_mode", "")).lower() == "host":
                hits.append(Hit("GV-CMP-002", _ln(svc, "network_mode"), ev))
            if str(svc.get("pid", "")).lower() == "host":
                hits.append(Hit("GV-CMP-003", _ln(svc, "pid"), ev))
            for key, value in _env_pairs(svc.get("environment")):
                if looks_like_secret_assignment(key, value):
                    hits.append(Hit("GV-CMP-004", _ln(svc, "environment"), f"{ev}:{key}"))
            image = svc.get("image")
            if isinstance(image, str) and _image_unpinned(image):
                hits.append(Hit("GV-CMP-005", _ln(svc, "image"), f"{ev}:image={image}"))
            user = svc.get("user")
            if user is not None and str(user).split(":")[0].strip().lower() in ("root", "0"):
                hits.append(Hit("GV-CMP-006", _ln(svc, "user"), ev))
            volumes = svc.get("volumes")
            if isinstance(volumes, list):
                for vol in volumes:
                    src = vol.get("source", "") if isinstance(vol, dict) else vol
                    if isinstance(src, str) and "docker.sock" in src:
                        hits.append(Hit("GV-CMP-007", _ln(svc, "volumes"), ev))
                        break
    return hits


# ============================================================ Kubernetes

_WORKLOADS = {
    "Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob",
    "ReplicationController",
}  # fmt: skip


def _dig(d: Any, *keys: str) -> Any:
    for k in keys:
        if not isinstance(d, dict):
            return None
        d = d.get(k)
    return d


def _pod_spec(doc: dict) -> dict | None:
    kind = doc.get("kind")
    if kind == "Pod":
        spec = doc.get("spec")
    elif kind == "CronJob":
        spec = _dig(doc, "spec", "jobTemplate", "spec", "template", "spec")
    else:
        spec = _dig(doc, "spec", "template", "spec")
    return spec if isinstance(spec, dict) else None


def check_kubernetes(docs: list[Any]) -> list[Hit]:
    hits: list[Hit] = []
    for doc in docs:
        if not isinstance(doc, dict) or "apiVersion" not in doc:
            continue
        kind = doc.get("kind")
        meta_name = _dig(doc, "metadata", "name")
        base = f"{kind}/{meta_name}"
        if kind == "NetworkPolicy":
            hits.extend(_k8s_netpol(doc, base))
        elif kind == "Service":
            if _dig(doc, "spec", "type") == "LoadBalancer":
                ranges = _dig(doc, "spec", "loadBalancerSourceRanges")
                if isinstance(ranges, list) and "0.0.0.0/0" in ranges:
                    hits.append(
                        Hit("GV-K8S-008", _ln(doc["spec"], "loadBalancerSourceRanges"), base)
                    )
        elif kind in _WORKLOADS:
            spec = _pod_spec(doc)
            if spec is not None:
                hits.extend(_k8s_pod(spec, base))
    return hits


def _k8s_netpol(doc: dict, base: str) -> list[Hit]:
    out: list[Hit] = []
    ingress = _dig(doc, "spec", "ingress")
    for rule in ingress if isinstance(ingress, list) else []:
        sources = rule.get("from") if isinstance(rule, dict) else None
        for src in sources if isinstance(sources, list) else []:
            block = src.get("ipBlock") if isinstance(src, dict) else None
            if isinstance(block, dict) and block.get("cidr") in ("0.0.0.0/0", "::/0"):
                out.append(Hit("GV-K8S-008", _ln(block, "cidr"), base))
    return out


def _k8s_pod(spec: dict, base: str) -> list[Hit]:
    out: list[Hit] = []
    if _truthy(spec.get("hostNetwork")):
        out.append(Hit("GV-K8S-002", _ln(spec, "hostNetwork"), base))
    if _truthy(spec.get("hostPID")):
        out.append(Hit("GV-K8S-003", _ln(spec, "hostPID"), base))
    pod_sc = spec.get("securityContext") if isinstance(spec.get("securityContext"), dict) else {}
    containers = [
        c
        for key in ("containers", "initContainers")
        if isinstance(spec.get(key), list)
        for c in spec[key]
        if isinstance(c, dict)
    ]
    for c in containers:
        ev = f"{base}:{c.get('name')}"
        sc = c.get("securityContext") if isinstance(c.get("securityContext"), dict) else {}
        if _truthy(sc.get("privileged")):
            out.append(Hit("GV-K8S-001", _ln(sc, "privileged"), ev))
        if _truthy(sc.get("allowPrivilegeEscalation")):
            out.append(Hit("GV-K8S-007", _ln(sc, "allowPrivilegeEscalation"), ev))
        for ctx in (sc, pod_sc):
            if ctx.get("runAsUser") == 0 or ctx.get("runAsNonRoot") is False:
                key = "runAsUser" if ctx.get("runAsUser") == 0 else "runAsNonRoot"
                out.append(Hit("GV-K8S-004", _ln(ctx, key), ev))
                break
        image = c.get("image")
        if isinstance(image, str) and _image_unpinned(image):
            out.append(Hit("GV-K8S-005", _ln(c, "image"), f"{ev}:image={image}"))
        for env in c.get("env") if isinstance(c.get("env"), list) else []:
            if not isinstance(env, dict) or "valueFrom" in env:
                continue
            name, value = str(env.get("name", "")), env.get("value")
            if value is not None and looks_like_secret_assignment(name, str(value)):
                out.append(Hit("GV-K8S-006", _ln(env, "value"), f"{ev}:{name}"))
    return out


# ============================================================ Terraform


@dataclass
class _Block:
    kind: str
    labels: list[str]
    parent: _Block | None
    line: int
    lines: list[tuple[int, str]] = field(default_factory=list)

    def top(self) -> _Block:
        b = self
        while b.parent is not None and b.parent.parent is not None:
            b = b.parent
        return b

    def address(self) -> str:
        t = self.top()
        return ".".join([t.kind, *t.labels])

    def text(self) -> str:
        return "\n".join(t for _, t in self.lines)


_HCL_HEADER = re.compile(
    r'\s{0,200}([A-Za-z_][\w\-]{0,100})((?:\s{1,50}(?:"_{0,200}"|[A-Za-z_][\w\-]{0,100})){0,4})\s{0,200}'
)
_QUOTED = re.compile(r'"([^"]{0,200})"')
_HEREDOC = re.compile(r"<<-?\s{0,3}([A-Za-z_]\w{0,60})\s{0,200}$")


def _hcl_blocks(text: str) -> list[_Block]:
    root = _Block("<root>", [], None, 0)
    blocks: list[_Block] = []
    stack = [root]
    in_comment = False
    heredoc: str | None = None
    for lineno, raw in enumerate(text.split("\n"), 1):
        raw = raw.rstrip("\r")[:_MAX_LINE]
        if heredoc is not None:
            if raw.strip() == heredoc:
                heredoc = None
            continue
        orig: list[str] = []
        blank: list[str] = []
        in_str = False
        i, n = 0, len(raw)
        while i < n:
            c = raw[i]
            if in_comment:
                if raw.startswith("*/", i):
                    in_comment = False
                    i += 2
                else:
                    i += 1
                continue
            if in_str:
                orig.append(c)
                if c == "\\" and i + 1 < n:
                    orig.append(raw[i + 1])
                    blank.extend("__")
                    i += 2
                    continue
                if c == '"':
                    in_str = False
                    blank.append('"')
                else:
                    blank.append("_")
                i += 1
                continue
            if c == "#" or raw.startswith("//", i):
                break
            if raw.startswith("/*", i):
                in_comment = True
                i += 2
                continue
            if c == '"':
                in_str = True
            orig.append(c)
            blank.append(c)
            i += 1
        code, bcode = "".join(orig), "".join(blank)
        owner = stack[-1]
        last = 0
        for idx, ch in enumerate(bcode):
            if ch == "{":
                prefix_b = bcode[last:idx]
                m = _HCL_HEADER.fullmatch(prefix_b)
                if m and not prefix_b.rstrip().endswith(("=", "(", ",", ":")):
                    labels = _QUOTED.findall(code[last:idx])
                    extra = [t for t in m.group(2).split() if not t.startswith('"')]
                    blk = _Block(m.group(1), labels + extra, stack[-1], lineno)
                else:
                    blk = _Block("", [], stack[-1], lineno)
                blocks.append(blk)
                stack.append(blk)
                owner = blk
                last = idx + 1
            elif ch == "}":
                if len(stack) > 1:
                    stack.pop()
                last = idx + 1
        owner.lines.append((lineno, code))
        hd = _HEREDOC.search(bcode)
        if hd:
            heredoc = hd.group(1)
    return blocks


_OPEN_CIDR = re.compile(r'"(?:0\.0\.0\.0/0|::/0)"')
_AZURE_OPEN = re.compile(
    r'source_address_prefix(?:es)?\s{0,40}=\s{0,40}\[?\s{0,40}"(?:\*|Internet)"'
)
_ASSIGN_STR = re.compile(
    r'\s{0,100}([A-Za-z_][\w\-]{0,100})\s{0,40}=\s{0,40}"([^"\\\n]{0,500})"\s{0,40},?\s{0,40}'
)
_PRIVILEGED = re.compile(r'\s{0,100}"?privileged"?\s{0,40}[=:]\s{0,40}"?true"?\b')
_HOST_NS = re.compile(
    r'\s{0,100}"?(?:host_network|host_pid|host_ipc|hostNetwork|hostPID|hostIPC)"?\s{0,40}[=:]\s{0,40}"?true"?\b'
    r'|\s{0,100}"?(?:pid_mode|pidMode|network_mode|networkMode)"?\s{0,40}[=:]\s{0,40}"host"'
)
_IMAGE_LATEST = re.compile(r'"?image"?\s{0,40}[=:]\s{0,40}"([^"\s]{1,300}:latest)"')
_PUBLIC_ACL = re.compile(r'\s{0,100}acl\s{0,40}=\s{0,40}"public-read(?:-write)?"')
_PUBLIC_DB = re.compile(r"\s{0,100}publicly_accessible\s{0,40}=\s{0,40}true\b")
_SECRET_TOP_KINDS = {"resource", "provider", "module", "data", "locals"}
_INGRESS_RULE_TYPES = {
    "aws_security_group_rule", "aws_vpc_security_group_ingress_rule", "google_compute_firewall",
    "azurerm_network_security_rule",
}  # fmt: skip


def _in_ingress(b: _Block) -> bool:
    while b.parent is not None:
        if b.kind == "ingress" or (b.kind == "dynamic" and b.labels[:1] == ["ingress"]):
            return True
        if b.kind in ("egress",) or (b.kind == "dynamic" and b.labels[:1] == ["egress"]):
            return False
        b = b.parent
    return False


def _is_ingress_rule(b: _Block) -> bool:
    if b.kind == "resource" and b.labels and b.labels[0] in _INGRESS_RULE_TYPES:
        rtype, body = b.labels[0], b.text()
    elif b.kind == "security_rule":
        rtype, body = "azurerm_network_security_rule", b.text()
    else:
        return False
    if rtype == "aws_security_group_rule":
        return re.search(r'\btype\s{0,40}=\s{0,40}"ingress"', body) is not None
    if rtype == "google_compute_firewall":
        return re.search(r'direction\s{0,40}=\s{0,40}"EGRESS"', body) is None
    if rtype == "azurerm_network_security_rule":
        return (
            re.search(r'direction\s{0,40}=\s{0,40}"Inbound"', body) is not None
            and re.search(r'access\s{0,40}=\s{0,40}"Allow"', body) is not None
        )
    return True


def check_terraform(text: str) -> list[Hit]:
    hits: list[Hit] = []
    for b in _hcl_blocks(text):
        if not b.parent:
            continue
        addr = b.address()
        if _in_ingress(b) or _is_ingress_rule(b):
            for lineno, line in b.lines:
                if _OPEN_CIDR.search(line) or _AZURE_OPEN.search(line):
                    hits.append(Hit("GV-TF-001", lineno, f"{addr}:L{lineno}"))
        top = b.top()
        for lineno, line in b.lines:
            if top.kind in _SECRET_TOP_KINDS or top.kind == "variable":
                m = _ASSIGN_STR.fullmatch(line)
                if m:
                    name, value = m.group(1), m.group(2)
                    if top.kind == "variable":
                        is_secret = (
                            b is top
                            and name == "default"
                            and looks_like_secret_assignment(
                                top.labels[0] if top.labels else "", value
                            )
                        )
                    else:
                        is_secret = looks_like_secret_assignment(name, value)
                    if is_secret:
                        hits.append(Hit("GV-TF-002", lineno, f"{addr}.{name}"))
            if _PRIVILEGED.fullmatch(line):
                hits.append(Hit("GV-TF-003", lineno, f"{addr}:L{lineno}"))
            if _HOST_NS.fullmatch(line):
                hits.append(Hit("GV-TF-004", lineno, f"{addr}:L{lineno}"))
            m = _IMAGE_LATEST.search(line)
            if m and "${" not in m.group(1):
                hits.append(Hit("GV-TF-005", lineno, f"{addr}:image={m.group(1)}"))
            if _PUBLIC_ACL.fullmatch(line):
                hits.append(Hit("GV-TF-006", lineno, addr))
            if _PUBLIC_DB.fullmatch(line):
                hits.append(Hit("GV-TF-007", lineno, addr))
    return hits


# ============================================================ engine

_COMPOSE_NAME = re.compile(r"(?:docker-)?compose(?:\.[\w\-]{1,40})?\.ya?ml")


def detect_kind(path: str) -> Literal["dockerfile", "terraform", "yaml"] | None:
    name = path.rsplit("/", 1)[-1].lower()
    if name in ("dockerfile", "containerfile") or name.startswith(
        ("dockerfile.", "containerfile.")
    ):
        return "dockerfile"
    if name.endswith(".dockerfile"):
        return "dockerfile"
    if name.endswith(".tf"):
        return "terraform"
    if name.endswith((".yaml", ".yml")):
        return "yaml"
    return None


class IacEngine:
    def __init__(self, rules: list[IacRule] | None = None) -> None:
        self.rules = {r.id: r for r in (rules if rules is not None else load_iac_rules())}

    def scan_text(
        self,
        text: str,
        *,
        path: str,
        blob_sha: str,
        commit: str | None,
        source: Source,
    ) -> tuple[list[Finding], list[ScanWarning]]:
        kind = detect_kind(path)
        if kind is None:
            return [], []
        warnings: list[ScanWarning] = []
        hits: list[Hit]
        if kind == "dockerfile":
            hits = check_dockerfile(text)
        elif kind == "terraform":
            hits = check_terraform(text)
        else:
            docs, problems = _load_yaml_docs(text)
            warnings = [
                ScanWarning(code="iac-parse-error", message=p, path=path, blob_sha=blob_sha)
                for p in problems
            ]
            name = path.rsplit("/", 1)[-1].lower()
            hits = check_kubernetes(docs)
            if _COMPOSE_NAME.fullmatch(name) or any(
                isinstance(d, dict) and "services" in d and "apiVersion" not in d for d in docs
            ):
                hits += check_compose(docs)
        return self._to_findings(hits, path, blob_sha, commit, source), warnings

    def _to_findings(
        self, hits: list[Hit], path: str, blob_sha: str, commit: str | None, source: Source
    ) -> list[Finding]:
        out: dict[tuple[str, str], Finding] = {}
        for hit in hits:
            rule = self.rules.get(hit.rule_id)
            key = (hit.rule_id, hit.evidence)
            if rule is None or key in out:
                continue
            out[key] = Finding(
                rule_id=rule.id,
                title=rule.title,
                category=Category.IAC,
                severity=rule.severity,
                cwe=rule.cwe,
                path=path,
                line=max(hit.line, 1),
                commit=commit,
                blob_sha=blob_sha,
                source=source,
                redacted_match=_safe_evidence(hit.evidence),
                fingerprint=fingerprint(rule.id, path, hit.evidence),
                remediation=rule.remediation,
            )
            if len(out) >= MAX_FINDINGS_PER_BLOB:
                break
        return list(out.values())


def _safe_evidence(evidence: str) -> str:
    """Evidence contains names/addresses only (never secret values), but bound its size."""
    return evidence[:200]
