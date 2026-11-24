from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from gitvigil.engine.iac import IMPLEMENTED_RULES, IacEngine, load_iac_rules
from gitvigil.engine.secrets import RuleLoadError
from gitvigil.models import Severity, Source

ENGINE = IacEngine()


def scan(path: str, text: str):
    findings, warnings = ENGINE.scan_text(
        text, path=path, blob_sha="a" * 40, commit=None, source=Source.HISTORY
    )
    return {f.rule_id for f in findings}, findings, warnings


def test_every_rule_has_severity_cwe_remediation_and_implementation():
    rules = load_iac_rules()
    assert {r.id for r in rules} == set(IMPLEMENTED_RULES)
    for rule in rules:
        assert isinstance(rule.severity, Severity)
        assert rule.cwe.startswith("CWE-")
        assert len(rule.remediation) > 10


# --------------------------------------------------------------------- Dockerfile

DOCKER_BAD = """\
FROM ubuntu:latest
ARG DB_PASSWORD=hunter2hunter2
ENV API_TOKEN=abcd1234efgh5678
RUN apt-get update
CMD ["app"]
"""


def test_dockerfile_bad():
    ids, findings, _ = scan("Dockerfile", DOCKER_BAD)
    assert {"GV-DKR-001", "GV-DKR-003", "GV-DKR-004"} <= ids
    assert all("hunter2" not in f.model_dump_json() for f in findings)  # no secret leakage


def test_dockerfile_explicit_root_and_untagged():
    ids, _, _ = scan("app.Dockerfile", "FROM python\nUSER root\n")
    assert {"GV-DKR-002", "GV-DKR-003"} <= ids
    assert "GV-DKR-001" not in ids


def test_dockerfile_good():
    good = (
        "FROM python:3.12-slim@sha256:" + "a" * 64 + "\n"
        "ARG VERSION=1.2.3\nENV PASSWORD_FILE=/run/secrets/pw\nENV TOKEN=${TOKEN}\n"
        'RUN useradd -u 10001 app \\\n  && echo ok\nUSER 10001\nCMD ["app"]\n'
    )
    assert scan("Dockerfile", good)[0] == set()


def test_dockerfile_multistage_inherits_and_alias_not_flagged_as_latest():
    text = 'FROM node:20 AS build\nUSER node\nFROM build\nCMD ["x"]\n'
    ids, _, _ = scan("Dockerfile", text)
    assert ids == set()


def test_dockerfile_final_scratch_ok():
    assert (
        scan("Dockerfile", "FROM golang:1.22 AS b\nUSER 1000\nFROM scratch\nCOPY --from=b /x /x\n")[
            0
        ]
        == set()
    )


# --------------------------------------------------------------------- compose

COMPOSE_BAD = """\
services:
  web:
    image: nginx:latest
    privileged: true
    network_mode: host
    pid: host
    user: root
    environment:
      DB_PASSWORD: s3cr3t-value-123
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
"""


def test_compose_bad_all_rules_with_lines():
    ids, findings, _ = scan("docker-compose.yml", COMPOSE_BAD)
    assert ids == {f"GV-CMP-00{i}" for i in range(1, 8)}
    by_rule = {f.rule_id: f.line for f in findings}
    assert by_rule["GV-CMP-001"] == 4
    assert by_rule["GV-CMP-002"] == 5


def test_compose_good():
    good = (
        "services:\n  web:\n    image: nginx:1.27\n    user: '1000:1000'\n"
        "    environment:\n      - DB_PASSWORD=${DB_PASSWORD}\n      - LOG_LEVEL=debug\n"
    )
    assert scan("compose.yaml", good)[0] == set()


# --------------------------------------------------------------------- Kubernetes

K8S_BAD = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      hostNetwork: true
      hostPID: true
      containers:
        - name: app
          image: nginx
          env:
            - name: API_SECRET
              value: "plain-text-secret-1"
            - name: OK_SECRET
              valueFrom:
                secretKeyRef: {name: s, key: k}
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
            runAsUser: 0
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: open
spec:
  ingress:
    - from:
        - ipBlock:
            cidr: 0.0.0.0/0
"""


def test_k8s_bad():
    ids, findings, warnings = scan("deploy/app.yaml", K8S_BAD)
    assert ids == {f"GV-K8S-00{i}" for i in range(1, 9)}
    assert not warnings
    assert sum(f.rule_id == "GV-K8S-006" for f in findings) == 1  # valueFrom is not flagged


def test_k8s_good():
    good = """\
apiVersion: v1
kind: Pod
metadata: {name: p}
spec:
  containers:
    - name: c
      image: registry.local/app:1.2.3
      securityContext: {runAsNonRoot: true, runAsUser: 10001, allowPrivilegeEscalation: false}
"""
    assert scan("pod.yml", good)[0] == set()


def test_k8s_loadbalancer_open_range():
    text = (
        "apiVersion: v1\nkind: Service\nmetadata: {name: s}\n"
        "spec:\n  type: LoadBalancer\n  loadBalancerSourceRanges: ['0.0.0.0/0']\n"
    )
    assert scan("svc.yaml", text)[0] == {"GV-K8S-008"}


# --------------------------------------------------------------------- Terraform

TF_BAD = """\
resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_security_group_rule" "r" {
  type        = "ingress"
  cidr_blocks = [
    "10.0.0.0/8",
    "::/0",
  ]
}
provider "aws" {
  access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYexample1"
  secret_key = "Zq8vN2pL5xR7tY1uW3eA9sD4fG6hJ0kK"
}
variable "db_password" {
  default = "correct-horse-battery-staple"
}
resource "aws_s3_bucket" "b" {
  acl = "public-read"
}
resource "aws_db_instance" "d" {
  publicly_accessible = true
}
resource "docker_container" "c" {
  image        = "nginx:latest"
  privileged   = true
  network_mode = "host"
}
resource "kubernetes_pod" "p" {
  spec {
    host_pid = true
  }
}
"""


def test_terraform_bad():
    ids, findings, _ = scan("infra/main.tf", TF_BAD)
    assert ids == {f"GV-TF-00{i}" for i in range(1, 8)}
    open_lines = sorted(f.line for f in findings if f.rule_id == "GV-TF-001")
    assert open_lines == [7, 17]  # egress 0.0.0.0/0 on line 11 is NOT flagged
    assert all("Zq8vN2pL" not in f.model_dump_json() for f in findings)


def test_terraform_good():
    good = """\
# cidr_blocks = ["0.0.0.0/0"]  (commented out)
resource "aws_security_group" "web" {
  ingress {
    cidr_blocks = ["10.0.0.0/8"]
  }
  egress { cidr_blocks = ["0.0.0.0/0"] }
}
variable "db_password" {
  type      = string
  sensitive = true
}
provider "aws" {
  access_key = var.access_key
  token      = "${var.token}"
}
resource "aws_db_instance" "d" {
  password            = var.db_password
  publicly_accessible = false
}
locals {
  note = <<EOT
    ingress { cidr_blocks = ["0.0.0.0/0"] }
EOT
}
"""
    assert scan("main.tf", good)[0] == set()


def test_terraform_single_line_ingress_block():
    assert scan(
        "a.tf",
        'resource "aws_security_group" "s" {\n  ingress { cidr_blocks = ["0.0.0.0/0"] }\n}\n',
    )[0] == {"GV-TF-001"}


# --------------------------------------------------------------------- adversarial


@pytest.mark.parametrize(
    "path,text",
    [
        ("a.yaml", "key: [unclosed"),
        ("a.yaml", "!!python/object/apply:os.system ['echo pwned']"),
        ("a.yaml", "a: &a [*a, *a]\n"),
        ("a.yaml", "[" * 20000),
        ("a.yaml", "\x00\x01\x02: x"),
        ("docker-compose.yml", "services: [1, 2]"),
        ("docker-compose.yml", "services:\n  x: null\n  y: 5\n"),
        ("a.yaml", "---\n" * 500),
        ("main.tf", "{" * 50000 + "}" * 10),
        ("main.tf", 'resource "' + "a" * 100000),
        ("main.tf", "/*" * 10000),
        ("Dockerfile", "FROM " + "a" * 100000),
        ("Dockerfile", "ENV " + 'A="' * 20000),
        ("Dockerfile", "RUN a \\\n" * 50000),
    ],
)
def test_malformed_iac_never_raises_or_hangs(path: str, text: str):
    scan(path, text)  # must not raise


def test_yaml_alias_bomb_is_bounded():
    bomb = "a: &a [x,x,x,x,x,x,x,x,x]\n" + "".join(
        f"{chr(98 + i)}: &{chr(98 + i)} [{', '.join(['*' + chr(97 + i)] * 9)}]\n" for i in range(9)
    )
    scan("bomb.yaml", bomb)


def _rules_file(tmp_path: Path, rule: dict) -> Path:
    p = tmp_path / "iac.yaml"
    p.write_text(yaml.safe_dump({"version": 1, "rules": [rule]}), encoding="utf-8")
    return p


GOOD_RULE = {
    "id": "GV-DKR-001", "title": "t", "targets": ["dockerfile"], "severity": "LOW",
    "cwe": "CWE-250", "description": "d", "remediation": "do something sensible",
}  # fmt: skip


@pytest.mark.parametrize(
    "mutation",
    [
        {"severity": "URGENT"},
        {"cwe": "250"},
        {"targets": ["cobol"]},
        {"targets": []},
        {"id": "GV-ZZZ-999"},  # no implementation
        {"extra": 1},
        {"remediation": None},
    ],
)
def test_malformed_iac_rules_rejected(tmp_path: Path, mutation: dict):
    with pytest.raises(RuleLoadError):
        load_iac_rules(_rules_file(tmp_path, {**GOOD_RULE, **mutation}))


def test_iac_rule_file_not_yaml_rejected(tmp_path: Path):
    p = tmp_path / "x.yaml"
    p.write_text("a: [", encoding="utf-8")
    with pytest.raises(RuleLoadError):
        load_iac_rules(p)
