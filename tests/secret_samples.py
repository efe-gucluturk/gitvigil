"""One synthetic, deterministic sample per secret rule.

Samples are assembled at runtime from fragments so this file never contains a literal that
looks like a real credential (keeps secret scanners and push-protection quiet).
"""

from __future__ import annotations

import base64
import random

_RNG = random.Random(20240607)
_ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_LOWER_HEX = "0123456789abcdef"


def r(n: int, alphabet: str = _ALNUM) -> str:
    return "".join(_RNG.choice(alphabet) for _ in range(n))


def b64url(obj: str) -> str:
    return base64.urlsafe_b64encode(obj.encode()).decode().rstrip("=")


def _jwt() -> str:
    return (
        f"{b64url('{"alg":"HS256","typ":"JWT"}')}.{b64url('{"sub":"1234567890","n":"x"}')}.{r(43)}"
    )


HEX_ = "0123456789abcdef"
URL_ = _ALNUM + "_-"

SAMPLES: dict[str, str] = {
    "aws-access-key-id": "AK" + "IA" + r(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
    "aws-secret-access-key": 'aws_secret_access_key = "' + r(40, _ALNUM + "/+") + '"',
    "aws-mws-auth-token": "amzn.mws." + "-".join(r(n, HEX_) for n in (8, 4, 4, 4, 12)),
    "gcp-service-account": '{"type": "service_' + 'account", "project_id": "p"}',
    "gcp-api-key": "AI" + "za" + r(35, URL_),
    "gcp-oauth-client-secret": "GOC" + "SPX-" + r(28, URL_),
    "gcp-oauth-access-token": "ya" + "29." + r(60, URL_),
    "azure-storage-account-key": "DefaultEndpointsProtocol=https;AccountName=a;Account"
    + "Key="
    + r(86, _ALNUM + "+/").replace("=", "")
    + "==",
    "azure-ad-client-secret": "ab1" + "8Q" + "~" + r(34, _ALNUM + "_.-"),
    "azure-sas-token": "https://a.blob.core.windows.net/c?sv=2021-06-08&ss=b&sp=r&sig="
    + r(46, _ALNUM + "%"),
    "azure-shared-access-key": "Endpoint=sb://x/;SharedAccess"
    + "Key="
    + r(43, _ALNUM + "+/")
    + "=",
    "github-pat-classic": "gh" + "p_" + r(36),
    "github-pat-fine-grained": "github" + "_pat_" + r(82, _ALNUM + "_"),
    "github-oauth-token": "gh" + "o_" + r(36),
    "github-user-to-server-token": "gh" + "u_" + r(36),
    "github-server-to-server-token": "gh" + "s_" + r(36),
    "github-refresh-token": "gh" + "r_" + r(40),
    "gitlab-pat": "gl" + "pat-" + r(20, URL_),
    "gitlab-pipeline-trigger-token": "gl" + "ptt-" + r(40, HEX_),
    "gitlab-runner-token": "gl" + "rt-" + r(24, URL_),
    "slack-bot-token": "xo" + "xb-" + r(11, "0123456789") + "-" + r(12, "0123456789") + "-" + r(24),
    "slack-user-token": "xo"
    + "xp-"
    + r(11, "0123456789")
    + "-"
    + r(11, "0123456789")
    + "-"
    + r(12, "0123456789")
    + "-"
    + r(28),
    "slack-app-token": "xa"
    + "pp-1-"
    + r(10, "ABCDEFGHIJ0123456789")
    + "-"
    + r(12, "0123456789")
    + "-"
    + r(48, HEX_),
    "slack-webhook-url": "https://hooks."
    + "slack.com/services/T"
    + r(9, "ABCDEFGH0123456789")
    + "/B"
    + r(9, "ABCDEFGH0123456789")
    + "/"
    + r(24),
    "stripe-live-secret-key": "sk" + "_live_" + r(30),
    "stripe-live-restricted-key": "rk" + "_live_" + r(30),
    "stripe-webhook-secret": "wh" + "sec_" + r(40),
    "openai-api-key-legacy": "sk-" + r(20) + "T3Blbk" + "FJ" + r(20),
    "openai-api-key-project": "sk-" + "proj-" + r(60, URL_),
    "anthropic-api-key": "sk-" + "ant-" + "api03-" + r(90, URL_),
    "private-key-block": "-----BEGIN " + "RSA PRIVATE KEY-----",
    "database-uri-credentials": "postgres://app_user:" + r(20) + "@db.internal.local:5432/app",
    "basic-auth-url": "https://deploy:" + r(20) + "@git.internal.local/repo.git",
    "jwt": _jwt(),
    "generic-high-entropy-secret": 'client_secret = "' + r(32) + '"',
    "generic-high-entropy-secret-colon": 'api_key: "' + r(32) + '"',
    "twilio-api-key": "S" + "K" + r(32, HEX_),
    "twilio-auth-token": 'TWILIO_AUTH_TOKEN="' + r(32, HEX_) + '"',
    "sendgrid-api-key": "S" + "G." + r(22, URL_) + "." + r(43, URL_),
    "mailgun-api-key": "ke" + "y-" + r(32, HEX_),
    "mailchimp-api-key": r(32, HEX_) + "-" + "us" + "12",
    "npm-access-token": "np" + "m_" + r(36),
    "pypi-upload-token": "py" + "pi-AgEIcHlwaS5vcmc" + r(70, URL_),
    "digitalocean-token": "do" + "p_v1_" + r(64, HEX_),
    "shopify-token": "shp" + "at_" + r(32, HEX_),
    "square-access-token": "EA" + "AA" + r(60, URL_),
    "terraform-cloud-token": r(14) + ".atlas" + "v1." + r(65, URL_),
    "databricks-token": "da" + "pi" + r(32, HEX_),
    "telegram-bot-token": r(9, "0123456789") + ":" + "A" + "A" + r(33, URL_),
    "discord-webhook-url": "https://discord"
    + ".com/api/webhooks/"
    + r(18, "0123456789")
    + "/"
    + r(68, URL_),
    "dockerhub-pat": "dck" + "r_pat_" + r(30, URL_),
    "linear-api-key": "lin" + "_api_" + r(40),
    "postman-api-key": "PM" + "AK-" + r(24, HEX_) + "-" + r(34, HEX_),
    "age-secret-key": "AGE-SECRET-" + "KEY-1" + r(58, "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"),
}
