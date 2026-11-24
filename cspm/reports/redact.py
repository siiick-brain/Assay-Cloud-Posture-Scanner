"""Redaction of secret-like values, account IDs, ARNs and home paths before storage or reporting."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

# Placeholders avoid <> and : so they stay valid inside ARNs, URIs, Markdown tables and file names.
PLACEHOLDER_PREFIX = "REDACTED"

_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)", re.DOTALL
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_VENDOR_TOKEN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|xox[abprs]-[A-Za-z0-9-]{10,})"
)
_BEARER = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}")
_URL_CREDS = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^\s:/@]+:)[^\s@/]+(@)")
_SECRET_ASSIGN = re.compile(
    r"(?i)\b((?:aws_)?(?:secret_access_key|secret_key|session_token|secretaccesskey|sessiontoken)"
    r"[\"']?\s*[:=]\s*[\"']?)([A-Za-z0-9/+=]{16,})"
)
_PASSWORD_ASSIGN = re.compile(
    r"(?i)\b((?:password|passwd|pwd|client_secret|api_key|apikey)[\"']?\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
)
_ACCESS_KEY_ID = re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|APKA|ABIA|ACCA)[A-Z0-9]{16}\b")
_ARN = re.compile(r"\barn:(aws[a-z-]*):([a-z0-9-]*):([a-z0-9-]*):(\d{12})?:([^\s\"'<>,]+)")
# Alnum guards stop hex digests and longer numbers from matching.
_ACCOUNT_ID = re.compile(r"(?<![0-9A-Za-z])\d{12}(?![0-9A-Za-z])")
_WIN_HOME = re.compile(r"(?i)\b([A-Z]:[\\/]+Users[\\/]+)[^\\/\s\"']+")
_POSIX_HOME = re.compile(r"(?<![\w.])(/(?:home|Users)/)[^/\s\"']+")

_SENSITIVE_KEY = re.compile(
    r"(?i)(?:^|[_-])(password|passwd|secret|token|private_?key|secret_?key|api_?key|credentials?|session_?key)$"
)
_SENSITIVE_KEY_CAMEL = re.compile(r"(Password|Secret|Token|PrivateKey|SecretKey|ApiKey|Credentials?)$")


class Redactor:
    """Replaces sensitive values with placeholders that are stable for the same input and salt.

    Account IDs and resource names get a short salted digest so the same resource keeps
    the same placeholder across scans. Pass a private salt for reports that leave the
    machine, since a 12 digit account ID can be brute forced from an unsalted digest.
    Secrets, passwords and keys get no digest at all.
    """

    def __init__(self, salt: str = "", names: Iterable[str] = ()) -> None:
        self._salt = salt.encode()
        self._known: set[str] = set()
        self._names: re.Pattern[str] | None = None
        self.learn_names(names)

    def learn_names(self, names: Iterable[str]) -> None:
        """Also mask these resource names wherever they appear as plain text."""
        self._known |= {n for n in names if len(n) >= 3 and not n.startswith(PLACEHOLDER_PREFIX)}
        # Longest first so a name that contains another is replaced whole.
        parts = sorted((re.escape(n) for n in self._known), key=len, reverse=True)
        self._names = re.compile(r"(?<![\w.-])(" + "|".join(parts) + r")(?![\w.-])") if parts else None

    def tag(self, kind: str, value: str) -> str:
        digest = hashlib.sha256(self._salt + kind.encode() + b"|" + value.encode()).hexdigest()[:8]
        return f"{PLACEHOLDER_PREFIX}_{kind}_{digest}"

    def text(self, value: str) -> str:
        """Redact one string."""
        out = _PRIVATE_KEY.sub(f"{PLACEHOLDER_PREFIX}_PRIVATE_KEY", value)
        out = _JWT.sub(f"{PLACEHOLDER_PREFIX}_TOKEN", out)
        out = _VENDOR_TOKEN.sub(f"{PLACEHOLDER_PREFIX}_TOKEN", out)
        out = _BEARER.sub(lambda m: f"{m.group(1)}{PLACEHOLDER_PREFIX}_TOKEN", out)
        out = _URL_CREDS.sub(lambda m: f"{m.group(1)}{PLACEHOLDER_PREFIX}_PASSWORD{m.group(2)}", out)
        out = _SECRET_ASSIGN.sub(lambda m: f"{m.group(1)}{PLACEHOLDER_PREFIX}_SECRET", out)
        out = _PASSWORD_ASSIGN.sub(lambda m: f"{m.group(1)}{PLACEHOLDER_PREFIX}_PASSWORD", out)
        out = _ACCESS_KEY_ID.sub(lambda m: self.tag("KEY_ID", m.group(0)), out)
        out = _ARN.sub(self._arn, out)
        if self._names is not None:
            out = self._names.sub(lambda m: self.tag("NAME", m.group(1)), out)
        out = _ACCOUNT_ID.sub(lambda m: self.tag("ACCOUNT", m.group(0)), out)
        out = _WIN_HOME.sub(lambda m: f"{m.group(1)}{PLACEHOLDER_PREFIX}_USER", out)
        return _POSIX_HOME.sub(lambda m: f"{m.group(1)}{PLACEHOLDER_PREFIX}_USER", out)

    def _arn(self, m: re.Match[str]) -> str:
        partition, service, region, account, resource = m.groups()
        account_part = self.tag("ACCOUNT", account) if account else ""
        return f"arn:{partition}:{service}:{region}:{account_part}:{self._resource(resource)}"

    def _resource(self, resource: str) -> str:
        # Keep the resource type prefix (role/, user/, key/) so reports stay readable.
        if resource.startswith(PLACEHOLDER_PREFIX):
            return resource
        for sep in ("/", ":"):
            head, found, tail = resource.partition(sep)
            if found and tail:
                return f"{head}{sep}{self.tag('NAME', tail)}"
        return self.tag("NAME", resource)

    def value(self, obj: Any, key: str | None = None) -> Any:
        """Redact any JSON-like value; strings under sensitive keys are dropped whole."""
        if isinstance(obj, str):
            if key is not None and _is_sensitive_key(key) and obj:
                return f"{PLACEHOLDER_PREFIX}_SECRET"
            return self.text(obj)
        if isinstance(obj, dict):
            return {self.text(str(k)): self.value(v, str(k)) for k, v in obj.items()}
        if isinstance(obj, list | tuple):
            return [self.value(v, key) for v in obj]
        return obj


def _is_sensitive_key(key: str) -> bool:
    return bool(_SENSITIVE_KEY.search(key) or _SENSITIVE_KEY_CAMEL.search(key))


def resource_names(findings: Iterable[Mapping[str, Any]]) -> set[str]:
    """Plain names behind each finding's resource_id, so evidence that repeats them gets masked."""
    out: set[str] = set()
    for f in findings:
        rid = str(f.get("resource_id", ""))
        tail = rid.rsplit(":", 1)[-1].rsplit("/", 1)[-1]
        if tail and not tail.isdigit():
            out.add(tail)
    return out


def redact(obj: Any, salt: str = "") -> Any:
    """Shortcut for Redactor(salt).value(obj)."""
    return Redactor(salt).value(obj)


def redact_file(src: Path, dst: Path, salt: str = "") -> None:
    """Redact a JSON file, or any text file line by line, into dst."""
    raw = src.read_text(encoding="utf-8", errors="replace")
    red = Redactor(salt)
    out: str
    try:
        out = json.dumps(red.value(json.loads(raw)), indent=2, ensure_ascii=False) + "\n"
    except json.JSONDecodeError:
        out = red.text(raw)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(out, encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None, write: Callable[[str], object] = sys.stderr.write) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        write("usage: python -m cspm.reports.redact SRC DST\n")
        return 2
    redact_file(Path(args[0]), Path(args[1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
