"""Static check: every boto3 client method the collectors call maps to an allowlisted operation."""

import re
from pathlib import Path

import boto3

from cspm.collectors.guard import load_allowlist

ROOT = Path(__file__).resolve().parents[2]
SOURCES = sorted((ROOT / "cspm").rglob("*.py"))
DIRECT = re.compile(r"\bclient\.([a-z][a-z0-9_]+)\(")
PAGED = re.compile(r'_paginate\(\s*client,\s*"([a-z0-9_]+)"')
NOT_API = {"get_paginator", "client"}


def _called_methods() -> set[str]:
    found: set[str] = set()
    for path in SOURCES:
        text = path.read_text(encoding="utf-8")
        found |= set(DIRECT.findall(text)) | set(PAGED.findall(text))
    return found - NOT_API


def _api_names() -> dict[str, set[str]]:
    """method name -> every service:Operation it can mean, for services on the allowlist."""
    allow = load_allowlist()
    services = {op.split(":")[0] for op in allow.operations}
    session = boto3.Session(region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x")
    names: dict[str, set[str]] = {}
    for svc in services:
        mapping = session.client(svc).meta.method_to_api_mapping  # type: ignore[call-overload]
        for method, op in mapping.items():
            names.setdefault(method, set()).add(f"{svc}:{op}")
    return names


def test_collectors_call_only_allowlisted_operations() -> None:
    allow = load_allowlist()
    names = _api_names()
    called = _called_methods()
    assert len(called) > 30
    unknown = sorted(m for m in called if m not in names)
    assert unknown == []
    blocked = sorted(m for m in called if not any(allow.permits(*key.split(":")) for key in names[m]))
    assert blocked == []


def test_scanner_does_not_import_botocore_clients_elsewhere() -> None:
    # Clients must come from AwsSession.client so the hook is always attached.
    offenders = [
        p.relative_to(ROOT).as_posix()
        for p in SOURCES
        if re.search(r"boto3\.(client|resource)\(|botocore\.session", p.read_text(encoding="utf-8"))
    ]
    assert offenders == []
