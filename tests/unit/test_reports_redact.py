import json
from pathlib import Path

import pytest

from cspm.reports.redact import Redactor, main, redact, redact_file, resource_names

R = Redactor()
# Split so secret scanners do not flag the synthetic test inputs.
KEY_HEAD = "-----BEGIN RSA " + "PRIVATE KEY-----"


@pytest.mark.parametrize(
    ("raw", "gone"),
    [
        ("key AKIAIOSFODNN7EXAMPLE in log", "AKIAIOSFODNN7EXAMPLE"),
        ("temp ASIA" + "QWERTYUIOPASDFGH", "QWERTYUIOPASDFGH"),
        ("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI"),
        ('"SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"', "wJalrXUtnFEMI"),
        ("password=hunter2&user=bob", "hunter2"),
        ('PASSWORD: "c0rrect horse"', "c0rrect horse"),
        ("postgres://admin:s3cr3tP@db.local:5432/x", "s3cr3tP"),
        ("Authorization: Bearer abcdef1234567890.xyz", "abcdef1234567890"),
        ("token eyJ" + "hbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.c2lnbmF0dXJl end", "hbGciOiJIUzI1NiJ9"),
        ("ghp_" + "a" * 36, "ghp_aaaa"),
        ("xoxb-1234567890-abcdefghij", "xoxb-1234567890"),
        (KEY_HEAD + "\nMIIEow\nabc\n-----END RSA PRIVATE KEY-----", "MIIEow"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----\ntruncated with no end", "truncated"),
        ("account 123456789012 owns it", "123456789012"),
        ("arn:aws:iam::123456789012:role/admin", "123456789012"),
        ("C:\\Users\\Davis\\Desktop\\x.tf", "Davis"),
        ("/home/alice/project/main.tf", "alice"),
        ("/Users/bob/src", "bob"),
    ],
)
def test_sensitive_values_removed(raw: str, gone: str) -> None:
    out = R.text(raw)
    assert gone not in out
    assert "REDACTED" in out


@pytest.mark.parametrize(
    "safe",
    [
        "sha 3f786850e387550fdab836ed7e6dc881de23001b",
        "id 0123456789abcdef",
        "epoch 1732363200123",
        "phone 1234567890123",
        "port 22 open to 0.0.0.0/0",
        "kms_key_id alias/aws/s3",
        "2026-11-23T12:00:00+00:00",
        "bucket-123456789012x",
    ],
)
def test_harmless_values_kept(safe: str) -> None:
    assert R.text(safe) == safe


def test_placeholders_are_stable_and_salted() -> None:
    a = R.text("arn:aws:iam::123456789012:role/admin")
    assert a == Redactor().text("arn:aws:iam::123456789012:role/admin")
    assert a.startswith("arn:aws:iam::REDACTED_ACCOUNT_")
    assert ":role/REDACTED_NAME_" in a
    assert Redactor("pepper").text("123456789012") != R.text("123456789012")
    assert R.text("111111111111") != R.text("222222222222")


def test_arn_without_account_and_without_type() -> None:
    out = R.text("arn:aws:s3:::my-private-bucket")
    assert out.startswith("arn:aws:s3:::REDACTED_NAME_")
    assert "my-private-bucket" not in out
    assert R.text(out) == out


def test_arn_account_matches_bare_account() -> None:
    bare = R.text("123456789012")
    assert bare in R.text("arn:aws:kms:eu-west-1:123456789012:key/abc")


def test_nested_structures_and_sensitive_keys() -> None:
    data = {
        "password_policy": {"minimum_length": 8},
        "has_console_password": True,
        "client_secret": "abc",
        "ClientSecret": "abc",
        "secret_name": "prod/db",
        "items": ["123456789012", {"api_key": "zzz"}],
        "arn:aws:iam::123456789012:root": "x",
        "empty_token": "",
        "count": 3,
    }
    out = redact(data)
    assert out["password_policy"] == {"minimum_length": 8}
    assert out["has_console_password"] is True
    assert out["client_secret"] == "REDACTED_SECRET"
    assert out["ClientSecret"] == "REDACTED_SECRET"
    assert out["secret_name"] == "prod/db"
    assert out["items"][0].startswith("REDACTED_ACCOUNT_")
    assert out["items"][1]["api_key"] == "REDACTED_SECRET"
    assert out["empty_token"] == ""
    assert out["count"] == 3
    assert not any("123456789012" in k for k in out)


def test_redact_file_json_and_text(tmp_path: Path) -> None:
    src = tmp_path / "in.json"
    src.write_text(json.dumps({"Target": "/home/carol/x", "a": "123456789012"}))
    dst = tmp_path / "out" / "o.json"
    redact_file(src, dst)
    assert "carol" not in dst.read_text() and "123456789012" not in dst.read_text()
    txt = tmp_path / "in.txt"
    txt.write_text("account 123456789012\n")
    assert main([str(txt), str(tmp_path / "o.txt")]) == 0
    assert "123456789012" not in (tmp_path / "o.txt").read_text()


def test_main_usage() -> None:
    seen: list[str] = []
    assert main([], write=seen.append) == 2
    assert "usage" in seen[0]


def test_bare_resource_names_in_evidence_are_masked() -> None:
    findings = [{"resource_id": "arn:aws:s3:::assay-insecure-unencrypted"}, {"resource_id": "sg-0abc123"}]
    r = Redactor("salt", resource_names(findings))
    out = r.value({"bucket": "assay-insecure-unencrypted", "note": "group sg-0abc123 open", "other": "keep-me"})
    assert "assay-insecure-unencrypted" not in str(out)
    assert "sg-0abc123" not in str(out)
    assert out["other"] == "keep-me"
    assert out["bucket"] == r.value({"x": "assay-insecure-unencrypted"})["x"]
