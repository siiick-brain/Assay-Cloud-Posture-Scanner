"""Tests for the static allowlist check in scripts/check_allowlist.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO = Path(__file__).resolve().parents[2]
ALLOWLIST = REPO / "cspm" / "live" / "allowlist.yaml"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_allowlist", REPO / "scripts" / "check_allowlist.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_allowlist"] = module
    spec.loader.exec_module(module)
    return module


ca = _load()

GOOD = '''
import boto3
from mypy_boto3_iam import IAMClient

class Collector:
    def __init__(self) -> None:
        self.s3 = boto3.client("s3", endpoint_url="http://localhost:5000")

    def buckets(self):
        return self.s3.list_buckets()

def users(iam: IAMClient):
    pages = iam.get_paginator("list_users")
    return iam.list_mfa_devices(UserName="a")

def kms():
    client = boto3.session.Session().client(service_name="kms")
    return client.get_key_rotation_status(KeyId="k")

def chained():
    return boto3.client("ec2").describe_security_groups()
'''

BAD_WRITE = '''
import boto3

def oops():
    s3 = boto3.client("s3")
    s3.put_bucket_acl(Bucket="b", ACL="private")
'''

BAD_DENIED = '''
import boto3

def oops():
    sm = boto3.client("secretsmanager")
    return sm.get_secret_value(SecretId="x")
'''

BAD_DYNAMIC = '''
import boto3

def oops(name):
    boto3.client(name).delete_bucket(Bucket="b")
'''

BAD_PAGINATOR = '''
from mypy_boto3_ec2 import EC2Client

def oops(ec2: EC2Client):
    return ec2.get_paginator("describe_snapshots")
'''


def _write(tmp_path: Path, source: str) -> Path:
    root = tmp_path / "pkg"
    root.mkdir()
    (root / "mod.py").write_text(source, encoding="utf-8")
    return root


@pytest.mark.parametrize(
    ("method", "operation"),
    [
        ("list_buckets", "ListBuckets"),
        ("get_bucket_acl", "GetBucketAcl"),
        ("describe_db_instances", "DescribeDbInstances"),
    ],
)
def test_to_operation(method: str, operation: str) -> None:
    assert ca.to_operation(method) == operation


def test_good_sample_passes(tmp_path: Path) -> None:
    root = _write(tmp_path, GOOD)
    calls, problems = ca.check(root, ALLOWLIST)
    assert problems == []
    ops = {(c.service, c.operation) for c in calls}
    assert ("s3", "ListBuckets") in ops
    assert ("iam", "ListUsers") in ops
    assert ("iam", "ListMFADevices") in ops
    assert ("kms", "GetKeyRotationStatus") in ops
    assert ("ec2", "DescribeSecurityGroups") in ops


@pytest.mark.parametrize("source", [BAD_WRITE, BAD_DENIED, BAD_PAGINATOR])
def test_bad_sample_fails(tmp_path: Path, source: str) -> None:
    root = _write(tmp_path, source)
    assert ca.main(["--root", str(root), "--allowlist", str(ALLOWLIST)]) == 1


def test_dynamic_client_write_fails(tmp_path: Path) -> None:
    root = _write(tmp_path, BAD_DYNAMIC)
    _, problems = ca.check(root, ALLOWLIST)
    assert len(problems) == 1


def test_repo_cspm_passes() -> None:
    assert ca.main(["--root", str(REPO / "cspm"), "--allowlist", str(ALLOWLIST)]) == 0
