"""Collector and CLI runs against the Moto server on localhost:5000.

Set CSPM_TESTBED=insecure or CSPM_TESTBED=secure after testbed/apply.sh to also check the testbed itself.
"""

import json
import os
import urllib.request
import uuid
from pathlib import Path
from typing import Any

import boto3
import pytest
import yaml

from cspm.cli.main import main
from cspm.collectors import collect
from cspm.collectors.aws import AwsSession
from cspm.collectors.guard import BlockedOperationError
from cspm.contracts import Provider, Resource, ScanMode

ENDPOINT = "http://localhost:5000"
ROOT = Path(__file__).resolve().parents[2]
KW: dict[str, Any] = {
    "endpoint_url": ENDPOINT,
    "region_name": "us-east-1",
    "aws_access_key_id": "testing",
    "aws_secret_access_key": "testing",
}


def _server_up() -> bool:
    try:
        with urllib.request.urlopen(f"{ENDPOINT}/moto-api/", timeout=2):  # noqa: S310
            return True
    except OSError:
        return False


pytestmark = [
    pytest.mark.emulator,
    pytest.mark.skipif(not _server_up(), reason="Moto server not running on localhost:5000"),
]


def test_collects_a_bucket_created_on_the_server() -> None:
    name = f"assay-it-{uuid.uuid4().hex[:8]}"
    s3 = boto3.client("s3", **KW)
    s3.create_bucket(Bucket=name)
    try:
        rs = collect(Provider.AWS, mode=ScanMode.EMULATOR, source=ENDPOINT)
        [bucket] = [r for r in rs if r.type == "aws.s3.bucket" and r.config["name"] == name]
        assert bucket.config["encryption"] is None
        assert any(r.type == "aws.iam.account" for r in rs)
    finally:
        s3.delete_bucket(Bucket=name)


def test_write_is_blocked_against_the_server() -> None:
    name = f"assay-blocked-{uuid.uuid4().hex[:8]}"
    s3 = AwsSession(mode=ScanMode.EMULATOR, endpoint=ENDPOINT, region="us-east-1").client("s3")
    with pytest.raises(BlockedOperationError):
        s3.create_bucket(Bucket=name)
    names = [b["Name"] for b in boto3.client("s3", **KW).list_buckets()["Buckets"]]
    assert name not in names


def test_cli_scan_against_the_server(tmp_path: Path) -> None:
    assert main(["scan", "--endpoint", ENDPOINT, "--out", str(tmp_path)]) == 0
    data = json.loads((tmp_path / "resources.json").read_text())
    assert any(r["type"] == "aws.cloudtrail.account" for r in data)


def _matches(res: Resource, row: dict[str, Any]) -> bool:
    if res.type != row["resource_type"]:
        return False
    if res.type in {"aws.iam.account", "aws.cloudtrail.account"}:
        return True
    if res.type == "aws.ec2.region_settings":
        return res.region == row["resource_name"]
    return row["resource_name"] in {res.config.get("name"), res.tags.get("Name")}


@pytest.mark.skipif(os.environ.get("CSPM_TESTBED") not in {"insecure", "secure"}, reason="CSPM_TESTBED not set")
def test_testbed_resources_collected() -> None:
    stack = os.environ["CSPM_TESTBED"]
    rs = collect(Provider.AWS, mode=ScanMode.EMULATOR, source=ENDPOINT)
    truth = [
        r
        for r in yaml.safe_load((ROOT / "testbed" / "ground-truth.yaml").read_text())["ground_truth"]
        if r["provider"] == "aws"
    ]
    names = {r.config.get("name") for r in rs} | {r.tags.get("Name") for r in rs}
    if stack == "insecure":
        missing = [row for row in truth if not any(_matches(r, row) for r in rs)]
        assert missing == []
        assert {"assay-insecure-public", "assay-insecure-open", "assay-insecure-dev"} <= names
    else:
        assert {"assay-secure-data", "assay-secure-trail", "assay-secure-app", "assay-secure-svc"} <= names
        trail = next(r for r in rs if r.type == "aws.cloudtrail.account")
        assert trail.config["has_logging_multi_region_trail"] is True
        assert next(r for r in rs if r.type == "aws.ec2.region_settings").config["ebs_encryption_by_default"]
