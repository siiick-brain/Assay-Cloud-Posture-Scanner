from pathlib import Path

import pytest
from moto import mock_aws

from cspm.collectors.aws import AwsSession
from cspm.collectors.guard import (
    BlockedOperationError,
    EndpointRefusedError,
    LiveModeRefusedError,
    check_emulator_endpoint,
    check_live_allowed,
    enforce_allowlist,
    load_allowlist,
)
from cspm.contracts import ScanMode


@pytest.fixture
def session() -> AwsSession:
    s = AwsSession(mode=ScanMode.EMULATOR, endpoint="http://localhost:5000", region="us-east-1")
    # Route to the in-process mock instead of the server.
    s.endpoint = None
    return s


def test_allowlist_rules() -> None:
    allow = load_allowlist()
    assert allow.permits("s3", "ListBuckets")
    assert not allow.permits("s3", "PutBucketAcl")
    assert not allow.permits("secretsmanager", "GetSecretValue")
    assert not allow.permits("s3", "GetObject")
    assert not allow.permits("ec2", "DescribeImages")


def test_deny_wins_even_when_listed(tmp_path: Path) -> None:
    f = tmp_path / "allow.yaml"
    f.write_text(
        "allowed_prefixes: [Get]\ndeny: [s3:GetObject]\noperations:\n  s3: [GetObject, GetBucketAcl, PutObject]\n"
    )
    allow = load_allowlist(f)
    assert not allow.permits("s3", "GetObject")
    assert allow.permits("s3", "GetBucketAcl")
    assert not allow.permits("s3", "PutObject")


@mock_aws
def test_write_calls_are_blocked_before_sending(session: AwsSession) -> None:
    s3 = session.client("s3")
    with pytest.raises(BlockedOperationError, match="s3:CreateBucket"):
        s3.create_bucket(Bucket="should-not-exist")
    with pytest.raises(BlockedOperationError, match="s3:PutBucketAcl"):
        s3.put_bucket_acl(Bucket="x", ACL="public-read")
    assert s3.list_buckets()["Buckets"] == []


@mock_aws
def test_secret_values_are_blocked(session: AwsSession) -> None:
    with pytest.raises(BlockedOperationError, match="secretsmanager:GetSecretValue"):
        session.client("secretsmanager").get_secret_value(SecretId="anything")


@mock_aws
def test_unlisted_read_is_blocked(session: AwsSession) -> None:
    with pytest.raises(BlockedOperationError, match="ec2:DescribeImages"):
        session.client("ec2").describe_images()


def test_hook_without_model_refuses() -> None:
    with pytest.raises(BlockedOperationError):
        enforce_allowlist()


@pytest.mark.parametrize(
    "endpoint", ["http://localhost:5000", "http://127.0.0.1:5000", "http://moto:5000", "https://localhost"]
)
def test_emulator_hosts_accepted(endpoint: str) -> None:
    assert check_emulator_endpoint(endpoint) == endpoint


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://s3.amazonaws.com",
        "http://169.254.169.254",
        "http://localhost.evil.example:5000",
        "ftp://localhost",
        "localhost:5000",
        "http://10.0.0.5:5000",
    ],
)
def test_other_hosts_refused(endpoint: str) -> None:
    with pytest.raises(EndpointRefusedError):
        check_emulator_endpoint(endpoint)


def test_session_refuses_remote_endpoint() -> None:
    with pytest.raises(EndpointRefusedError):
        AwsSession(mode=ScanMode.EMULATOR, endpoint="https://ec2.us-east-1.amazonaws.com", region="us-east-1")


def test_live_needs_flag_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CSPM_ALLOW_LIVE", raising=False)
    with pytest.raises(LiveModeRefusedError):
        check_live_allowed(True)
    monkeypatch.setenv("CSPM_ALLOW_LIVE", "1")
    with pytest.raises(LiveModeRefusedError):
        check_live_allowed(False)
    check_live_allowed(True)
    monkeypatch.setenv("CSPM_ALLOW_LIVE", "yes")
    with pytest.raises(LiveModeRefusedError):
        check_live_allowed(True)


def test_live_session_refused_without_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CSPM_ALLOW_LIVE", raising=False)
    with pytest.raises(LiveModeRefusedError):
        AwsSession(mode=ScanMode.LIVE, endpoint=None, region="us-east-1")


def test_live_session_needs_env_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CSPM_ALLOW_LIVE", "1")
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    with pytest.raises(RuntimeError, match="AWS_ACCESS_KEY_ID"):
        AwsSession(mode=ScanMode.LIVE, endpoint=None, region="us-east-1")


def test_live_session_rejects_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CSPM_ALLOW_LIVE", "1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLEONLY")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "example-only")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "example-token")
    with pytest.raises(ValueError, match="endpoint"):
        AwsSession(mode=ScanMode.LIVE, endpoint="http://localhost:5000", region="us-east-1")
    s = AwsSession(mode=ScanMode.LIVE, endpoint=None, region="us-east-1")
    assert s.endpoint is None


def test_emulator_session_ignores_real_env_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAREALLOOKING")
    s = AwsSession(mode=ScanMode.EMULATOR, endpoint=None, region="us-east-1")
    creds = s._session.get_credentials()
    assert creds is not None
    assert creds.access_key == "testing"
