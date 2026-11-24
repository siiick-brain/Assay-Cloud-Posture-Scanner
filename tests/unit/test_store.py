from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cspm.contracts import FindingState, ScanMode, Severity, Source, VerificationStatus
from cspm.store import SLA_DAYS, InvalidTransitionError, ScanMeta, Store, due_date_for
from tests.unit.test_reports_fixtures import make_finding, scan_meta

T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
S3 = make_finding()
SG = make_finding("ASSAY-EC2-001", "arn:aws:ec2:us-east-1:123456789012:security-group/sg-1", Severity.CRITICAL, 9.6)
AZ = make_finding("ASSAY-AZ-KV-001", "/subscriptions/x/vaults/kv1", Severity.MEDIUM, 5.0, provider="azure")


def meta(n: int, mode: ScanMode = ScanMode.EMULATOR, **kw: object) -> ScanMeta:
    return ScanMeta(f"scan-{n}", mode, T0 + timedelta(days=n), **kw)  # type: ignore[arg-type]


@pytest.fixture
def store() -> Iterator[Store]:
    with Store(":memory:") as s:
        yield s


def states(store: Store, fid: str) -> list[str]:
    return [t.to_state.value for t in store.history(fid)]


def test_first_sighting_is_new_with_sla(store: Store) -> None:
    diff = store.record_scan(meta(0), [S3, SG])
    assert set(diff.new) == {S3.id, SG.id}
    got = store.get(SG.id)
    assert got is not None
    assert got.state is FindingState.NEW
    assert got.verification_status is VerificationStatus.NOT_VERIFIED
    assert got.due_date == T0 + timedelta(days=7)
    assert store.get(S3.id).due_date == T0 + timedelta(days=30)  # type: ignore[union-attr]


def test_second_sighting_opens(store: Store) -> None:
    store.record_scan(meta(0), [S3])
    diff = store.record_scan(meta(1), [S3])
    assert diff.still_open == (S3.id,)
    assert states(store, S3.id) == ["new", "open"]
    store.record_scan(meta(2), [S3])
    assert states(store, S3.id) == ["new", "open"]


def test_assign_sets_owner(store: Store) -> None:
    store.record_scan(meta(0), [S3])
    got = store.assign(S3.id, "alice", at=T0, actor="lead")
    assert got.state is FindingState.ASSIGNED
    assert got.owner == "alice"
    last = store.history(S3.id)[-1]
    assert (last.actor, last.note, last.scan_id) == ("lead", "assigned to alice", None)
    store.record_scan(meta(1), [S3])
    assert store.get(S3.id).state is FindingState.ASSIGNED  # type: ignore[union-attr]


def test_fixed_claimed_then_rescan_clean_closes_verified(store: Store) -> None:
    store.record_scan(meta(0), [S3, SG])
    store.assign(S3.id, "bob")
    store.claim_fixed(S3.id, note="turned on BPA")
    diff = store.record_scan(meta(1), [SG])
    assert diff.closed == (S3.id,)
    got = store.get(S3.id)
    assert got is not None
    assert got.state is FindingState.VERIFIED_CLOSED
    assert got.verification_status is VerificationStatus.VERIFIED
    assert got.closed_at == T0 + timedelta(days=1)
    assert states(store, S3.id) == ["new", "assigned", "fixed_claimed", "verified_closed"]
    assert store.history(S3.id)[-1].note == "absent on rescan after fix claim"


def test_fixture_mode_rescan_is_verified(store: Store) -> None:
    store.record_scan(meta(0, ScanMode.FIXTURE), [S3])
    store.record_scan(meta(1, ScanMode.FIXTURE), [])
    assert store.get(S3.id).verification_status is VerificationStatus.VERIFIED  # type: ignore[union-attr]


def test_live_rescan_is_observed_unverified_never_verified(store: Store) -> None:
    store.record_scan(meta(0, ScanMode.LIVE), [S3])
    store.claim_fixed(S3.id)
    store.record_scan(meta(1, ScanMode.LIVE), [])
    got = store.get(S3.id)
    assert got is not None
    assert got.state is FindingState.VERIFIED_CLOSED
    assert got.verification_status is VerificationStatus.OBSERVED_UNVERIFIED
    assert all(t.verification_status is not VerificationStatus.VERIFIED for t in store.history(S3.id))


def test_rescan_still_failing_after_claim_reopens(store: Store) -> None:
    store.record_scan(meta(0), [S3])
    store.claim_fixed(S3.id)
    diff = store.record_scan(meta(1), [S3])
    assert diff.reopened == (S3.id,)
    got = store.get(S3.id)
    assert got is not None
    assert got.state is FindingState.REOPENED
    assert got.verification_status is VerificationStatus.NOT_VERIFIED
    assert store.history(S3.id)[-1].note == "rescan still fails after fix claim"


def test_regression_after_closure_reopens_with_new_due_date(store: Store) -> None:
    store.record_scan(meta(0), [S3])
    store.record_scan(meta(1), [])
    diff = store.record_scan(meta(5), [S3])
    assert diff.reopened == (S3.id,)
    got = store.get(S3.id)
    assert got is not None
    assert got.state is FindingState.REOPENED
    assert got.closed_at is None
    assert got.first_seen == T0
    assert got.due_date == T0 + timedelta(days=5 + SLA_DAYS[Severity.HIGH])  # type: ignore[operator]
    assert states(store, S3.id) == ["new", "verified_closed", "reopened"]
    store.assign(S3.id, "carol")
    store.claim_fixed(S3.id)
    store.record_scan(meta(6), [])
    assert store.get(S3.id).state is FindingState.VERIFIED_CLOSED  # type: ignore[union-attr]


def test_closed_finding_stays_closed_when_absent(store: Store) -> None:
    store.record_scan(meta(0), [S3])
    store.record_scan(meta(1), [])
    diff = store.record_scan(meta(2), [])
    assert diff.closed == ()
    assert len(store.history(S3.id)) == 2


def test_out_of_scope_findings_are_not_closed(store: Store) -> None:
    store.record_scan(meta(0), [S3, AZ])
    trivy = meta(1, sources=frozenset({Source.TRIVY}))
    assert store.record_scan(trivy, []).closed == ()
    aws_only = meta(2, providers=frozenset({"aws"}))
    diff = store.record_scan(aws_only, [])
    assert diff.closed == (S3.id,)
    assert store.get(AZ.id).state is FindingState.NEW  # type: ignore[union-attr]


def test_invalid_manual_transitions(store: Store) -> None:
    store.record_scan(meta(0), [S3])
    store.record_scan(meta(1), [])
    with pytest.raises(InvalidTransitionError):
        store.claim_fixed(S3.id)
    with pytest.raises(InvalidTransitionError):
        store.assign(S3.id, "dan")
    with pytest.raises(KeyError):
        store.assign("0" * 16, "dan")
    store.record_scan(meta(2), [S3])
    with pytest.raises(ValueError, match="owner"):
        store.assign(S3.id, " ")
    store.claim_fixed(S3.id)
    with pytest.raises(InvalidTransitionError):
        store.claim_fixed(S3.id)


def test_duplicate_scan_id_rejected(store: Store) -> None:
    store.record_scan(meta(0), [S3])
    with pytest.raises(ValueError, match="already recorded"):
        store.record_scan(meta(0), [S3])


def test_duplicate_findings_in_one_scan_keep_highest_score(store: Store) -> None:
    low = make_finding(score=3.0)
    high = make_finding(score=8.5)
    store.record_scan(meta(0), [low, high, low])
    assert store.get(low.id).score == 8.5  # type: ignore[union-attr]


def test_stored_data_is_redacted(store: Store) -> None:
    f = make_finding(evidence={"note": "key AKIAIOSFODNN7EXAMPLE", "password": "pw1"})
    store.record_scan(meta(0), [f, SG])
    got = store.get(SG.id)
    assert got is not None
    assert "123456789012" not in got.resource_id
    assert got.data["id"] == SG.id
    raw = store.get(f.id).data  # type: ignore[union-attr]
    assert raw["evidence"]["password"] == "REDACTED_SECRET"
    assert "AKIA" not in raw["evidence"]["note"]


def test_report_scan_dict_accepted_and_persisted(tmp_path: Path) -> None:
    db = tmp_path / "s.db"
    with Store(db) as s:
        diff = s.record_scan(scan_meta("r1"), [S3])
        assert diff.mode is ScanMode.EMULATOR
    with Store(db) as s:
        assert s.scan_ids() == ["r1"]
        assert s.get(S3.id) is not None


def test_scan_meta_from_dict_without_providers() -> None:
    raw = scan_meta() | {"providers": [], "started_at": None}
    m = ScanMeta.from_dict(raw, sources=[Source.CHECKOV])
    assert m.providers is None
    assert m.started_at is None
    assert m.sources == frozenset({Source.CHECKOV})


def test_diff_between_scans(store: Store) -> None:
    sg_low = make_finding(SG.rule_id, SG.resource_id, Severity.HIGH, 7.0)
    store.record_scan(meta(0), [S3, SG])
    store.record_scan(meta(1), [sg_low, AZ])
    d = store.diff("scan-0", "scan-1")
    assert d.added == (AZ.id,)
    assert d.removed == (S3.id,)
    assert d.persisting == (SG.id,)
    assert d.band_changed == ((SG.id, "critical", "high"),)
    with pytest.raises(KeyError):
        store.diff("scan-0", "nope")


def test_trend_counts(store: Store) -> None:
    store.record_scan(meta(0), [S3, SG])
    store.record_scan(meta(1), [SG])
    store.record_scan(meta(2), [SG, S3])
    t = store.trend()
    assert [p.scan_id for p in t] == ["scan-0", "scan-1", "scan-2"]
    assert (t[0].new, t[0].closed, t[0].reopened, t[0].active_after) == (2, 0, 0, 2)
    assert (t[1].new, t[1].closed, t[1].active_after, t[1].observed) == (0, 1, 1, 1)
    assert (t[2].reopened, t[2].active_after) == (1, 2)
    assert t[0].by_band["critical"] == 1 and t[0].by_band["high"] == 1


def test_findings_filter_and_overdue(store: Store) -> None:
    info = make_finding("ASSAY-S3-005", "arn:aws:s3:::logs", Severity.INFO, 0.5)
    store.record_scan(meta(0), [S3, SG, info])
    assert store.findings()[0].id == SG.id
    assert store.findings([FindingState.VERIFIED_CLOSED]) == []
    assert store.get(info.id).due_date is None  # type: ignore[union-attr]
    late = store.overdue(T0 + timedelta(days=8))
    assert [f.id for f in late] == [SG.id]
    assert {f.id for f in store.overdue(T0 + timedelta(days=400))} == {S3.id, SG.id}
    assert len(store.history()) == 3


def test_due_date_for_every_band() -> None:
    for band, days in SLA_DAYS.items():
        expected = None if days is None else T0 + timedelta(days=days)
        assert due_date_for(band, T0) == expected
