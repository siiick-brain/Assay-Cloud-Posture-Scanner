"""Shared helpers for rule classes: metadata lookup, policy parsing, time and network checks."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime
from typing import Any

from cspm.contracts.rule import RuleMeta
from cspm.contracts.rule_ids import RULE_IDS

_FROZEN = {r.id: r for r in RULE_IDS}

INTERNET_V4 = "0.0.0.0/0"
INTERNET_V6 = "::/0"


def meta(
    rule_id: str,
    *,
    rationale: str,
    impact: str,
    remediation: str,
    references: tuple[str, ...] = (),
) -> RuleMeta:
    """Build RuleMeta so title, resource type and severity always come from the frozen list."""
    frozen = _FROZEN[rule_id]
    return RuleMeta(
        id=frozen.id,
        title=frozen.summary,
        resource_types=(frozen.resource_type,),
        severity_base=frozen.severity_base,
        rationale=rationale,
        impact=impact,
        remediation=remediation,
        references=references,
    )


def as_list(value: Any) -> list[Any]:
    """IAM fields accept a single value or a list; treat both the same."""
    if value is None:
        return []
    if isinstance(value, list | tuple):
        return list(value)
    return [value]


def statements(document: Mapping[str, Any] | None) -> list[Mapping[str, Any]]:
    if not document:
        return []
    return [s for s in as_list(document.get("Statement")) if isinstance(s, Mapping)]


def allow_statements(document: Mapping[str, Any] | None) -> Iterator[tuple[int, Mapping[str, Any]]]:
    """Yield (index, statement) for Allow statements; Deny never widens access."""
    for index, stmt in enumerate(statements(document)):
        if stmt.get("Effect") == "Allow":
            yield index, stmt


def statement_label(index: int, stmt: Mapping[str, Any]) -> str:
    sid = stmt.get("Sid")
    return str(sid) if sid else f"#{index}"


def principal_is_wildcard(principal: Any) -> bool:
    """True for "*" and for any principal map whose values include "*"."""
    if principal == "*":
        return True
    if isinstance(principal, Mapping):
        return any("*" in as_list(v) for v in principal.values())
    return False


def has_condition(stmt: Mapping[str, Any]) -> bool:
    return bool(stmt.get("Condition"))


def wildcard_principal_statements(document: Mapping[str, Any] | None) -> list[str]:
    """Labels of Allow statements open to any principal with no Condition to narrow them."""
    return [
        statement_label(i, s)
        for i, s in allow_statements(document)
        if principal_is_wildcard(s.get("Principal")) and not has_condition(s)
    ]


def grants_full_admin(stmt: Mapping[str, Any]) -> bool:
    """Allow on every resource with Action "*" or with NotAction, which leaves almost everything allowed."""
    if "*" not in as_list(stmt.get("Resource")):
        return False
    actions = [str(a) for a in as_list(stmt.get("Action"))]
    if any(a in ("*", "*:*") for a in actions):
        return True
    return bool(as_list(stmt.get("NotAction")))


def admin_statements(document: Mapping[str, Any] | None) -> list[str]:
    return [statement_label(i, s) for i, s in allow_statements(document) if grants_full_admin(s)]


def parse_time(value: Any) -> datetime | None:
    """Parse an ISO 8601 string; naive values are taken as UTC because the contract says UTC."""
    if not value:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def age_days(value: Any, now: datetime) -> float | None:
    parsed = parse_time(value)
    if parsed is None:
        return None
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    return (now - parsed).total_seconds() / 86400


def is_internet_cidr(cidr: Any) -> bool:
    """Any prefix of length 0 counts, so 0.0.0.0/0 and ::/0 and odd spellings like ::0/0 all match."""
    try:
        return ipaddress.ip_network(str(cidr), strict=False).prefixlen == 0
    except ValueError:
        return False


def open_to_internet(rule: Mapping[str, Any]) -> list[str]:
    sources = as_list(rule.get("cidrs")) + as_list(rule.get("ipv6_cidrs"))
    return [str(c) for c in sources if is_internet_cidr(c)]


_TCP = {"tcp", "6"}
_UDP = {"udp", "17"}
_ALL = {"-1", "all"}


def protocol_matches(protocol: Any, wanted: frozenset[str]) -> bool:
    proto = str(protocol).lower()
    if proto in _ALL:
        return True
    if "tcp" in wanted and proto in _TCP:
        return True
    return "udp" in wanted and proto in _UDP


def covers_port(rule: Mapping[str, Any], port: int, wanted: frozenset[str] = frozenset({"tcp"})) -> bool:
    """True when the ingress entry allows `port` over one of the wanted protocols."""
    if not protocol_matches(rule.get("protocol"), wanted):
        return False
    if str(rule.get("protocol")).lower() in _ALL:
        return True
    low, high = rule.get("from_port"), rule.get("to_port")
    if low is None or high is None:
        return True
    return int(low) <= port <= int(high)


def allows_all_traffic(rule: Mapping[str, Any]) -> bool:
    proto = str(rule.get("protocol")).lower()
    if proto in _ALL:
        return True
    low, high = rule.get("from_port"), rule.get("to_port")
    if low is None or high is None:
        return True
    return int(low) <= 0 and int(high) >= 65535
