"""Security group ingress rules."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from cspm.contracts.resource import Resource
from cspm.contracts.rule import ScanContext, Violation
from rules._base import allows_all_traffic, covers_port, meta, open_to_internet

DB_PORTS: tuple[int, ...] = (1433, 1521, 3306, 5432, 5439, 6379, 9200, 27017)


def _open_entries(resource: Resource, matches: Callable[[Mapping[str, Any]], bool]) -> list[Violation]:
    hits = []
    for entry in resource.config.get("ingress") or []:
        sources = open_to_internet(entry)
        if sources and matches(entry):
            hits.append(
                {
                    "protocol": str(entry.get("protocol")),
                    "from_port": entry.get("from_port"),
                    "to_port": entry.get("to_port"),
                    "sources": sources,
                }
            )
    if not hits:
        return []
    evidence = {"group_id": resource.config.get("group_id"), "open_ingress": hits}
    return [Violation(evidence=evidence, exposure="internet")]


class SgSshOpen:
    meta = meta(
        "ASSAY-EC2-001",
        rationale="SSH from anywhere invites constant password and key guessing against every attached host.",
        impact="A weak key, leaked key or SSH bug becomes a direct shell on the host.",
        remediation="Limit port 22 to known admin ranges or remove it and use Session Manager.",
        references=("https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        return _open_entries(resource, lambda e: covers_port(e, 22))


class SgRdpOpen:
    meta = meta(
        "ASSAY-EC2-002",
        rationale="RDP from anywhere is a top entry point for ransomware crews.",
        impact="Brute force or an RDP flaw gives interactive control of a Windows host.",
        remediation="Limit port 3389 to known admin ranges or reach hosts through Fleet Manager or a bastion.",
        references=("https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        return _open_entries(resource, lambda e: covers_port(e, 3389, frozenset({"tcp", "udp"})))


class SgDatabaseOpen:
    meta = meta(
        "ASSAY-EC2-003",
        rationale="Database listeners should only accept connections from application tiers.",
        impact="The database login and any unauthenticated service such as Redis is reachable from the internet.",
        remediation="Restrict database ports to the security groups of the application tier.",
        references=("https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        return _open_entries(resource, lambda e: any(covers_port(e, p) for p in DB_PORTS))


class SgAllTrafficOpen:
    meta = meta(
        "ASSAY-EC2-004",
        rationale="Allowing every port and protocol from anywhere removes the network layer entirely.",
        impact="Every service on every attached host is exposed, including ones never meant to listen publicly.",
        remediation="Replace the rule with entries for the specific ports the workload serves.",
        references=("https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html",),
    )

    def evaluate(self, resource: Resource, ctx: ScanContext) -> list[Violation]:
        return _open_entries(resource, allows_all_traffic)
