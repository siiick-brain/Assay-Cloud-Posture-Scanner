"""Terraform plan collector. Reads `terraform show -json` output and maps planned AWS resources to the contract."""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cspm.collectors.aws import policy_is_public
from cspm.contracts import Provider, Resource

CANNED_ACLS: dict[str, list[tuple[str, str]]] = {
    "public-read": [("http://acs.amazonaws.com/groups/global/AllUsers", "READ")],
    "public-read-write": [
        ("http://acs.amazonaws.com/groups/global/AllUsers", "READ"),
        ("http://acs.amazonaws.com/groups/global/AllUsers", "WRITE"),
    ],
    "authenticated-read": [("http://acs.amazonaws.com/groups/global/AuthenticatedUsers", "READ")],
    "log-delivery-write": [
        ("http://acs.amazonaws.com/groups/s3/LogDelivery", "WRITE"),
        ("http://acs.amazonaws.com/groups/s3/LogDelivery", "READ_ACP"),
    ],
}
POLICY_ATTACHMENTS = (
    "aws_iam_user_policy_attachment",
    "aws_iam_role_policy_attachment",
    "aws_iam_group_policy_attachment",
    "aws_iam_policy_attachment",
)


@dataclass
class PlanResource:
    address: str
    type: str
    values: dict[str, Any]
    refs: dict[str, list[str]] = field(default_factory=dict)


def _walk(module: dict[str, Any]) -> Iterator[dict[str, Any]]:
    yield from module.get("resources", [])
    for child in module.get("child_modules", []):
        yield from _walk(child)


def _doc(raw: Any) -> dict[str, Any] | None:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else None
    return None


def _first(values: dict[str, Any], key: str) -> dict[str, Any]:
    block = values.get(key) or [{}]
    first = block[0] if isinstance(block, list) and block else {}
    return first if isinstance(first, dict) else {}


class PlanIndex:
    """Planned resources plus the references between them taken from the configuration block."""

    def __init__(self, plan: dict[str, Any]) -> None:
        refs: dict[str, dict[str, list[str]]] = defaultdict(dict)
        for conf in plan.get("configuration", {}).get("root_module", {}).get("resources", []):
            for key, expr in (conf.get("expressions") or {}).items():
                if isinstance(expr, dict) and expr.get("references"):
                    refs[conf["address"]][key] = list(expr["references"])
        self.items = [
            PlanResource(r["address"], r["type"], r.get("values") or {}, refs.get(_conf_address(r["address"]), {}))
            for r in _walk(plan.get("planned_values", {}).get("root_module", {}))
            if r.get("mode", "managed") == "managed"
        ]
        self.by_address = {r.address: r for r in self.items}
        provider = plan.get("configuration", {}).get("provider_config", {}).get("aws", {})
        region = provider.get("expressions", {}).get("region", {}).get("constant_value")
        self.region = str(region) if region else "unknown"

    def of_type(self, rtype: str) -> list[PlanResource]:
        return [r for r in self.items if r.type == rtype]

    def linked(
        self, child_type: str, key: str, parent: PlanResource, name_key: str | None = None
    ) -> list[PlanResource]:
        """Children whose `key` references the parent, or matches its name when the value is known."""
        out = []
        name = parent.values.get(name_key) if name_key else None
        for child in self.of_type(child_type):
            if parent.address in child.refs.get(key, []) or (name is not None and child.values.get(key) == name):
                out.append(child)
        return out


def _conf_address(address: str) -> str:
    # Configuration addresses drop instance keys such as [0] or ["a"].
    return address.split("[", 1)[0]


def _tags(values: dict[str, Any]) -> dict[str, str]:
    raw = values.get("tags") or values.get("tags_all") or {}
    return {str(k): str(v) for k, v in raw.items()}


def _res(idx: PlanIndex, item: PlanResource, rtype: str, config: dict[str, Any], region: str | None = None) -> Resource:
    return Resource(item.address, rtype, Provider.TERRAFORM, region or idx.region, config, _tags(item.values))


def _buckets(idx: PlanIndex) -> list[Resource]:
    out = []
    for b in idx.of_type("aws_s3_bucket"):
        v = b.values
        grants: list[dict[str, Any]] = []
        for acl in idx.linked("aws_s3_bucket_acl", "bucket", b, "bucket"):
            grants += [{"grantee_uri": u, "permission": p} for u, p in CANNED_ACLS.get(acl.values.get("acl") or "", [])]
            for policy in acl.values.get("access_control_policy") or []:
                for g in policy.get("grant", []):
                    uri = _first(g, "grantee").get("uri")
                    if uri:
                        grants.append({"grantee_uri": uri, "permission": g.get("permission")})
        policy_doc = None
        for pol in idx.linked("aws_s3_bucket_policy", "bucket", b, "bucket"):
            policy_doc = _doc(pol.values.get("policy"))
        pab = {
            "block_public_acls": False,
            "ignore_public_acls": False,
            "block_public_policy": False,
            "restrict_public_buckets": False,
        }
        for block in idx.linked("aws_s3_bucket_public_access_block", "bucket", b, "bucket"):
            pab = {k: bool(block.values.get(k, False)) for k in pab}
        encryption = None
        for enc in idx.linked("aws_s3_bucket_server_side_encryption_configuration", "bucket", b, "bucket"):
            default = _first(_first(enc.values, "rule"), "apply_server_side_encryption_by_default")
            encryption = {"algorithm": default.get("sse_algorithm"), "kms_key_id": default.get("kms_master_key_id")}
        versioning = "Disabled"
        for ver in idx.linked("aws_s3_bucket_versioning", "bucket", b, "bucket"):
            versioning = str(_first(ver.values, "versioning_configuration").get("status") or "Disabled")
        logging = bool(idx.linked("aws_s3_bucket_logging", "bucket", b, "bucket"))
        config = {
            "name": v.get("bucket") or b.address,
            "acl_grants": grants,
            "policy": policy_doc,
            "policy_is_public": policy_is_public(policy_doc),
            "public_access_block": pab,
            "encryption": encryption,
            "versioning": versioning,
            "logging_enabled": logging,
        }
        out.append(_res(idx, b, "aws.s3.bucket", config))
    return out


def _ingress_from_block(rule: dict[str, Any]) -> dict[str, Any]:
    proto = str(rule.get("protocol") or rule.get("ip_protocol") or "-1")
    all_ports = proto == "-1"
    cidrs = rule.get("cidr_blocks") or ([rule["cidr_ipv4"]] if rule.get("cidr_ipv4") else [])
    v6 = rule.get("ipv6_cidr_blocks") or ([rule["cidr_ipv6"]] if rule.get("cidr_ipv6") else [])
    return {
        "protocol": proto,
        "from_port": None if all_ports else rule.get("from_port"),
        "to_port": None if all_ports else rule.get("to_port"),
        "cidrs": list(cidrs),
        "ipv6_cidrs": list(v6),
    }


def _security_groups(idx: PlanIndex) -> list[Resource]:
    out = []
    for sg in idx.of_type("aws_security_group"):
        ingress = [_ingress_from_block(r) for r in sg.values.get("ingress") or []]
        for rule in idx.linked("aws_security_group_rule", "security_group_id", sg):
            if rule.values.get("type") == "ingress":
                ingress.append(_ingress_from_block(rule.values))
        for rule in idx.linked("aws_vpc_security_group_ingress_rule", "security_group_id", sg):
            ingress.append(_ingress_from_block(rule.values))
        config = {
            "group_id": sg.values.get("id") or sg.address,
            "name": sg.values.get("name") or "",
            "vpc_id": sg.values.get("vpc_id"),
            "ingress": ingress,
        }
        out.append(_res(idx, sg, "aws.ec2.security_group", config))
    return out


def _ec2_misc(idx: PlanIndex) -> list[Resource]:
    out = []
    config: dict[str, Any]
    for vol in idx.of_type("aws_ebs_volume"):
        config = {
            "volume_id": vol.values.get("id") or vol.address,
            "encrypted": bool(vol.values.get("encrypted", False)),
            "kms_key_id": vol.values.get("kms_key_id"),
            "attached_instance_ids": [],
        }
        out.append(_res(idx, vol, "aws.ec2.volume", config))
    for setting in idx.of_type("aws_ebs_encryption_by_default"):
        config = {"ebs_encryption_by_default": bool(setting.values.get("enabled", True))}
        out.append(_res(idx, setting, "aws.ec2.region_settings", config))
    for db in idx.of_type("aws_db_instance"):
        config = {
            "identifier": db.values.get("identifier") or db.address,
            "engine": db.values.get("engine") or "",
            "publicly_accessible": bool(db.values.get("publicly_accessible", False)),
            "storage_encrypted": bool(db.values.get("storage_encrypted", False)),
            "security_group_ids": list(db.values.get("vpc_security_group_ids") or []),
        }
        out.append(_res(idx, db, "aws.rds.instance", config))
    return out


def _policy_ref(idx: PlanIndex, att: PlanResource) -> str:
    arn = att.values.get("policy_arn")
    if arn:
        return str(arn)
    for ref in att.refs.get("policy_arn", []):
        if ref in idx.by_address:
            return ref
    return ""


def _iam(idx: PlanIndex) -> list[Resource]:
    out = []
    attached_refs = {_policy_ref(idx, a) for t in POLICY_ATTACHMENTS for a in idx.of_type(t)}
    for pol in idx.of_type("aws_iam_policy"):
        arn = pol.values.get("arn") or pol.address
        config = {
            "name": pol.values.get("name") or pol.address,
            "arn": arn,
            "document": _doc(pol.values.get("policy")) or {},
            "attached": pol.address in attached_refs or arn in attached_refs,
            "aws_managed": False,
        }
        out.append(_res(idx, pol, "aws.iam.policy", config, "global"))
    for user in idx.of_type("aws_iam_user"):
        keys = [
            {"key_id_suffix": "", "status": k.values.get("status") or "Active", "created": None}
            for k in idx.linked("aws_iam_access_key", "user", user, "name")
        ]
        config = {
            "name": user.values.get("name") or user.address,
            "has_console_password": bool(idx.linked("aws_iam_user_login_profile", "user", user, "name")),
            "mfa_devices": 0,
            "access_keys": keys,
            "attached_policy_arns": [
                _policy_ref(idx, a) for a in idx.linked("aws_iam_user_policy_attachment", "user", user, "name")
            ],
            "inline_policies": [
                {"name": p.values.get("name") or p.address, "document": _doc(p.values.get("policy")) or {}}
                for p in idx.linked("aws_iam_user_policy", "user", user, "name")
            ],
        }
        out.append(_res(idx, user, "aws.iam.user", config, "global"))
    for role in idx.of_type("aws_iam_role"):
        config = {
            "name": role.values.get("name") or role.address,
            "trust_policy": _doc(role.values.get("assume_role_policy")) or {},
            "attached_policy_arns": [
                _policy_ref(idx, a) for a in idx.linked("aws_iam_role_policy_attachment", "role", role, "name")
            ],
            "inline_policies": [
                {"name": p.values.get("name") or p.address, "document": _doc(p.values.get("policy")) or {}}
                for p in idx.linked("aws_iam_role_policy", "role", role, "name")
            ],
        }
        out.append(_res(idx, role, "aws.iam.role", config, "global"))
    for pp in idx.of_type("aws_iam_account_password_policy"):
        v = pp.values
        policy = {
            "minimum_length": v.get("minimum_password_length") or 6,
            "require_symbols": bool(v.get("require_symbols", False)),
            "require_numbers": bool(v.get("require_numbers", False)),
            "require_uppercase": bool(v.get("require_uppercase_characters", False)),
            "require_lowercase": bool(v.get("require_lowercase_characters", False)),
            "max_age_days": v.get("max_password_age") or None,
        }
        # A plan cannot see the root user, so those fields keep their safe defaults.
        config = {"root_access_keys_present": False, "root_mfa_enabled": True, "password_policy": policy}
        out.append(_res(idx, pp, "aws.iam.account", config, "global"))
    return out


def _logging_and_keys(idx: PlanIndex) -> list[Resource]:
    out = []
    trails = []
    for t in idx.of_type("aws_cloudtrail"):
        config = {
            "name": t.values.get("name") or t.address,
            "is_multi_region": bool(t.values.get("is_multi_region_trail", False)),
            "is_logging": bool(t.values.get("enable_logging", True)),
            "log_file_validation": bool(t.values.get("enable_log_file_validation", False)),
            "home_region": idx.region,
        }
        trails.append(_res(idx, t, "aws.cloudtrail.trail", config))
    out += trails
    if trails:
        account = {
            "trail_names": sorted(str(t.config["name"]) for t in trails),
            "has_logging_multi_region_trail": any(
                t.config["is_multi_region"] and t.config["is_logging"] for t in trails
            ),
        }
        out.append(
            Resource("terraform:cloudtrail-account", "aws.cloudtrail.account", Provider.TERRAFORM, "global", account)
        )
    for key in idx.of_type("aws_kms_key"):
        v = key.values
        config = {
            "key_id": v.get("key_id") or key.address,
            "manager": "CUSTOMER",
            "state": "Enabled" if v.get("is_enabled", True) else "Disabled",
            "rotation_enabled": bool(v.get("enable_key_rotation", False)),
            "policy": _doc(v.get("policy")),
            "key_spec": v.get("customer_master_key_spec") or "SYMMETRIC_DEFAULT",
        }
        out.append(_res(idx, key, "aws.kms.key", config))
    for sec in idx.of_type("aws_secretsmanager_secret"):
        rotated = idx.linked("aws_secretsmanager_secret_rotation", "secret_id", sec)
        config = {
            "name": sec.values.get("name") or sec.address,
            "rotation_enabled": bool(rotated),
            "last_rotated": None,
            "created": "",
        }
        out.append(_res(idx, sec, "aws.secretsmanager.secret", config))
    return out


def resources_from_plan(plan: dict[str, Any]) -> list[Resource]:
    """Map a parsed plan document to contract resources."""
    idx = PlanIndex(plan)
    return _buckets(idx) + _security_groups(idx) + _ec2_misc(idx) + _iam(idx) + _logging_and_keys(idx)


def collect_plan(source: str | None) -> list[Resource]:
    """Read a plan JSON file. This never touches the network."""
    if not source:
        raise ValueError("Terraform plan mode needs the path to `terraform show -json` output")
    return resources_from_plan(json.loads(Path(source).read_text(encoding="utf-8")))
