"""Entry point behind `cspm tls-check [host:port] [--cert FILE]`."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cspm.tls.certs import EXPIRY_WARN_DAYS, check_certificate_file
from cspm.tls.endpoint import scan_endpoint


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cspm tls-check", description="Check a TLS endpoint or certificate files.")
    p.add_argument("target", nargs="?", help="host:port, loopback only unless --allow-remote")
    p.add_argument("--cert", type=Path, action="append", default=[], help="PEM or DER certificate file")
    p.add_argument("--ca-bundle", type=Path, help="CA bundle used to validate the endpoint chain")
    p.add_argument("--server-name", help="name to validate the certificate against (default: host)")
    p.add_argument("--allow-remote", action="store_true", help="allow a non-loopback host you own")
    p.add_argument("--warn-days", type=int, default=EXPIRY_WARN_DAYS)
    p.add_argument("--json", action="store_true")
    return p


def _split(target: str) -> tuple[str, int]:
    host, sep, port = target.rpartition(":")
    if not sep or not host or not port.isdigit():
        raise ValueError(f"target must be host:port, got {target!r}")
    return host.strip("[]"), int(port)


def main_tls_check(argv: Sequence[str] | None = None) -> int:
    """Exit 0 when nothing is flagged, 1 when something is and 2 on bad input or a refused host."""
    args = _parser().parse_args(argv)
    if not args.target and not args.cert:
        print("tls-check: give host:port or --cert", file=sys.stderr)
        return 2
    now = datetime.now(UTC)
    result: dict[str, Any] = {"certificates": {}, "endpoint": None}
    try:
        for path in args.cert:
            found = check_certificate_file(path, now, warn_days=args.warn_days)
            result["certificates"][str(path)] = [dict(v.evidence) for v in found]
        if args.target:
            host, port = _split(args.target)
            report = scan_endpoint(host, port, ca_bundle=args.ca_bundle, server_hostname=args.server_name,
                                   allow_remote=args.allow_remote, now=now)
            result["endpoint"] = report.to_dict()
    except (OSError, ValueError) as exc:
        print(f"tls-check: {exc}", file=sys.stderr)
        return 2
    flagged = [v for vs in result["certificates"].values() for v in vs]
    if result["endpoint"]:
        flagged += result["endpoint"]["violations"]
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for item in flagged:
            print(f"[{item['severity']}] {item['check']}: " + ", ".join(
                f"{k}={v}" for k, v in item.items() if k not in ("check", "severity")))
        if result["endpoint"]:
            for note in result["endpoint"]["untestable"]:
                print(f"untestable: {note}")
        print(f"{len(flagged)} issue(s)")
    return 1 if flagged else 0
