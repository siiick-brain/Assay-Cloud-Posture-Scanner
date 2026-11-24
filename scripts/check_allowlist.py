"""Static check that every boto3 client call in cspm/ is on the read-only allowlist.

The runtime botocore hook blocks unlisted calls, but only on code paths a test
happens to run. This check reads the source instead, so CI catches a write call
on a path no test reaches.

Usage: python scripts/check_allowlist.py [--root cspm] [--allowlist cspm/live/allowlist.yaml]
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

# Client methods that run locally and never reach an AWS API.
HELPER_METHODS = frozenset({"get_paginator", "get_waiter", "can_paginate", "close"})
UNKNOWN = "?"


@dataclass(frozen=True)
class Call:
    path: Path
    line: int
    service: str
    operation: str


def to_operation(method: str) -> str:
    """Turn a boto3 snake_case method name into the API operation name."""
    return "".join(part[:1].upper() + part[1:] for part in method.split("_"))


def load_allowlist(path: Path) -> tuple[dict[str, set[str]], set[str]]:
    """Return allowed operations per service and the deny set, as the runtime hook reads them."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    prefixes = tuple(data.get("allowed_prefixes") or ())
    ops = {
        svc: {name for name in names if name.startswith(prefixes)}
        for svc, names in (data.get("operations") or {}).items()
    }
    return ops, set(data.get("deny") or [])


def _client_service(node: ast.expr) -> str | None:
    """Return the service name when node is a `<x>.client("svc")` call."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return None
    if node.func.attr != "client":
        return None
    arg: ast.expr | None = node.args[0] if node.args else None
    for kw in node.keywords:
        if kw.arg == "service_name":
            arg = kw.value
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value
    return UNKNOWN


def _target_key(node: ast.expr) -> str | None:
    """Key for a name or a `self.attr` style target so later calls can be matched."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    return None


def _annotation_name(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.rsplit(".", 1)[-1]
    return None


def _stub_types(tree: ast.Module) -> dict[str, str]:
    """Map mypy_boto3 client type names (S3Client and so on) to their service."""
    types: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            m = re.match(r"mypy_boto3_(\w+?)(?:\.|$)", node.module)
            if m:
                for alias in node.names:
                    if alias.name.endswith("Client"):
                        types[alias.asname or alias.name] = m.group(1).replace("_", "-")
    return types


def _bindings(nodes: list[ast.stmt], stub_types: dict[str, str], *, names: bool) -> dict[str, str]:
    """Client bindings made directly in these statements, not inside nested functions.

    Plain names are kept only when `names` is set, so a local `client = ...` in one
    function never leaks into another. `self.attr` bindings always count.
    """
    found: dict[str, str] = {}
    stack: list[ast.AST] = list(nodes)
    while stack:
        node = stack.pop()
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            continue
        key: str | None = None
        svc: str | None = None
        if isinstance(node, ast.Assign):
            svc = _client_service(node.value)
            for t in node.targets:
                k = _target_key(t)
                if k and svc and (names or "." in k):
                    found[k] = svc
        elif isinstance(node, ast.AnnAssign):
            key = _target_key(node.target)
            ann = _annotation_name(node.annotation)
            svc = (_client_service(node.value) if node.value else None) or stub_types.get(ann or "")
            if key and svc and (names or "." in key):
                found[key] = svc
        stack.extend(ast.iter_child_nodes(node))
    return found


def _function_bindings(fn: ast.FunctionDef | ast.AsyncFunctionDef, stub_types: dict[str, str]) -> dict[str, str]:
    local = _bindings(fn.body, stub_types, names=True)
    for arg in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]:
        ann = _annotation_name(arg.annotation)
        if ann in stub_types:
            local[arg.arg] = stub_types[ann]
    return local


def _operation(node: ast.Call, method: str) -> str | None:
    """Operation a client method call reaches, or None for local helpers."""
    if method == "get_paginator":
        first = node.args[0] if node.args else None
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return to_operation(first.value)
        return None
    if method in HELPER_METHODS:
        return None
    return to_operation(method)


def _calls_in(nodes: list[ast.stmt], clients: dict[str, str], path: Path) -> list[Call]:
    calls: list[Call] = []
    stack: list[ast.AST] = list(nodes)
    while stack:
        node = stack.pop()
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            receiver = node.func.value
            svc = _client_service(receiver)
            if svc is None:
                key = _target_key(receiver)
                svc = clients.get(key) if key else None
                # A client passed in without a typed stub still reaches AWS, so check it as dynamic.
                if svc is None and key and key.rsplit(".", 1)[-1].lower().endswith("client"):
                    svc = UNKNOWN
            op = _operation(node, node.func.attr) if svc else None
            if svc and op:
                calls.append(Call(path, node.lineno, svc, op))
        stack.extend(ast.iter_child_nodes(node))
    return calls


def find_calls(path: Path) -> list[Call]:
    """List the AWS operations a module calls through boto3 clients."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    stub_types = _stub_types(tree)
    shared = _bindings(tree.body, stub_types, names=False)
    for fn in ast.walk(tree):
        if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
            shared.update({k: v for k, v in _function_bindings(fn, stub_types).items() if "." in k})
    module = {**shared, **_bindings(tree.body, stub_types, names=True)}
    calls = _calls_in(tree.body, module, path)
    for fn in ast.walk(tree):
        if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
            calls += _calls_in(fn.body, {**shared, **_function_bindings(fn, stub_types)}, path)
    return sorted(calls, key=lambda c: c.line)


def check(root: Path, allowlist: Path) -> tuple[list[Call], list[str]]:
    """Return every client call found under root and one problem line per unlisted call."""
    ops, deny = load_allowlist(allowlist)
    # Plain CamelCase loses acronyms (ListMfaDevices for ListMFADevices), so
    # match on the lowercased name and report the allowlist spelling.
    by_lower = {svc: {op.lower(): op for op in names} for svc, names in ops.items()}
    any_lower = {op.lower() for names in ops.values() for op in names}
    deny_lower = {d.lower() for d in deny}
    calls: list[Call] = []
    problems: list[str] = []
    for path in sorted(root.rglob("*.py")):
        for c in find_calls(path):
            canonical = by_lower.get(c.service, {}).get(c.operation.lower(), c.operation)
            calls.append(Call(c.path, c.line, c.service, canonical))
    for c in calls:
        where = f"{c.path.as_posix()}:{c.line}"
        op = c.operation.lower()
        if c.service == UNKNOWN:
            # Service is only known at run time, so the operation must at least
            # be allowed for some service and denied for none.
            if op not in any_lower or any(d.endswith(f":{op}") for d in deny_lower):
                problems.append(f"{where}: {c.operation} on a dynamic client is not on the allowlist")
            continue
        if f"{c.service}:{op}" in deny_lower:
            problems.append(f"{where}: {c.service}:{c.operation} is on the deny list")
        elif op not in by_lower.get(c.service, {}):
            problems.append(f"{where}: {c.service}:{c.operation} is not on the allowlist")
    return calls, problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path("cspm"))
    parser.add_argument("--allowlist", type=Path, default=Path("cspm/live/allowlist.yaml"))
    args = parser.parse_args(argv)
    calls, problems = check(args.root, args.allowlist)
    for p in problems:
        print(p)
    if problems:
        print(f"check_allowlist: {len(problems)} unlisted call(s) out of {len(calls)}")
        return 1
    print(f"check_allowlist: ok ({len(calls)} client call(s) checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
