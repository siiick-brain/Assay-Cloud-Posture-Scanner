"""SHA-256 manifest for one report set and its verification."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

MANIFEST_NAME = "manifest.json"


def sha256_file(path: Path) -> str:
    """Hex SHA-256 of a file."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest(out_dir: Path, files: Sequence[str], scan_id: str) -> Path:
    """Write manifest.json listing each file with its size and digest."""
    entries = [
        {"path": name, "sha256": sha256_file(out_dir / name), "bytes": (out_dir / name).stat().st_size}
        for name in sorted(files)
    ]
    manifest: dict[str, Any] = {"algorithm": "sha256", "scan_id": scan_id, "files": entries}
    path = out_dir / MANIFEST_NAME
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return path


def verify_manifest(manifest_path: Path) -> list[str]:
    """Return problems found; an empty list means every listed file matches."""
    base = manifest_path.parent
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    problems: list[str] = []
    for entry in manifest.get("files", []):
        name = str(entry["path"])
        target = (base / name).resolve()
        # A tampered manifest must not point the check outside the report folder.
        if base.resolve() not in target.parents:
            problems.append(f"{name}: outside report folder")
        elif not target.is_file():
            problems.append(f"{name}: missing")
        elif sha256_file(target) != entry["sha256"]:
            problems.append(f"{name}: digest mismatch")
    if not manifest.get("files"):
        problems.append("manifest lists no files")
    return problems
