"""Print one line per finding from a findings.json report, highest score first."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> None:
    report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    findings = sorted(report["findings"], key=lambda f: (-f["score"], f["rule_id"]))
    print(f"{'band':<9}{'score':>5}  {'rule':<15}title")
    for f in findings:
        print(f"{f['band']:<9}{f['score']:>5.1f}  {f['rule_id']:<15}{f['title']}")


if __name__ == "__main__":
    main()
