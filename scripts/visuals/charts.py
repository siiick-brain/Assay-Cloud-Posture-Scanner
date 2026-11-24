"""Draw the README charts: findings per band from a real report and seeded issues found per tool."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

BANDS = ["critical", "high", "medium", "low", "info"]
BAND_COLOURS = ["#c62828", "#ef6c00", "#f9a825", "#1565c0", "#757575"]
TOOLS = ["Trivy config", "Checkov", "Prowler iac", "assay-cspm"]
ROW = "| Seeded AWS issues found (of 16) |"


def _style(ax: plt.Axes) -> None:
    ax.spines[["top", "right"]].set_visible(False)
    ax.set_axisbelow(True)
    ax.grid(axis="y", color="#e0e0e0")


def _label_bars(ax: plt.Axes, bars: object, values: list[int]) -> None:
    for bar, value in zip(bars, values, strict=True):  # type: ignore[call-overload]
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.15, str(value), ha="center", va="bottom")


def severity_chart(findings_json: Path, out: Path) -> dict[str, int]:
    report = json.loads(findings_json.read_text(encoding="utf-8"))
    counts = Counter(f["band"] for f in report["findings"])
    values = [counts.get(b, 0) for b in BANDS]
    fig, ax = plt.subplots(figsize=(7, 4), dpi=150, facecolor="white")
    bars = ax.bar(BANDS, values, color=BAND_COLOURS)
    _label_bars(ax, bars, values)
    _style(ax)
    ax.set_xlabel("Severity band")
    ax.set_ylabel("Findings")
    ax.set_ylim(0, max(values) + 1.5)
    ax.set_title(f"assay-cspm on the insecure Moto testbed: {sum(values)} findings")
    fig.tight_layout()
    fig.savefig(out, facecolor="white")
    plt.close(fig)
    return dict(zip(BANDS, values, strict=True))


def comparison_numbers(doc: Path) -> list[int]:
    for line in doc.read_text(encoding="utf-8").splitlines():
        if line.startswith(ROW):
            return [int(c) for c in re.findall(r"\|\s*(\d+)\s*(?=\|)", line[len(ROW) - 1 :])]
    raise SystemExit(f"row not found in {doc}: {ROW}")


def comparison_chart(doc: Path, out: Path) -> list[int]:
    values = comparison_numbers(doc)
    if len(values) != len(TOOLS):
        raise SystemExit(f"expected {len(TOOLS)} numbers, got {values}")
    fig, ax = plt.subplots(figsize=(7, 4), dpi=150, facecolor="white")
    colours = ["#90a4ae"] * 3 + ["#2e7d32"]
    bars = ax.bar(TOOLS, values, color=colours)
    _label_bars(ax, bars, values)
    _style(ax)
    ax.axhline(16, color="#424242", linestyle="--", linewidth=1)
    ax.text(-0.4, 16.2, "16 seeded", va="bottom", fontsize=9, color="#424242")
    ax.set_xlabel("Tool")
    ax.set_ylabel("Seeded AWS issues found (of 16)")
    ax.set_ylim(0, 18.5)
    ax.set_title("Seeded issues found on the insecure testbed")
    fig.tight_layout()
    fig.savefig(out, facecolor="white")
    plt.close(fig)
    return values


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", type=Path, required=True)
    parser.add_argument("--comparison-doc", type=Path, default=Path("docs/tool-comparison.md"))
    parser.add_argument("--out-dir", type=Path, default=Path("docs/images"))
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    print("bands", severity_chart(args.findings, args.out_dir / "findings-by-severity.png"))
    print(
        "tools",
        dict(zip(TOOLS, comparison_chart(args.comparison_doc, args.out_dir / "tool-comparison.png"), strict=True)),
    )


if __name__ == "__main__":
    main()
