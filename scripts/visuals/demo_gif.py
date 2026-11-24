"""Build the remediation demo GIF from the recorded output in docs/demo/remediation-demo.md."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

from PIL import Image

sys.path.insert(0, str(Path(__file__).parent))
from term_render import render


def code_blocks(md: str) -> list[list[str]]:
    return [block.splitlines() for block in re.findall(r"```text\n(.*?)```", md, flags=re.S)]


def split_on(lines: list[str], start: re.Pattern[str]) -> list[list[str]]:
    groups: list[list[str]] = []
    for line in lines:
        if start.match(line) or not groups:
            groups.append([])
        groups[-1].append(line)
    return groups


def frames_text(md: str) -> list[list[str]]:
    scans_block, store_block = code_blocks(md)[:2]
    scans = split_on(scans_block, re.compile(r"\$ terraform apply"))
    trend_at = next(i for i, line in enumerate(store_block) if line.startswith("trend:"))
    steps = split_on(store_block[1:trend_at], re.compile(r"step \d+:"))
    if len(scans) != len(steps):
        raise SystemExit(f"{len(scans)} scan groups but {len(steps)} store steps")
    frames = []
    for i, (scan, step) in enumerate(zip(scans, steps, strict=True)):
        header = f"# fix-and-rescan demo, step {i} of {len(scans) - 1} (recorded against Moto 5.2.6)"
        frames.append([header, *scan, "", store_block[0], *step])
    frames.append(["# finding counts per scan, read back from the store", "", *store_block[trend_at:]])
    return frames


def build(md_path: Path, out: Path, work: Path, seconds: float) -> None:
    frames = frames_text(md_path.read_text(encoding="utf-8"))
    rows = max(len(f) for f in frames)
    cols = max(len(line) for f in frames for line in f)
    work.mkdir(parents=True, exist_ok=True)
    pngs = []
    for i, text in enumerate(frames):
        padded = text + [""] * (rows - len(text))
        pngs.append(render(padded, work / f"frame{i:02d}.png", "remediation demo", size=13, min_cols=cols))
    ffmpeg = shutil.which("ffmpeg")
    if ffmpeg:
        listing = work / "frames.txt"
        entries = [
            f"file '{p.name}'\nduration {seconds * (2 if i in (0, len(pngs) - 1) else 1)}" for i, p in enumerate(pngs)
        ]
        # The concat demuxer drops the last duration unless the last file repeats.
        listing.write_text("\n".join(entries) + f"\nfile '{pngs[-1].name}'\n", encoding="utf-8")
        filters = "split[a][b];[a]palettegen=max_colors=64[p];[b][p]paletteuse=dither=none"
        # ffmpeg comes from PATH and every argument is built here, not read from input.
        subprocess.run(  # noqa: S603
            [
                ffmpeg,
                "-y",
                "-loglevel",
                "error",
                "-f",
                "concat",
                "-i",
                listing.name,
                "-vf",
                filters,
                "-loop",
                "0",
                str(out),
            ],
            check=True,
            cwd=work,
        )
        print(f"ffmpeg: {len(pngs)} frames -> {out}")
        return
    images = [Image.open(p).convert("P", palette=Image.Palette.ADAPTIVE, colors=64) for p in pngs]
    durations = [int(seconds * 1000 * (2 if i in (0, len(images) - 1) else 1)) for i in range(len(images))]
    images[0].save(out, save_all=True, append_images=images[1:], duration=durations, loop=0, optimize=True)
    print(f"pillow (ffmpeg not found): {len(images)} frames -> {out}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--md", type=Path, default=Path("docs/demo/remediation-demo.md"))
    parser.add_argument("--out", type=Path, default=Path("docs/images/demo.gif"))
    parser.add_argument("--work", type=Path, default=Path("artifacts/vis/frames"))
    parser.add_argument("--seconds", type=float, default=2.5)
    args = parser.parse_args()
    build(args.md, args.out.resolve(), args.work, args.seconds)


if __name__ == "__main__":
    main()
