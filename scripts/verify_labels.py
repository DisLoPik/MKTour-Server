"""Phase 3 check: load out/rizin/labels.rz into rizin in timed chunks and spot-check labels.

Usage: python scripts/verify_labels.py [--chunk 20000] [--limit N]
Opens libil2cpp.so once via rzpipe (default rizin config, like `rizin -i labels.rz libil2cpp.so`),
then runs the script chunk by chunk with `. <file>` and reports the time per chunk and the command mix,
so a slow command type is visible. Errors: rizin prints them on stderr; rzpipe does not capture stderr,
so error-checking of the full file is done separately with a plain `rizin -i` run (see NOTES.md).
"""
import argparse
import re

import time
from collections import Counter
from pathlib import Path

import rzpipe

ROOT = Path(__file__).resolve().parent.parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chunk", type=int, default=20000)
    ap.add_argument("--limit", type=int, default=0, help="stop after N lines (0 = all)")
    args = ap.parse_args()
    lines = (ROOT / "out/rizin/labels.rz").read_text(encoding="utf-8").splitlines()
    if args.limit:
        lines = lines[: args.limit]
    t0 = time.time()
    rz = rzpipe.open(str(ROOT / "work/originals/libil2cpp.so"), flags=["-2"])
    print(f"opened in {time.time() - t0:.0f}s", flush=True)
    tmpdir = ROOT / "work/rz_chunks"
    tmpdir.mkdir(parents=True, exist_ok=True)
    for i in range(0, len(lines), args.chunk):
        part = lines[i:i + args.chunk]
        mix = Counter(re.match(r"^(\S+)", l).group(1) for l in part if l and not l.startswith("#"))
        f = tmpdir / f"chunk_{i}.rz"
        f.write_text("\n".join(part) + "\n", encoding="utf-8")
        t = time.time()
        rz.cmd(f". {f.as_posix()}")
        dt = time.time() - t
        print(f"lines {i:>7}-{i + len(part):>7}: {dt:7.1f}s  {dict(mix.most_common(4))}", flush=True)
    print(f"total {time.time() - t0:.0f}s")
    print("flag count:", rz.cmd("f~?").strip(), " comments:", rz.cmd("CCl~?").strip())
    first = next(l for l in lines if l.startswith("f+ "))
    print("first flag line:", first, "->", rz.cmd(f"fl. @ {first.rsplit('@', 1)[1].strip()}").strip())
    for addr in ("0x3dd77c8", "0x53c63d4", "0x5b8b270"):
        print(f"--- {addr}")
        print(rz.cmd(f"fl. @ {addr}").strip())
        print(rz.cmd(f"CC. @ {addr}").strip())
    # Time the follow-up commands used in the original -qc smoke test, one by one.
    for c in ("fs", "CC. @ 0x3dd77c8", "tsc Game_SakashoV2SecurityManager_o", "tsc MethodInfo",
              "af @ 0x3dd77c8", "afn m.Game.SakashoV2SecurityManager.get_AndroidAppSetId @ 0x3dd77c8",
              "pdf @ 0x3dd77c8"):
        t = time.time()
        out = rz.cmd(c)
        print(f"[{time.time() - t:6.1f}s] {c}", flush=True)
        print(out.strip()[:1500], flush=True)
    rz.quit()


if __name__ == "__main__":
    main()
