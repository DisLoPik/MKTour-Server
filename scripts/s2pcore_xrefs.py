"""Find code references (ADRP+ADD) to given strings in libs2pcore.so and name the containing function.

usage: python scripts/s2pcore_xrefs.py "X-Sks-Session-Token" "X-Sks-Title-Id" ...
Function starts come from rizin `aa` (work/s2pcore_aflj.json) plus ELF symbols.
"""
import bisect
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from analyze_s2pcore import Lib, sx  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def main():
    lib = Lib(ROOT / "work/originals/libs2pcore.so")
    targets = {}
    for s in sys.argv[1:]:
        needle = s.encode() + b"\0"
        i = lib.data.find(needle)
        while i >= 0:
            # Only whole strings (preceded by NUL).
            if i == 0 or lib.data[i - 1] == 0:
                for vaddr, off, size in lib.loads:
                    if off <= i < off + size:
                        targets[vaddr + (i - off)] = s
            i = lib.data.find(needle, i + 1)
    funcs = {}
    f = ROOT / "work/s2pcore_aflj.json"
    if f.exists():
        for fn in json.loads(f.read_text()):
            funcs[fn["offset"]] = fn["name"]
    for name, (addr, size, typ) in lib.syms.items():
        if typ == "STT_FUNC":
            funcs[addr] = name
    starts = sorted(funcs)
    text = [(v, o, s) for v, o, s in lib.loads if s > 0x100000][0:2]
    hits = []
    for vaddr, off, size in lib.loads:
        page = {}
        for k in range(0, size - 4, 4):
            insn = struct.unpack_from("<I", lib.data, off + k)[0]
            pc = vaddr + k
            if (insn & 0x9F000000) == 0x90000000:
                page[insn & 0x1F] = (pc & ~0xFFF) + (sx((((insn >> 5) & 0x7FFFF) << 2) | ((insn >> 29) & 3), 21) << 12)
            elif (insn & 0xFF800000) == 0x91000000:
                rn = (insn >> 5) & 0x1F
                if rn in page:
                    t = page[rn] + (((insn >> 10) & 0xFFF) << (12 if (insn >> 22) & 1 else 0))
                    if t in targets:
                        i = bisect.bisect_right(starts, pc) - 1
                        fn = starts[i] if i >= 0 else 0
                        hits.append((targets[t], pc, fn, funcs.get(fn, "?")))
    for s, pc, fn, name in sorted(hits):
        print(f"{s:<26} ref @ {pc:#x}  in {fn:#x} {name}")


if __name__ == "__main__":
    main()
