"""Fast static cross-references for il2cpp methods (no rizin needed).

For a method address it decodes the AArch64 instructions between this method's start and the next known
method start and resolves:
  * ADRP + ADD/LDR pairs -> string literals, TypeInfo / MethodInfo / FieldInfo slots (from script.json)
  * BL / B to other il2cpp methods -> callee names
Works on the supplied libil2cpp.so (relocations already applied at base 0).

    from il2cpp_refs import Image
    img = Image()
    for r in img.refs(0x3DD77C8): print(r)
CLI: python scripts/il2cpp_refs.py 0x53c63d4 [more addrs or Class$$Method names]
"""
import bisect
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def sx(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


class Image:
    def __init__(self, so=ROOT / "work/originals/libil2cpp.so", script=ROOT / "work/il2cppdumper/script.json"):
        from elftools.elf.elffile import ELFFile
        self.data = Path(so).read_bytes()
        with open(so, "rb") as f:
            elf = ELFFile(f)
            self.loads = [(s["p_vaddr"], s["p_offset"], s["p_filesz"]) for s in elf.iter_segments()
                          if s["p_type"] == "PT_LOAD"]
        sj = json.loads(Path(script).read_text(encoding="utf-8"))
        self.methods = {}
        for m in sj["ScriptMethod"]:
            self.methods.setdefault(m["Address"], m["Name"])
        self.sigs = {m["Address"]: m["Signature"] for m in sj["ScriptMethod"]}
        self.starts = sorted(set(sj["Addresses"]) | set(self.methods))
        self.strings = {s["Address"]: s["Value"] for s in sj["ScriptString"]}
        self.meta = {s["Address"]: s["Name"] for s in sj["ScriptMetadata"]}
        self.metam = {s["Address"]: (s["Name"], s.get("MethodAddress")) for s in sj["ScriptMetadataMethod"]}
        self.by_name = {}
        for a, n in self.methods.items():
            self.by_name.setdefault(n, []).append(a)
        self.helpers = {}

    def off(self, va):
        for vaddr, off, size in self.loads:
            if vaddr <= va < vaddr + size:
                return va - vaddr + off
        return None

    def u32(self, va):
        o = self.off(va)
        return struct.unpack_from("<I", self.data, o)[0]

    def u64(self, va):
        o = self.off(va)
        return struct.unpack_from("<Q", self.data, o)[0] if o is not None else None

    def end_of(self, start):
        i = bisect.bisect_right(self.starts, start)
        end = self.starts[i] if i < len(self.starts) else start + 0x4000
        return min(end, start + 0x20000)

    def name(self, addr):
        return self.methods.get(addr)

    def classify(self, target):
        if target in self.strings:
            return "string", self.strings[target]
        if target in self.meta:
            return "typeinfo", self.meta[target]
        if target in self.metam:
            return "methodinfo", self.metam[target][0]
        return None, None

    def refs(self, start, end=None):
        """Yield dicts: {at, kind, target, name} in program order."""
        end = end or self.end_of(start)
        page = {}
        out = []
        pc = start
        while pc < end:
            o = self.off(pc)
            if o is None:
                break
            insn = struct.unpack_from("<I", self.data, o)[0]
            if (insn & 0x9F000000) == 0x90000000:  # ADRP
                rd = insn & 0x1F
                imm = sx((((insn >> 5) & 0x7FFFF) << 2) | ((insn >> 29) & 3), 21) << 12
                page[rd] = (pc & ~0xFFF) + imm
            elif (insn & 0xFF800000) == 0x91000000:  # ADD Xd, Xn, #imm{, lsl 12}
                rd, rn = insn & 0x1F, (insn >> 5) & 0x1F
                if rn in page:
                    imm = ((insn >> 10) & 0xFFF) << (12 if (insn >> 22) & 1 else 0)
                    t = page[rn] + imm
                    k, n = self.classify(t)
                    if k:
                        out.append({"at": pc, "kind": k, "target": t, "name": n, "op": "add"})
                    if rd != rn:
                        page.pop(rd, None)
                    else:
                        page.pop(rd, None)
            elif (insn & 0xFFC00000) in (0xF9400000, 0xB9400000, 0x39400000, 0xF9000000):  # LDR/STR imm
                size = {0xF9400000: 8, 0xB9400000: 4, 0x39400000: 1, 0xF9000000: 8}[insn & 0xFFC00000]
                rt, rn = insn & 0x1F, (insn >> 5) & 0x1F
                if rn in page:
                    t = page[rn] + ((insn >> 10) & 0xFFF) * size
                    k, n = self.classify(t)
                    if k:
                        out.append({"at": pc, "kind": k, "target": t, "name": n,
                                    "op": "ldrb" if size == 1 else ("str" if (insn & 0xFFC00000) == 0xF9000000 else "ldr")})
                    elif size == 1 and (insn & 0xFFC00000) == 0x39400000:
                        pass
                if (insn & 0xFFC00000) != 0xF9000000:
                    page.pop(rt, None)
            elif (insn & 0x7C000000) == 0x14000000:  # B / BL
                t = pc + (sx(insn & 0x3FFFFFF, 26) << 2)
                kind = "call" if insn & 0x80000000 else "jump"
                if kind == "call" or not (start <= t < end):
                    out.append({"at": pc, "kind": kind, "target": t, "name": self.methods.get(t)})
                if kind == "call":
                    for r in range(0, 19):
                        page.pop(r, None)
            pc += 4
        return out


def main():
    img = Image()
    for a in sys.argv[1:]:
        if a.startswith("0x"):
            addrs = [int(a, 16)]
        else:
            addrs = img.by_name.get(a, [])
        for addr in addrs:
            print(f"== {addr:#x} {img.name(addr)}  (ends {img.end_of(addr):#x})")
            for r in img.refs(addr):
                tgt = f"{r['target']:#x}"
                print(f"  {r['at']:#x} {r['kind']:<10} {tgt:<12} {r['name']!r}")


if __name__ == "__main__":
    main()
