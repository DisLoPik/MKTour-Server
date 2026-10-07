"""Phase 4.3 (native half): map every Sks* export in libs2pcore.so to its REST path and HTTP method.

Pattern found by decompiling SksRankRaceUpdateScore (rz-ghidra):
    std::string path("/v3/booster/rank_race/update_score");        // adrp/add -> .rodata
    req = new (0x150) SksRequest(path, ..., Poco::Net::HTTPRequest::HTTP_POST);  // GOT -> HTTP_* symbol
For each export we decode its body (ELF symbol size gives the range), resolve ADRP+ADD to C strings and
ADRP+LDR to GOT slots (R_AARCH64_GLOB_DAT symbol names), and follow direct calls one level deep when the
export itself holds no path.

Usage: python scripts/analyze_s2pcore.py work/originals/libs2pcore.so -> work/s2pcore_exports.json
"""
import json
import re
import struct
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

ROOT = Path(__file__).resolve().parent.parent


def sx(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


class Lib:
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        with open(path, "rb") as f:
            elf = ELFFile(f)
            self.loads = [(s["p_vaddr"], s["p_offset"], s["p_filesz"]) for s in elf.iter_segments()
                          if s["p_type"] == "PT_LOAD"]
            self.syms = {}
            self.sym_at = {}
            for sec in elf.iter_sections():
                if isinstance(sec, SymbolTableSection):
                    for s in sec.iter_symbols():
                        if s["st_value"] and s.name:
                            self.syms[s.name] = (s["st_value"], s["st_size"], s["st_info"]["type"])
                            self.sym_at.setdefault(s["st_value"], s.name)
            self.got = {}
            self.rel_addend = {}
            for sec in elf.iter_sections():
                if isinstance(sec, RelocationSection):
                    symtab = elf.get_section(sec["sh_link"])
                    for r in sec.iter_relocations():
                        if r["r_info_sym"]:
                            self.got[r["r_offset"]] = symtab.get_symbol(r["r_info_sym"]).name
                        elif r["r_info_type"] == 1027:
                            self.rel_addend[r["r_offset"]] = r["r_addend"]

    def off(self, va):
        for vaddr, off, size in self.loads:
            if vaddr <= va < vaddr + size:
                return va - vaddr + off
        return None

    def cstr(self, va, maxlen=200):
        o = self.off(va)
        if o is None:
            return None
        end = self.data.find(b"\0", o, o + maxlen)
        if end < 0:
            return None
        try:
            s = self.data[o:end].decode("ascii")
        except UnicodeDecodeError:
            return None
        return s if s and all(32 <= ord(c) < 127 for c in s) else None

    def func_size(self, start, limit=0x4000):
        """Linear-sweep function end: first RET/tail-B past the furthest forward branch target."""
        furthest = start
        pc = start
        while pc < start + limit:
            insn = struct.unpack_from("<I", self.data, self.off(pc))[0]
            tgt = None
            if (insn & 0x7C000000) == 0x14000000 and not insn & 0x80000000:  # B
                tgt = pc + (sx(insn & 0x3FFFFFF, 26) << 2)
                if pc >= furthest and not (start <= tgt < start + limit and tgt > pc):
                    return pc + 4 - start  # unconditional tail jump out
            elif (insn & 0xFF000010) == 0x54000000:  # B.cond
                tgt = pc + (sx((insn >> 5) & 0x7FFFF, 19) << 2)
            elif (insn & 0x7E000000) == 0x34000000:  # CBZ/CBNZ
                tgt = pc + (sx((insn >> 5) & 0x7FFFF, 19) << 2)
            elif (insn & 0x7E000000) == 0x36000000:  # TBZ/TBNZ
                tgt = pc + (sx((insn >> 5) & 0x3FFF, 14) << 2)
            elif insn == 0xD65F03C0 and pc >= furthest:  # RET
                return pc + 4 - start
            if tgt is not None and tgt > furthest:
                furthest = tgt
            pc += 4
        return limit

    def scan(self, start, size):
        page, out = {}, []
        for pc in range(start, start + size, 4):
            o = self.off(pc)
            insn = struct.unpack_from("<I", self.data, o)[0]
            if (insn & 0x9F000000) == 0x90000000:
                page[insn & 0x1F] = (pc & ~0xFFF) + (sx((((insn >> 5) & 0x7FFFF) << 2) | ((insn >> 29) & 3), 21) << 12)
            elif (insn & 0xFF800000) == 0x91000000:
                rd, rn = insn & 0x1F, (insn >> 5) & 0x1F
                if rn in page:
                    t = page[rn] + (((insn >> 10) & 0xFFF) << (12 if (insn >> 22) & 1 else 0))
                    s = self.cstr(t)
                    if s:
                        out.append(("str", pc, t, s))
                    page.pop(rd, None)
            elif (insn & 0xFFC00000) == 0xF9400000:
                rt, rn = insn & 0x1F, (insn >> 5) & 0x1F
                if rn in page:
                    t = page[rn] + ((insn >> 10) & 0xFFF) * 8
                    if t in self.got:
                        out.append(("got", pc, t, self.got[t]))
                    elif t in self.rel_addend:
                        out.append(("ptr", pc, t, self.rel_addend[t]))
                page.pop(rt, None)
            elif (insn & 0xFC000000) == 0x94000000:
                t = pc + (sx(insn & 0x3FFFFFF, 26) << 2)
                out.append(("call", pc, t, self.sym_at.get(t)))
                for r in range(19):
                    page.pop(r, None)
            elif (insn & 0x7FE0FFE0) == 0x52800000 or (insn & 0x7F800000) == 0x52800000:  # MOVZ
                out.append(("imm", pc, insn & 0x1F, (insn >> 5) & 0xFFFF))
        return out


PATH_RE = re.compile(r"^/v\d/")
METHOD_RE = re.compile(r"HTTPRequest(\d+)HTTP_(\w+)E$")


FUNCS = {}
RZ = None


def rz_func_size(addr):
    """Ask rizin to analyse a function at addr (af) and return its linear size."""
    global RZ
    if RZ is None:
        import rzpipe
        RZ = rzpipe.open(str(ROOT / "work/originals/libs2pcore.so"), flags=["-2", "-e", "bin.strings=false"])
    RZ.cmd(f"af @ {addr:#x}")
    info = RZ.cmdj(f"afij @ {addr:#x}")
    if not info:
        return 0
    return info[0].get("realsz") or info[0].get("size") or 0


def load_funcs():
    """Function sizes from rizin `aa; aflj` (work/s2pcore_aflj.json) for internal (unnamed) helpers."""
    f = ROOT / "work/s2pcore_aflj.json"
    if f.exists():
        for fn in json.loads(f.read_text()):
            if not fn["name"].startswith("case."):
                FUNCS[fn["offset"]] = fn.get("realsz") or fn["size"]


def analyze(lib, name):
    addr, size, _ = lib.syms[name]
    rs = lib.scan(addr, size)
    paths = [r[3] for r in rs if r[0] == "str" and PATH_RE.match(r[3])]
    methods = [METHOD_RE.search(r[3]).group(2) for r in rs if r[0] == "got" and METHOD_RE.search(r[3] or "")]
    other_strs = [r[3] for r in rs if r[0] == "str" and not PATH_RE.match(r[3])]
    via = None
    if not paths:
        # Follow local callees one level (helper that builds the request).
        for r in rs:
            if r[0] == "call" and r[2] not in (addr,):
                callee = r[2]
                csym = lib.sym_at.get(callee)
                csize = FUNCS.get(callee) or (lib.syms[csym][1] if csym in lib.syms else 0) or rz_func_size(callee)
                if csize <= 0 or csize > 0x4000:
                    continue
                try:
                    sub = lib.scan(callee, csize)
                except Exception:
                    continue
                p2 = [x[3] for x in sub if x[0] == "str" and PATH_RE.match(x[3])]
                if p2:
                    paths = p2
                    methods = methods or [METHOD_RE.search(x[3]).group(2) for x in sub
                                          if x[0] == "got" and METHOD_RE.search(x[3] or "")]
                    via = f"{callee:#x} {csym or ''}".strip()
                    break
    return {"export": name, "addr": f"{addr:#x}", "size": size, "paths": paths, "http_methods": methods,
            "via": via, "other_strings": other_strs[:12]}


def main():
    so = sys.argv[1] if len(sys.argv) > 1 else str(ROOT / "work/originals/libs2pcore.so")
    lib = Lib(so)
    load_funcs()
    exports = sorted(n for n, (_, _, typ) in lib.syms.items() if n.startswith("Sks") and typ == "STT_FUNC")
    res = [analyze(lib, n) for n in exports]
    out = ROOT / "work/s2pcore_exports.json"
    out.write_text(json.dumps(res, indent=1))
    with_path = sum(1 for r in res if r["paths"])
    print(f"{len(res)} Sks* exports, {with_path} with a REST path")
    for r in res:
        print(f"{r['export']:<55} {','.join(r['http_methods']) or '-':<10} {' | '.join(r['paths']) or '-'}"
              f"{'  (via ' + r['via'] + ')' if r['via'] else ''}")


if __name__ == "__main__":
    main()
