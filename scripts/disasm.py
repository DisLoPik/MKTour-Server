"""Quick AArch64 disassembly of libil2cpp.so with il2cpp names (capstone), for spot checks.
usage: python scripts/disasm.py <addr|Class$$Method> [max_insns]"""
import sys
from pathlib import Path
import capstone
sys.path.insert(0, str(Path(__file__).parent))
from il2cpp_refs import Image

img = Image()
arg = sys.argv[1]
start = int(arg, 16) if arg.startswith("0x") else img.by_name[arg][0]
end = img.end_of(start)
n = int(sys.argv[2]) if len(sys.argv) > 2 else 10**9
refs = {r["at"]: r for r in img.refs(start, end)}
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
code = img.data[img.off(start):img.off(start) + (end - start)]
print(f"; {start:#x} {img.name(start)}")
for i, ins in enumerate(md.disasm(code, start)):
    if i >= n:
        break
    r = refs.get(ins.address)
    note = f"  ; {r['kind']} {r['name']!r}" if r and r.get("name") else ""
    print(f"{ins.address:#010x}  {ins.mnemonic:<6} {ins.op_str}{note}")
