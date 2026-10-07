"""Phase 3: turn Il2CppDumper's script.json (+ il2cpp.h) into rizin command scripts.

Usage:
  python scripts/make_rizin_labels.py [--script work/il2cppdumper/script.json]
         [--header work/il2cppdumper/il2cpp.h] [--out out/rizin]
         [--type-seeds out/restore_targets_types.txt]

Writes:
  out/rizin/labels.rz        flags + comments for methods, string literals, TypeInfo/MethodInfo slots,
                             and `to il2cpp_types.h` for the C types
  out/rizin/il2cpp_types.h   il2cpp.h subset (runtime prelude + seed classes + by-value deps),
                             rewritten so rizin's C parser accepts it
  out/rizin/functions.rz     `af <name> @ addr` for every method address (slow; optional)
  out/rizin/names.json       addr -> list of full C# names (used by later phases)

Load:  rizin -i out/rizin/labels.rz libil2cpp.so
"""
import argparse
import base64
import json
import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def flag_safe(name, maxlen=180):
    s = name.replace("$$", ".")
    s = re.sub(r"[^A-Za-z0-9_.]", "_", s)
    s = re.sub(r"_+", "_", s).strip("._")
    return s[:maxlen] or "anon"


def b64(text):
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


class Namer:
    """Rizin flag names are unique; a second `f name` moves the flag. Disambiguate."""

    def __init__(self):
        self.used = set()

    def __call__(self, base, addr):
        name = base
        if name in self.used:
            name = f"{base}_{addr:x}"
            i = 1
            while name in self.used:
                name = f"{base}_{addr:x}_{i}"
                i += 1
        self.used.add(name)
        return name


# ---------------------------------------------------------------- il2cpp.h subset

DECL_RE = re.compile(r"^(struct|union)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", re.M)


def split_header(text):
    """Return (prelude_text, {name: body_text}) for the regular part of Il2CppDumper's il2cpp.h."""
    first = re.search(r"^struct _Module__Fields \{", text, re.M)
    prelude = text[: first.start()]
    decls = {}
    order = []
    pos = first.start()
    for m in DECL_RE.finditer(text, pos):
        end = text.index("\n};", m.end()) + 3
        decls[m.group(2)] = text[m.start():end]
        order.append(m.group(2))
    return prelude, decls, order


def fix_for_rizin(src):
    # rizin's tree-sitter C parser rejects K&R empty parameter lists and anonymous union members.
    src = src.replace("typedef void(*Il2CppMethodPointer)();", "typedef void (*Il2CppMethodPointer)(void);")
    n = [0]

    def name_union(m):
        n[0] += 1
        return m.group(1) + f" _u{n[0]};"

    src = re.sub(r"(union\s*\{[^{}]*\})\s*;", name_union, src)
    # Empty structs -> give them a placeholder member so the parser keeps them.
    src = re.sub(r"\{\s*\};", "{\n\tuint8_t _empty;\n};", src)
    return src


IDENT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")


def by_value_deps(body, known):
    """Types used by value (not behind a pointer) must be fully defined; pointers only need a forward decl."""
    deps_val, deps_ptr = set(), set()
    for line in body.splitlines()[1:]:
        line = line.strip().rstrip(";")
        if not line or line.startswith("}"):
            continue
        is_ptr = "*" in line
        for ident in IDENT_RE.findall(line):
            if ident in known:
                (deps_ptr if is_ptr else deps_val).add(ident)
    return deps_val, deps_ptr


def build_types(header_path, seeds):
    text = Path(header_path).read_text(encoding="utf-8", errors="replace")
    prelude, decls, order = split_header(text)
    known = set(decls)
    want = set()
    stack = []
    for s in seeds:
        for suffix in ("_o", "_c", "_Fields", "_StaticFields", "_VTable", "_RGCTXs"):
            if s + suffix in known:
                stack.append(s + suffix)
    fwd = set()
    while stack:
        n = stack.pop()
        if n in want:
            continue
        want.add(n)
        val, ptr = by_value_deps(decls[n], known)
        stack.extend(val - want)
        fwd |= ptr
    # Keep the original order (definitions precede by-value uses in il2cpp.h).
    out = [fix_for_rizin(prelude)]
    for n in sorted(fwd - want):
        out.append(f"struct {n};")
    for n in order:
        if n in want:
            out.append(fix_for_rizin(decls[n]))
    return "\n".join(out) + "\n", len(want), len(fwd - want)


# ---------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--script", default=str(ROOT / "work/il2cppdumper/script.json"))
    ap.add_argument("--header", default=str(ROOT / "work/il2cppdumper/il2cpp.h"))
    ap.add_argument("--out", default=str(ROOT / "out/rizin"))
    ap.add_argument("--type-seeds", default=None,
                    help="file with one il2cpp.h type prefix per line (e.g. Game_SakashoV2SecurityManager)")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    data = json.loads(Path(args.script).read_text(encoding="utf-8"))

    lines = ["# rizin labels generated from Il2CppDumper script.json by scripts/make_rizin_labels.py",
             "# Load with:  rizin -i out/rizin/labels.rz <libil2cpp.so>   (one-time open of the 119 MB binary is slow)",
             "# Flagspaces: il2cpp.methods / il2cpp.strings / il2cpp.typeinfo / il2cpp.methodinfo (switch with `fs <name>`, list with `fs`).",
             "e asm.cmt.right=true"]
    namer = Namer()

    # Methods: one flag per name, one comment per address listing every C# name folded there.
    by_addr = defaultdict(list)
    for m in data["ScriptMethod"]:
        by_addr[m["Address"]].append(m)
    lines.append("fs il2cpp.methods")
    names_json = {}
    for addr in sorted(by_addr):
        ms = by_addr[addr]
        for m in ms:
            lines.append(f"f+ {namer('m.' + flag_safe(m['Name']), addr)} 0 @ {addr:#x}")
        full = [m["Name"] for m in ms]
        names_json[f"{addr:#x}"] = [{"name": m["Name"], "sig": m["Signature"]} for m in ms]
        cmt = full[0] if len(full) == 1 else f"{full[0]}  (+{len(full) - 1} folded: {'; '.join(full[1:4])}{' ...' if len(full) > 4 else ''})"
        lines.append(f"CCu base64:{b64(cmt)} @ {addr:#x}")
    # Plain method addresses that have no named entry (e.g. generic instances) still get a flag.
    extra = [a for a in data["Addresses"] if a not in by_addr]
    for a in extra:
        lines.append(f"f+ {namer('m.unnamed', a)} 0 @ {a:#x}")

    lines.append("fs il2cpp.strings")
    for s in data["ScriptString"]:
        a = s["Address"]
        v = s["Value"]
        lines.append(f"f+ {namer('str.' + flag_safe(v, 60), a)} 8 @ {a:#x}")
        lines.append(f"CCu base64:{b64('StringLiteral: ' + json.dumps(v, ensure_ascii=False)[:400])} @ {a:#x}")

    lines.append("fs il2cpp.typeinfo")
    for s in data["ScriptMetadata"]:
        lines.append(f"f+ {namer('ti.' + flag_safe(s['Name']), s['Address'])} 8 @ {s['Address']:#x}")
    lines.append("fs il2cpp.methodinfo")
    for s in data["ScriptMetadataMethod"]:
        lines.append(f"f+ {namer('mi.' + flag_safe(s['Name']), s['Address'])} 8 @ {s['Address']:#x}")
    # Leave the session in the main flagspace. NOTE: do NOT use `fs *` here - rizin 0.9 rejects it
    # ("fs *" returns an error), and `rizin -i` treats any erroring script line as fatal and aborts the
    # whole script (the rzpipe `. file` loader silently continues past it, which masked this). Re-selecting
    # a real flagspace is the valid way to end. Switch spaces later with `fs il2cpp.strings` etc.; `fs` lists.
    lines.append("fs il2cpp.methods")

    seeds = ["System_String", "System_Object"]
    if args.type_seeds and Path(args.type_seeds).exists():
        seeds += [l.strip() for l in Path(args.type_seeds).read_text().splitlines() if l.strip()]
    types_src, n_def, n_fwd = build_types(args.header, seeds)
    (out / "il2cpp_types.h").write_text(types_src, encoding="utf-8")
    lines.append(f"to {(out / 'il2cpp_types.h').resolve().as_posix()}")

    (out / "labels.rz").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (out / "names.json").write_text(json.dumps(names_json), encoding="utf-8")

    fn = Namer()
    flines = ["# Create functions at every il2cpp method address (slow on the full binary)."]
    for addr in sorted(set(by_addr) | set(extra)):
        base = flag_safe(by_addr[addr][0]["Name"]) if addr in by_addr else "unnamed"
        flines.append(f"af {fn('fcn.' + base, addr)} @ {addr:#x}")
    (out / "functions.rz").write_text("\n".join(flines) + "\n", encoding="utf-8")

    print(f"methods: {len(data['ScriptMethod'])} entries at {len(by_addr)} unique addresses "
          f"(+{len(extra)} unnamed addresses)")
    print(f"strings: {len(data['ScriptString'])}  typeinfo: {len(data['ScriptMetadata'])}  "
          f"methodinfo: {len(data['ScriptMetadataMethod'])}")
    print(f"types: {n_def} struct definitions + {n_fwd} forward declarations from seeds {seeds[:5]}...")
    print(f"wrote {out / 'labels.rz'} ({len(lines)} lines), il2cpp_types.h, functions.rz, names.json")


if __name__ == "__main__":
    main()
