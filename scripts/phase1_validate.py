"""Phase 1: validate global-metadata.dat and characterise libil2cpp.so.

Usage:
  python scripts/phase1_validate.py <global-metadata.dat> <libil2cpp.so> [<apk libil2cpp.so>]

Read-only on all inputs. Prints a report and writes out/phase1_report.json.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

# Il2CppGlobalMetadataHeader for metadata v29 / v31 (31 offset/size pairs after sanity+version).
HEADER_FIELDS = [
    "stringLiteral", "stringLiteralData", "string", "events", "properties", "methods",
    "parameterDefaultValues", "fieldDefaultValues", "fieldAndParameterDefaultValueData",
    "fieldMarshaledSizes", "parameters", "fields", "genericParameters",
    "genericParameterConstraints", "genericContainers", "nestedTypes", "interfaces",
    "vtableMethods", "interfaceOffsets", "typeDefinitions", "images", "assemblies",
    "fieldRefs", "referencedAssemblies", "attributeData", "attributeDataRange",
    "unresolvedVirtualCallParameterTypes", "unresolvedVirtualCallParameterRanges",
    "windowsRuntimeTypeNames", "windowsRuntimeStrings", "exportedTypeDefinitions",
]

# Record sizes we expect for v31 (used to check that table sizes divide evenly).
V31_RECORD_SIZES = {
    "stringLiteral": 8, "events": 24, "properties": 20, "methods": 36,
    "parameterDefaultValues": 12, "fieldDefaultValues": 12, "fieldMarshaledSizes": 12,
    "parameters": 12, "fields": 12, "genericParameters": 16, "genericParameterConstraints": 4,
    "genericContainers": 16, "nestedTypes": 4, "interfaces": 4, "vtableMethods": 4,
    "interfaceOffsets": 8, "typeDefinitions": 88, "images": 40, "assemblies": 64,
    "fieldRefs": 8, "referencedAssemblies": 4, "attributeDataRange": 8,
    "unresolvedVirtualCallParameterTypes": 4, "unresolvedVirtualCallParameterRanges": 8,
    "exportedTypeDefinitions": 4,
}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_metadata(path):
    data = Path(path).read_bytes()
    rep = {"path": str(path), "size": len(data), "sha256": sha256(path), "problems": []}
    magic = data[:4]
    rep["magic"] = magic.hex(" ")
    if magic != bytes.fromhex("AF1BB1FA"):
        rep["problems"].append(f"bad magic {magic.hex()}")
    version = struct.unpack_from("<i", data, 4)[0]
    rep["version"] = version
    pairs = struct.unpack_from("<" + "ii" * len(HEADER_FIELDS), data, 8)
    tables = []
    for i, name in enumerate(HEADER_FIELDS):
        off, size = pairs[2 * i], pairs[2 * i + 1]
        t = {"name": name, "offset": off, "size": size, "end": off + size}
        if off < 0 or size < 0 or off + size > len(data):
            rep["problems"].append(f"{name}: [{off:#x},{off + size:#x}) outside file ({len(data):#x})")
        rs = V31_RECORD_SIZES.get(name)
        if rs:
            t["record_size_v31"] = rs
            t["count"] = size / rs
            if size % rs:
                rep["problems"].append(f"{name}: size {size:#x} not a multiple of v31 record size {rs}")
        tables.append(t)
    header_end = 8 + 8 * len(HEADER_FIELDS)
    rep["header_size"] = header_end
    # Contiguity / overlap check.
    nonempty = sorted((t for t in tables if t["size"]), key=lambda t: t["offset"])
    prev_end = header_end
    gaps = []
    for t in nonempty:
        if t["offset"] < prev_end:
            rep["problems"].append(f"{t['name']} overlaps previous table ({t['offset']:#x} < {prev_end:#x})")
        elif t["offset"] > prev_end:
            gaps.append({"before": t["name"], "from": prev_end, "to": t["offset"]})
        prev_end = max(prev_end, t["end"])
    rep["gaps"] = gaps
    rep["last_table_end"] = prev_end
    rep["trailing_bytes"] = len(data) - prev_end
    trailing = data[prev_end:]
    rep["trailing_nonzero_bytes"] = sum(1 for b in trailing if b)
    rep["trailing_head_hex"] = trailing[:64].hex(" ")
    rep["tables"] = tables
    # Quick content sanity: first strings in the string table, first string literal.
    s_off = tables[2]["offset"]
    first_strings = data[s_off:s_off + 200].split(b"\0")[:8]
    rep["first_strings"] = [s.decode("utf-8", "replace") for s in first_strings]
    lit_len, lit_idx = struct.unpack_from("<Ii", data, tables[0]["offset"])
    ld_off = tables[1]["offset"]
    rep["first_string_literal"] = data[ld_off + lit_idx: ld_off + lit_idx + min(lit_len, 80)].decode("utf-8", "replace")
    # Image names.
    img_off, img_size = tables[20]["offset"], tables[20]["size"]
    names = []
    for i in range(img_size // 40):
        name_idx = struct.unpack_from("<i", data, img_off + i * 40)[0]
        end = data.index(b"\0", s_off + name_idx)
        names.append(data[s_off + name_idx:end].decode())
    rep["images"] = names
    return rep


def elf_summary(path):
    with open(path, "rb") as f:
        elf = ELFFile(f)
        out = {"path": str(path), "size": Path(path).stat().st_size, "sha256": sha256(path),
               "machine": elf["e_machine"], "type": elf["e_type"], "entry": elf["e_entry"]}
        out["segments"] = [
            {"type": s["p_type"], "offset": s["p_offset"], "vaddr": s["p_vaddr"],
             "filesz": s["p_filesz"], "memsz": s["p_memsz"], "flags": s["p_flags"]}
            for s in elf.iter_segments()
        ]
        out["sections"] = [
            {"name": s.name, "type": s["sh_type"], "addr": s["sh_addr"], "offset": s["sh_offset"],
             "size": s["sh_size"]}
            for s in elf.iter_sections()
        ]
        # Build-id / note
        for s in elf.iter_sections():
            if s["sh_type"] == "SHT_NOTE":
                for n in s.iter_notes():
                    if n["n_type"] == "NT_GNU_BUILD_ID":
                        out["build_id"] = n["n_desc"]
        return out


def relative_relocs(path):
    """Return {vaddr: addend} for R_AARCH64_RELATIVE relocations."""
    rel = {}
    with open(path, "rb") as f:
        elf = ELFFile(f)
        for s in elf.iter_sections():
            if isinstance(s, RelocationSection):
                for r in s.iter_relocations():
                    if r["r_info_type"] == 1027:  # R_AARCH64_RELATIVE
                        rel[r["r_offset"]] = r["r_addend"]
    return rel


def vaddr_to_off(segments, va):
    for s in segments:
        if s["type"] == "PT_LOAD" and s["vaddr"] <= va < s["vaddr"] + s["filesz"]:
            return va - s["vaddr"] + s["offset"]
    return None


def compare_so(supplied, apk):
    a = Path(supplied).read_bytes()
    b = Path(apk).read_bytes()
    rep = {"same_size": len(a) == len(b)}
    if len(a) != len(b):
        return rep
    # Diff ranges (8-byte granularity is enough to describe pointer fixups).
    diffs = []
    n = len(a)
    i = 0
    import itertools
    mv_a, mv_b = memoryview(a), memoryview(b)
    step = 1 << 16
    for blk in range(0, n, step):
        if mv_a[blk:blk + step] != mv_b[blk:blk + step]:
            for j in range(blk, min(blk + step, n)):
                if a[j] != b[j]:
                    diffs.append(j)
    rep["diff_bytes"] = len(diffs)
    # Coalesce into ranges.
    ranges = []
    for k, g in itertools.groupby(enumerate(diffs), key=lambda t: t[1] - t[0]):
        g = list(g)
        ranges.append((g[0][1], g[-1][1] + 1))
    merged = []
    for s, e in ranges:
        if merged and s - merged[-1][1] <= 16:
            merged[-1][1] = e
        else:
            merged.append([s, e])
    rep["diff_range_count"] = len(merged)
    rep["diff_first"] = diffs[0] if diffs else None
    rep["diff_last"] = diffs[-1] if diffs else None
    rep["_diffset"] = merged
    return rep, a, b


def main():
    meta_path, so_path = sys.argv[1], sys.argv[2]
    apk_path = sys.argv[3] if len(sys.argv) > 3 else None
    report = {"metadata": check_metadata(meta_path)}
    m = report["metadata"]
    print(f"[metadata] magic={m['magic']} version={m['version']} size={m['size']:#x} header={m['header_size']:#x}")
    for t in m["tables"]:
        c = f" count={t['count']:g}" if "count" in t else ""
        print(f"  {t['name']:<40} off={t['offset']:#010x} size={t['size']:#010x} end={t['end']:#010x}{c}")
    print(f"  gaps between tables: {m['gaps']}")
    print(f"  last table ends {m['last_table_end']:#x}; trailing bytes {m['trailing_bytes']} (nonzero {m['trailing_nonzero_bytes']})")
    print(f"  trailing head: {m['trailing_head_hex']}")
    print(f"  first strings: {m['first_strings']}")
    print(f"  first string literal: {m['first_string_literal']!r}")
    print(f"  {len(m['images'])} images: {', '.join(m['images'])}")
    print(f"  PROBLEMS: {m['problems'] or 'none'}")

    so = elf_summary(so_path)
    report["so"] = so
    print(f"[so] {so_path} machine={so['machine']} type={so['type']} build_id={so.get('build_id')}")
    for s in so["segments"]:
        if s["type"] in ("PT_LOAD", "PT_DYNAMIC", "PT_GNU_RELRO"):
            print(f"  {s['type']:<14} off={s['offset']:#x} vaddr={s['vaddr']:#x} filesz={s['filesz']:#x} memsz={s['memsz']:#x} flags={s['flags']}")

    if apk_path:
        apk = elf_summary(apk_path)
        report["apk_so"] = {k: apk[k] for k in ("sha256", "size", "build_id")}
        print(f"[apk so] build_id={apk.get('build_id')} sha256={apk['sha256']}")
        cmp, a, b = compare_so(so_path, apk_path)
        merged = cmp.pop("_diffset")
        # Map diff ranges to sections.
        secs = [s for s in so["sections"] if s["size"] and s["type"] != "SHT_NOBITS"]
        per_sec = {}
        for s, e in merged:
            hit = next((x["name"] for x in secs if x["offset"] <= s < x["offset"] + x["size"]), "<none>")
            per_sec[hit] = per_sec.get(hit, 0) + (e - s)
        cmp["diff_bytes_by_section"] = per_sec
        # Are diffs explained by R_AARCH64_RELATIVE relocations applied at some base?
        rel = relative_relocs(apk_path)
        explained = 0
        bases = {}
        checked = 0
        for va, addend in rel.items():
            off = vaddr_to_off(so["segments"], va)
            if off is None:
                continue
            va_new = struct.unpack_from("<Q", a, off)[0]
            va_old = struct.unpack_from("<Q", b, off)[0]
            checked += 1
            base = va_new - addend
            bases[base] = bases.get(base, 0) + 1
            if va_old == 0 or va_old == addend:
                explained += 1
        top = sorted(bases.items(), key=lambda kv: -kv[1])[:5]
        cmp["relative_relocs"] = len(rel)
        cmp["relative_relocs_in_file"] = checked
        cmp["implied_bases_top5"] = [(hex(k), v) for k, v in top]
        report["so_vs_apk"] = cmp
        print(f"[so vs apk] diff bytes={cmp['diff_bytes']} ranges={cmp['diff_range_count']} first={cmp['diff_first']:#x} last={cmp['diff_last']:#x}")
        print(f"  diff bytes by section: {per_sec}")
        print(f"  R_AARCH64_RELATIVE relocs={len(rel)} in-file={checked}; implied base (value-addend) top5: {cmp['implied_bases_top5']}")

    out = Path("out/phase1_report.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=1, default=str))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
