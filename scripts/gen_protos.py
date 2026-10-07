"""Phase 4.2: regenerate .proto files from protobuf-net contracts.

Sources (both from the same il2cpp dump):
  * work/dllmeta_all.json  - Mono.Cecil dump of Il2CppDumper's DummyDll (fully-qualified types, nesting,
                             enum constants). Built by scripts/dllmeta (dotnet).
  * work/il2cppdumper/dump.cs - ProtoMember / ProtoEnum / DefaultValue attribute *arguments*
                             (DummyDll lacks the ProtoMember constructor args).
  Also scans stringliteral.json for serialized FileDescriptorProto blobs (4.2a).

Usage: python scripts/gen_protos.py   ->  out/protos/**.proto, out/protos/INDEX.md, out/protos/contracts.json
"""
import base64
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from dumpcs import load_dump, load_typedef_table  # noqa: E402

OUT = ROOT / "out/protos"
ASSEMBLIES = {"schema.dll", "bridging_model.dll", "sakasho2p.dll", "bridging_model_serializer.dll",
              "Assembly-CSharp.dll", "NPFSDK.dll"}

# protobuf-net DataFormat enum
DF = {0: "Default", 1: "ZigZag", 2: "TwosComplement", 3: "FixedSize", 4: "Group", 5: "WellKnown"}

SCALARS = {
    # clr type: {DataFormat: proto type}
    "System.Int32": {0: "int32", 2: "int32", 1: "sint32", 3: "sfixed32"},
    "System.UInt32": {0: "uint32", 2: "uint32", 3: "fixed32"},
    "System.Int64": {0: "int64", 2: "int64", 1: "sint64", 3: "sfixed64"},
    "System.UInt64": {0: "uint64", 2: "uint64", 3: "fixed64"},
    "System.Boolean": {0: "bool", 2: "bool"},
    "System.Single": {0: "float", 3: "float"},
    "System.Double": {0: "double", 3: "double"},
    "System.String": {0: "string"},
    "System.Byte[]": {0: "bytes"},
    "System.Byte": {0: "uint32", 2: "uint32"},
    "System.SByte": {0: "int32", 2: "int32", 1: "sint32"},
    "System.Int16": {0: "int32", 2: "int32", 1: "sint32"},
    "System.UInt16": {0: "uint32", 2: "uint32"},
}


def parse_attr_args(s):
    """'ProtoMember(1, IsRequired = False, Name = "count", DataFormat = 2)' -> (positional, named)."""
    m = re.match(r"\w+\((.*)\)$", s)
    if not m:
        return [], {}
    body = m.group(1)
    parts, cur, q = [], "", False
    for ch in body:
        if ch == '"' and (not cur.endswith("\\")):
            q = not q
        if ch == "," and not q:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur.strip())
    pos, named = [], {}
    for p in parts:
        mm = re.match(r"^(\w+) = (.*)$", p)
        if mm:
            named[mm.group(1)] = mm.group(2)
        else:
            pos.append(p)
    return pos, named


def unquote(v):
    if v is None:
        return None
    if v.startswith('"') and v.endswith('"'):
        return v[1:-1]
    return v


def find_attr(attrs, name):
    for a in attrs:
        if a.startswith(name + "(") or a == name:
            return a
    return None


def scan_descriptor_blobs():
    lits = json.loads((ROOT / "work/il2cppdumper/stringliteral.json").read_text(encoding="utf-8"))
    hits = []
    try:
        from google.protobuf import descriptor_pb2
    except ImportError:
        descriptor_pb2 = None
    for x in lits:
        v = x["value"]
        if len(v) < 16 or not re.fullmatch(r"[A-Za-z0-9+/=_-]+", v):
            continue
        try:
            raw = base64.b64decode(v + "=" * (-len(v) % 4), altchars=b"-_" if ("-" in v or "_" in v) else None)
        except Exception:
            continue
        ok = None
        if descriptor_pb2:
            fd = descriptor_pb2.FileDescriptorProto()
            try:
                fd.ParseFromString(raw)
                if fd.name.endswith(".proto") and (fd.message_type or fd.enum_type):
                    ok = fd.name
            except Exception:
                pass
        hits.append({"address": x["address"], "len": len(v), "head": v[:24], "is_file_descriptor": ok})
    return hits


def main():
    meta = json.loads((ROOT / "work/dllmeta_all.json").read_text(encoding="utf-8"))
    dump = load_dump(ROOT / "work/il2cppdumper/dump.cs")
    tokens, _declaring = load_typedef_table(ROOT / "work/originals/global-metadata.dat")
    by_image_token = {(dump.by_index[i].image, tok): i for i, tok in enumerate(tokens)}

    by_full = {t["full"]: t for t in meta}

    def token_of(t):
        for a in t["attrs"]:
            if a["type"] == "Il2CppDummyDll.TokenAttribute":
                return int(a["named"]["Token"], 16)
        return None

    def dump_type(t):
        tok = token_of(t)
        if tok is None:
            return None
        i = by_image_token.get((t["assembly"], tok))
        return dump.by_index.get(i) if i is not None else None

    def is_contract(t):
        return any(a["type"] == "ProtoBuf.ProtoContractAttribute" for a in t["attrs"])

    contracts = [t for t in meta if is_contract(t)]
    # Proto naming: package = namespace of the outermost type; nested types nest.
    def outermost(t):
        while t.get("declaring"):
            t = by_full[t["declaring"]]
        return t

    def proto_name(t):
        chain = []
        x = t
        while x:
            chain.append(contract_name(x))
            x = by_full[x["declaring"]] if x.get("declaring") else None
        return ".".join(reversed(chain))

    def contract_name(t):
        for a in t["attrs"]:
            if a["type"] == "ProtoBuf.ProtoContractAttribute" and a["named"].get("Name"):
                return a["named"]["Name"]
        return t["name"]

    def package(t):
        return outermost(t)["namespace"] or "_global"

    def fq(t):
        return "." + package(t) + "." + proto_name(t)

    problems = []
    unknown_types = defaultdict(int)

    def resolve(clr, data_format, where):
        """CLR type name -> (label, proto type, referenced contract or None)."""
        label = None
        m = re.match(r"^System\.Nullable`1<(.+)>$", clr)
        if m:
            clr = m.group(1)
            label = "optional"
        m = re.match(r"^System\.Collections\.Generic\.List`1<(.+)>$", clr)
        if m:
            clr = m.group(1)
            label = "repeated"
        elif clr.endswith("[]") and clr != "System.Byte[]":
            clr = clr[:-2]
            label = "repeated"
        m = re.match(r"^System\.Collections\.Generic\.Dictionary`2<(.+),(.+)>$", clr)
        if m:
            k, _, _ = resolve(m.group(1), 0, where)
            v, _, _ = resolve(m.group(2), 0, where)
            return "map", f"map<{k}, {v}>", None
        if clr in SCALARS:
            table = SCALARS[clr]
            pt = table.get(data_format) or table.get(0)
            if data_format not in table:
                problems.append(f"{where}: DataFormat {DF.get(data_format)} unusual for {clr}; used {pt}")
            return label, pt, None
        t = by_full.get(clr)
        if t is not None and (is_contract(t) or t["is_enum"]):
            return label, fq(t), t
        unknown_types[clr] += 1
        problems.append(f"{where}: unresolved CLR type {clr} (emitted as bytes)")
        return label, "bytes", None

    # Build message/enum model.
    model = {}  # full clr name -> dict
    for t in contracts:
        dt = dump_type(t)
        where = t["full"]
        if dt is None:
            problems.append(f"{where}: no dump.cs match (token)")
        if t["is_enum"]:
            values = []
            for f in t["fields"]:
                if not f["literal"]:
                    continue
                dfield = next((x for x in (dt.fields if dt else []) if x.name == f["name"]), None)
                pe = find_attr(dfield.attrs, "ProtoEnum") if dfield else None
                name = unquote(parse_attr_args(pe)[1].get("Name")) if pe else f["name"]
                values.append((name, int(f["constant"]), f["name"]))
            model[t["full"]] = {"kind": "enum", "t": t, "values": values}
            continue
        fields = []
        for p in t["props"]:
            dprop = next((x for x in (dt.props if dt else []) if x.name == p["name"]), None)
            if dprop is None:
                continue
            pm = find_attr(dprop.attrs, "ProtoMember")
            if not pm:
                continue
            pos, named = parse_attr_args(pm)
            tag = int(pos[0])
            fmt = int(named.get("DataFormat", "0"))
            req = named.get("IsRequired") == "True"
            pname = unquote(named.get("Name")) or p["name"]
            label, ptype, ref = resolve(p["type"], fmt, f"{where}.{p['name']}")
            if label == "map":
                label = ""
            elif req:
                label = "required"
            elif label is None:
                label = "optional"
            opts = []
            dv = find_attr(dprop.attrs, "DefaultValue")
            if dv:
                dpos, _ = parse_attr_args(dv)
                if dpos:
                    v = dpos[0]
                    if v not in ('""', "0", "False", "0L", "0U", "0UL", "0D", "0F", "null"):
                        if ptype in ("bool",):
                            v = v.lower()
                        elif ref is not None and ref["is_enum"]:
                            # DefaultValue holds the enum member name or number
                            v = v.split(".")[-1]
                        opts.append(f"default = {v}")
            if named.get("IsPacked") == "True":
                opts.append("packed = true")
            if fmt == 4:
                problems.append(f"{where}.{p['name']}: DataFormat Group (emitted as message)")
            fields.append({"tag": tag, "label": label, "type": ptype, "name": pname, "opts": opts,
                           "clr_prop": p["name"], "clr_type": p["type"], "data_format": DF.get(fmt, fmt),
                           "required": req})
        fields.sort(key=lambda f: f["tag"])
        tags = [f["tag"] for f in fields]
        if len(tags) != len(set(tags)):
            problems.append(f"{where}: duplicate tags {tags}")
        model[t["full"]] = {"kind": "message", "t": t, "fields": fields}

    # Group by package, nest children under parents.
    children = defaultdict(list)
    tops = defaultdict(list)
    for full, m in model.items():
        t = m["t"]
        if t.get("declaring") and t["declaring"] in model:
            children[t["declaring"]].append(full)
        elif t.get("declaring"):
            problems.append(f"{full}: declaring type {t['declaring']} is not a contract; emitted top-level")
            tops[package(t)].append(full)
        else:
            tops[package(t)].append(full)

    def deps_of(full, acc):
        m = model[full]
        if m["kind"] == "message":
            for f in m["fields"]:
                for ref in re.findall(r"\.([A-Za-z0-9_.]+)", f["type"]):
                    acc.add(ref)
        for c in children[full]:
            deps_of(c, acc)

    # Map fully-qualified proto names -> package for imports.
    fq_pkg = {fq(m["t"])[1:]: package(m["t"]) for m in model.values()}

    def emit(full, indent):
        m = model[full]
        t = m["t"]
        pad = "  " * indent
        out = []
        name = contract_name(t)
        if m["kind"] == "enum":
            out.append(f"{pad}enum {name} {{  // CLR {t['full']}")
            vals = m["values"]
            if vals and not any(v == 0 for _, v, _ in vals):
                problems.append(f"{t['full']}: enum has no zero value (proto2 allows this)")
            seen = {}
            alias = len({v for _, v, _ in vals}) != len(vals)
            if alias:
                out.append(f"{pad}  option allow_alias = true;")
            for n, v, clrn in vals:
                cm = f"  // CLR {clrn}" if clrn != n else ""
                out.append(f"{pad}  {n} = {v};{cm}")
            out.append(f"{pad}}}")
            return out
        out.append(f"{pad}message {name} {{  // CLR {t['full']}")
        for c in children[full]:
            out.extend(emit(c, indent + 1))
        for f in m["fields"]:
            o = f" [{', '.join(f['opts'])}]" if f["opts"] else ""
            lab = f"{f['label']} " if f["label"] else ""
            out.append(f"{pad}  {lab}{f['type']} {f['name']} = {f['tag']}{o};")
        out.append(f"{pad}}}")
        return out

    if OUT.exists():
        for p in OUT.rglob("*.proto"):
            p.unlink()
    OUT.mkdir(parents=True, exist_ok=True)
    files = {}
    for pkg in sorted(tops):
        refs = set()
        for full in tops[pkg]:
            deps_of(full, refs)
        imports = sorted({fq_pkg[r] for r in refs if r in fq_pkg and fq_pkg[r] != pkg})
        rel = pkg.replace(".", "/") + ".proto"
        body = [
            "// Generated by scripts/gen_protos.py from protobuf-net contracts in the il2cpp dump.",
            "// Field numbers, names, labels and wire types come from [ProtoMember]/[ProtoEnum] attributes.",
            'syntax = "proto2";',
            "",
            f"package {pkg};",
            "",
        ]
        for imp in imports:
            body.append(f'import "{imp.replace(".", "/")}.proto";')
        if imports:
            body.append("")
        for full in sorted(tops[pkg], key=lambda f: model[f]["t"]["name"]):
            body.extend(emit(full, 0))
            body.append("")
        path = OUT / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(body), encoding="utf-8")
        files[pkg] = rel

    blobs = scan_descriptor_blobs()
    contracts_json = {
        full: {
            "kind": m["kind"],
            "assembly": m["t"]["assembly"],
            "proto": fq(m["t"]),
            "file": files.get(package(m["t"])),
            "fields": m.get("fields"),
            "values": m.get("values"),
        } for full, m in model.items()
    }
    (OUT / "contracts.json").write_text(json.dumps(contracts_json, indent=1), encoding="utf-8")

    n_msg = sum(1 for m in model.values() if m["kind"] == "message")
    n_enum = sum(1 for m in model.values() if m["kind"] == "enum")
    n_fields = sum(len(m.get("fields") or []) for m in model.values())
    idx = ["# Regenerated protobuf schemas", "",
           f"{len(contracts)} protobuf-net contracts -> {n_msg} messages, {n_enum} enums, {n_fields} fields, "
           f"{len(files)} .proto files (one per C# namespace/package).", "",
           "## 4.2a FileDescriptorProto blobs in string literals", "",
           f"{len(blobs)} base64-looking literals >= 16 chars; "
           f"{sum(1 for b in blobs if b['is_file_descriptor'])} parse as a FileDescriptorProto.", ""]
    for b in blobs:
        if b["head"].startswith("Cg"):
            idx.append(f"- {b['address']} len {b['len']} `{b['head']}...` descriptor={b['is_file_descriptor']}")
    idx += ["", "## Files", ""]
    for pkg, rel in sorted(files.items()):
        idx.append(f"- `{rel}` ({len(tops[pkg])} top-level types)")
    idx += ["", "## Problems / notes", ""]
    idx += [f"- {p}" for p in problems] or ["- none"]
    (OUT / "INDEX.md").write_text("\n".join(idx) + "\n", encoding="utf-8")
    print(f"{len(contracts)} contracts: {n_msg} messages, {n_enum} enums, {n_fields} fields, {len(files)} files")
    print(f"descriptor blobs: {sum(1 for b in blobs if b['is_file_descriptor'])} of {len(blobs)} candidates")
    print(f"{len(problems)} problems")
    for p in problems[:30]:
        print("  ", p)


if __name__ == "__main__":
    main()
