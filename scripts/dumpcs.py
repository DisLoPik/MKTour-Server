"""Parser for Il2CppDumper's dump.cs (shared by the phase 4 and phase 6 scripts).

    from dumpcs import load_dump
    dump = load_dump("work/il2cppdumper/dump.cs")
    t = dump.by_full["Game.SakashoV2SecurityManager"]
    for m in t.methods: print(hex(m.rva or 0), m.signature)
"""
import pickle
import re
from dataclasses import dataclass, field
from pathlib import Path

IMAGE_RE = re.compile(r"^// Image (\d+): (\S+) - (\d+)$")
TYPE_RE = re.compile(
    r"^(?P<mods>(?:[a-z]+ )*)(?P<kind>class|struct|enum|interface) (?P<name>.+?)"
    r"(?: : (?P<bases>.+?))? // TypeDefIndex: (?P<idx>\d+)$")
RVA_RE = re.compile(r"^\s*// RVA: (?P<rva>-1|0x[0-9A-F]+) Offset: (?P<off>-1|0x[0-9A-F]+) VA: (?P<va>-1|0x[0-9A-F]+)(?: Slot: (?P<slot>\d+))?")
FIELD_RE = re.compile(r"^\s*(?P<decl>.+?);(?: // (?P<off>0x[0-9A-F]+))?$")
METHOD_RE = re.compile(r"^\s*(?P<decl>.+?\))\s*\{ \}$")
GEN_RVA_RE = re.compile(r"^\s*\|-RVA: (0x[0-9A-F]+) Offset: (0x[0-9A-F]+) VA: (0x[0-9A-F]+)")
GEN_NAME_RE = re.compile(r"^\s*\|-(.+)$")


@dataclass
class Field:
    decl: str
    name: str
    type: str
    offset: int | None
    static: bool
    const: bool
    attrs: list
    value: str | None = None


@dataclass
class Prop:
    decl: str
    name: str
    type: str
    attrs: list


@dataclass
class Method:
    decl: str
    name: str
    rva: int | None
    slot: int | None
    attrs: list
    static: bool
    generic_insts: list = field(default_factory=list)  # [(rva, name)]

    @property
    def signature(self):
        return self.decl


@dataclass
class Type:
    namespace: str
    name: str            # as printed, nested types are Outer.Inner
    kind: str
    mods: str
    bases: list
    index: int
    image: str
    attrs: list
    fields: list = field(default_factory=list)
    props: list = field(default_factory=list)
    methods: list = field(default_factory=list)
    line: int = 0

    @property
    def full(self):
        return f"{self.namespace}.{self.name}" if self.namespace else self.name


@dataclass
class Dump:
    images: list
    types: list
    by_full: dict
    by_index: dict
    by_rva: dict


def _split_decl_name(decl):
    """'private static readonly Nullable<long> cGCPProjectNumber' -> (type, name, flags)."""
    d = decl
    value = None
    if " = " in d:
        d, value = d.split(" = ", 1)
    toks = d.split()
    mods = []
    while toks and toks[0] in ("public", "private", "protected", "internal", "static", "readonly", "const",
                               "volatile", "fixed", "new", "unsafe", "extern", "override", "virtual",
                               "abstract", "sealed", "event"):
        mods.append(toks.pop(0))
    name = toks[-1] if toks else ""
    typ = " ".join(toks[:-1])
    return typ, name, mods, value


def _image_for(images, idx):
    cur = None
    for num, name, first in images:
        if idx >= first:
            cur = name
    return cur


def parse(path):
    text = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    images = []
    types = []
    ns = ""
    attrs = []
    cur = None
    section = None
    pending_rva = None
    pending_slot = None
    last_method = None
    for ln, line in enumerate(text, 1):
        if cur is None:
            m = IMAGE_RE.match(line)
            if m:
                images.append((int(m.group(1)), m.group(2), int(m.group(3))))
                continue
            if line.startswith("// Namespace: "):
                ns = line[len("// Namespace: "):].strip()
                attrs = []
                continue
            if line.startswith("[") and line.endswith("]"):
                attrs.append(line[1:-1])
                continue
            m = TYPE_RE.match(line)
            if m:
                idx = int(m.group("idx"))
                cur = Type(ns, m.group("name"), m.group("kind"), (m.group("mods") or "").strip(),
                           [b.strip() for b in (m.group("bases") or "").split(",") if b.strip()],
                           idx, _image_for(images, idx), attrs, line=ln)
                attrs = []
                section = None
            continue
        s = line.strip()
        if s in ("}", "{}") and not line.startswith("\t"):
            types.append(cur)
            cur = None
            continue
        if s in ("// Fields", "// Properties", "// Methods"):
            section = s[3:]
            attrs = []
            continue
        if not s or s == "{":
            continue
        if s.startswith("[") and s.endswith("]"):
            attrs.append(s[1:-1])
            continue
        if section == "Methods":
            m = RVA_RE.match(line)
            if m:
                pending_rva = None if m.group("rva") == "-1" else int(m.group("rva"), 16)
                pending_slot = int(m.group("slot")) if m.group("slot") else None
                continue
            if s.startswith("/* GenericInstMethod"):
                continue
            g = GEN_RVA_RE.match(line)
            if g and last_method is not None:
                last_method._gen_rva = int(g.group(1), 16)
                continue
            g = GEN_NAME_RE.match(line)
            if g and last_method is not None and hasattr(last_method, "_gen_rva"):
                last_method.generic_insts.append((last_method._gen_rva, g.group(1)))
                continue
            if s.startswith("*/") or s.startswith("|"):
                continue
            m = METHOD_RE.match(line)
            if m:
                decl = m.group("decl")
                head = decl.split("(", 1)[0]
                name = head.split()[-1] if head.split() else head
                meth = Method(decl, name, pending_rva, pending_slot, attrs, " static " in f" {head} ")
                cur.methods.append(meth)
                last_method = meth
                pending_rva = pending_slot = None
                attrs = []
            continue
        if section == "Fields":
            m = FIELD_RE.match(line)
            if m:
                typ, name, mods, value = _split_decl_name(m.group("decl"))
                off = int(m.group("off"), 16) if m.group("off") else None
                cur.fields.append(Field(m.group("decl"), name, typ, off, "static" in mods, "const" in mods,
                                        attrs, value))
                attrs = []
            continue
        if section == "Properties":
            if "{" in s:
                head = s.split("{", 1)[0].strip()
                typ, name, mods, _ = _split_decl_name(head)
                cur.props.append(Prop(s, name, typ, attrs))
                attrs = []
            continue
    by_full = {}
    by_index = {}
    by_rva = {}
    for t in types:
        by_full.setdefault(t.full, t)
        by_index[t.index] = t
        for m in t.methods:
            if m.rva:
                by_rva.setdefault(m.rva, []).append((t, m))
    return Dump(images, types, by_full, by_index, by_rva)


def load_dump(path="work/il2cppdumper/dump.cs"):
    path = Path(path)
    cache = path.with_suffix(".pickle")
    if cache.exists() and cache.stat().st_mtime > path.stat().st_mtime:
        with open(cache, "rb") as f:
            return pickle.load(f)
    d = parse(path)
    with open(cache, "wb") as f:
        pickle.dump(d, f)
    return d


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from dumpcs import load_dump as _load  # pickle under the module name, not __main__
    d = _load(sys.argv[1] if len(sys.argv) > 1 else "work/il2cppdumper/dump.cs")
    print(f"{len(d.types)} types, {sum(len(t.methods) for t in d.types)} methods, {len(d.by_rva)} distinct RVAs")


# ---------------------------------------------------------------- metadata side-tables

def load_typedef_table(metadata_path="work/originals/global-metadata.dat"):
    """Read v31 Il2CppTypeDefinition records: returns (tokens, declaring) indexed by TypeDefIndex.

    tokens[i]    original ECMA metadata token of type i (0x02xxxxxx), matches DummyDll [Token]
    declaring[i] TypeDefIndex of the enclosing type, or None
    """
    import struct
    data = Path(metadata_path).read_bytes()
    hdr = struct.unpack_from("<" + "ii" * 31, data, 8)
    nested_off, nested_size = hdr[2 * 15], hdr[2 * 15 + 1]
    td_off, td_size = hdr[2 * 19], hdr[2 * 19 + 1]
    n = td_size // 88
    tokens, declaring = [], [None] * n
    nested = struct.unpack_from(f"<{nested_size // 4}i", data, nested_off)
    for i in range(n):
        rec = data[td_off + i * 88: td_off + (i + 1) * 88]
        nested_start = struct.unpack_from("<i", rec, 48)[0]
        nested_count = struct.unpack_from("<H", rec, 64 + 8)[0]
        tokens.append(struct.unpack_from("<I", rec, 84)[0])
        for j in range(nested_count):
            declaring[nested[nested_start + j]] = i
    return tokens, declaring
