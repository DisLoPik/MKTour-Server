"""Build a whole-binary xref index for libil2cpp.so (callers, string/TypeInfo/MethodInfo users).

Output: work/xref_index.pickle  {
   'callers':   {callee_addr: set(caller_method_start)},
   'calls':     {method_start: [callee_addr,...]},
   'str_users': {string_slot: set(method_start)},
   'ti_users':  {typeinfo_slot: set(method_start)},
   'mi_users':  {methodinfo_slot: set(method_start)},
   'method_refs': {method_start: [(kind, target)]} }
Uses the same decoder as il2cpp_refs.Image.refs, over every method range.
"""
import pickle
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from il2cpp_refs import Image  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def main():
    t0 = time.time()
    img = Image()
    callers = defaultdict(set)
    calls = {}
    str_users, ti_users, mi_users = defaultdict(set), defaultdict(set), defaultdict(set)
    method_refs = {}
    starts = img.starts
    for i, s in enumerate(starts):
        e = starts[i + 1] if i + 1 < len(starts) else s + 0x400
        if e - s > 0x20000:
            e = s + 0x20000
        rs = img.refs(s, e)
        cl = []
        mr = []
        for r in rs:
            k, t = r["kind"], r["target"]
            if k in ("call", "jump"):
                callers[t].add(s)
                cl.append(t)
            elif k == "string":
                str_users[t].add(s)
            elif k == "typeinfo":
                ti_users[t].add(s)
            elif k == "methodinfo":
                mi_users[t].add(s)
            mr.append((k, t))
        calls[s] = cl
        method_refs[s] = mr
        if i % 20000 == 0:
            print(f"{i}/{len(starts)} {time.time() - t0:.0f}s", flush=True)
    out = ROOT / "work/xref_index.pickle"
    with open(out, "wb") as f:
        pickle.dump({"callers": dict(callers), "calls": calls, "str_users": dict(str_users),
                     "ti_users": dict(ti_users), "mi_users": dict(mi_users), "method_refs": method_refs}, f)
    # Most-called non-method targets are il2cpp runtime helpers; list them for labelling.
    helper_counts = sorted(((len(v), k) for k, v in callers.items() if k not in img.methods), reverse=True)[:60]
    with open(ROOT / "work/top_helpers.txt", "w") as f:
        for n, a in helper_counts:
            f.write(f"{a:#x} {n}\n")
    print(f"done in {time.time() - t0:.0f}s -> {out}")


if __name__ == "__main__":
    main()
