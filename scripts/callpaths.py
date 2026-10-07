"""Static reachability: which Sakasho endpoints / NPF calls can a C# method reach?

usage: python scripts/callpaths.py <Class$$Method> [--depth N]
Walks the il2cpp call graph (work/xref_index.pickle; direct BL/B targets plus methods referenced through
MethodInfo, which is how delegates / coroutine bodies are wired) breadth-first and prints, in BFS order,
every public Sks.<Area> API it reaches (joined to out/endpoints_map.csv) and every NPF.* method.
This is reachability, not proof of execution order.
"""
import argparse
import csv
import pickle
import re
import sys
from collections import deque
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from il2cpp_refs import Image  # noqa: E402

GENERIC_ARGS = re.compile(r"<[^<>]*>")


def load_graph(img):
    with open(ROOT / "work/xref_index.pickle", "rb") as f:
        xr = pickle.load(f)
    # Map MethodInfo slot -> method address (delegates, coroutines, lambdas).
    mi_target = {slot: addr for slot, (_, addr) in img.metam.items() if addr}
    # Coroutine bodies: Class.<name>d__N$$MoveNext are reached via `new <name>d__N`, i.e. a TypeInfo ref.
    movenext = {}
    for name, addrs in img.by_name.items():
        if name.endswith("$$MoveNext"):
            movenext[name[: -len("$$MoveNext")] + "_TypeInfo"] = addrs[0]
    ti_by_slot = {slot: n for slot, n in img.meta.items()}
    return xr, mi_target, movenext, ti_by_slot


def endpoint_index():
    idx = {}
    with open(ROOT / "out/endpoints_map.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            for api in r["calling_class_method"].split("; "):
                idx.setdefault(api, []).append(f"{r['method']} {r['path']}")
    return idx


def walk(img, start_name, depth=12, graph=None, eps=None):
    xr, mi_target, movenext, ti_by_slot = graph or load_graph(img)
    eps = eps if eps is not None else endpoint_index()
    starts = img.by_name.get(start_name, [])
    seen = set(starts)
    q = deque((a, 0, [start_name]) for a in starts)
    hits = []
    while q:
        a, d, path = q.popleft()
        name = img.name(a) or f"sub_{a:x}"
        if name in eps and name != start_name:
            hits.append((name, eps[name], path))
            continue
        if name.startswith("NPF.") and "$$" in name and name != start_name:
            hits.append((name, ["NPF SDK"], path))
            continue
        if d >= depth:
            continue
        nxt = list(xr["calls"].get(a, []))
        for kind, t in xr["method_refs"].get(a, []):
            if kind == "methodinfo" and t in mi_target:
                nxt.append(mi_target[t])
            elif kind == "typeinfo" and ti_by_slot.get(t, "") in movenext:
                nxt.append(movenext[ti_by_slot[t]])
        for b in nxt:
            if b in seen or b not in img.methods:
                continue
            bn = img.methods[b]
            # Don't wander into the BCL / Unity / generic plumbing.
            if bn.startswith(("System.", "UnityEngine.", "Util.", "MessagePack", "ProtoBuf.", "Mono.", "Unity.")):
                continue
            seen.add(b)
            q.append((b, d + 1, path + [bn]))
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("method")
    ap.add_argument("--depth", type=int, default=12)
    ap.add_argument("--paths", action="store_true", help="print the call chain for each hit")
    a = ap.parse_args()
    img = Image()
    for name, eps, path in walk(img, a.method, a.depth):
        print(f"{name}  ->  {', '.join(sorted(set(eps)))}")
        if a.paths:
            print("      via " + " > ".join(path[1:]))


if __name__ == "__main__":
    main()
