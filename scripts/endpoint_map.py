"""Phase 4.3: out/endpoints_map.csv - Sakasho REST path -> HTTP method, request/response protobuf types.

Inputs (all produced earlier in this workspace):
  work/s2pcore_exports.json   native export -> path + HTTP method      (scripts/analyze_s2pcore.py)
  work/xref_index.pickle      il2cpp callers / TypeInfo users            (scripts/build_xref_index.py)
  work/dllmeta_all.json       Cecil view of DummyDll (full type names)   (scripts/dllmeta)
  out/protos/contracts.json   protobuf-net contracts -> proto names      (scripts/gen_protos.py)
  ref/MKTour-Server/data/endpoints.csv   the preservation repo's path list (for coverage)

How each column is derived:
  method        Poco::Net::HTTPRequest::HTTP_* passed by the native export (or the helper it calls)
  request_type  ProtoContract TypeInfo referenced by the C# method(s) that call the P/Invoke stub
                Sks.<Area>$$Sks<Name> (these closures do `new Request()` then RequestBody<Request>)
  response_type parameter type of the result class constructor ResultOf<Api>::.ctor(<Response>),
                where <Api> is the public Sks.<Area> method owning the closure
  calling       public Sks.<Area>.<Api> method + up to 3 game-side (Assembly-CSharp) callers of it
Anything not established this way is written as UNKNOWN.
"""
import csv
import json
import pickle
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from il2cpp_refs import Image  # noqa: E402
from dumpcs import load_dump  # noqa: E402

CALLBACK_PARAM_RE = re.compile(r"(IntPtr handle|CallbackWrapper \w+|DebugOption \w+)")

CLOSURE_RE = re.compile(r"^(?P<cls>.+?)\.<>c(?:__DisplayClass[\d_]+)?\$\$<(?P<api>\w+)>b__[\d_]+$")


def load_inputs():
    img = Image()
    with open(ROOT / "work/xref_index.pickle", "rb") as f:
        xr = pickle.load(f)
    native = json.loads((ROOT / "work/s2pcore_exports.json").read_text())
    cecil = {t["full"]: t for t in json.loads((ROOT / "work/dllmeta_all.json").read_text(encoding="utf-8"))}
    contracts = json.loads((ROOT / "out/protos/contracts.json").read_text())
    return img, xr, native, cecil, contracts


def main():
    img, xr, native, cecil, contracts = load_inputs()
    dump = load_dump(ROOT / "work/il2cppdumper/dump.cs")
    decl_at = {}
    for t in dump.types:
        for m in t.methods:
            if m.rva:
                decl_at.setdefault(m.rva, m.decl)

    def native_args(stub_addr):
        d = decl_at.get(stub_addr, "")
        if "(" not in d:
            return "UNKNOWN"
        params = [x.strip() for x in d.split("(", 1)[1].rsplit(")", 1)[0].split(",") if x.strip()]
        keep = [x for x in params if not CALLBACK_PARAM_RE.search(x)]
        return ", ".join(keep) if keep else "(none)"

    def register_callbacks(api_addr):
        out = []
        for kind, target in xr["method_refs"].get(api_addr, []):
            if kind == "methodinfo":
                n = img.metam[target][0]
                if "RegisterCallback" in n and n not in out:
                    out.append(n.replace("Method$Sks.Core.SksAPI.", ""))
        return out
    contract_ti = {f"{full.replace('/', '.')}_TypeInfo": full for full in contracts}

    def contract_typeinfos(method_addr):
        out = []
        for kind, target in xr["method_refs"].get(method_addr, []):
            if kind == "typeinfo":
                n = img.meta.get(target, "")
                if n in contract_ti and contract_ti[n] not in out:
                    out.append(contract_ti[n])
        return out

    def callers_of(addr):
        return sorted(xr["callers"].get(addr, ()))

    rows = []
    for e in native:
        exp = e["export"]
        if not e["paths"]:
            continue
        path = e["paths"][0]
        method = e["http_methods"][0] if e["http_methods"] else "UNKNOWN"
        notes = []
        if len(set(e["paths"])) > 1 or len(set(e["http_methods"])) > 1:
            notes.append(f"native code references several paths/methods: {e['paths']} {e['http_methods']}")
        if e.get("via"):
            notes.append(f"request built in helper {e['via']}")

        # P/Invoke stub(s) in sakasho2p named exactly like the export.
        stubs = [a for n, addrs in img.by_name.items() if n.endswith("$$" + exp) for a in addrs]
        req_types, apis, closures = [], [], []
        for s in stubs:
            for c in callers_of(s):
                cname = img.name(c) or f"sub_{c:x}"
                closures.append(cname)
                for t in contract_typeinfos(c):
                    if t not in req_types:
                        req_types.append(t)
                m = CLOSURE_RE.match(cname)
                if m:
                    api = f"{m.group('cls')}$${m.group('api')}"
                    if api not in apis:
                        apis.append(api)
                elif cname not in apis:
                    apis.append(cname)
        if not stubs:
            notes.append("no C# P/Invoke stub with this name")
        elif not closures:
            notes.append("P/Invoke stub exists but has no caller in this build")

        # Response type from ResultOf<Api> constructor parameter.
        resp_types = []
        for api in apis:
            cls, _, name = api.partition("$$")
            result_cls = cecil.get(f"{cls}/ResultOf{name}")
            if result_cls:
                for m in result_cls["methods"]:
                    if m["name"] == ".ctor":
                        for p in m["params"]:
                            if p["type"] in contracts and p["type"] not in resp_types:
                                resp_types.append(p["type"])
        resp_source = "ResultOf<Api>::.ctor parameter" if resp_types else ""
        if not resp_types:
            # Converter lambdas `<Api>b__N(Response result)` in the closure classes of Sks.<Area>.
            for api in apis:
                cls, _, name = api.partition("$$")
                for full, t in cecil.items():
                    if not full.startswith(cls + "/<>c"):
                        continue
                    for m in t["methods"]:
                        if m["name"].startswith(f"<{name}>b__"):
                            for prm in m["params"]:
                                if prm["type"] in contracts and prm["type"] not in resp_types:
                                    resp_types.append(prm["type"])
            if resp_types:
                resp_source = "converter lambda parameter"
        if not resp_types:
            # Shared handler factories called by the API (e.g. CreateHandlerForGetProducts) return
            # SuccessCallbackHandler<T, <Response>>; read the generic argument from the Cecil signature.
            for api in apis:
                for a in img.by_name.get(api, []):
                    for callee in xr["calls"].get(a, []):
                        cn = img.name(callee) or ""
                        if not cn.startswith("Sks.") or "$$" not in cn:
                            continue
                        ccls, _, cmeth = cn.partition("$$")
                        ct = cecil.get(ccls)
                        for m in (ct["methods"] if ct else []):
                            if m["name"] == cmeth:
                                for full in re.findall(r"[A-Za-z0-9_.]+(?:/[A-Za-z0-9_]+)*", m["return"]):
                                    if full in contracts and full.endswith("Response") and full not in resp_types:
                                        resp_types.append(full)
            if resp_types:
                resp_source = "return type of handler factory called by the API"
        # Request types: keep the ones that look like the request message of this call.
        reqs = [t for t in req_types if t.endswith(".Request") or t.endswith("/Request")] or req_types

        args = "; ".join(native_args(st) for st in stubs) or "UNKNOWN"
        cbs = []
        for api in apis:
            for a in img.by_name.get(api, []):
                for c in register_callbacks(a):
                    if c not in cbs:
                        cbs.append(c)

        # Naming-based candidates (NOT evidence): sibling Request/Response in the same proto namespace.
        cands = []
        for t in resp_types + reqs:
            ns = t.rsplit(".", 1)[0]
            for sib in (ns + ".Request", ns + ".Response"):
                if sib in contracts and sib not in reqs and sib not in resp_types and sib not in cands:
                    cands.append(sib)

        game_callers = []
        for api in apis:
            for a in img.by_name.get(api, []):
                for c in callers_of(a):
                    n = img.name(c)
                    if n and not n.startswith("Sks.") and n not in game_callers:
                        game_callers.append(n)

        conf = "high"
        if not reqs:
            conf = "medium" if resp_types else "low"
            notes.append("request type not found as a ProtoContract TypeInfo in the calling closure")
        none_parsed = bool(cbs) and all("," not in c for c in cbs)
        if resp_source and resp_source != "ResultOf<Api>::.ctor parameter":
            notes.append(f"response type from {resp_source}")
        if not resp_types and none_parsed:
            notes.append("C# registers RegisterCallback<T> with no protobuf schema: the client does not parse a "
                         "response body for this call")
        elif not resp_types:
            if conf == "high":
                conf = "medium"
            notes.append("response type not found (no ResultOf ctor, converter lambda or handler factory)")
        if conf == "low" and none_parsed:
            conf = "medium"  # response handling is established from code (client ignores the body)
        if not stubs or not closures:
            conf = "low"
        if method == "UNKNOWN":
            conf = "low"

        def proto(t):
            return contracts[t]["proto"].lstrip(".") if t in contracts else t

        rows.append({
            "path": path,
            "method": method,
            "request_type": " | ".join(proto(t) for t in reqs) or "UNKNOWN",
            "response_type": " | ".join(proto(t) for t in resp_types) or ("NONE_PARSED" if none_parsed else "UNKNOWN"),
            "native_export": exp,
            "csharp_args_to_native": args,
            "csharp_response_handling": "; ".join(cbs) or "UNKNOWN",
            "naming_candidates_unverified": " | ".join(proto(t) for t in cands),
            "calling_class_method": "; ".join(apis) or "UNKNOWN",
            "game_callers": "; ".join(game_callers[:3]) + (f" (+{len(game_callers) - 3} more)" if len(game_callers) > 3 else ""),
            "confidence": conf,
            "notes": "; ".join(notes),
        })

    # Coverage against the preservation repo's 80 paths.
    known = []
    with open(ROOT / "ref/MKTour-Server/data/endpoints.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["service"].startswith("Sakasho"):
                known.append(r["path"])
    mapped = {r["path"] for r in rows}
    for p in known:
        if p not in mapped:
            rows.append({"path": p, "method": "UNKNOWN", "request_type": "UNKNOWN", "response_type": "UNKNOWN",
                         "native_export": "UNKNOWN", "csharp_args_to_native": "UNKNOWN",
                         "csharp_response_handling": "UNKNOWN", "naming_candidates_unverified": "",
                         "calling_class_method": "UNKNOWN", "game_callers": "",
                         "confidence": "low",
                         "notes": "path string exists in libs2pcore.so but no Sks* export references it"})

    rows.sort(key=lambda r: (r["path"], r["native_export"]))
    out = ROOT / "out/endpoints_map.csv"
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    by_conf = defaultdict(int)
    for r in rows:
        by_conf[r["confidence"]] += 1
    print(f"{len(rows)} rows ({len(mapped)} distinct paths from native code, {len(known)} paths in the preservation list, "
          f"{len(set(known) - mapped)} of those unmatched) -> {out}")
    print(dict(by_conf))
    print("request UNKNOWN:", sum(r["request_type"] == "UNKNOWN" for r in rows),
          " response UNKNOWN:", sum(r["response_type"] == "UNKNOWN" for r in rows))


if __name__ == "__main__":
    main()
