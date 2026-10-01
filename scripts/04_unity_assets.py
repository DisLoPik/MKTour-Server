"""Part 1.7 - catalogue Unity assets bundled in base.apk using UnityPy.
Also extracts MonoScript class names (useful because global-metadata.dat is encrypted).
"""
import csv, json, os, collections
import UnityPy

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT, "work", "base_unzipped", "assets", "bin", "Data")
OUT = os.path.join(ROOT, "data")
EXPORT = os.path.join(ROOT, "unity_export")
os.makedirs(EXPORT, exist_ok=True)

rows, scripts, summary = [], [], {}
for fname in ("data.unity3d", "unity default resources"):
    path = os.path.join(DATA_DIR, fname)
    env = UnityPy.load(path)
    per_type = collections.Counter()
    per_type_bytes = collections.Counter()
    versions = set()
    for fobj_name, fobj in env.files.items():
        v = getattr(fobj, "unity_version", None) or getattr(fobj, "version_engine", None)
        if v:
            versions.add(str(v))
    containers = {}
    try:
        for cpath, obj in env.container.items():
            containers[obj.path_id] = cpath
    except Exception:
        pass
    for obj in env.objects:
        t = obj.type.name
        per_type[t] += 1
        size = getattr(obj, "byte_size", 0) or 0
        per_type_bytes[t] += size
        name = ""
        extra = ""
        try:
            data = obj.read()
            name = getattr(data, "m_Name", "") or getattr(data, "name", "") or ""
            if t == "MonoScript":
                scripts.append({
                    "file": fname,
                    "assembly": getattr(data, "m_AssemblyName", ""),
                    "namespace": getattr(data, "m_Namespace", ""),
                    "class": getattr(data, "m_ClassName", ""),
                })
            elif t == "TextAsset":
                script = getattr(data, "m_Script", b"")
                if isinstance(script, str):
                    script = script.encode("utf-8", "surrogateescape")
                extra = f"{len(script)} bytes"
                safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in (name or str(obj.path_id)))
                with open(os.path.join(EXPORT, f"TextAsset_{safe}.bytes"), "wb") as f:
                    f.write(script)
            elif t == "Texture2D":
                extra = f"{getattr(data,'m_Width','?')}x{getattr(data,'m_Height','?')} fmt={getattr(data,'m_TextureFormat','?')}"
            elif t == "Shader":
                try:
                    pn = data.m_ParsedForm.m_Name
                    name = name or pn
                except Exception:
                    pass
            elif t == "PlayerSettings":
                ps = {}
                for k in ("companyName", "productName", "bundleVersion", "AndroidProfiler", "scriptingBackend"):
                    if hasattr(data, k):
                        ps[k] = str(getattr(data, k))
                extra = json.dumps(ps)
            elif t == "BuildSettings":
                scenes = getattr(data, "scenes", None) or getattr(data, "levels", None)
                ver = getattr(data, "m_Version", "")
                extra = json.dumps({"scenes": list(scenes) if scenes else [], "version": str(ver)})
        except Exception as e:
            extra = f"<read error: {e.__class__.__name__}>"
        rows.append({"file": fname, "path_id": obj.path_id, "type": t, "name": name,
                     "container_path": containers.get(obj.path_id, ""), "byte_size": size, "details": extra})
    summary[fname] = {"unity_versions": sorted(versions), "object_count": sum(per_type.values()),
                      "types": {k: {"count": per_type[k], "bytes": per_type_bytes[k]} for k in sorted(per_type, key=lambda k: -per_type[k])}}

with open(os.path.join(OUT, "unity_assets.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    w.writeheader(); w.writerows(rows)
with open(os.path.join(OUT, "unity_monoscripts.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["file", "assembly", "namespace", "class"])
    w.writeheader(); w.writerows(sorted(scripts, key=lambda s: (s["assembly"], s["namespace"], s["class"])))
with open(os.path.join(OUT, "unity_assets_summary.json"), "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2)

for fn, s in summary.items():
    print("==", fn, s["unity_versions"], s["object_count"], "objects")
    for k, v in list(s["types"].items())[:40]:
        print(f"   {k:28} {v['count']:6} {v['bytes']:>12}")
print("MonoScripts:", len(scripts))
print(collections.Counter(s["assembly"] for s in scripts).most_common(30))
for r in rows:
    if r["type"] in ("PlayerSettings", "BuildSettings", "TextAsset"):
        print(r["type"], r["name"], r["details"][:300])
