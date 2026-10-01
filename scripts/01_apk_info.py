"""Part 1.2 / 1.3 - manifest extraction, signing certs, file inventory for both APKs.
Reads only from mkt_archive/originals (read-only copies). Writes to apk_info/ and data/.
"""
import csv, hashlib, json, os, sys, zipfile, collections
from androguard.core.apk import APK
from androguard.util import set_log

set_log("ERROR")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ORIG = os.path.join(ROOT, "originals")
OUT_INFO = os.path.join(ROOT, "apk_info")
OUT_DATA = os.path.join(ROOT, "data")
os.makedirs(OUT_INFO, exist_ok=True)
os.makedirs(OUT_DATA, exist_ok=True)

APKS = ["base.apk", "split_config.arm64_v8a.apk"]


def cert_info(c):
    """c is an asn1crypto x509.Certificate"""
    der = c.dump()
    return {
        "subject": c.subject.human_friendly,
        "issuer": c.issuer.human_friendly,
        "serial": hex(c.serial_number),
        "not_before": str(c["tbs_certificate"]["validity"]["not_before"].native),
        "not_after": str(c["tbs_certificate"]["validity"]["not_after"].native),
        "signature_algorithm": c["signature_algorithm"]["algorithm"].native,
        "public_key_algorithm": c.public_key.algorithm,
        "public_key_bits": c.public_key.bit_size,
        "sha256": hashlib.sha256(der).hexdigest(),
        "sha1": hashlib.sha1(der).hexdigest(),
        "md5": hashlib.md5(der).hexdigest(),
    }


def ftype(name):
    n = name.lower()
    base = os.path.basename(n)
    if n.startswith("lib/") and n.endswith(".so"):
        return "native_library"
    if n.endswith(".dex"):
        return "dex_bytecode"
    if n.startswith("meta-inf/"):
        return "signature_meta"
    if n.startswith("assets/_nabe_/"):
        return "nabe_zstd_asset"
    if n.startswith("assets/bin/data/"):
        return "unity_data"
    if n.startswith("assets/audio/"):
        return "wwise_audio_meta"
    if n.startswith("assets/"):
        return "asset_other"
    if n == "androidmanifest.xml" or n == "resources.arsc":
        return "android_binary_xml_or_arsc"
    if n.startswith("res/"):
        ext = os.path.splitext(base)[1]
        if ext in (".png", ".webp", ".jpg", ".9.png"):
            return "res_image"
        if ext == ".xml":
            return "res_xml"
        return "res_other"
    if n.endswith(".properties") or n.endswith(".version"):
        return "library_version_properties"
    if n.endswith(".proto") or n.endswith(".json"):
        return "schema_or_config"
    if n.endswith(".kotlin_builtins") or n.endswith(".kotlin_module") or n.startswith("kotlin/"):
        return "kotlin_metadata"
    return "other"


summary = {}
inv_rows = []
for apk_name in APKS:
    path = os.path.join(ORIG, apk_name)
    a = APK(path)
    info = {
        "file": apk_name,
        "package": a.get_package(),
        "split": a.get_attribute_value("manifest", "split"),
        "version_code": a.get_androidversion_code(),
        "version_name": a.get_androidversion_name(),
        "min_sdk": a.get_min_sdk_version(),
        "target_sdk": a.get_target_sdk_version(),
        "compile_sdk": a.get_attribute_value("manifest", "compileSdkVersion"),
        "app_label": None,
        "main_activity": a.get_main_activity(),
        "permissions": sorted(a.get_permissions()),
        "declared_permissions": sorted(a.get_declared_permissions()),
        "activities": sorted(a.get_activities()),
        "services": sorted(a.get_services()),
        "receivers": sorted(a.get_receivers()),
        "providers": sorted(a.get_providers()),
        "features": sorted(a.get_features()),
        "libraries": sorted(a.get_libraries()),
        "signature_schemes": {
            "v1": a.is_signed_v1(),
            "v2": a.is_signed_v2(),
            "v3": a.is_signed_v3(),
        },
        "certificates_v1": [],
        "certificates_v2": [],
        "certificates_v3": [],
    }
    try:
        info["app_label"] = a.get_app_name()
    except Exception as e:  # resources may be missing in split
        info["app_label"] = f"<unavailable: {e.__class__.__name__}>"
    try:
        info["certificates_v1"] = [cert_info(c) for c in a.get_certificates_v1()]
    except Exception as e:
        info["certificates_v1_error"] = repr(e)
    try:
        info["certificates_v2"] = [cert_info(c) for c in a.get_certificates_v2()]
    except Exception as e:
        info["certificates_v2_error"] = repr(e)
    try:
        info["certificates_v3"] = [cert_info(c) for c in a.get_certificates_v3()]
    except Exception as e:
        info["certificates_v3_error"] = repr(e)

    xml = a.get_android_manifest_xml()
    ns = "{http://schemas.android.com/apk/res/android}"
    meta = []
    for m in xml.iter("meta-data"):
        meta.append({"name": m.get(ns + "name"), "value": m.get(ns + "value"), "resource": m.get(ns + "resource")})
    info["meta_data"] = meta
    schemes = []
    for d in xml.iter("data"):
        s = {k.replace(ns, ""): v for k, v in d.attrib.items()}
        if s:
            schemes.append(s)
    info["intent_filter_data"] = schemes
    app = xml.find("application")
    if app is not None:
        info["application_attrs"] = {k.replace(ns, ""): v for k, v in app.attrib.items()}
    info["queries"] = []
    q = xml.find("queries")
    if q is not None:
        for el in q:
            info["queries"].append({"tag": el.tag, **{k.replace(ns, ""): v for k, v in el.attrib.items()}})
            for sub in el.iter():
                if sub is not el:
                    info["queries"].append({"tag": "  " + sub.tag, **{k.replace(ns, ""): v for k, v in sub.attrib.items()}})

    from lxml import etree
    with open(os.path.join(OUT_INFO, apk_name + ".AndroidManifest.xml"), "wb") as f:
        f.write(etree.tostring(xml, pretty_print=True, encoding="utf-8"))

    summary[apk_name] = info

    with zipfile.ZipFile(path) as z:
        for zi in z.infolist():
            if zi.is_dir():
                continue
            inv_rows.append({
                "apk": apk_name,
                "path": zi.filename,
                "type": ftype(zi.filename),
                "extension": os.path.splitext(zi.filename)[1].lower() or "(none)",
                "compressed_size": zi.compress_size,
                "uncompressed_size": zi.file_size,
                "compression": {0: "stored", 8: "deflate"}.get(zi.compress_type, str(zi.compress_type)),
                "crc32": f"{zi.CRC:08x}",
            })

with open(os.path.join(OUT_INFO, "apk_manifest_summary.json"), "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2, default=str)

with open(os.path.join(OUT_DATA, "permissions.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["apk", "permission", "kind"])
    for apk_name, info in summary.items():
        for p in info["permissions"]:
            w.writerow([apk_name, p, "uses-permission"])
        for p in info["declared_permissions"]:
            w.writerow([apk_name, p, "declared-permission"])

with open(os.path.join(OUT_DATA, "components.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["apk", "component_type", "name"])
    for apk_name, info in summary.items():
        for t in ("activities", "services", "receivers", "providers"):
            for c in info[t]:
                w.writerow([apk_name, t[:-1] if t != "activities" else "activity", c])

with open(os.path.join(OUT_DATA, "file_inventory.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(inv_rows[0].keys()))
    w.writeheader()
    w.writerows(inv_rows)

grp = collections.defaultdict(lambda: {"files": 0, "compressed": 0, "uncompressed": 0})
for r in inv_rows:
    g = grp[(r["apk"], r["type"])]
    g["files"] += 1
    g["compressed"] += r["compressed_size"]
    g["uncompressed"] += r["uncompressed_size"]
grp_rows = [{"apk": k[0], "type": k[1], **v} for k, v in sorted(grp.items(), key=lambda kv: (kv[0][0], -kv[1]["uncompressed"]))]
with open(os.path.join(OUT_DATA, "file_inventory_by_type.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["apk", "type", "files", "compressed", "uncompressed"])
    w.writeheader()
    w.writerows(grp_rows)
ext = collections.defaultdict(lambda: {"files": 0, "uncompressed": 0})
for r in inv_rows:
    e = ext[(r["apk"], r["extension"])]
    e["files"] += 1
    e["uncompressed"] += r["uncompressed_size"]
with open(os.path.join(OUT_DATA, "file_inventory_by_extension.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["apk", "extension", "files", "uncompressed"])
    for k, v in sorted(ext.items(), key=lambda kv: (kv[0][0], -kv[1]["uncompressed"])):
        w.writerow([k[0], k[1], v["files"], v["uncompressed"]])

for apk_name, info in summary.items():
    print("==", apk_name)
    for k in ("package", "split", "version_code", "version_name", "min_sdk", "target_sdk", "compile_sdk", "app_label", "main_activity", "signature_schemes"):
        print(f"  {k}: {info[k]}")
    print("  permissions:", len(info["permissions"]), "activities:", len(info["activities"]), "services:", len(info["services"]), "receivers:", len(info["receivers"]), "providers:", len(info["providers"]))
    for kind in ("certificates_v1", "certificates_v2", "certificates_v3"):
        for c in info[kind]:
            print(f"  {kind}: {c['subject']} | sha256={c['sha256']} | {c['not_before']} -> {c['not_after']}")
print("inventory rows:", len(inv_rows))
for r in grp_rows:
    print(f"  {r['apk']:30} {r['type']:28} {r['files']:6} {r['uncompressed']:>12}")
