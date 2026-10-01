"""Part 1.4 SDK inventory + Part 1.5 IL2CPP metadata investigation record + Pia string subset."""
import csv, json, os, math, collections, re
from elftools.elf.elffile import ELFFile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
LIB = os.path.join(ROOT, "work", "split_unzipped", "lib", "arm64-v8a")
BASE = os.path.join(ROOT, "work", "base_unzipped")

sdks = [
    # name, category, version, evidence
    ("Unity (IL2CPP, arm64-v8a)", "engine", "2022.3.69f1 (621633b9d04b)", "libunity.so strings; data.unity3d serialized version; boot.config build-guid"),
    ("Nintendo NPF SDK (Nintendo Platform Framework)", "Nintendo account / BaaS / IAP", "unknown (runtime value)", "com.nintendo.npf.* (jadx), NPFSDK.dll, assets/npf.json"),
    ("Sakasho SDK ('s2p' core) + Booster extensions", "game backend client (DeNA Sakasho)", "native core build id d695073f (string near API table)", "libs2pcore.so (117 Sks* exports), sakasho2p.dll, assets/SakashoServerConfig"),
    ("Nintendo Pia (PiaUnity)", "P2P multiplayer / NAT traversal / relay", "PIA_7_2_1", "libil2cpp.so strings (statically linked), com.nintendo.piaunity.dll, nn.pia.* MonoScripts"),
    ("Nabe (Nintendo asset packing)", "asset container (zstd + dictionary)", "", "libnabe-android.so, jp.co.nintendo.nabe.AndroidUtil, Nabe.dll, assets/_nabe_/"),
    ("zstd-jni (com.github.luben.zstd)", "compression", "", "libzstd-jni.so, jadx com/github/luben"),
    ("Audiokinetic Wwise", "audio", "2023.1.14.8770 (generator)", "libAkSoundEngine.so, assets/Audio/GeneratedSoundBanks/ProjectInfo.xml (project 'Booster')"),
    ("OpenSSL", "TLS (used by Sakasho core)", "3.3.1 (4 Jun 2024)", "libs2pcore.so strings"),
    ("POCO C++ Libraries (Net/NetSSL/JSON/XML)", "HTTP client for Sakasho core", "1.12.5p2", "libs2pcore.so strings"),
    ("Google protobuf (C++ lite) + abseil lts_20240116", "serialization (native)", "", "libs2pcore.so /tmp/work/protobuf/... paths"),
    ("protobuf-net", "serialization (managed)", "", "ScriptingAssemblies.json"),
    ("MessagePack-CSharp", "serialization (managed)", "", "ScriptingAssemblies.json (MessagePackCSharp.dll)"),
    ("Newtonsoft.Json", "serialization (managed)", "", "ScriptingAssemblies.json"),
    ("MoonSharp", "Lua interpreter (managed)", "", "ScriptingAssemblies.json (MoonSharp.Interpreter.dll)"),
    ("Nintendo MessageStudio (LMS)", "localisation text", "", "Nintendo.MessageStudio.Lib MonoScripts"),
    ("Sead / Uge (Nintendo in-house)", "game framework", "", "MonoScript namespaces Sead, Uge"),
    ("libcurl (inside libunity)", "Unity networking", "8.10.1", "libunity.so strings"),
    ("Firebase Analytics", "analytics", "22.4.0", "firebase-analytics.properties; Firebase.Analytics.dll"),
    ("Firebase Cloud Messaging (+ C++ SDK)", "push notifications", "C++ 12.10.0", "libFirebaseCppApp-12_10_0.so, libFirebaseCppMessaging.so, Firebase.Messaging.dll"),
    ("Firebase IID / Installations / encoders / datatransport", "Firebase infra", "iid 21.1.0", "*.properties"),
    ("Google Play Services (base/basement/tasks/location/nearby/drive/appset/ads-identifier/stats/measurement)", "Google Play services", "base 18.6.0; measurement 22.4.0; location 19.0.0; nearby 18.0.2", "*.properties"),
    ("Google Play Games Services v2 + Unity plugin", "achievements/sign-in", "17.0.0; Unity plugin 0.11.01; APP_ID 482624233067", "play-services-games-v2.properties; manifest meta-data"),
    ("Google Play Billing", "in-app purchases", "7.1.1", "billing.properties; manifest meta-data"),
    ("Google Play Integrity", "device attestation", "1.3.0 (java) / 1.3.2 (unity)", "integrity.properties; META-INF version; SksV2SecurityVerifyPlayIntegrityJWT"),
    ("Google Play Core / Common", "Play core", "1.8.1", "META-INF/com.google.play.core.version"),
    ("Google Cloud Pub/Sub client (pubsub.v1.json)", "analytics transport", "", "pubsub.v1.json in APK root; pubsub.googleapis.com in capture"),
    ("Bugsnag (Android 6.12.1 + NDK + ANR plugin + Unity)", "crash reporting", "Android notifier 6.12.1", "com/bugsnag/android/Notifier.java; libbugsnag-*.so; BugsnagUnity.dll"),
    ("Unity Mobile Notifications", "local notifications", "", "Unity.Notifications.Android.dll; com.unity.androidnotifications"),
    ("Booster local push (jp.co.nintendo.booster.android.localpush)", "local notifications", "", "manifest receiver"),
    ("NativeGallery (yasirkula)", "save screenshots", "", "NativeGallery.Runtime.dll; com.yasirkula"),
    ("Sns.Twitter", "social share", "", "Sns.Twitter.dll"),
    ("AndroidX / Kotlin coroutines", "Android support", "appcompat 1.6.1; core 1.9.0; coroutines 1.7.3", "META-INF/*.version"),
    ("Android Privacy Sandbox ads-adservices", "ads attribution API", "1.1.0-beta11", "META-INF version; uses-library android.ext.adservices"),
    ("Google Ads conversion / AdServices (via measurement)", "ad attribution (no ad SDK UI)", "", "classes.dex googleadservices.com; google_analytics_adid_collection_enabled=false"),
]
with open(os.path.join(DATA, "third_party_sdks.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["sdk", "category", "version", "evidence"])
    w.writerows(sdks)

def ent(b):
    c = collections.Counter(b); n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values()) if n else 0


lib = os.path.join(LIB, "libil2cpp.so")
raw = open(lib, "rb").read()
e = ELFFile(open(lib, "rb"))
secs = [{"name": s.name, "offset": hex(s["sh_offset"]), "size": s["sh_size"], "type": s["sh_type"]} for s in e.iter_sections() if s.name]
data = e.get_section_by_name(".data")
d0, dsz = data["sh_offset"], data["sh_size"]
blk = 0x1000
regions, cur = [], None
for off in range(d0, d0 + dsz, blk):
    hi = ent(raw[off:off + blk]) > 7.5
    if hi and cur is None:
        cur = off
    elif not hi and cur is not None:
        if off - cur >= 0x100000:
            regions.append({"start": hex(cur), "end": hex(off), "size_bytes": off - cur, "mean_entropy": round(ent(raw[cur:off]), 3)})
        cur = None
if cur is not None and d0 + dsz - cur >= 0x100000:
    regions.append({"start": hex(cur), "end": hex(d0 + dsz), "size_bytes": d0 + dsz - cur, "mean_entropy": round(ent(raw[cur:d0 + dsz]), 3)})
magic = bytes.fromhex("AF1BB1FA")
found = {}
for root, _, files in os.walk(os.path.join(ROOT, "work")):
    if "jadx" in root or "apktool" in root:
        continue
    for fn in files:
        p = os.path.join(root, fn)
        if os.path.getsize(p) > 0 and magic in open(p, "rb").read():
            found[os.path.relpath(p, ROOT)] = True
il2 = {
    "global_metadata_dat_in_base_apk": any(n.endswith("global-metadata.dat") for n in [l.split(",")[1] for l in open(os.path.join(DATA, "file_inventory.csv"), encoding="utf-8").read().splitlines()[1:]]),
    "files_containing_magic_AF1BB1FA": list(found.keys()),
    "libil2cpp_contains_string_global-metadata.dat": b"global-metadata.dat" in raw,
    "libil2cpp_size": len(raw),
    "libil2cpp_sections": secs,
    "libil2cpp_data_section": {"offset": hex(d0), "size": dsz, "entropy": round(ent(raw[d0:d0 + dsz]), 3)},
    "high_entropy_regions_in_.data_(>=1MiB, >7.5 bits/byte)": regions,
    "compression_magics_in_.data": {k: raw[d0:d0 + dsz].count(v) for k, v in {"zstd": b"\x28\xb5\x2f\xfd", "lz4_frame": b"\x04\x22\x4d\x18", "gzip": b"\x1f\x8b\x08", "xz": b"\xfd7zXZ"}.items()},
    "conclusion": ("global-metadata.dat is NOT shipped as a file. libil2cpp.so has no 'global-metadata.dat' string and no metadata magic; "
                   "its .data section (27.8 MB) carries roughly 12-16 MB of high-entropy data (7.6-8.0 bits/byte, depending on block threshold) with no compression container signature. This is consistent with "
                   "metadata embedded in libil2cpp.so and encrypted/obfuscated by a customised IL2CPP loader. Il2CppDumper could not be run statically."),
    "il2cppdumper_run": False,
    "il2cppdumper_version_installed": "v6.7.46 (net6 win) in tools/Il2CppDumper",
}
with open(os.path.join(DATA, "il2cpp_metadata_analysis.json"), "w", encoding="utf-8") as f:
    json.dump(il2, f, indent=2)
print(json.dumps({k: v for k, v in il2.items() if k not in ("libil2cpp_sections",)}, indent=1)[:3000])

rx = re.compile(r"(\bnn::pia|nn3pia|[Pp]ia[A-Z_ ]|PIA_|[Ii]zumo|[Nn]pln|NatCheck|NatTraversal|[Rr]elay|Turn[A-Z]|Mesh[A-Z]|[A-Za-z]Mesh|Reckoning|Matchmak|StationManager|SessionProtocol|\.srv\.nintendo)")
keep = []
for line in open(os.path.join(ROOT, "strings", "libil2cpp.so.strings.txt"), encoding="utf-8"):
    txt = line.split(" ", 2)[2].rstrip("\n")
    if rx.search(txt) and len(txt) < 300 and not txt.startswith("_ZNSt"):
        keep.append(line.rstrip("\n"))
with open(os.path.join(ROOT, "strings", "pia_izumo_npln_strings.txt"), "w", encoding="utf-8") as f:
    f.write("# subset of libil2cpp.so strings matching Pia/Izumo/NPLN/session keywords\n" + "\n".join(keep))
print("pia subset lines:", len(keep))
