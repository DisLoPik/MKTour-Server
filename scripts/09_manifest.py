"""Write manifest.txt: SHA-256 of the original inputs and of every generated file.
Run last (after 10_sanitize_for_publication.py) so the hashes match the published files.
tools/ is third-party software, so only its pip freeze is hashed; manifest.txt cannot hash itself.
All paths are relative to the repository root and use forward slashes; the timestamp is UTC."""
import hashlib, os, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ORIGS = ["base.apk", "split_config.arm64_v8a.apk", "PCAPdroid_29_Sep_22_19_48.pcap"]
# SHA-256 of the inputs as supplied, recorded before any work started
EXPECTED = {
    "base.apk": "c69366ac9d378c04069cda2751a3fc8fd78f2c6d93867e2d523dcfd0498c0c8c",
    "split_config.arm64_v8a.apk": "f2cc97f871957d1e2a713cf5be238b6342a992242a6cae930f32c922a6a29d55",
    "PCAPdroid_29_Sep_22_19_48.pcap": "a79774f5d15c126917b27d361cca86c8d6ded1e10cd669d89225c3aa3abe6342",
}
SIZES = {"base.apk": 90499986, "split_config.arm64_v8a.apk": 81651251, "PCAPdroid_29_Sep_22_19_48.pcap": 5814424}


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def rel(p):
    return os.path.relpath(p, ROOT).replace("\\", "/")


lines = []
w = lines.append
w("# Mario Kart Tour preservation archive - SHA-256 manifest")
w(f"# generated {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
w("# format: sha256  size_bytes  path (relative to the repository root)")
w("# originals/, work/, unity_export/, strings/*.strings.txt and tools/ are listed for integrity but are not published (see .gitignore)")
w("")
w("## 1. ORIGINAL INPUTS (hash recorded before analysis, and hash of the read-only copy in originals/)")
for o in ORIGS:
    w(f"{EXPECTED[o]}  {SIZES[o]:>12}  {o} (as supplied)")
    cp = os.path.join(ROOT, "originals", o)
    if os.path.exists(cp):
        h = sha(cp)
        w(f"{h}  {os.path.getsize(cp):>12}  originals/{o}  [{'matches' if h == EXPECTED[o] else 'MISMATCH'}]")
w("# note: the app's external data folder (mkt_data) was not available for this analysis")
w("")
w("## 2. TOOLS")
freeze = os.path.join(ROOT, "tools", "python_requirements_freeze.txt")
if os.path.exists(freeze):
    w(f"{sha(freeze)}  {os.path.getsize(freeze):>12}  {rel(freeze)}")
w("")
w("## 3. GENERATED FILES")
count = 0
for top in (".gitignore", "REPORT.md", "apk_info", "data", "pcap", "strings", "unity_export", "scripts", "work"):
    p0 = os.path.join(ROOT, top)
    if not os.path.exists(p0):
        continue
    paths = [p0] if os.path.isfile(p0) else sorted(os.path.join(dp, f) for dp, _, fs in os.walk(p0) for f in fs)
    w(f"### {top}")
    for p in paths:
        if "__pycache__" in p:
            continue
        w(f"{sha(p)}  {os.path.getsize(p):>12}  {rel(p)}")
        count += 1
w("")
w(f"# {count} generated files hashed. manifest.txt itself is not listed (a file cannot contain its own hash).")
with open(os.path.join(ROOT, "manifest.txt"), "w", encoding="ascii", newline="\n") as f:
    f.write("\n".join(lines) + "\n")
print("generated files:", count)
