"""Part 2.3 (certs) + Part 2.7 cross-reference of capture hostnames with APK strings.
Outputs data/tls_server_certs.csv, data/apk_hostnames.csv, data/hosts_crossref.csv, data/hosts.json
"""
import csv, json, os, re, subprocess, collections, hashlib, shutil
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP = os.path.join(ROOT, "originals", "PCAPdroid_29_Sep_22_19_48.pcap")
TSHARK = os.environ.get("TSHARK") or shutil.which("tshark") or r"C:\Program Files\Wireshark\tshark.exe"
DATA = os.path.join(ROOT, "data")

out = subprocess.run([TSHARK, "-r", PCAP, "-Y", "tls.handshake.type==11", "-T", "fields", "-E", "occurrence=a", "-E", "aggregator=|",
                      "-e", "tcp.stream", "-e", "tls.handshake.extensions_server_name", "-e", "tls.handshake.certificate"],
                     capture_output=True, text=True).stdout
sni_by_stream = {}
with open(os.path.join(DATA, "tls_connections.csv"), encoding="utf-8") as f:
    for r in csv.DictReader(f):
        sni_by_stream[r["tcp_stream"]] = r["sni"]
certs = {}
for line in out.splitlines():
    parts = line.split("\t")
    stream, chain = parts[0], parts[2] if len(parts) > 2 else ""
    for pos, hx in enumerate(filter(None, chain.split("|"))):
        der = bytes.fromhex(hx.replace(":", ""))
        fp = hashlib.sha256(der).hexdigest()
        c = certs.get(fp)
        if not c:
            cert = x509.load_der_x509_certificate(der)
            try:
                sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                sans = []
            c = certs[fp] = {
                "sha256": fp, "chain_position": pos, "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
                "serial": format(cert.serial_number, "x"), "not_before": cert.not_valid_before_utc.isoformat(),
                "not_after": cert.not_valid_after_utc.isoformat(), "sig_alg": cert.signature_algorithm_oid._name,
                "key": f"{cert.public_key().__class__.__name__.replace('_', '')}", "sans": ";".join(sans), "seen_for_sni": set(), "streams": set()}
        c["seen_for_sni"].add(sni_by_stream.get(stream, "")); c["streams"].add(stream)
cert_rows = []
for c in certs.values():
    c = dict(c); c["seen_for_sni"] = ";".join(sorted(c["seen_for_sni"])); c["streams"] = len(c["streams"])
    cert_rows.append(c)
with open(os.path.join(DATA, "tls_server_certs.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(cert_rows[0].keys()))
    w.writeheader(); w.writerows(sorted(cert_rows, key=lambda r: (r["seen_for_sni"], r["chain_position"])))

TLDS = r"(?:com|net|org|io|jp|co\.jp|info|me|us|cn|kr|tw|hk|de|uk|fr|gl|dev|cloud|nintendo\.net)"
host_re = re.compile(r"(?<![A-Za-z0-9_\-.])((?:%s|[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)*\.%s)(?![A-Za-z0-9_\-])" % ("%s", TLDS))
PKG_PREFIX = ("com.", "org.", "net.", "io.", "jp.", "android.", "androidx.", "java.", "javax.", "kotlin.", "dalvik.", "sun.", "libcore.")
apk_hosts = collections.defaultdict(set)


def scan_text(text, src):
    for m in host_re.finditer(text):
        h = m.group(1).lower()
        labels = h.split(".")
        if h.startswith(PKG_PREFIX) and len(labels) >= 2 and labels[0] in ("com", "org", "net", "io", "jp", "android", "androidx", "java", "javax", "kotlin"):
            continue  # java package names
        if len(labels[-2]) < 2 or re.fullmatch(r"[0-9.]+", h):
            continue
        apk_hosts[h].add(src)


for fn in os.listdir(os.path.join(ROOT, "strings")):
    with open(os.path.join(ROOT, "strings", fn), encoding="utf-8", errors="replace") as f:
        scan_text(f.read(), fn.replace(".strings.txt", ""))
for base, label in ((os.path.join(ROOT, "work", "jadx", "sources", "com", "nintendo"), "jadx:com.nintendo"),
                    (os.path.join(ROOT, "work", "jadx", "sources", "jp"), "jadx:jp.co.nintendo"),
                    (os.path.join(ROOT, "work", "apktool", "res", "values"), "res/values")):
    for dp, _, files in os.walk(base):
        for fn in files:
            with open(os.path.join(dp, fn), encoding="utf-8", errors="replace") as f:
                scan_text(f.read(), label)
for rel in ("assets/npf.json", "assets/SakashoServerConfig"):
    with open(os.path.join(ROOT, "work", "base_unzipped", *rel.split("/")), encoding="utf-8", errors="replace") as f:
        scan_text(f.read(), rel)

NOISE = re.compile(r"(^|\.)(example\.com|w3\.org|apache\.org|xml\.org|appinf\.com|openssl\.org|cppreference\.com|googlesource\.com|github\.com|"
                   r"sil\.org|ascendercorp\.com|chilliant\.blogspot\.com|developer\.android\.com|docs\.bugsnag\.com|firebase\.google\.com|"
                   r"curl\.se|microsoft\.com|yahoo\.com|facebook\.com|twitter\.com|gc\.apple\.com|arm\.com|x\.org|adobe\.com|goo\.gl|"
                   r"kotlinx\.coroutines\.io|libcore\.io|plus\.me|schemas\.android\.com)$")
apk_rows = []
for h, srcs in sorted(apk_hosts.items()):
    apk_rows.append({"hostname": h, "category": "doc/library-reference" if NOISE.search(h) else "possible-endpoint", "sources": ";".join(sorted(srcs))})
with open(os.path.join(DATA, "apk_hostnames.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["hostname", "category", "sources"])
    w.writeheader(); w.writerows(apk_rows)

templates = {r"^[^.]+\.lp1\.p\.srv\.nintendo\.net$": "%s.lp1.p.srv.nintendo.net (libil2cpp.so)",
             r"^[^.]+\.dd1\.p\.srv\.nintendo\.net$": "%s.dd1.p.srv.nintendo.net (libil2cpp.so)"}

cap = {}
with open(os.path.join(DATA, "pcap_hosts.csv"), encoding="utf-8") as f:
    for r in csv.DictReader(f):
        cap[r["hostname"]] = r
all_apk_text = None


def apk_text_contains(needle):
    global all_apk_text
    if all_apk_text is None:
        parts = []
        for fn in os.listdir(os.path.join(ROOT, "strings")):
            parts.append(open(os.path.join(ROOT, "strings", fn), encoding="utf-8", errors="replace").read().lower())
        all_apk_text = "\n".join(parts)
    return needle.lower() in all_apk_text


ROLE = {
    "api.mariokarttour.com": "Sakasho/Booster game API (protobuf over HTTPS, libs2pcore OpenSSL client)",
    "pvp.mariokarttour.com": "PvP / Izumo matchmaking gateway (custom binary TCP 11401; redirects to room server)",
    "nat-check-0.mariokarttour.com": "Pia NAT-type check (UDP 33334/34543)",
    "nat-check-1.mariokarttour.com": "Pia NAT-type check (UDP 34543)",
    "g2122d301.lp1.p.srv.nintendo.net": "NPLN / Pia monitoring (UDP 34343, one-way)",
    "a6913b7b80402974409b47079c29d775.baas.nintendo.com": "Nintendo BaaS (NPF SDK login, users, analytics config)",
    "api.accounts.nintendo.com": "Nintendo Account API (session_token / token exchange)",
    "c-lp1.accounts.nintendo.com": "Nintendo Account web content (in-app browser / auth UI)",
    "public-content-cdn-mariokarttour.akamaized.net": "Game content CDN (Akamai)",
    "download-cdn-mariokarttour.akamaized.net": "Asset download CDN (Akamai)",
    "support-cdn-mariokarttour.akamaized.net": "Support / help pages CDN (Akamai)",
    "support.mariokarttour.com": "Support site (AWS ALB)",
    "announcement-resource-cdn.mariokarttour.com": "News / announcement resources (Akamai)",
    "pubsub.googleapis.com": "Google Cloud Pub/Sub (NPF analytics upload?)",
    "firebaselogging.googleapis.com": "Firebase / Google data-transport logging",
    "sessions.bugsnag.com": "Bugsnag session tracking",
}
# EC2 host names embed the instance IP, so match the pattern instead of a literal name
EC2_ROLE = (re.compile(r"^ec2-[^.]+\.[a-z0-9-]+\.compute\.amazonaws\.com$"),
            "Izumo room / relay server (TCP+UDP 14106), address handed out by pvp")


def role_for(h):
    return ROLE.get(h) or (EC2_ROLE[1] if EC2_ROLE[0].match(h) else "")

x_rows = []
for h, r in cap.items():
    if h.startswith("[ip]") or h == "_dns.resolver.arpa":
        continue
    status, evidence = "capture only", ""
    if h in apk_hosts:
        status, evidence = "both (exact)", ";".join(sorted(apk_hosts[h]))
    else:
        for rx, t in templates.items():
            if re.match(rx, h):
                status, evidence = "both (APK format-string template)", t
        if status == "capture only":
            dom = ".".join(h.split(".")[-2:])
            if h.endswith(".baas.nintendo.com") and apk_text_contains(h):
                status, evidence = "both (exact)", "assets/npf.json baasHost"
            elif apk_text_contains(h.split(".")[0]) and len(h.split(".")[0]) > 12:
                status, evidence = "both (label match)", h.split(".")[0]
            else:
                evidence = f"registrable domain '{dom}' {'IS' if apk_text_contains(dom) else 'NOT'} present in APK plaintext"
    x_rows.append({"hostname": h, "status": status, "role": role_for(h), "ips": r["ips"], "ports": r["ports"],
                   "flows": r["flows"], "bytes": r["total_bytes"], "apk_evidence": evidence})
cap_names = set(x["hostname"] for x in x_rows)
for a in apk_rows:
    if a["category"] == "possible-endpoint" and a["hostname"] not in cap_names and not a["hostname"].startswith("%s"):
        x_rows.append({"hostname": a["hostname"], "status": "APK only", "role": "", "ips": "", "ports": "", "flows": 0, "bytes": 0,
                       "apk_evidence": a["sources"]})
for rx, t in templates.items():
    x_rows.append({"hostname": t.split(" ")[0], "status": "APK template (instantiated in capture)" if any(re.match(rx, h) for h in cap_names) else "APK only (template, dev environment)",
                   "role": "NPLN host template", "ips": "", "ports": "", "flows": 0, "bytes": 0, "apk_evidence": t})
with open(os.path.join(DATA, "hosts_crossref.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(x_rows[0].keys()))
    w.writeheader(); w.writerows(x_rows)
with open(os.path.join(DATA, "hosts.json"), "w", encoding="utf-8") as f:
    json.dump({"capture_hosts": [x for x in x_rows if x["status"] != "APK only"],
               "apk_only_hosts": [x for x in x_rows if x["status"] == "APK only"]}, f, indent=2)

print("certs:", len(cert_rows))
for c in cert_rows:
    print(" ", c["chain_position"], c["subject"][:70], "|", c["not_after"][:10], "|", c["seen_for_sni"])
print("apk hostnames:", len(apk_rows), "possible endpoints:", sum(1 for a in apk_rows if a["category"] == "possible-endpoint"))
for x in x_rows:
    print(f"{x['status']:38} {x['hostname'][:60]:60} {x['apk_evidence'][:70]}")
