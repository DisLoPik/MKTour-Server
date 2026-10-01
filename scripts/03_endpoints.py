"""Build the consolidated API endpoint catalogue.

Sources:
  * jadx Java output (NPF SDK -> Nintendo BaaS + Nintendo Account)
  * libs2pcore.so strings + exported Sks* symbols (Sakasho / Booster game API)
  * libil2cpp.so strings (NPLN multiplayer host templates)
Outputs data/endpoints.csv, data/endpoints.json, data/sakasho_sdk_functions.csv, data/java_network_classes.csv
"""
import csv, json, os, re, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JADX = os.path.join(ROOT, "work", "jadx", "sources")
STR = os.path.join(ROOT, "strings")
DATA = os.path.join(ROOT, "data")

endpoints = []


def add(**kw):
    base = {"service": "", "host": "", "method": "", "path": "", "content_type": "", "auth": "",
            "client_function": "", "source": "", "notes": ""}
    base.update(kw)
    endpoints.append(base)


VERB = {"d": "GET", "l": "GET", "e": "POST", "m": "POST", "n": "PATCH", "o": "PUT"}
fmt_re = re.compile(r'String\.format\([^"]*"([^"]+)"\s*,\s*(?:java\.util\.Arrays\.copyOf\(new java\.lang\.Object\[\]\{)?\s*"(/[a-z]+/v\d)"')
literal_call_re = re.compile(r'this\.f\d+a\.([delmno])\("(/[A-Za-z0-9_./-]+)"')
explicit_re = re.compile(r'\.[ac]\("(GET|POST|PUT|PATCH|DELETE)",\s*"?(/[^",]+)')
call_re = re.compile(r'this\.f\d+a\.([delmno])\((str\w*|path|java\.lang\.String\.format)')
explicit_call_re = re.compile(r'this\.f\d+a\.[ac]\("(GET|POST|PUT|PATCH|DELETE)"')
ctype_re = re.compile(r'"(application/[a-z+\-]+)"')

npf_root = os.path.join(JADX, "com", "nintendo", "npf")
for dp, _, files in os.walk(npf_root):
    for fn in files:
        if not fn.endswith(".java"):
            continue
        p = os.path.join(dp, fn)
        rel = os.path.relpath(p, JADX).replace("\\", "/")
        lines = open(p, encoding="utf-8", errors="replace").read().splitlines()
        for i, ln in enumerate(lines):
            m = fmt_re.search(ln)
            if m:
                fmt, prefix = m.group(1), m.group(2)
                # substitute first %s / %1$s with prefix, rest -> {param}
                path = re.sub(r"%(1\$)?s", prefix, fmt, count=1)
                path = re.sub(r"%(\d\$)?s", "{param}", path)
                verb, ctype = "", ""
                window = " ".join(lines[i:i + 8])
                cm = call_re.search(window) or None
                em = explicit_call_re.search(window)
                if em:
                    verb = em.group(1)
                elif cm:
                    verb = VERB.get(cm.group(1), "")
                c = ctype_re.search(window)
                if c:
                    ctype = c.group(1)
                elif verb == "PATCH":
                    ctype = "application/json-patch+json"
                elif verb in ("PUT",):
                    ctype = "application/json"
                auth = "Bearer <BaaS access token>" if "getAccessToken" in window else ""
                add(service="Nintendo BaaS (NPF SDK)", host="a6913b7b80402974409b47079c29d775.baas.nintendo.com",
                    method=verb or "?", path=path, content_type=ctype or ("application/json" if verb == "POST" else ""),
                    auth=auth, client_function=rel.rsplit("/", 1)[-1].replace(".java", ""), source=f"{rel}:{i+1}")
            for lm in literal_call_re.finditer(ln):
                v, path = lm.group(1), lm.group(2)
                host = "api.accounts.nintendo.com" if path.startswith(("/connect/1.0.0/api", "/api/1.0.0")) else ""
                c = ctype_re.search(" ".join(lines[i:i + 2]))
                add(service="Nintendo Account (NA)" if host else "Nintendo BaaS (NPF SDK)", host=host,
                    method=VERB[v], path=path, content_type=c.group(1) if c else ("application/x-www-form-urlencoded" if "session_token" in path else ""),
                    client_function=fn.replace(".java", ""), source=f"{rel}:{i+1}")

# Nintendo Account browser-flow endpoints (built from StringBuilder, not format strings)
add(service="Nintendo Account (NA)", host="accounts.nintendo.com", method="GET (browser)", path="/connect/1.0.0/authorize?...",
    notes="OAuth2/OIDC authorize with PKCE (session_token_code_challenge, S256). Redirect npf5dbf84c0c704b31b://auth",
    client_function="NaAuthenticationActivity", source="com/nintendo/npf/sdk/internal/app/NaAuthenticationActivity.java:130")
add(service="Nintendo Account (NA)", host="accounts.nintendo.com", method="GET (browser)", path="/mii_studio?redirect_uri=npf5dbf84c0c704b31b://mii_studio&client_id=5dbf84c0c704b31b&lang=..",
    client_function="MiiStudioActivity", source="com/nintendo/npf/sdk/core/w2.java:104")
add(service="Nintendo Account (NA)", host="accounts.nintendo.com", method="GET (browser)", path="/term_chooser/faq",
    source="com/nintendo/npf/sdk/core/d3.java:226")
add(service="My Nintendo point program", host="<pointProgramHost from capabilities>", method="GET (browser)",
    path="/inapp?platform=google&client_id=%s&country=%s&page=%s...", source="com/nintendo/npf/sdk/mynintendo/PointProgramService.java:85")

s2p_strings = [l.split(" ", 2)[2] for l in open(os.path.join(STR, "libs2pcore.so.strings.txt"), encoding="utf-8").read().splitlines() if l.split(" ", 2)[1] == "a"]
paths = sorted({s for s in s2p_strings if re.fullmatch(r"/v\d+/[A-Za-z0-9_@/]+", s)})
exports = [l.strip() for l in open(os.path.join(ROOT, "work", "s2p_exports.txt"))]
sks = sorted(e for e in exports if e.startswith("Sks"))


def norm(s):
    return re.sub(r"[^a-z0-9]", "", s.lower())


def singular(t):
    if t.endswith("ies"):
        return t[:-3] + "y"
    if t.endswith("ses"):
        return t[:-2]
    if t.endswith("s") and len(t) > 3:
        return t[:-1]
    return t


GENERIC = {"players", "me", "booster", "na", "v1", "v2", "v3", ""}


def best_function(path):
    toks = []
    for seg in path.split("/"):
        seg = seg.replace("@", "")
        if seg in GENERIC or seg == "_" or re.fullmatch(r"v\d+", seg):
            continue
        toks += [singular(t) for t in seg.split("_") if t]
    scored = []
    for f in sks:
        n = norm(f[3:])
        if toks and toks[0] not in n:  # primary noun must match
            continue
        sc = sum(len(t) for t in set(toks) if t in n)
        if sc:
            scored.append((sc, f))
    if not scored:
        return ""
    top = max(sc for sc, _ in scored)
    return " | ".join(sorted(f for sc, f in scored if sc == top))


for p in paths:
    add(service="Sakasho / Booster game API (libs2pcore)", host="<unknown - from SakashoServerConfig / C# (encrypted metadata)>",
        method="?", path=p, content_type="application/x-protobuf",
        auth="X-Sks-Session-Token (from POST session create)", client_function=best_function(p),
        source="libs2pcore.so strings", notes="method not recoverable from strings; client has Get/Post/Delete request classes")

for s in ("%s.lp1.p.srv.nintendo.net", "%s.dd1.p.srv.nintendo.net"):
    add(service="NPLN (Nintendo network platform - multiplayer / Pia)", host=s, method="n/a", path="",
        source="libil2cpp.so strings", notes="lp1 = live production, dd1 = dev; %s likely an app/tenant id. Classes: NplnConnection, NplnTransport, NplnClientCall, NplnDetail")

third = [
    ("Firebase Installations", "firebaseinstallations.googleapis.com", "", "classes.dex"),
    ("Firebase Realtime DB (config only)", "npf-booster-a6913b7.firebaseio.com", "", "res/values/strings.xml firebase_database_url"),
    ("Firebase / Google Analytics (Scion)", "app-measurement.com", "/a", "classes.dex"),
    ("Firebase / Google Analytics (Scion)", "app-measurement.com", "/s/d", "classes.dex"),
    ("Bugsnag error reporting", "notify.bugsnag.com", "/", "classes.dex"),
    ("Bugsnag session tracking", "sessions.bugsnag.com", "/", "classes.dex"),
    ("Google OAuth", "oauth2.googleapis.com", "/token", "classes.dex"),
    ("Google Cloud Pub/Sub (NPF bigdata?)", "pubsub.googleapis.com", "/", "classes.dex + pubsub.v1.json in APK root"),
    ("Google Ads conversion", "www.googleadservices.com", "/pagead/conversion/app/deeplink", "classes.dex"),
]
for svc, host, path, src in third:
    add(service=svc, host=host, method="", path=path, source=src)

os.makedirs(DATA, exist_ok=True)
seen, out = set(), []
for e in endpoints:
    k = (e["service"], e["host"], e["method"], e["path"])
    if k in seen:
        continue
    seen.add(k); out.append(e)
with open(os.path.join(DATA, "endpoints.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(out[0].keys()))
    w.writeheader(); w.writerows(out)
with open(os.path.join(DATA, "endpoints.json"), "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2)

rev = collections.defaultdict(list)
for e in out:
    if e["client_function"].startswith("Sks"):
        for fnm in e["client_function"].split(" | "):
            rev[fnm].append(e["path"])
with open(os.path.join(DATA, "sakasho_sdk_functions.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["export", "area", "matched_paths_heuristic"])
    for s in sks:
        area = re.match(r"Sks(V2)?([A-Z][a-z0-9]+(?:[A-Z][a-z0-9]+)?)", s)
        w.writerow([s, re.findall(r"[A-Z][a-z0-9]+", s[3:])[0] if len(s) > 3 else "", " | ".join(rev.get(s, []))])

jrows = []
for dp, _, files in os.walk(os.path.join(JADX, "com", "nintendo")):
    for fn in files:
        if fn.endswith(".java"):
            p = os.path.join(dp, fn); rel = os.path.relpath(p, JADX).replace("\\", "/")
            src = open(p, encoding="utf-8", errors="replace").read()
            tags = [t for t, rx in (("http", r"HttpURLConnection|openConnection"), ("api-path", r'"/[a-z]+/v\d"|/connect/1\.0\.0'),
                                   ("jwt/hmac", r"HmacSHA|Mac\.getInstance"), ("json", r"JSONObject"),
                                   ("auth-header", r'"Authorization"|Bearer'), ("user-agent", r'"User-Agent"')) if re.search(rx, src)]
            if any(t in tags for t in ("http", "api-path", "jwt/hmac", "auth-header", "user-agent")):
                jrows.append([rel, ",".join(tags)])
with open(os.path.join(DATA, "java_network_classes.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f); w.writerow(["class_file", "tags"]); w.writerows(sorted(jrows))

c = collections.Counter(e["service"] for e in out)
for k, v in c.most_common():
    print(f"{v:4}  {k}")
print("sks functions:", len(sks), "mapped:", sum(1 for s in sks if rev.get(s)))
print("java network classes:", len(jrows))
