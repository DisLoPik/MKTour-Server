"""Strings pass (ASCII + UTF-16LE, min length 5) over native libs, dex, metadata blobs.
Writes strings/<name>.strings.txt and a network-focused extraction to data/.
"""
import os, re, json, csv, sys, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.path.join(ROOT, "work")
OUT = os.path.join(ROOT, "strings")
os.makedirs(OUT, exist_ok=True)

MIN = 5
ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % MIN)
utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN)


def extract(path):
    d = open(path, "rb").read()
    out = []
    for m in ascii_re.finditer(d):
        out.append((m.start(), "a", m.group().decode("ascii")))
    for m in utf16_re.finditer(d):
        out.append((m.start(), "u", m.group().decode("utf-16le")))
    out.sort()
    return out


targets = []
lib_dir = os.path.join(WORK, "split_unzipped", "lib", "arm64-v8a")
for f in sorted(os.listdir(lib_dir)):
    targets.append(os.path.join(lib_dir, f))
base = os.path.join(WORK, "base_unzipped")
for f in ("classes.dex", "classes2.dex", "resources.arsc"):
    targets.append(os.path.join(base, f))
for rel in ("assets/bin/Data/data.unity3d", "assets/bin/Data/unity default resources",
            "assets/UdemaeRestoreList.encrypt_encoded.bytes"):
    targets.append(os.path.join(base, *rel.split("/")))

all_strings = {}
for t in targets:
    name = os.path.basename(t)
    s = extract(t)
    all_strings[name] = s
    with open(os.path.join(OUT, name + ".strings.txt"), "w", encoding="utf-8") as f:
        for off, kind, txt in s:
            f.write(f"{off:#010x} {kind} {txt}\n")
    print(f"{name:45} {len(s):8} strings")

url_re = re.compile(r"(?:https?|wss?|ftp)://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%{}]+")
host_re = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|jp|co|app|dev|cloud|info|me|us|cn|kr|tw|hk|de|uk|fr|ly|gl|gle|google|googleapis|firebaseio|appspot|nintendo|ninja|link|page))\b", re.I)
path_re = re.compile(r"^/(?:[A-Za-z0-9_\-{}.:%]+/?){1,8}(?:\?[\w=&{}%.\-]*)?$")
kw_re = re.compile(r"(api|endpoint|request|response|token|auth|session|signature|sign|hmac|sha1|sha256|md5|aes|rsa|encrypt|decrypt|cipher|protobuf|msgpack|json|baas|npf|sakasho|pia|matchmak|lobby|relay|nat|stun|turn|udp|tcp|websocket|grpc|cdn)", re.I)

rows = []
seen = set()
for src, s in all_strings.items():
    for off, kind, txt in s:
        for m in url_re.finditer(txt):
            u = m.group().rstrip(".,;)\"'")
            k = ("url", src, u)
            if k not in seen:
                seen.add(k); rows.append({"kind": "url", "source": src, "offset": hex(off), "value": u})
        for m in host_re.finditer(txt):
            h = m.group(1).lower()
            if h.endswith((".so", ".dll", ".java", ".cs")):
                continue
            k = ("host", src, h)
            if k not in seen:
                seen.add(k); rows.append({"kind": "hostname", "source": src, "offset": hex(off), "value": h})
        if path_re.match(txt) and len(txt) > 3 and not txt.startswith(("/system", "/proc", "/data", "/dev", "/sys", "/vendor", "/storage", "/sdcard", "/mnt", "/apex", "/usr", "/etc", "/bin", "/tmp")):
            k = ("path", src, txt)
            if k not in seen:
                seen.add(k); rows.append({"kind": "path", "source": src, "offset": hex(off), "value": txt})

with open(os.path.join(ROOT, "data", "apk_network_strings_raw.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["kind", "source", "offset", "value"])
    w.writeheader(); w.writerows(rows)

c = collections.Counter((r["kind"], r["source"]) for r in rows)
for k, v in sorted(c.items()):
    print(k, v)
