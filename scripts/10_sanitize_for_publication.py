"""Prepare the archive for publication. Run after 01-08 and before 09_manifest.py.

* Replaces every IP address with [IP REDACTED]:
    - dotted IPv4 and IPv6 addresses in every published text file
    - addresses embedded in EC2-style host names (ec2-a-b-c-d.region.compute.amazonaws.com)
    - addresses inside packet payload hex dumps: ASCII forms, and the raw 4-byte form of every address
      seen in the capture (this includes the reflexive address returned by the NAT-check servers).
      The TCP payload dumps are regenerated from the capture with byte-level redaction.
* Removes machine-specific details: absolute path of this checkout and its parent, home directory,
  user name (in paths) and host name. These are detected at run time, so nothing is hard-coded here.
* Converts every published text file to plain ASCII (typographic characters are transliterated,
  anything else becomes a \\uXXXX escape).

Scope: every file git would publish, i.e. not matched by .gitignore.
Exits with status 1 if anything that looks like an IP address, a local path or non-ASCII text remains.
"""
import fnmatch, getpass, ipaddress, os, re, shutil, socket, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP = os.path.join(ROOT, "originals", "PCAPdroid_29_Sep_22_19_48.pcap")
TSHARK = os.environ.get("TSHARK") or shutil.which("tshark") or r"C:\Program Files\Wireshark\tshark.exe"
RED = "[IP REDACTED]"
# files whose long hex tokens are packet payloads (scanned byte-by-byte for embedded addresses)
PAYLOAD_HEX_FILES = {"pcap/udp_samples.txt", "data/udp_flows.csv"}
STREAM_PORTS = {11401: "pvp_11401", 14106: "relay_14106"}


def load_gitignore():
    pats = []
    path = os.path.join(ROOT, ".gitignore")
    if not os.path.exists(path):
        sys.exit(".gitignore not found - refusing to guess what will be published")
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        neg = line.startswith("!")
        pat = line[1:] if neg else line
        dir_only = pat.endswith("/")
        pat = pat.strip("/")
        pats.append((neg, pat, dir_only, "/" in pat))
    return pats


IGNORE = load_gitignore()


def is_ignored(rel, is_dir=False):
    parts = rel.split("/")
    result = False
    for neg, pat, dir_only, anchored in IGNORE:
        hit = False
        for i in range(1, len(parts) + 1):
            sub_is_dir = is_dir or i < len(parts)
            if dir_only and not sub_is_dir:
                continue
            target = "/".join(parts[:i]) if anchored else parts[i - 1]
            if fnmatch.fnmatchcase(target, pat):
                hit = True
                break
        if hit:
            result = not neg
    return result


def published_files():
    out = []
    for dp, dns, fns in os.walk(ROOT):
        reld = os.path.relpath(dp, ROOT).replace("\\", "/")
        reld = "" if reld == "." else reld + "/"
        dns[:] = [d for d in dns if d != ".git" and not is_ignored(reld + d, is_dir=True)]
        out += [reld + f for f in fns if not is_ignored(reld + f)]
    return sorted(out)


def tshark(args):
    return subprocess.run([TSHARK, "-r", PCAP] + args, capture_output=True, text=True, encoding="utf-8", errors="replace").stdout


def capture_addresses():
    addrs = set()
    if not os.path.exists(PCAP) or not (os.path.exists(TSHARK) or shutil.which(TSHARK)):
        print("warning: capture or tshark missing - binary address matching disabled")
        return addrs
    out = tshark(["-T", "fields", "-E", "occurrence=a", "-E", "aggregator=,", "-e", "ip.src", "-e", "ip.dst",
                  "-e", "ipv6.src", "-e", "ipv6.dst", "-e", "dns.a", "-e", "dns.aaaa"])
    for tok in re.split(r"[\s,]+", out):
        try:
            addrs.add(ipaddress.ip_address(tok))
        except ValueError:
            pass
    # NAT-check replies ("NC" + type + reflexive IPv4 + port) carry an address that is not in any IP header
    out = tshark(["-Y", "udp && data.data", "-T", "fields", "-e", "data.data"])
    for hx in out.split():
        b = bytes.fromhex(hx)
        if len(b) == 9 and b[:2] == b"NC":
            addrs.add(ipaddress.IPv4Address(b[3:7]))
    return addrs


ADDRS = capture_addresses()
BIN_PATTERNS = set()
for a in ADDRS:
    packed = a.packed
    if len(set(packed)) < 3:  # e.g. an address made of one repeated byte - too generic to match safely as raw bytes
        continue
    BIN_PATTERNS.add(packed)
    BIN_PATTERNS.add(packed[::-1])


B_V4 = re.compile(rb"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9])")
B_DASH = re.compile(rb"(?i)(?<=ec2-)\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}")


def valid_v4(txt, sep="."):
    parts = txt.split(sep)
    return len(parts) == 4 and all(p.isdigit() and int(p) < 256 for p in parts)


def redact_spans(b):
    spans = []
    for m in B_V4.finditer(b):
        if valid_v4(m.group().decode()):
            spans.append((m.start(), m.end()))
    for m in B_DASH.finditer(b):
        if valid_v4(m.group().decode(), "-"):
            spans.append((m.start(), m.end()))
    for pat in BIN_PATTERNS:
        i = b.find(pat)
        while i >= 0:
            spans.append((i, i + len(pat)))
            i = b.find(pat, i + 1)
    spans.sort()
    merged = []
    for s, e in spans:
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(e, merged[-1][1]))
        else:
            merged.append((s, e))
    return merged


def segments(b):
    """split bytes into [(redacted?, bytes)]"""
    out, pos = [], 0
    for s, e in redact_spans(b):
        if s > pos:
            out.append((False, b[pos:s]))
        out.append((True, b[s:e]))
        pos = e
    if pos < len(b):
        out.append((False, b[pos:]))
    return out


def hex_redacted(b):
    return "".join(RED if red else seg.hex() for red, seg in segments(b))


def ascii_view(b):
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


def regenerate_tcp_dumps():
    if not ADDRS:
        return
    for f in os.listdir(os.path.join(ROOT, "pcap")):
        if f.startswith("follow_tcp"):
            os.remove(os.path.join(ROOT, "pcap", f))
    flt = " || ".join(f"tcp.port=={p}" for p in STREAM_PORTS)
    rows = []
    out = tshark(["-Y", f"tcp.len>0 && ({flt})", "-T", "fields", "-e", "frame.number", "-e", "frame.time_relative",
                  "-e", "tcp.stream", "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "tcp.len", "-e", "tcp.payload"])
    for line in out.splitlines():
        fr, t, st, sp, dp, ln, pl = line.split("\t")
        rows.append((int(fr), float(t), int(st), int(sp), int(dp), int(ln), bytes.fromhex(pl)))
    with open(os.path.join(ROOT, "pcap", "plaintext_nontls_tcp.txt"), "w", encoding="ascii", newline="\n") as f:
        f.write("# Plaintext / non-TLS application data in the capture\n")
        f.write("# tshark -Y 'http || http2 || websocket' -> 0 frames. No plaintext HTTP exists in this capture.\n")
        f.write("# Only non-TLS TCP application protocol: pvp.mariokarttour.com:11401 and the Izumo room server on :14106.\n")
        f.write("# Other TCP segments that tshark does not label 'tls' are TLS record continuations and are omitted here.\n")
        f.write(f"# IP addresses (and IP-bearing bytes inside payloads) are replaced with {RED}.\n")
        f.write("# columns: frame  time_rel_s  tcp.stream  src_port  dst_port  tcp.len  payload_hex\n")
        for fr, t, st, sp, dp, ln, pl in rows:
            f.write(f"{fr}\t{t:.6f}\t{st}\t{sp}\t{dp}\t{ln}\t{hex_redacted(pl)}\n")
    streams = {}
    for r in rows:
        streams.setdefault(r[2], []).append(r)
    for st, rs in streams.items():
        server_port = next(p for p in (rs[0][3], rs[0][4]) if p in STREAM_PORTS)
        client_port = rs[0][3] if rs[0][4] == server_port else rs[0][4]
        name = f"follow_tcp{st}_{STREAM_PORTS[server_port]}.txt"
        with open(os.path.join(ROOT, "pcap", name), "w", encoding="ascii", newline="\n") as f:
            f.write(f"# TCP stream {st}: application payload, client {RED}:{client_port} <-> server {RED}:{server_port}\n")
            f.write(f"# C>S = client to server, S>C = server to client. IP addresses and IP-bearing bytes are replaced with {RED}.\n")
            f.write("# each line: 16 bytes hex | printable ASCII\n\n")
            for fr, t, _, sp, dp, ln, pl in rs:
                f.write(f"{'C>S' if dp == server_port else 'S>C'}  t={t:.6f}s  frame {fr}  {ln} bytes\n")
                for red, seg in segments(pl):
                    if red:
                        f.write(f"  {RED}\n")
                        continue
                    for i in range(0, len(seg), 16):
                        chunk = seg[i:i + 16]
                        f.write(f"  {chunk.hex(' '):<47}  |{ascii_view(chunk)}|\n")
                f.write("\n")
        print("wrote pcap/" + name)


T_V4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
T_DASH = re.compile(r"(?i)\b(ec2|ip)-(\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3})(?![\d-])")
T_V6 = re.compile(r"(?<![\w:.\[])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
HEX_TOKEN = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){4,}(?![0-9A-Fa-f])")
KNOWN_V6 = {a for a in ADDRS if a.version == 6}


def is_v6(tok):
    if "::" not in tok and tok.count(":") != 7:
        return False
    try:
        a = ipaddress.IPv6Address(tok)
    except ValueError:
        return False
    return a in KNOWN_V6 or sum(c in "0123456789abcdefABCDEF" for c in tok) >= 4


def redact_text(s, payload_hex=False):
    if payload_hex:
        s = HEX_TOKEN.sub(lambda m: hex_redacted(bytes.fromhex(m.group())), s)
    s = T_DASH.sub(lambda m: f"{m.group(1)}-{RED}" if valid_v4(m.group(2), "-") else m.group(), s)
    s = T_V4.sub(lambda m: RED if valid_v4(m.group()) else m.group(), s)
    s = T_V6.sub(lambda m: RED if is_v6(m.group()) else m.group(), s)
    s = re.sub(r"\[IP REDACTED\](?:[;|]\[IP REDACTED\])+", RED, s)  # collapse address lists
    return s


def path_forms(p):
    p = os.path.normpath(p)
    fwd = p.replace("\\", "/")
    forms = {p, fwd, p.replace("\\", "\\\\")}
    if re.match(r"^[A-Za-z]:", p):  # Git-Bash / MSYS form: /d/dir/...
        forms.add("/" + p[0].lower() + fwd[2:])
    return sorted(forms, key=len, reverse=True)


LOCAL = []  # (regex, replacement), most specific first
for path, repl in ((ROOT, "."), (os.path.dirname(ROOT), "<input folder>"), (os.path.expanduser("~"), "~")):
    for form in path_forms(path):
        if len(form) > 3:
            LOCAL.append((re.compile(re.escape(form), re.I), repl))
USER = getpass.getuser()
HOSTS = {h for h in (socket.gethostname(), os.environ.get("COMPUTERNAME", "")) if len(h) > 2}
LOCAL.append((re.compile(r"(?i)(?<=[\\/])" + re.escape(USER) + r"(?=[\\/])"), "<user>"))
for h in HOSTS:
    LOCAL.append((re.compile(r"(?i)(?<![\w-])" + re.escape(h) + r"(?![\w-])"), "<host>"))


def scrub_local(s):
    for rx, repl in LOCAL:
        s = rx.sub(repl, s)
    return s


TRANSLIT = [(" \u00b7 ", "; "), ("\u00b7", "-"), ("\u2026", "..."), ("\u2013", "-"), ("\u2014", "-"), ("\u2212", "-"),
            ("\u00a7", "Section "), ("\u00d7", "x"), ("\u2248", "~"), ("\u00b5", "u"), ("\u03bc", "u"),
            ("\u2192", "->"), ("\u2190", "<-"), ("\u2194", "<->"), ("\u2018", "'"), ("\u2019", "'"),
            ("\u201c", '"'), ("\u201d", '"'), ("\u00a0", " "), ("\u2265", ">="), ("\u2264", "<="),
            ("\u00b1", "+/-"), ("\u2022", "*"), ("\u00b0", " deg"), ("\ufeff", "")]


def to_ascii(s):
    for a, b in TRANSLIT:
        s = s.replace(a, b)
    out = []
    for ch in s:
        o = ord(ch)
        if o < 128 and (o >= 32 or ch in "\t\n\r"):
            out.append(ch)
        elif o < 32 or o == 127:
            out.append("\\x%02x" % o)
        elif o <= 0xFFFF:
            out.append("\\u%04x" % o)
        else:
            out.append("\\U%08x" % o)
    return "".join(out)


def process(rel):
    p = os.path.join(ROOT, rel)
    raw = open(p, "rb").read()
    if b"\x00" in raw[:4096]:
        return "binary"  # published binaries are not expected; reported by verify()
    s = raw.decode("utf-8", errors="surrogateescape")
    new = to_ascii(redact_text(scrub_local(s), payload_hex=rel in PAYLOAD_HEX_FILES))
    if rel == "scripts/10_sanitize_for_publication.py":
        new = to_ascii(scrub_local(s))  # its own regexes must not be rewritten
    if new != s:
        with open(p, "w", encoding="ascii", newline="") as f:
            f.write(new)
        return "changed"
    return "ok"


def verify(files):
    problems = []
    for rel in files:
        raw = open(os.path.join(ROOT, rel), "rb").read()
        if b"\x00" in raw[:4096]:
            problems.append(f"{rel}: binary file would be published")
            continue
        bad = [c for c in raw if c > 126 or (c < 32 and c not in (9, 10, 13))]
        if bad:
            problems.append(f"{rel}: {len(bad)} non-ASCII/control bytes")
        s = raw.decode("ascii", errors="replace")
        if rel == "scripts/10_sanitize_for_publication.py":
            s = re.sub(r"(?m)^.*(re\.compile|T_V6|valid_v4).*$", "", s)
        for m in T_V4.finditer(s):
            if valid_v4(m.group()):
                problems.append(f"{rel}: IPv4 {m.group()}")
        for m in T_DASH.finditer(s):
            if valid_v4(m.group(2), "-"):
                problems.append(f"{rel}: host-embedded IPv4 {m.group()}")
        for m in T_V6.finditer(s):
            if is_v6(m.group()):
                problems.append(f"{rel}: IPv6 {m.group()}")
        for rx, _ in LOCAL:
            m = rx.search(s)
            if m:
                problems.append(f"{rel}: machine-specific string at offset {m.start()}")
        for m in HEX_TOKEN.finditer(s):
            b = bytes.fromhex(m.group())
            if any(pat in b for pat in BIN_PATTERNS) and rel in PAYLOAD_HEX_FILES | {"pcap/plaintext_nontls_tcp.txt"}:
                problems.append(f"{rel}: raw address bytes in payload hex")
    return problems


if __name__ == "__main__":
    print(f"addresses seen in capture: {len(ADDRS)}; raw-byte patterns: {len(BIN_PATTERNS)}")
    regenerate_tcp_dumps()
    files = published_files()
    stats = {}
    for rel in files:
        r = process(rel)
        stats[r] = stats.get(r, 0) + 1
        if r == "changed":
            print("sanitized", rel)
    print(f"published files: {len(files)}  {stats}")
    problems = verify(files)
    for p in problems[:200]:
        print("PROBLEM:", p)
    if problems:
        sys.exit(1)
    print("verification passed: no IP addresses, machine-specific strings or non-ASCII text in published files")
