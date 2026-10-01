"""Part 2.5 - UDP flow analysis (multiplayer).
Per flow: role classification, ports, size distribution, packet rate, inter-arrival,
and byte-position header analysis (constant / counter / random) per direction.
Outputs data/udp_flows.csv, data/udp_header_analysis.json, pcap/udp_samples.txt
"""
import csv, json, os, subprocess, collections, statistics, ipaddress, math, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP = os.path.join(ROOT, "originals", "PCAPdroid_29_Sep_22_19_48.pcap")
TSHARK = os.environ.get("TSHARK") or shutil.which("tshark") or r"C:\Program Files\Wireshark\tshark.exe"
DATA = os.path.join(ROOT, "data")
OUTP = os.path.join(ROOT, "pcap")

fields = ["udp.stream", "frame.time_relative", "ip.src", "ip.dst", "udp.srcport", "udp.dstport", "udp.length", "data.data"]
cmd = [TSHARK, "-r", PCAP, "-Y", "udp && !dns", "-T", "fields", "-E", "separator=\t"]
for f in fields:
    cmd += ["-e", f]
out = subprocess.run(cmd, capture_output=True, text=True).stdout

dns_names = {}
with open(os.path.join(DATA, "pcap_hosts.csv"), encoding="utf-8") as f:
    for r in csv.DictReader(f):
        for ip in r["ips"].split(";"):
            if ip and not r["hostname"].startswith("[ip]"):
                dns_names.setdefault(ip, r["hostname"])

flows = collections.OrderedDict()
for line in out.splitlines():
    p = line.split("\t")
    p += [""] * (len(fields) - len(p))
    d = dict(zip(fields, p))
    src_priv = ipaddress.ip_address(d["ip.src"]).is_private
    direction = "out" if src_priv else "in"
    remote_ip = d["ip.dst"] if src_priv else d["ip.src"]
    remote_port = d["udp.dstport"] if src_priv else d["udp.srcport"]
    local_port = d["udp.srcport"] if src_priv else d["udp.dstport"]
    fl = flows.setdefault(d["udp.stream"], {"remote_ip": remote_ip, "remote_port": remote_port, "local_port": local_port, "pk": []})
    fl["pk"].append((float(d["frame.time_relative"]), direction, int(d["udp.length"]) - 8, bytes.fromhex(d["data.data"]) if d["data.data"] else b""))


def classify(fl):
    host = dns_names.get(fl["remote_ip"], "")
    first = next((x[3] for x in fl["pk"] if x[3]), b"")
    if "nat-check" in host:
        return host, "Pia NAT-check (NAT type probe, 'NC' magic)"
    if host.endswith("srv.nintendo.net"):
        return host, "NPLN / Pia monitoring (one-way telemetry, Pia magic, unencrypted header)"
    if host.startswith("ec2-") or fl["remote_port"] in ("14106", "14101"):
        return host, "Izumo room/relay server (UDP side of TCP control channel on same port)"
    if first[:4] == bytes.fromhex("32ab9864"):
        return host, "Pia P2P peer (direct mesh connection to another player)"
    return host, "unknown"


def pct(vals, q):
    s = sorted(vals)
    if not s:
        return 0
    k = (len(s) - 1) * q
    lo, hi = math.floor(k), math.ceil(k)
    return s[lo] if lo == hi else round(s[lo] + (s[hi] - s[lo]) * (k - lo), 1)


def header_analysis(payloads, n=24):
    """For each byte offset, describe how it behaves across packets."""
    res = []
    payloads = [p for p in payloads if len(p) >= 4]
    if not payloads:
        return res
    for i in range(min(n, min(len(p) for p in payloads))):
        col = [p[i] for p in payloads]
        c = collections.Counter(col)
        distinct = len(c)
        if distinct == 1:
            kind = f"constant 0x{col[0]:02x}"
        elif distinct <= 4:
            kind = "few values: " + ",".join(f"0x{v:02x}({k})" for v, k in c.most_common())
        else:
            inc = sum(1 for a, b in zip(col, col[1:]) if (b - a) % 256 == 1)
            if inc > 0.5 * (len(col) - 1):
                kind = f"incrementing counter ({distinct} values)"
            elif distinct > 0.8 * min(256, len(col)):
                kind = f"high-variance ({distinct} distinct)"
            else:
                kind = f"varies ({distinct} distinct; top " + ",".join(f"0x{v:02x}" for v, _ in c.most_common(3)) + ")"
        res.append({"offset": i, "behaviour": kind})
    return res


rows, hdr, samples = [], {}, []
for sid, fl in flows.items():
    pk = fl["pk"]
    host, role = classify(fl)
    up = [x for x in pk if x[1] == "out"]
    dn = [x for x in pk if x[1] == "in"]
    sizes = [x[2] for x in pk]
    t0, t1 = pk[0][0], pk[-1][0]
    dur = t1 - t0
    iat_up = [b[0] - a[0] for a, b in zip(up, up[1:])]
    size_hist = collections.Counter((s // 32) * 32 for s in sizes)
    rows.append({
        "udp_stream": sid, "role": role, "remote_host": host or "(no DNS - peer IP)", "remote_ip": fl["remote_ip"],
        "remote_port": fl["remote_port"], "local_port": fl["local_port"],
        "pkts_out": len(up), "pkts_in": len(dn), "bytes_out": sum(x[2] for x in up), "bytes_in": sum(x[2] for x in dn),
        "start_rel_s": round(t0, 3), "end_rel_s": round(t1, 3), "duration_s": round(dur, 3),
        "pps_total": round(len(pk) / dur, 2) if dur > 0 else "", "pps_out": round(len(up) / dur, 2) if dur > 0 else "",
        "payload_min": min(sizes), "payload_p25": pct(sizes, .25), "payload_median": pct(sizes, .5), "payload_mean": round(statistics.mean(sizes), 1),
        "payload_p95": pct(sizes, .95), "payload_max": max(sizes),
        "iat_out_median_ms": round(pct(iat_up, .5) * 1000, 1) if iat_up else "",
        "top_sizes": ";".join(f"{s}B x{c}" for s, c in collections.Counter(sizes).most_common(6)),
        "size_hist_32B_bins": ";".join(f"{b}-{b+31}:{c}" for b, c in sorted(size_hist.items())),
        "first_bytes_out": up[0][3][:16].hex() if up and up[0][3] else "",
        "first_bytes_in": dn[0][3][:16].hex() if dn and dn[0][3] else "",
    })
    hdr[sid] = {"role": role, "remote": f"{host or fl['remote_ip']}:{fl['remote_port']}",
                "out": header_analysis([x[3] for x in up]), "in": header_analysis([x[3] for x in dn])}
    samples.append(f"===== udp.stream {sid}  {role}  remote={host or fl['remote_ip']}:{fl['remote_port']}")
    for x in pk[:6] + (pk[len(pk)//2:len(pk)//2+3] if len(pk) > 12 else []):
        samples.append(f"{x[0]:10.3f} {x[1]:3} {x[2]:5}  {x[3][:48].hex()}")

with open(os.path.join(DATA, "udp_flows.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    w.writeheader(); w.writerows(rows)
with open(os.path.join(DATA, "udp_header_analysis.json"), "w", encoding="utf-8") as f:
    json.dump(hdr, f, indent=1)
with open(os.path.join(OUTP, "udp_samples.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(samples))

p2p = [x for sid, fl in flows.items() if classify(fl)[1].startswith("Pia P2P") for x in fl["pk"]]
per_sec = collections.Counter(int(x[0]) for x in p2p)
with open(os.path.join(DATA, "udp_p2p_rate_per_second.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(["second_rel", "p2p_packets"])
    for s in range(min(per_sec), max(per_sec) + 1):
        w.writerow([s, per_sec.get(s, 0)])

for r in rows:
    print(f"{r['udp_stream']:>3} {r['role'][:40]:40} {r['remote_port']:>6} out={r['pkts_out']:5} in={r['pkts_in']:5} dur={r['duration_s']:8} pps={r['pps_total']:>6} med={r['payload_median']:>6} p95={r['payload_p95']:>6} max={r['payload_max']:5} iat={r['iat_out_median_ms']}")
