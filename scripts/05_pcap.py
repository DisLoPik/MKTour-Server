"""Part 2 - PCAP analysis driven by tshark (Wireshark 4.6).
Outputs into pcap/ and data/.
"""
import csv, json, os, subprocess, collections, statistics, ipaddress, re, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP = os.path.join(ROOT, "originals", "PCAPdroid_29_Sep_22_19_48.pcap")
TSHARK = os.environ.get("TSHARK") or shutil.which("tshark") or r"C:\Program Files\Wireshark\tshark.exe"
OUTP = os.path.join(ROOT, "pcap")
DATA = os.path.join(ROOT, "data")
os.makedirs(OUTP, exist_ok=True)


def tshark_fields(display_filter, fields, extra=None):
    cmd = [TSHARK, "-r", PCAP, "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=|"]
    if display_filter:
        cmd += ["-Y", display_filter]
    for f in fields:
        cmd += ["-e", f]
    if extra:
        cmd += extra
    out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        parts += [""] * (len(fields) - len(parts))
        rows.append(dict(zip(fields, parts)))
    return rows


def tshark_stat(stat):
    return subprocess.run([TSHARK, "-r", PCAP, "-q", "-z", stat], capture_output=True, text=True, encoding="utf-8", errors="replace").stdout


UTC_ENV = dict(os.environ, TZ="UTC")
CAPINFOS = os.path.join(os.path.dirname(TSHARK), "capinfos.exe" if TSHARK.lower().endswith(".exe") else "capinfos")
with open(os.path.join(OUTP, "capinfos.txt"), "w", encoding="utf-8") as f:
    f.write("# capinfos -A (absolute times shown in UTC)\n")
    f.write(subprocess.run([CAPINFOS, "-A", os.path.relpath(PCAP, ROOT)], cwd=ROOT, env=UTC_ENV,
                           capture_output=True, text=True, encoding="utf-8", errors="replace").stdout)
with open(os.path.join(OUTP, "protocol_hierarchy.txt"), "w", encoding="utf-8") as f:
    f.write(tshark_stat("io,phs"))
dns_fields = ["frame.number", "frame.time_relative", "ip.src", "ip.dst", "dns.id", "dns.flags.response", "dns.qry.name",
              "dns.qry.type", "dns.flags.rcode", "dns.a", "dns.aaaa", "dns.cname", "dns.resp.ttl"]
dns_cmd = [TSHARK, "-r", PCAP, "-Y", "dns", "-T", "fields", "-E", "header=y", "-E", "separator=,", "-E", "quote=d"]
for fld in dns_fields:
    dns_cmd += ["-e", fld]
with open(os.path.join(OUTP, "dns.csv"), "w", encoding="utf-8", newline="") as f:
    f.write(subprocess.run(dns_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace").stdout)

dns = tshark_fields("dns.flags.response==1", ["dns.qry.name", "dns.cname", "dns.a", "dns.aaaa"])
ip2names = collections.defaultdict(set)
cname_chain = {}
for r in dns:
    q = r["dns.qry.name"]
    if r["dns.cname"]:
        cname_chain[q] = r["dns.cname"].split("|")
    for ip in (r["dns.a"].split("|") + r["dns.aaaa"].split("|")):
        if ip:
            ip2names[ip].add(q)

TLSV = {"0x0301": "TLS1.0", "0x0302": "TLS1.1", "0x0303": "TLS1.2", "0x0304": "TLS1.3"}
ch = tshark_fields("tls.handshake.type==1", [
    "tcp.stream", "frame.time_relative", "ip.src", "tcp.srcport", "ip.dst", "tcp.dstport",
    "tls.handshake.extensions_server_name", "tls.handshake.version", "tls.handshake.extensions.supported_version",
    "tls.handshake.extensions_alpn_str", "tls.handshake.ja3", "tls.handshake.ja4"])
sh = tshark_fields("tls.handshake.type==2", [
    "tcp.stream", "tls.handshake.version", "tls.handshake.extensions.supported_version",
    "tls.handshake.extensions_alpn_str", "tls.handshake.ciphersuite", "tls.handshake.ja3s"])
certs = tshark_fields("tls.handshake.type==11", [
    "tcp.stream", "x509sat.printableString", "x509sat.uTF8String", "x509ce.dNSName",
    "x509af.utcTime", "x509af.generalizedTime", "x509af.serialNumber", "tls.handshake.certificate_length",
    "x509if.RelativeDistinguishedName_item_element", "x509af.algorithm.id"])
shm = {r["tcp.stream"]: r for r in sh}
certm = collections.defaultdict(list)
for r in certs:
    certm[r["tcp.stream"]].append(r)

tls_rows = []
for r in ch:
    s = r["tcp.stream"]
    srv = shm.get(s, {})
    neg = srv.get("tls.handshake.extensions.supported_version") or srv.get("tls.handshake.version", "")
    crt = certm.get(s, [])
    cert_info = ""
    if crt:
        c = crt[0]
        cert_info = json.dumps({
            "names(printable|utf8)": (c["x509sat.printableString"] + "|" + c["x509sat.uTF8String"]).strip("|"),
            "SANs": c["x509ce.dNSName"],
            "validity(utc)": c["x509af.utcTime"] or c["x509af.generalizedTime"],
            "serials": c["x509af.serialNumber"],
        })
    tls_rows.append({
        "tcp_stream": s, "time_rel_s": r["frame.time_relative"], "client": f'{r["ip.src"]}:{r["tcp.srcport"]}',
        "server_ip": r["ip.dst"], "server_port": r["tcp.dstport"], "sni": r["tls.handshake.extensions_server_name"],
        "dns_names_for_ip": ";".join(sorted(ip2names.get(r["ip.dst"], []))),
        "client_offered_versions": ";".join(TLSV.get(v, v) for v in r["tls.handshake.extensions.supported_version"].split("|") if v),
        "negotiated_version": ";".join(TLSV.get(v, v) for v in neg.split("|") if v) if srv else "(no ServerHello captured)",
        "alpn_offered": r["tls.handshake.extensions_alpn_str"].replace("|", ";"),
        "alpn_selected": srv.get("tls.handshake.extensions_alpn_str", ""),
        "cipher_suite": srv.get("tls.handshake.ciphersuite", ""),
        "ja3": r["tls.handshake.ja3"], "ja4": r["tls.handshake.ja4"], "ja3s": srv.get("tls.handshake.ja3s", ""),
        "server_cert_visible": "yes" if crt else "no (TLS1.3 encrypts Certificate)" if "0x0304" in neg else "no",
        "server_cert_details": cert_info,
    })
with open(os.path.join(DATA, "tls_connections.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(tls_rows[0].keys()))
    w.writeheader(); w.writerows(tls_rows)

conv = {}
for proto in ("tcp", "udp", "ip"):
    txt = tshark_stat(f"conv,{proto}")
    open(os.path.join(OUTP, f"conversations_{proto}.txt"), "w", encoding="utf-8").write(txt)

# per-flow table built from packet fields (more precise than the stats text)
pk = tshark_fields("", ["frame.number", "frame.time_epoch", "frame.time_relative", "ip.src", "ip.dst", "ip.proto",
                        "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "frame.len", "tcp.stream", "udp.stream",
                        "tcp.len", "udp.length", "tcp.flags.syn", "tcp.flags.ack", "quic.version", "_ws.col.Protocol"])


def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


flows = {}
for p in pk:
    proto = {"6": "TCP", "17": "UDP"}.get(p["ip.proto"], p["ip.proto"])
    if proto == "TCP":
        sport, dport, sid = p["tcp.srcport"], p["tcp.dstport"], "t" + p["tcp.stream"]
    elif proto == "UDP":
        sport, dport, sid = p["udp.srcport"], p["udp.dstport"], "u" + p["udp.stream"]
    else:
        sport = dport = ""; sid = "o" + p["ip.src"] + p["ip.dst"]
    a, b = (p["ip.src"], sport), (p["ip.dst"], dport)
    # orient: client = private address side
    if is_private(p["ip.src"]) and not is_private(p["ip.dst"]):
        cli, srv, up = a, b, True
    elif is_private(p["ip.dst"]) and not is_private(p["ip.src"]):
        cli, srv, up = b, a, False
    else:
        cli, srv, up = (a, b, True) if a <= b else (b, a, False)
    f = flows.setdefault(sid, {"flow_id": sid, "proto": proto, "client_ip": cli[0], "client_port": cli[1], "server_ip": srv[0],
                               "server_port": srv[1], "packets_up": 0, "packets_down": 0, "bytes_up": 0, "bytes_down": 0,
                               "payload_up": 0, "payload_down": 0, "first_rel_s": float(p["frame.time_relative"]),
                               "last_rel_s": 0.0, "first_epoch": float(p["frame.time_epoch"]), "app_proto": set()})
    L = int(p["frame.len"] or 0)
    pl = int(p["tcp.len"] or 0) if proto == "TCP" else max(0, int(p["udp.length"] or 8) - 8) if proto == "UDP" else 0
    if up:
        f["packets_up"] += 1; f["bytes_up"] += L; f["payload_up"] += pl
    else:
        f["packets_down"] += 1; f["bytes_down"] += L; f["payload_down"] += pl
    f["last_rel_s"] = float(p["frame.time_relative"])
    if p["quic.version"]:
        f["app_proto"].add("QUIC")
    f["app_proto"].add(p["_ws.col.Protocol"])

sni_by_stream = {("t" + r["tcp_stream"]): r["sni"] for r in tls_rows}
conv_rows = []
for f in sorted(flows.values(), key=lambda x: x["first_rel_s"]):
    f = dict(f)
    f["duration_s"] = round(f["last_rel_s"] - f["first_rel_s"], 3)
    f["first_rel_s"] = round(f["first_rel_s"], 3); f["last_rel_s"] = round(f["last_rel_s"], 3)
    f["app_proto"] = ";".join(sorted(x for x in f["app_proto"] if x))
    f["sni"] = sni_by_stream.get(f["flow_id"], "")
    f["dns_names"] = ";".join(sorted(ip2names.get(f["server_ip"], [])))
    f["hostname"] = f["sni"] or (sorted(ip2names.get(f["server_ip"], [""]))[0] if ip2names.get(f["server_ip"]) else "")
    conv_rows.append(f)
fields = ["flow_id", "proto", "app_proto", "client_ip", "client_port", "server_ip", "server_port", "hostname", "sni", "dns_names",
          "packets_up", "packets_down", "bytes_up", "bytes_down", "payload_up", "payload_down", "first_rel_s", "last_rel_s",
          "duration_s", "first_epoch"]
with open(os.path.join(DATA, "connections.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader(); w.writerows(conv_rows)

hosts = collections.defaultdict(lambda: {"ips": set(), "flows": 0, "tcp_flows": 0, "udp_flows": 0, "bytes": 0, "ports": set(), "sources": set(), "cnames": []})
for q, chain in cname_chain.items():
    hosts[q]["cnames"] = chain
    hosts[q]["sources"].add("dns")
for ip, names in ip2names.items():
    for n in names:
        hosts[n]["ips"].add(ip); hosts[n]["sources"].add("dns")
for r in tls_rows:
    if r["sni"]:
        hosts[r["sni"]]["sources"].add("tls_sni")
for f in conv_rows:
    names = set(filter(None, [f["sni"]])) or set(ip2names.get(f["server_ip"], [])) or {f"[ip] {f['server_ip']}"}
    for n in names:
        h = hosts[n]
        h["ips"].add(f["server_ip"]); h["flows"] += 1; h["bytes"] += f["bytes_up"] + f["bytes_down"]
        h["ports"].add(f"{f['proto']}/{f['server_port']}")
        h["tcp_flows" if f["proto"] == "TCP" else "udp_flows"] += 1
        if n.startswith("[ip]"):
            h["sources"].add("ip_only")
host_rows = []
for n, h in sorted(hosts.items(), key=lambda kv: -kv[1]["bytes"]):
    host_rows.append({"hostname": n, "ips": ";".join(sorted(h["ips"])), "cname_chain": " -> ".join(h["cnames"]),
                      "ports": ";".join(sorted(h["ports"])), "flows": h["flows"], "tcp_flows": h["tcp_flows"], "udp_flows": h["udp_flows"],
                      "total_bytes": h["bytes"], "seen_via": ";".join(sorted(h["sources"]))})
with open(os.path.join(DATA, "pcap_hosts.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(host_rows[0].keys()))
    w.writeheader(); w.writerows(host_rows)

print("TLS client hellos:", len(tls_rows), " flows:", len(conv_rows), " hosts:", len(host_rows))
for h in host_rows:
    print(f"{h['hostname'][:55]:55} {h['ports'][:40]:40} flows={h['flows']:3} bytes={h['total_bytes']:>9} via={h['seen_via']}")
