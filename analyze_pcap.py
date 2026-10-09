#!/usr/bin/env python3
"""
Passive analysis of 2019-06-22-traffic-analysis-exercise.pcap (Phenomenoc case).
Reads the capture only: no network access, no execution of any sample.

Usage:  python3 analyze_pcap.py <pcap> [alerts.txt]
Needs:  pip install dpkt
Prints: host identification (DHCP/NBNS/Kerberos), HTTP request timeline,
        external traffic volumes, and an alert summary.
Kerberos user extraction is a string heuristic: confirm in Wireshark with
    kerberos.CNameString && ip.src == <host>
"""
import collections, datetime, re, socket, sys
import dpkt

def utc(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def main(pcap_path, alerts_path=None):
    dhcp, nbns, macs, krb_users = {}, {}, collections.defaultdict(set), collections.defaultdict(set)
    http, vol = [], collections.defaultdict(lambda: [0, 0, 0, 0])  # ip -> pkts, bytes, tx_bytes, rx_bytes
    n, first, last = 0, None, None
    with open(pcap_path, "rb") as f:
        for ts, buf in dpkt.pcap.Reader(f):
            n += 1
            first = first or ts
            last = ts
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            src, dst = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
            mac = ":".join("%02x" % b for b in eth.src)
            if src.startswith("10.0.76."):
                macs[src].add(mac)
            for ipaddr, tx in ((src, True), (dst, False)):
                v = vol[ipaddr]; v[0] += 1; v[1] += len(buf)
                v[2 if tx else 3] += len(buf)
            l4 = ip.data
            if isinstance(l4, dpkt.udp.UDP):
                if l4.sport == 68 and l4.dport == 67:
                    try:
                        opts = {o[0]: o[1] for o in dpkt.dhcp.DHCP(l4.data).opts}
                        if opts.get(12):
                            dhcp[(src, mac)] = opts[12].decode(errors="replace")
                    except Exception:
                        pass
            elif isinstance(l4, dpkt.tcp.TCP):
                if l4.dport == 80 and l4.data[:4] in (b"GET ", b"POST"):
                    lines = l4.data.split(b"\r\n")
                    host = next((l[5:].strip().decode(errors="replace") for l in lines if l.lower().startswith(b"host:")), "")
                    clen = next((l.split(b":")[1].strip().decode() for l in lines if l.lower().startswith(b"content-length")), "")
                    http.append((ts, src, dst, lines[0][:90].decode(errors="replace"), host, clen))
                if l4.dport == 88 and len(l4.data) > 10:
                    strs = [s.decode() for s in re.findall(rb"[\x20-\x7e]{4,}", l4.data)]
                    if "krbtgt" in strs:
                        for s in strs[: strs.index("krbtgt")]:
                            if re.fullmatch(r"[A-Za-z0-9._$-]{4,40}", s) and s.upper() not in ("PHENOMENOC", "PHENOMENOC.COM") and not s.startswith("c0a0"):
                                krb_users[src].add(s)
                                break

    print("== Capture ==")
    print(f"packets: {n}\nstart:   {utc(first)} UTC\nend:     {utc(last)} UTC\n")
    print("== Host identification (internal 10.0.76.0/24) ==")
    for ip_ in sorted(macs, key=lambda x: tuple(map(int, x.split(".")))):
        names = {v for (i, m), v in dhcp.items() if i == ip_}
        print(f"{ip_:<14} MAC {', '.join(sorted(macs[ip_]))}  DHCP host name: {', '.join(names) or '-'}  Kerberos principals: {', '.join(sorted(krb_users.get(ip_, []))) or '-'}")
    print("\n(principals ending in $ are machine accounts; the others are user accounts)\n")
    print("== HTTP request timeline from 10.0.76.109 (UTC) ==")
    for ts, s, d, rl, host, clen in http:
        if s == "10.0.76.109":
            print(f"{utc(ts)}  {d:<15} {rl:<60} Host: {host} {('Content-Length: ' + clen) if clen else ''}")
    print("\n== Selected external endpoints (packets, total bytes, host->ext bytes, ext->host bytes) ==")
    for ip_ in ("37.46.135.170", "8.209.83.76", "91.235.129.60"):
        v = vol[ip_]
        print(f"{ip_:<15} pkts={v[0]:<5} bytes={v[1]:<8} tx(to ext)={v[3]:<8} rx(from ext)={v[2]}")
    if alerts_path:
        print("\n== IDS alert summary (from alert text export) ==")
        txt = open(alerts_path, encoding="utf-8", errors="replace").read()
        for blk in re.split(r"-{20,}", txt):
            m = re.search(r"Count:(\d+) Event#\S+ (\S+ \S+ UTC)\s+(.+?)\s+([\d.]+) -> ([\d.]+)", blk.replace("\r", ""), re.S)
            if m:
                print(f"count={m.group(1):<3} {m.group(2)}  {m.group(4)} -> {m.group(5)}  {m.group(3).strip()}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
