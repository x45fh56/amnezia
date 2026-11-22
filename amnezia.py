#!/usr/bin/env python3
"""
Amnezia Config Bulk Generator
از هر Worker یک اکانت WARP می‌گیرد (حداکثر 4 اکانت) و با هر اکانت
برای تمام IP های IP.txt کانفیگ می‌سازد.

خروجی‌ها:
  configs.txt          -> کانفیگ‌های AmneziaWG نسخه 3.0 و 3.1 (متن)
  amnezia-mobile.json  -> آرایه کانفیگ Xray برای PingNG (WireGuard ساده، برای تست import)
  amnezia-mahsang.txt  -> لینک‌های wireguard:// برای MahsaNG (هر خط یک لینک)
"""
import json
import urllib.parse
import urllib.request
from datetime import datetime, timezone

IP_URL = "https://raw.githubusercontent.com/DarknessShade/Amnezia-VPN-Config/main/IP.txt"
API_ENDPOINTS = [
    "https://warp.configwireguard.workers.dev/",
    "https://warp.configwireguard2.workers.dev/",
    "https://warp.configwireguard3.workers.dev/",
    "https://warp.configwireguard4.workers.dev/",
]

# ======================= تنظیمات (مثل پیش‌فرض سایت) =======================
MTU = 1280
JUNK = {"Jc": 3, "Jmin": 1, "Jmax": 3}          # حالت سنگین: 5 / 10 / 40
ENABLE_AMNEZIA_15 = True                         # پارامترهای I1 و I2 (Set 1)
I1 = "<r 2><b 0x0100000100000000000003777777056170706c6503636f6d0000010001>"
I2 = "<r 2><b 0x0100000100000000000003777777056170706c6503636f6d00001c0001>"

AWG3 = {                                         # Amnezia 3.0
    "ContentPaddingAddition": "27-97",
    "MaxHandshakeAttempts": "18-26",
    "KeepaliveTimeout": "9-16",
    "RejectAfterTime": "171-196",
    "RekeyAfterTime": "116-131",
    "RekeyTimeout": "6-9",
}
AWG31 = ["RandomTrailers = on", "DisableCookies = on"]   # Amnezia 3.1


# ======================= توابع کمکی =======================
def http_get(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")


def enc(s):
    # معادل encodeURIComponent در جاوااسکریپت
    return urllib.parse.quote(str(s), safe="!~*'()")


def fetch_ips():
    text = http_get(IP_URL)
    return [l.strip() for l in text.splitlines() if l.strip() and not l.startswith("#")]


def fetch_account(url):
    """یک اکانت از یک Worker مشخص. خروجی: (متن کانفیگ، تاریخ انقضا)"""
    raw = http_get(url)
    try:
        data = json.loads(raw)
        config = data.get("config") or raw
        expires = (data.get("account_info") or {}).get("expires", "-")
        return config, expires
    except json.JSONDecodeError:
        return raw, "-"


def parse_base(text):
    data, section = {}, None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].lower()
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            data[(section, k.strip().lower())] = v.strip()
    return {
        "private_key": data[("interface", "privatekey")],
        "address": data[("interface", "address")],
        "dns": data.get(("interface", "dns"), ""),
        "public_key": data[("peer", "publickey")],
        "preshared": data.get(("peer", "presharedkey")),
        "allowed": data[("peer", "allowedips")],
    }


# ======================= خروجی ۱: کانفیگ متنی AmneziaWG =======================
def build_config(base, endpoint, version):
    lines = ["# Generated AmneziaWG Config",
             "[Interface]",
             f"PrivateKey = {base['private_key']}",
             f"Address = {base['address']}"]
    if base["dns"]:
        lines.append(f"DNS = {base['dns']}")
    lines.append(f"MTU = {MTU}")
    lines += [f"Jc = {JUNK['Jc']}", f"Jmin = {JUNK['Jmin']}", f"Jmax = {JUNK['Jmax']}",
              "S1 = 0", "S2 = 0", "H1 = 1", "H2 = 2", "H3 = 3", "H4 = 4"]
    if ENABLE_AMNEZIA_15:
        lines += [f"I1 = {I1}", f"I2 = {I2}"]

    if version == "3.0":
        lines += [f"{k} = {v}" for k, v in AWG3.items()]
    elif version == "3.1":
        lines += AWG31

    lines += ["", "[Peer]", f"PublicKey = {base['public_key']}"]
    if base["preshared"]:
        lines.append(f"PresharedKey = {base['preshared']}")
    lines += [f"AllowedIPs = {base['allowed']}", f"Endpoint = {endpoint}"]
    return "\n".join(lines)


# ======================= خروجی ۲: JSON موبایل (PingNG / v2rayNG) =======================
def build_xray_mobile(accounts, ips):
    items = []
    for n, base, expires in accounts:
        addresses = [a.strip() for a in base["address"].split(",")]
        allowed = [a.strip() for a in base["allowed"].split(",")]
        for i, ip in enumerate(ips, 1):
            items.append({
                "log": {"loglevel": "warning"},
                "dns": {
                    "hosts": {
                        "cloudflare-dns.com": ["104.16.249.249", "104.16.248.249"],
                        "dns.google": ["8.8.8.8", "8.8.4.4"],
                    },
                    "servers": [
                        {"address": "localhost", "domains": ["geosite:category-ir", "domain:ir"],
                         "skipFallback": True, "tag": "direct-dns"},
                        "https://cloudflare-dns.com/dns-query",
                        "https://dns.google/dns-query",
                        "8.8.8.8",
                    ],
                    "tag": "dns-module",
                },
                "inbounds": [{
                    "tag": "socks",
                    "port": 10808,
                    "listen": "127.0.0.1",
                    "protocol": "mixed",
                    "sniffing": {"enabled": False, "destOverride": ["http", "tls"], "routeOnly": False},
                    "settings": {"auth": "noauth", "udp": True, "allowTransparent": False},
                }],
                "outbounds": [
                    {
                        "protocol": "wireguard",
                        "settings": {
                            "secretKey": base["private_key"],
                            "address": addresses,
                            "peers": [{
                                "publicKey": base["public_key"],
                                "allowedIPs": allowed,
                                "endpoint": ip,
                            }],
                            "mtu": MTU,
                        },
                        "tag": "proxy",
                    },
                    {"tag": "direct", "protocol": "freedom"},
                    {"tag": "block", "protocol": "blackhole"},
                ],
                "routing": {
                    "domainStrategy": "AsIs",
                    "rules": [
                        {"type": "field", "outboundTag": "direct", "ip": ["geoip:private"]},
                        {"type": "field", "outboundTag": "direct", "domain": ["geosite:private"]},
                        {"type": "field", "outboundTag": "direct", "domain": ["domain:ir", "geosite:category-ir"]},
                        {"type": "field", "outboundTag": "direct", "ip": ["geoip:ir"]},
                        {"type": "field", "inboundTag": ["direct-dns"], "outboundTag": "direct"},
                        {"type": "field", "inboundTag": ["dns-module"], "outboundTag": "proxy"},
                    ],
                },
                "remarks": f"WG | A{n}-{i} | {ip}",
            })
    return json.dumps(items, indent=2)


# ======================= خروجی ۳: لینک‌های MahsaNG (wireguard://) =======================
def build_mahsa_links(accounts, ips):
    links = []
    for n, base, expires in accounts:
        addresses = ",".join(a.strip() for a in base["address"].split(","))
        for i, ip in enumerate(ips, 1):
            host_port = ip
            if ip.count(":") > 1:                       # IPv6 با پورت: [addr]:port
                addr, port = ip.rsplit(":", 1)
                host_port = f"[{addr}]:{port}"
            q = [
                ("address", addresses),
                ("publickey", base["public_key"]),
                ("mtu", str(MTU)),
            ]
            query = "&".join(f"{a}={enc(b)}" for a, b in q)
            name = f"WG | A{n}-{i} | {ip}"
            links.append(f"wireguard://{enc(base['private_key'])}@{host_port}?{query}#{enc(name)}")
    return "\n".join(links)


# ======================= اجرای اصلی =======================
def main():
    print("Fetching IP list ...")
    ips = fetch_ips()
    print(f"{len(ips)} IPs found.\n")

    # از هر Worker یک اکانت
    accounts = []
    for n, url in enumerate(API_ENDPOINTS, 1):
        try:
            text, expires = fetch_account(url)
            accounts.append((n, parse_base(text), expires))
            print(f"Worker {n} OK (expires: {expires})")
        except Exception as e:
            print(f"Worker {n} FAILED: {e}")

    if not accounts:
        raise SystemExit("No worker responded")   # exit code 1 => هیچ commit ای انجام نمی‌شود

    # --- configs.txt ---
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    parts = [f"# Generated: {now} | Accounts: {len(accounts)} | IPs: {len(ips)}"]
    for ver in ("3.0", "3.1"):
        parts.append(f"\n{'=' * 20} AMNEZIA {ver} {'=' * 20}")
        for n, base, expires in accounts:
            parts.append(f"\n########## Account {n} | expires: {expires} | Amnezia {ver} ##########")
            for i, ip in enumerate(ips, 1):
                parts.append(f"##### [A{n}-{i}] Endpoint: {ip} #####\n{build_config(base, ip, ver)}\n")
    with open("configs.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(parts))

    # --- amnezia-mobile.json ---
    with open("amnezia-mobile.json", "w", encoding="utf-8") as f:
        f.write(build_xray_mobile(accounts, ips))

    # --- amnezia-mahsang.txt ---
    with open("amnezia-mahsang.txt", "w", encoding="utf-8") as f:
        f.write(build_mahsa_links(accounts, ips))

    print(f"\nDone: configs.txt ({len(accounts) * len(ips) * 2} configs), "
          f"amnezia-mobile.json + amnezia-mahsang.txt ({len(accounts) * len(ips)} entries each)")


if __name__ == "__main__":
    main()
