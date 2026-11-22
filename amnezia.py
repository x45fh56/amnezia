#!/usr/bin/env python3
"""
Amnezia Config Bulk Generator
از هر Worker یک اکانت می‌گیرد (حداکثر 4 اکانت) و با هر اکانت
برای تمام IP های IP.txt کانفیگ می‌سازد.
خروجی: configs_amnezia_3.0_*.txt و configs_amnezia_3.1_*.txt
"""
import json
import urllib.request
from datetime import datetime
from datetime import datetime, timezone

IP_URL = "https://raw.githubusercontent.com/DarknessShade/Amnezia-VPN-Config/main/IP.txt"
API_ENDPOINTS = [
    "https://warp.configwireguard.workers.dev/",
    "https://warp.configwireguard2.workers.dev/",
    "https://warp.configwireguard3.workers.dev/",
    "https://warp.configwireguard4.workers.dev/",
]

# --- تنظیمات (مثل پیش‌فرض سایت) ---
MTU = 1280
JUNK = {"Jc": 3, "Jmin": 1, "Jmax": 3}          # سنگین: 5 / 10 / 40
ENABLE_AMNEZIA_15 = True
I1 = "<r 2><b 0x0100000100000000000003777777056170706c6503636f6d0000010001>"
I2 = "<r 2><b 0x0100000100000000000003777777056170706c6503636f6d00001c0001>"

AWG3 = {
    "ContentPaddingAddition": "27-97",
    "MaxHandshakeAttempts": "18-26",
    "KeepaliveTimeout": "9-16",
    "RejectAfterTime": "171-196",
    "RekeyAfterTime": "116-131",
    "RekeyTimeout": "6-9",
}
AWG31 = ["RandomTrailers = on", "DisableCookies = on"]


def http_get(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")


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


def main():
    print("Fetching IP list ...")
    ips = fetch_ips()
    print(f"{len(ips)} IPs found.\n")

    accounts = []
    for n, url in enumerate(API_ENDPOINTS, 1):
        try:
            text, expires = fetch_account(url)
            accounts.append((n, parse_base(text), expires))
            print(f"Worker {n} OK (expires: {expires})")
        except Exception as e:
            print(f"Worker {n} FAILED: {e}")

    if not accounts:
        raise SystemExit("No worker responded")  # exit code 1 => workflow fails, nothing gets committed

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
    print(f"Done: configs.txt ({len(accounts) * len(ips) * 2} configs)")

if __name__ == "__main__":
    main()