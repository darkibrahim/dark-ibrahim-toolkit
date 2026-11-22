"""Subdomain enumeration: passive (crt.sh) + wordlist brute force."""
import random
import socket
import string
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

from . import ui

WORDLIST = Path(__file__).resolve().parent.parent / "wordlists" / "subdomains.txt"


def _resolve(host):
    try:
        return tuple(sorted(set(socket.gethostbyname_ex(host)[2])))
    except (socket.gaierror, socket.herror, UnicodeError, OSError):
        return ()


def _crtsh(domain, rec):
    rec.add("[*] Querying crt.sh (certificate transparency)...", ui.C.CYAN)
    try:
        r = requests.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
                         timeout=30)
        if r.status_code != 200:
            rec.add(f"[!] crt.sh returned HTTP {r.status_code}", ui.C.YELLOW)
            return set()
        names = set()
        for row in r.json():
            for n in row.get("name_value", "").splitlines():
                n = n.strip().lower().lstrip("*.")
                if n == domain or n.endswith("." + domain):
                    names.add(n)
        rec.add(f"[+] crt.sh found {len(names)} name(s)", ui.C.GREEN)
        return names
    except (requests.RequestException, ValueError) as e:
        rec.add(f"[!] crt.sh unavailable: {e}", ui.C.YELLOW)
        return set()


def run(rec):
    domain = ui.ask_domain()
    if not domain:
        return None
    if not ui.confirm_permission():
        ui.warn("Cancelled.")
        return None
    threads = ui.ask_int("Threads", 30, 1, 100)

    rec.add(f"[*] Subdomain enumeration for {domain}", ui.C.CYAN)
    found = {}

    for name in _crtsh(domain, rec):
        found[name] = None

    wildcard = _resolve("".join(random.choices(string.ascii_lowercase, k=14)) + "." + domain)
    if wildcard:
        rec.add(f"[!] Wildcard DNS detected ({', '.join(wildcard)}) - filtering false positives.",
                ui.C.YELLOW)

    if WORDLIST.exists():
        words = [w.strip() for w in WORDLIST.read_text().splitlines()
                 if w.strip() and not w.startswith("#")]
        rec.add(f"[*] Brute forcing {len(words)} words...", ui.C.CYAN)
        hosts = [f"{w}.{domain}" for w in words]
        try:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                for host, ips in zip(hosts, ex.map(_resolve, hosts)):
                    if ips and ips != wildcard:
                        found[host] = ips
        except KeyboardInterrupt:
            rec.add("[!] Interrupted - showing results so far.", ui.C.YELLOW)
    else:
        rec.add(f"[!] Wordlist missing: {WORDLIST}", ui.C.YELLOW)

    # resolve passive names that have no IP yet
    pending = [h for h, ips in found.items() if ips is None]
    if pending:
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for host, ips in zip(pending, ex.map(_resolve, pending)):
                found[host] = ips

    rec.add()
    live = {h: i for h, i in found.items() if i}
    for host in sorted(live):
        rec.add(f"  {host:<45}{', '.join(live[host])}", ui.C.GREEN)
    dead = len(found) - len(live)
    rec.add()
    rec.add(f"[+] {len(live)} live subdomain(s); {dead} found in certificates but not resolving.",
            ui.C.CYAN)
    return domain
