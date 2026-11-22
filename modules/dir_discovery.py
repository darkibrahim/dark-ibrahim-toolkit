"""Directory / file discovery using a wordlist."""
import random
import string
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests
import urllib3

from . import ui

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
WORDLIST = Path(__file__).resolve().parent.parent / "wordlists" / "directories.txt"
HEADERS = {"User-Agent": "Mozilla/5.0 (DARK-IBRAHIM-Toolkit/1.0)"}
INTERESTING = {200, 204, 301, 302, 307, 308, 401, 403, 405, 500}


def run(rec):
    base = ui.ask_url("Enter target URL (e.g. https://example.com): ")
    if not base:
        return None
    base = base.rstrip("/")
    if not ui.confirm_permission():
        ui.warn("Cancelled.")
        return None
    threads = ui.ask_int("Threads", 20, 1, 50)
    exts_raw = input("Extensions to try (e.g. php,html,txt - Enter for none): ").strip()
    exts = [e.strip().lstrip(".") for e in exts_raw.split(",") if e.strip()]

    if not WORDLIST.exists():
        rec.add(f"[!] Wordlist missing: {WORDLIST}", ui.C.RED)
        return None
    words = [w.strip().lstrip("/") for w in WORDLIST.read_text().splitlines()
             if w.strip() and not w.startswith("#")]
    paths = list(words)
    for w in words:
        for e in exts:
            paths.append(f"{w}.{e}")

    session = requests.Session()
    session.headers.update(HEADERS)

    # baseline for soft-404 detection
    junk = "".join(random.choices(string.ascii_lowercase, k=16))
    try:
        b = session.get(f"{base}/{junk}", timeout=10, verify=False, allow_redirects=False)
    except requests.RequestException as e:
        rec.add(f"[-] Cannot reach target: {e}", ui.C.RED)
        return ui.clean_host(base)
    base_status, base_len = b.status_code, len(b.content)

    rec.add(f"[*] Directory discovery on {base} ({len(paths)} paths)", ui.C.CYAN)
    if base_status != 404:
        rec.add(f"[!] Soft-404 detected (random path returns {base_status}); filtering by size.",
                ui.C.YELLOW)
    rec.add()

    results = []
    lock = threading.Lock()

    def check(path):
        try:
            r = session.get(f"{base}/{path}", timeout=8, verify=False, allow_redirects=False)
        except requests.RequestException:
            return
        if r.status_code not in INTERESTING:
            return
        if r.status_code == base_status and abs(len(r.content) - base_len) < 15:
            return
        with lock:
            results.append((path, r.status_code, len(r.content), r.headers.get("Location", "")))

    try:
        with ThreadPoolExecutor(max_workers=threads) as ex:
            list(ex.map(check, paths))
    except KeyboardInterrupt:
        rec.add("[!] Interrupted - showing results so far.", ui.C.YELLOW)

    for path, status, size, loc in sorted(results):
        color = ui.C.GREEN if status < 300 else ui.C.CYAN if status < 400 else ui.C.YELLOW
        extra = f" -> {loc}" if loc else ""
        rec.add(f"  /{path:<30} [{status}] {size:>8} bytes{extra}", color)
    rec.add()
    rec.add(f"[+] {len(results)} interesting path(s) found.", ui.C.CYAN)
    return ui.clean_host(base)
