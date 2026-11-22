"""HTTP probe: status, redirects, server, title, timing."""
import re
import time

import requests
import urllib3

from . import ui

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
HEADERS = {"User-Agent": "Mozilla/5.0 (DARK-IBRAHIM-Toolkit/1.0)"}
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def probe(target, rec):
    """Probe one host. Tries https then http when no scheme is given."""
    urls = [target] if re.match(r"^https?://", target, re.I) else [f"https://{target}", f"http://{target}"]
    for url in urls:
        try:
            start = time.time()
            r = requests.get(url, headers=HEADERS, timeout=10, verify=False, allow_redirects=True)
            elapsed = time.time() - start
        except requests.RequestException as e:
            rec.add(f"  {url:<45}DOWN ({type(e).__name__})", ui.C.RED)
            continue
        title = TITLE_RE.search(r.text[:200000]) if "html" in r.headers.get("Content-Type", "") else None
        title = re.sub(r"\s+", " ", title.group(1)).strip()[:80] if title else "-"
        color = ui.C.GREEN if r.status_code < 300 else ui.C.YELLOW if r.status_code < 400 else ui.C.RED
        rec.add(f"  {url}", color)
        rec.add(f"    Status   : {r.status_code} {r.reason}", color)
        if r.history:
            chain = " -> ".join(str(h.status_code) for h in r.history)
            rec.add(f"    Redirects: {chain} -> {r.url}")
        rec.add(f"    Server   : {r.headers.get('Server', '-')}")
        rec.add(f"    Type     : {r.headers.get('Content-Type', '-')}")
        rec.add(f"    Size     : {len(r.content)} bytes")
        rec.add(f"    Title    : {title}")
        rec.add(f"    Time     : {elapsed:.2f}s")
        return True
    return False


def run(rec):
    raw = input("Enter domain/URL (comma separated for many): ").strip()
    if not raw:
        ui.warn("No input given.")
        return None
    targets = [t.strip() for t in raw.split(",") if t.strip()]
    rec.add(f"[*] Probing {len(targets)} target(s)", ui.C.CYAN)
    rec.add()
    for t in targets:
        probe(t, rec)
        rec.add()
    return ui.clean_host(targets[0]) or "targets"
