"""WHOIS lookup: IANA -> registry referral, with RDAP fallback."""
import re
import socket

import requests

from . import ui


def _query(server, query, timeout=10):
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", "ignore")


def _find_server(domain, rec):
    tld = domain.rsplit(".", 1)[-1]
    rec.add("[*] Contacting IANA WHOIS...", ui.C.YELLOW)
    resp = _query("whois.iana.org", tld)
    m = re.search(r"^whois:\s*(\S+)", resp, re.M | re.I)
    return m.group(1) if m else None


def _rdap(domain, rec):
    rec.add("[*] Trying RDAP fallback...", ui.C.YELLOW)
    r = requests.get(f"https://rdap.org/domain/{domain}", timeout=15,
                     headers={"Accept": "application/rdap+json"})
    if r.status_code != 200:
        rec.add(f"RDAP returned HTTP {r.status_code} - no data available.", ui.C.RED)
        return
    d = r.json()
    rec.add(f"Domain : {d.get('ldhName', domain)}", ui.C.GREEN)
    rec.add(f"Status : {', '.join(d.get('status', [])) or 'n/a'}", ui.C.GREEN)
    for ev in d.get("events", []):
        rec.add(f"{ev.get('eventAction', 'event'):<14}: {ev.get('eventDate')}", ui.C.GREEN)
    for ns in d.get("nameservers", []):
        rec.add(f"Nameserver    : {ns.get('ldhName')}", ui.C.GREEN)
    for ent in d.get("entities", []):
        roles = ",".join(ent.get("roles", []))
        vcard = ent.get("vcardArray") or [None, []]
        for item in vcard[1]:
            if item and item[0] == "fn":
                rec.add(f"Entity ({roles}): {item[3]}", ui.C.GREEN)


def run(rec):
    domain = ui.ask_domain()
    if not domain:
        return None
    rec.add()
    iana_failed = False
    try:
        server = _find_server(domain, rec)
    except OSError as e:
        rec.add(f"WHOIS Error: {e}", ui.C.RED)
        server = None
        iana_failed = True

    if server:
        rec.add(f"[*] WHOIS Server: {server}", ui.C.CYAN)
        try:
            text = _query(server, domain)
            # follow registrar referral (thin registries such as .com/.net)
            m = re.search(r"Registrar WHOIS Server:\s*(\S+)", text, re.I)
            if m and m.group(1).lower() != server.lower():
                ref = m.group(1).replace("whois://", "").strip("/")
                rec.add(f"[*] Following referral: {ref}", ui.C.CYAN)
                try:
                    text = _query(ref, domain)
                except OSError:
                    pass
            rec.add()
            rec.add(text.strip() or "(empty response)")
            return domain
        except OSError as e:
            rec.add(f"WHOIS Error: {e}", ui.C.RED)
    elif not iana_failed:
        rec.add("[!] No WHOIS server published by IANA for this TLD.", ui.C.YELLOW)

    try:
        _rdap(domain, rec)
    except (requests.RequestException, ValueError) as e:
        rec.add(f"RDAP Error: {e}", ui.C.RED)
    return domain
