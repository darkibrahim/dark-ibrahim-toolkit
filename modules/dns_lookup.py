"""DNS lookup (A, AAAA, CNAME, MX, NS, TXT, SOA)."""
import socket

from . import ui

try:
    import dns.exception
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:  # graceful fallback
    HAS_DNSPYTHON = False

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]


def _fallback(domain, rec):
    rec.add("dnspython not installed - showing A/AAAA only (pip install dnspython).", ui.C.YELLOW)
    try:
        infos = socket.getaddrinfo(domain, None)
    except socket.gaierror as e:
        rec.add(f"Resolution failed: {e}", ui.C.RED)
        return
    seen = set()
    for fam, _, _, _, addr in infos:
        ip = addr[0]
        if ip in seen:
            continue
        seen.add(ip)
        rec.add(f"  {'AAAA' if fam == socket.AF_INET6 else 'A':<6}{ip}", ui.C.GREEN)


def run(rec):
    domain = ui.ask_domain()
    if not domain:
        return None
    rec.add(f"[*] DNS lookup for {domain}", ui.C.CYAN)
    rec.add()
    if not HAS_DNSPYTHON:
        _fallback(domain, rec)
        return domain

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 6
    resolver.timeout = 3
    found = False
    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
        except dns.resolver.NXDOMAIN:
            rec.add("Domain does not exist (NXDOMAIN).", ui.C.RED)
            return domain
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue
        except dns.exception.Timeout:
            rec.add(f"  {rtype:<6}timeout", ui.C.YELLOW)
            continue
        except Exception as e:  # noqa: BLE001
            rec.add(f"  {rtype:<6}error: {e}", ui.C.YELLOW)
            continue
        for r in answers:
            found = True
            rec.add(f"  {rtype:<6}{r.to_text()}", ui.C.GREEN)
    if not found:
        rec.add("No records found.", ui.C.YELLOW)
    return domain
