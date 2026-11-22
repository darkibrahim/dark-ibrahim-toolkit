"""Localhost-only TCP port scanner (127.0.0.1)."""
import socket
from concurrent.futures import ThreadPoolExecutor

from . import ui

HOST = "127.0.0.1"


def _check(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.4)
        return port if s.connect_ex((HOST, port)) == 0 else None


def run(rec):
    ui.info("This scanner only scans your own device (127.0.0.1).")
    start = ui.ask_int("Start port", 1, 1, 65535)
    end = ui.ask_int("End port", 1024, 1, 65535)
    if end < start:
        start, end = end, start
    rec.add(f"[*] Scanning {HOST} ports {start}-{end}", ui.C.CYAN)
    open_ports = []
    try:
        with ThreadPoolExecutor(max_workers=200) as ex:
            for p in ex.map(_check, range(start, end + 1)):
                if p:
                    open_ports.append(p)
    except KeyboardInterrupt:
        rec.add("[!] Interrupted.", ui.C.YELLOW)
    rec.add()
    for p in sorted(open_ports):
        try:
            svc = socket.getservbyport(p, "tcp")
        except OSError:
            svc = "unknown"
        rec.add(f"  {p:<6}/tcp  open  {svc}", ui.C.GREEN)
    if not open_ports:
        rec.add("No open ports found in this range.", ui.C.YELLOW)
    rec.add()
    rec.add(f"[+] Scan complete: {len(open_ports)} open port(s).", ui.C.CYAN)
    return "localhost"
