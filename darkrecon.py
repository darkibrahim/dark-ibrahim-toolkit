#!/usr/bin/env python3
"""DARK IBRAHIM - Bug Bounty Toolkit (Recon Dashboard)."""
import sys

if sys.version_info < (3, 8):
    sys.exit("Python 3.8+ is required.")

try:
    import requests  # noqa: F401
except ImportError:
    sys.exit("Missing dependency. Run: pip install -r requirements.txt")

from modules import (dir_discovery, dns_lookup, http_probe, port_scanner, report,
                     subdomain, tech_detect, ui, whois_lookup)

TOOLS = {
    "1": ("dns", dns_lookup),
    "2": ("whois", whois_lookup),
    "3": ("subdomains", subdomain),
    "4": ("httpprobe", http_probe),
    "5": ("techdetect", tech_detect),
    "6": ("dirscan", dir_discovery),
    "7": ("portscan", port_scanner),
    "8": ("report", report),
}


def main():
    rec = ui.Recorder()
    while True:
        ui.clear()
        ui.banner()
        ui.menu()
        try:
            choice = ui.prompt().lstrip("0") or "0"
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if choice == "0":
            break
        if choice not in TOOLS:
            ui.err("Invalid option.")
            ui.pause()
            continue
        name, module = TOOLS[choice]
        rec.reset()
        print()
        try:
            target = module.run(rec)
        except KeyboardInterrupt:
            print()
            ui.warn("Cancelled.")
            target = None
        except Exception as e:  # noqa: BLE001
            ui.err(f"Unexpected error: {type(e).__name__}: {e}")
            target = None
        if target and rec.lines and name != "report":
            path = report.save(name, target, rec.lines)
            print()
            ui.ok(f"Report saved: {path}")
        ui.pause()
    print(ui.C.CYAN + "\nStay legal. Stay dark. Goodbye." + ui.C.RESET)


if __name__ == "__main__":
    main()
