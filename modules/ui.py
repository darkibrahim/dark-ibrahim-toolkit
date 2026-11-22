"""Terminal UI helpers: colours, banner, menu, prompts, report recorder."""
import os
import re
import sys

from . import __version__


class C:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"


if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    for _k in [k for k in vars(C) if k.isupper()]:
        setattr(C, _k, "")

BANNER = r"""
 ____    _    ____  _  __
|  _ \  / \  |  _ \| |/ /
| | | |/ _ \ | |_) | ' /
| |_| / ___ \|  _ <| . \
|____/_/   \_\_| \_\_|\_\
"""

LINE = "=" * 44

MENU = [
    ("01", "DNS Lookup"),
    ("02", "WHOIS Lookup"),
    ("03", "Subdomain Enumeration"),
    ("04", "HTTP Probe"),
    ("05", "Web Technology Detection"),
    ("06", "Directory Discovery"),
    ("07", "Localhost Port Scanner"),
    ("08", "View Saved Report"),
]

ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def banner():
    print(C.BLUE + BANNER + C.RESET)
    print(C.BLUE + "         DARK IBRAHIM" + C.RESET)
    print(C.BLUE + "     CYBER SECURITY EXPERT" + C.RESET)
    print(C.CYAN + "       BUG BOUNTY TOOLKIT" + C.RESET + f"  v{__version__}")
    print()
    print("Darkness is my kingdom,")
    print("Cyber world my weapon.")
    print("I speak in code & rule shadows.")
    print()


def menu():
    print(C.BLUE + LINE + C.RESET)
    print(C.GREEN + "            RECON DASHBOARD" + C.RESET)
    print(C.BLUE + LINE + C.RESET)
    for num, name in MENU:
        print(f"  [{num}] {name}")
    print()
    print(C.RED + "  [00] Exit" + C.RESET)
    print()
    print(C.BLUE + LINE + C.RESET)
    print()


def prompt():
    return input(f"{C.BLUE}DARK IBRAHIM@KALI:~ ${C.RESET} ").strip()


def info(msg):
    print(f"{C.CYAN}[*]{C.RESET} {msg}")


def ok(msg):
    print(f"{C.GREEN}[+]{C.RESET} {msg}")


def warn(msg):
    print(f"{C.YELLOW}[!]{C.RESET} {msg}")


def err(msg):
    print(f"{C.RED}[-] {msg}{C.RESET}")


def pause():
    try:
        input("\nPress Enter to continue...")
    except EOFError:
        pass


def clean_host(value):
    """Strip scheme, path, port and whitespace -> bare hostname."""
    value = value.strip().lower()
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value)
    value = value.split("/")[0].split("?")[0].split("#")[0]
    value = value.split("@")[-1]
    value = value.split(":")[0]
    return value.strip(".")


HOST_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def valid_domain(value):
    return bool(HOST_RE.match(value))


def ask_domain(label="Enter domain: "):
    raw = input(label)
    host = clean_host(raw)
    if not host:
        warn("No input given.")
        return None
    if not valid_domain(host):
        err(f"'{host}' does not look like a valid domain (example: example.com).")
        return None
    return host


def ask_url(label="Enter URL or domain: "):
    raw = input(label).strip()
    if not raw:
        warn("No input given.")
        return None
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    return raw


def confirm_permission():
    warn("Only test targets you own or are explicitly authorised to test")
    warn("(e.g. an in-scope bug bounty program).")
    ans = input("Do you have permission to test this target? (y/N): ").strip().lower()
    return ans in ("y", "yes")


def ask_int(label, default, lo=1, hi=10**9):
    raw = input(f"{label} [{default}]: ").strip()
    if not raw:
        return default
    try:
        val = int(raw)
    except ValueError:
        warn(f"Invalid number, using {default}.")
        return default
    return max(lo, min(hi, val))


class Recorder:
    """Prints coloured output and keeps a plain-text copy for the report."""

    def __init__(self):
        self.lines = []

    def reset(self):
        self.lines = []

    def add(self, text="", color=""):
        print(f"{color}{text}{C.RESET}" if color else text)
        self.lines.append(ANSI_RE.sub("", text))
