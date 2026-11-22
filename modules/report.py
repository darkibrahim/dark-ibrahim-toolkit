"""Save and view text reports."""
import re
from datetime import datetime
from pathlib import Path

from . import ui

REPORT_DIR = Path(__file__).resolve().parent.parent / "reports"


def save(tool, target, lines):
    REPORT_DIR.mkdir(exist_ok=True)
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", target)[:80]
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORT_DIR / f"{tool}_{safe}_{stamp}.txt"
    header = [
        "DARK IBRAHIM BUG BOUNTY TOOLKIT - REPORT",
        f"Tool   : {tool}",
        f"Target : {target}",
        f"Date   : {datetime.now():%Y-%m-%d %H:%M:%S}",
        "=" * 44,
        "",
    ]
    path.write_text("\n".join(header + lines) + "\n", encoding="utf-8")
    return path


def list_reports():
    if not REPORT_DIR.exists():
        return []
    return sorted(REPORT_DIR.glob("*.txt"), key=lambda p: p.stat().st_mtime, reverse=True)


def run(rec):
    files = list_reports()
    if not files:
        ui.warn("No saved reports yet. Run a scan first.")
        return None
    ui.info("Saved reports (newest first):")
    for i, f in enumerate(files[:30], 1):
        print(f"  [{i:02d}] {f.name}")
    raw = input("\nSelect report number (Enter to cancel): ").strip()
    if not raw:
        return None
    try:
        f = files[int(raw) - 1]
    except (ValueError, IndexError):
        ui.err("Invalid selection.")
        return None
    print()
    print(f.read_text(encoding="utf-8", errors="replace"))
    return None
