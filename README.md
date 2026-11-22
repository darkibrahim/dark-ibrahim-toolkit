```
 ____    _    ____  _  __
|  _ \  / \  |  _ \| |/ /
| | | |/ _ \ | |_) | ' /
| |_| / ___ \|  _ <| . \
|____/_/   \_\_| \_\_|\_\
```

# DARK IBRAHIM — Bug Bounty Toolkit

**CYBER SECURITY EXPERT · BUG BOUNTY TOOLKIT**

> Darkness is my kingdom,
> Cyber world my weapon.
> I speak in code & rule shadows.

A lightweight terminal **Recon Dashboard** for bug bounty beginners and security learners.
Works on Kali Linux, Termux and any system with Python 3.8+.

## Features

| #  | Tool                     | What it does                                                      |
|----|--------------------------|-------------------------------------------------------------------|
| 01 | DNS Lookup               | A, AAAA, CNAME, MX, NS, TXT, SOA records                          |
| 02 | WHOIS Lookup             | IANA → registry referral, RDAP fallback                           |
| 03 | Subdomain Enumeration    | crt.sh (certificate transparency) + wordlist brute force          |
| 04 | HTTP Probe               | Status, redirects, server, title, response time                   |
| 05 | Web Technology Detection | Headers, cookies, HTML signatures, security-header check          |
| 06 | Directory Discovery      | Threaded wordlist scan with soft-404 filtering                    |
| 07 | Localhost Port Scanner   | Scans only `127.0.0.1` (your own device)                          |
| 08 | View Saved Report        | Every scan is saved automatically to `reports/`                   |

## Install

```bash
git clone https://github.com/darkibrahim/dark-ibrahim-toolkit.git
cd dark-ibrahim-toolkit
pip install -r requirements.txt
python3 darkrecon.py
```

Termux: `pkg install python git && pip install -r requirements.txt`

> `dnspython` is optional. Without it, DNS Lookup falls back to A/AAAA only.

## Project structure

```
darkrecon.py        main dashboard
modules/            one file per tool (+ ui.py, report.py)
wordlists/          subdomains.txt, directories.txt (edit freely)
reports/            saved scan reports (git-ignored)
```

## Legal disclaimer

This toolkit is for **educational use and authorised security testing only**.
Only scan domains you own or that are explicitly **in scope** of a bug bounty
program / written permission. Subdomain and directory scans ask for confirmation
before running. The author is not responsible for misuse.

## License

MIT © 2026 Dark Ibrahim
