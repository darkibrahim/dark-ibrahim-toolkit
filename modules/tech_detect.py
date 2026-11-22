"""Web technology detection from headers, cookies and HTML."""
import re

import requests
import urllib3

from . import ui

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
HEADERS = {"User-Agent": "Mozilla/5.0 (DARK-IBRAHIM-Toolkit/1.0)"}

HTML_SIGNATURES = {
    "WordPress": ["wp-content/", "wp-includes/"],
    "Joomla": ["/media/jui/", "content=\"joomla"],
    "Drupal": ["drupal-settings-json", "sites/default/files"],
    "Shopify": ["cdn.shopify.com", "shopify.theme"],
    "Magento": ["mage/cookies", "/static/frontend/magento"],
    "WooCommerce": ["woocommerce"],
    "PrestaShop": ["prestashop"],
    "Wix": ["static.wixstatic.com"],
    "Squarespace": ["squarespace.com"],
    "React": ["data-reactroot", "react-dom", "__next_data__"],
    "Next.js": ["/_next/static", "__next_data__"],
    "Vue.js": ["vue.js", "vue.min.js", "data-v-"],
    "Nuxt.js": ["/_nuxt/"],
    "Angular": ["ng-version", "ng-app"],
    "jQuery": ["jquery"],
    "Bootstrap": ["bootstrap.min.css", "bootstrap.min.js"],
    "Tailwind CSS": ["tailwind"],
    "Font Awesome": ["font-awesome", "fontawesome"],
    "Google Analytics": ["google-analytics.com", "gtag/js", "googletagmanager.com"],
    "Facebook Pixel": ["connect.facebook.net", "fbq("],
    "Cloudflare (scripts)": ["cdnjs.cloudflare.com", "cloudflare"],
    "reCAPTCHA": ["recaptcha"],
    "Laravel": ["laravel_session", "csrf-token"],
}

HEADER_SIGNATURES = {
    "cf-ray": "Cloudflare",
    "x-vercel-id": "Vercel",
    "x-nf-request-id": "Netlify",
    "x-amz-cf-id": "Amazon CloudFront",
    "x-drupal-cache": "Drupal",
    "x-shopify-stage": "Shopify",
    "x-litespeed-cache": "LiteSpeed Cache",
    "x-wp-total": "WordPress",
    "x-akamai-transformed": "Akamai",
    "x-sucuri-id": "Sucuri WAF",
}

COOKIE_SIGNATURES = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java (JSP/Servlet)",
    "ASP.NET_SessionId": "ASP.NET",
    "laravel_session": "Laravel",
    "csrftoken": "Django",
    "connect.sid": "Node.js (Express)",
    "__cfduid": "Cloudflare",
    "wordpress_": "WordPress",
}


def run(rec):
    url = ui.ask_url()
    if not url:
        return None
    rec.add(f"[*] Detecting technologies on {url}", ui.C.CYAN)
    try:
        r = requests.get(url, headers=HEADERS, timeout=12, verify=False, allow_redirects=True)
    except requests.RequestException as e:
        rec.add(f"Request failed: {e}", ui.C.RED)
        return ui.clean_host(url)

    rec.add(f"[+] Final URL: {r.url}  (HTTP {r.status_code})", ui.C.GREEN)
    detected = {}

    def hit(name, why):
        detected.setdefault(name, why)

    h = {k.lower(): v for k, v in r.headers.items()}
    if "server" in h:
        hit(f"Server: {h['server']}", "Server header")
    if "x-powered-by" in h:
        hit(f"Powered by: {h['x-powered-by']}", "X-Powered-By header")
    if "x-generator" in h:
        hit(f"Generator: {h['x-generator']}", "X-Generator header")
    for key, name in HEADER_SIGNATURES.items():
        if key in h:
            hit(name, f"{key} header")
    for cname, name in COOKIE_SIGNATURES.items():
        if any(c.name.startswith(cname) for c in r.cookies):
            hit(name, f"cookie {cname}")

    body = r.text[:500000].lower()
    for name, sigs in HTML_SIGNATURES.items():
        for s in sigs:
            if s.lower() in body:
                hit(name, f"HTML contains '{s}'")
                break
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', r.text, re.I)
    if gen:
        hit(f"Generator: {gen.group(1)}", "meta generator tag")

    rec.add()
    if not detected:
        rec.add("No known technologies detected.", ui.C.YELLOW)
    for name, why in sorted(detected.items()):
        rec.add(f"  {name:<38}({why})", ui.C.GREEN)

    sec = ["strict-transport-security", "content-security-policy", "x-frame-options",
           "x-content-type-options", "referrer-policy"]
    rec.add()
    rec.add("[*] Security headers:", ui.C.CYAN)
    for s in sec:
        if s in h:
            rec.add(f"  [present] {s}", ui.C.GREEN)
        else:
            rec.add(f"  [missing] {s}", ui.C.YELLOW)
    return ui.clean_host(url)
