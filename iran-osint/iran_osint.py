#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IRAN-OSINT-SEARCHER — Search a username / ID / name / phone number / email
across ALL major Iranian platforms & messengers, automatically.
Channel: @Shadow_Acadmey

The tool auto-detects the input type, checks everything it can automatically
and only prints FOUND results (clean output). Full details + manual
deep-search links go into the report file.

Modes (auto-detected):
  * USERNAME/ID -> public profile check on 23 Iranian platforms
  * PHONE       -> WhatsApp account check (returns the owner name too!)
  * EMAIL       -> Gravatar public profile + same-ID probe on all platforms
  * NAME        -> deep-search links for Iranian sites (in report)

Calibration:
  python3 iran_osint.py --probe
      -> checks a known + a random handle on every platform and shows a raw
         verdict table. Run it from an IRANIAN IP to verify all sites.

Usage:
  python3 iran_osint.py                 (interactive)
  python3 iran_osint.py 09123456789     (direct target)
"""

import os
import sys
import re
import hashlib
import html
import urllib.parse
import requests
from concurrent.futures import ThreadPoolExecutor

# ANSI Color Codes for Terminal Styling
GREEN = "\033[1;32m"
CYAN = "\033[1;36m"
RED = "\033[1;31m"
YELLOW = "\033[1;33m"
RESET = "\033[0m"

BANNER = f"""{GREEN}
  _      _      _      _      _
 / \\    / \\    / \\    / \\    / \\
(  {CYAN}I{GREEN}  )(  {CYAN}R{GREEN}  )(  {CYAN}A{GREEN}  )(  {CYAN}N{GREEN}  )(  {CYAN}-{GREEN}  )
 \\_/    \\_/    \\_/    \\_/    \\_/
  _      _      _      _      _      _      _      _
 / \\    / \\    / \\    / \\    / \\    / \\    / \\    / \\
(  {CYAN}O{GREEN}  )(  {CYAN}S{GREEN}  )(  {CYAN}I{GREEN}  )(  {CYAN}N{GREEN}  )(  {CYAN}T{GREEN}  )(  {CYAN}-{GREEN}  )(  {CYAN}I{GREEN}  )(  {CYAN}T{GREEN}  )
 \\_/    \\_/    \\_/    \\_/    \\_/    \\_/    \\_/    \\_/

       {CYAN}========================================{GREEN}
              SHADOW ACADEMY IRAN OSINT
             Channel: {YELLOW}@Shadow_Acadmey{GREEN}
       {CYAN}========================================{RESET}
"""

# ---------------------------------------------------------------------------
# Iranian platforms with public profile URLs (23 sites / messengers)
# ---------------------------------------------------------------------------
IRAN_PLATFORMS = {
    # --- messengers ---
    "Telegram": {
        "url": "https://t.me/{username}",
        "error_indicator": ["If you have <strong>Telegram</strong>, you can contact"]
    },
    "Eitaa": {
        "url": "https://eitaa.com/{username}",
        "error_indicator": ["کانالی با این مشخصات یافت نشد", "کاربری با این مشخصات یافت نشد", "مورد یافت نشد"]
    },
    "Rubika": {
        "url": "https://rubika.ir/{username}",
        "error_indicator": ["page-not-found", "صفحه مورد نظر یافت نشد"]
    },
    "Bale": {
        "url": "https://ble.ir/{username}",
        "error_indicator": ["کاربر یافت نشد", "صفحه مورد نظر پیدا نشد"]
    },
    "Soroush": {
        "url": "https://splus.ir/{username}",
        "error_indicator": ["وجود ندارد"]
    },
    "Gap": {
        "url": "https://gap.im/{username}",
        "error_indicator": ["کاربر یافت نشد"]
    },
    "iGap": {
        "url": "https://profile.igap.net/{username}",
        "error_indicator": ["صفحه مورد نظر یافت نشد", "Not Found"]
    },
    # --- video / blog / content ---
    "Aparat": {
        "url": "https://www.aparat.com/{username}",
        "error_indicator": ["کانالی یافت نشد", "صفحه مورد نظر یافت نشد"]
    },
    "Virgool": {
        "url": "https://virgool.io/@{username}",
        "error_indicator": []
    },
    "Blogfa": {
        "url": "https://{username}.blogfa.com/",
        "error_indicator": ["یافت نشد"],
        "not_found_status": [404]
    },
    "MihanBlog": {
        "url": "https://{username}.mihanblog.com/",
        "error_indicator": ["یافت نشد", "وجود ندارد"],
        "not_found_status": [404]
    },
    "Blog.ir": {
        "url": "https://{username}.blog.ir/",
        "error_indicator": ["یافت نشد", "صفحه پیدا نشد"],
        "not_found_status": [404]
    },
    "PersianBlog": {
        "url": "https://{username}.persianblog.ir/",
        "error_indicator": ["یافت نشد"],
        "not_found_status": [404]
    },
    # --- social / market / media ---
    "Facenama": {
        "url": "https://facenama.com/{username}",
        "error_indicator": ["یافت نشد", "وجود ندارد"],
        "not_found_status": [404]
    },
    "Lenzor": {
        "url": "https://lenzor.com/{username}",
        "error_indicator": ["یافت نشد"],
        "not_found_status": [404]
    },
    "CafeBazaar": {
        "url": "https://cafebazaar.ir/dev/{username}",
        "error_indicator": ["یافت نشد"],
        "not_found_status": [404]
    },
    "Shenoto": {
        "url": "https://shenoto.com/{username}",
        "error_indicator": ["یافت نشد"],
        "not_found_status": [404]
    },
    "Zoomit": {
        "url": "https://www.zoomit.ir/user/{username}/",
        "error_indicator": ["یافت نشد", "پیدا نشد"],
        "not_found_status": [404]
    },
    "Javabyab": {
        "url": "https://javabyab.com/user/{username}",
        "error_indicator": ["یافت نشد"],
        "not_found_status": [404]
    },
    "Namava": {
        "url": "https://www.namava.ir/profile/{username}",
        "error_indicator": ["یافت نشد"],
        "not_found_status": [404]
    },
    # --- freelance / market ---
    "Ponisha": {
        "url": "https://ponisha.ir/profile/{username}",
        "error_indicator": ["یافت نشد", "صفحه مورد نظر"],
        "not_found_status": [404]
    },
    "Basalam": {
        "url": "https://basalam.com/{username}",
        "error_indicator": ["یافت نشد", "موجود نیست"],
        "not_found_status": [404]
    },
    # --- business ads / shops (کاربران برای کسب‌وکارشان آگهی/فروشگاه ثبت می‌کنند) ---
    "Sheypoor Shop": {
        "url": "https://sheypoor.com/shop/{username}",
        "error_indicator": ["یافت نشد", "صفحه مورد نظر", "موجود نیست"],
        "not_found_status": [404]
    }
}

BOT_WALL_MARKERS = (
    "just a moment",
    "client challenge",
    "checking your browser",
    "attention required"
)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Accept-Language": "fa-IR,fa;q=0.9,en-US;q=0.8,en;q=0.7"
}


def init_terminal_colors():
    if sys.platform == "win32":
        os.system("color")


def _is_bot_wall(html_content):
    head = html_content[:6000].lower()
    return any(marker in head for marker in BOT_WALL_MARKERS)


# ---------------------------------------------------------------------------
# PLATFORM CHECK — returns (name, url, True found / False missing / None unknown)
# ---------------------------------------------------------------------------
def check_platform(name, config, username):
    url = config["url"].format(username=username)
    try:
        with requests.Session() as session:
            response = session.get(url, headers=HEADERS, timeout=12, allow_redirects=True)

            if response.status_code in config.get("not_found_status", [404]):
                return name, url, False

            # Subdomain platforms redirect missing blogs to their main site:
            # e.g.  nonexisting.blogfa.com  ->  www.blogfa.com  (a certain MISS)
            miss_hosts = config.get("redirect_host_miss")
            if miss_hosts:
                host = urllib.parse.urlparse(response.url or "").netloc.lower()
                host = host[4:] if host.startswith("www.") else host
                if host in miss_hosts:
                    return name, url, False

            if response.status_code in (403, 429):
                return name, url, None

            if "/login" in (response.url or ""):
                return name, url, None

            html_content = response.text

            if _is_bot_wall(html_content):
                return name, url, None

            for indicator in config.get("error_indicator", []):
                if indicator in html_content:
                    return name, url, False

            return name, url, True
    except Exception:
        return name, url, None


def run_platform_scan(username, label=""):
    """
    Checks the username/ID on every Iranian platform.
    CLEAN OUTPUT: prints ONLY found profiles, then a one-line summary.
    Returns (found, unknown) lists.
    """
    if label:
        print(f"\n{GREEN}[*] {label}{RESET}")
    print(f"{GREEN}[*] Checking {len(IRAN_PLATFORMS)} Iranian platforms (this takes a few seconds)...{RESET}\n")

    found, unknown = [], []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_platform, name, cfg, username)
                   for name, cfg in IRAN_PLATFORMS.items()]
        for future in futures:
            name, url, exists = future.result()
            if exists is True:
                print(f"{GREEN}[+] FOUND: {name} -> {url}{RESET}")
                found.append((name, url))
            elif exists is None:
                unknown.append((name, url))

    total = len(IRAN_PLATFORMS)
    missing = total - len(found) - len(unknown)
    print(f"\n{CYAN}[*] Result: {len(found)} found | {missing} not found | "
          f"{len(unknown)} unverifiable from this network{RESET}")
    if unknown:
        print(f"{YELLOW}    (the unverifiable ones are geo/CDN-blocked for this IP — "
              f"run the tool from inside Iran on a home connection){RESET}")
    return found, unknown


# ---------------------------------------------------------------------------
# PHONE MODE
# ---------------------------------------------------------------------------
def normalize_phone(raw):
    digits = re.sub(r"[^\d+]", "", raw.strip())
    m = re.fullmatch(r"(?:\+?98|0098|0)?(9\d{9})", digits)
    if m:
        local = m.group(1)
        return {
            "national": "0" + local,
            "intl": "98" + local,
            "plus": "+98" + local
        }, None
    m = re.fullmatch(r"\+(\d{8,15})", digits)
    if m:
        n = m.group(1)
        return {"national": n, "intl": n, "plus": "+" + n}, None
    return None, "Phone number not recognized. Use: 09123456789 / +989123456789"


def whatsapp_check(wa_number):
    """
    Server-side WhatsApp verdict:
      existing account -> og:image from pps.whatsapp.net + owner name
      non-existing     -> generic 'Share on WhatsApp' page
    """
    try:
        en_headers = {**HEADERS, "Accept-Language": "en-US,en;q=0.9"}
        r = requests.get(f"https://wa.me/{wa_number}", headers=en_headers,
                         timeout=15, allow_redirects=True)
        if r.status_code == 404:
            return False, None
        t = r.text
        og_title = re.search(r'<meta property="og:title" content="([^"]*)"', t)
        og_image = re.search(r'<meta property="og:image" content="([^"]*)"', t)
        title = html.unescape(og_title.group(1).strip()) if og_title else ""
        image = og_image.group(1) if og_image else ""

        if "pps.whatsapp.net" in image:
            return True, (title or "WhatsApp User")
        if title == "Share on WhatsApp":
            return False, None
        if title:
            return True, title
        return None, None
    except Exception:
        return None, None


def run_phone_mode(raw):
    variants, err = normalize_phone(raw)
    if err:
        print(f"{RED}[-] Error: {err}{RESET}")
        return None

    print(f"\n{GREEN}[*] PHONE MODE — normalized number:{RESET}")
    print(f"{CYAN}    National : {variants['national']}{RESET}")
    print(f"{CYAN}    Intl     : {variants['plus']}{RESET}")

    auto_lines = []
    print(f"\n{GREEN}[*] Checking WhatsApp (public account check)...{RESET}")
    exists, title = whatsapp_check(variants["intl"])
    if exists is True:
        print(f"{GREEN}[+] WHATSAPP ACCOUNT FOUND: {title}  (wa.me/{variants['intl']}){RESET}")
        auto_lines.append(f"WhatsApp: ACTIVE — name: {title} — https://wa.me/{variants['intl']}")
    elif exists is False:
        print(f"{RED}[-] No WhatsApp account on this number{RESET}")
        auto_lines.append("WhatsApp: no account on this number")
    else:
        print(f"{YELLOW}[!] WhatsApp could not be verified (connection issue){RESET}")
        auto_lines.append("WhatsApp: could not be verified")

    n, intl = variants["national"], variants["intl"]
    q = urllib.parse.quote(f'"{n}" OR "{variants["plus"]}" OR "{intl}"')
    links = [
        ("WhatsApp (direct)", f"https://wa.me/{intl}"),
        ("Google — number everywhere", f"https://www.google.com/search?q={q}"),
        ("Google — Divar ads", f"https://www.google.com/search?q={urllib.parse.quote('site:divar.ir ' + chr(34) + n + chr(34))}"),
        ("Google — Sheypoor ads", f"https://www.google.com/search?q={urllib.parse.quote('site:sheypoor.com ' + chr(34) + n + chr(34))}"),
        ("Yandex — number", f"https://yandex.com/search/?text={q}"),
        ("Truecaller (needs login)", f"https://www.truecaller.com/search/global/{intl}"),
    ]
    return auto_lines, links


# ---------------------------------------------------------------------------
# EMAIL MODE
# ---------------------------------------------------------------------------
def gravatar_check(email):
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    try:
        r = requests.get(f"https://gravatar.com/{h}.json", headers=HEADERS, timeout=15)
        if r.status_code == 200:
            entry = r.json().get("entry", [])
            name = entry[0].get("displayName") if entry else None
            return True, name
        if r.status_code == 404:
            return False, None
        return None, None
    except Exception:
        return None, None


def run_email_mode(email):
    auto_lines = []

    print(f"\n{GREEN}[*] EMAIL MODE{RESET}")

    # 1) Gravatar public profile (global, works everywhere)
    print(f"{GREEN}[*] Checking Gravatar public profile...{RESET}")
    exists, name = gravatar_check(email)
    if exists is True:
        print(f"{GREEN}[+] GRAVATAR PROFILE FOUND: {name}{RESET}")
        auto_lines.append(f"Gravatar: PUBLIC PROFILE — name: {name} — "
                          f"https://gravatar.com/{hashlib.md5(email.strip().lower().encode()).hexdigest()}")
    elif exists is False:
        print(f"{RED}[-] No public Gravatar profile for this email{RESET}")
        auto_lines.append("Gravatar: no public profile")
    else:
        print(f"{YELLOW}[!] Gravatar could not be verified{RESET}")
        auto_lines.append("Gravatar: could not be verified")

    # 2) Probe the email local-part (before @) as an ID on all Iranian platforms
    local = email.split("@")[0].strip().lower()
    found, unknown = [], []
    if re.fullmatch(r"[a-zA-Z0-9_.\-]{3,32}", local):
        found, unknown = run_platform_scan(
            local,
            label=f"Probing same-ID '{local}' (username part of the email):")

    q = urllib.parse.quote(f'"{email}"')
    links = [
        ("HaveIBeenPwned — breaches", f"https://haveibeenpwned.com/unifiedsearch/{email}"),
        ("Google — email everywhere", f"https://www.google.com/search?q={q}"),
        ("Google — Iranian sites", f"https://www.google.com/search?q={urllib.parse.quote('site:ir ' + chr(34) + email + chr(34))}"),
        ("Yandex — email", f"https://yandex.com/search/?text={q}"),
        ("Bing — email", f"https://www.bing.com/search?q={q}"),
    ]
    return auto_lines, found, unknown, links


# ---------------------------------------------------------------------------
# NAME MODE
# ---------------------------------------------------------------------------
def run_name_mode(name, print_links=True):
    n = name.strip()
    q = urllib.parse.quote(f'"{n}"')
    sites = " OR ".join(f"site:{s}" for s in
                        ("aparat.com", "virgool.io", "eitaa.com", "ble.ir",
                         "rubika.ir", "divar.ir", "sheypoor.com", "linkedin.com"))
    links = [
        ("Google — all Iranian platforms", f"https://www.google.com/search?q={urllib.parse.quote(chr(34) + n + chr(34) + ' (' + sites + ')')}"),
        ("Google — general search", f"https://www.google.com/search?q={q}"),
        ("Google — Divar/Sheypoor ads", f"https://www.google.com/search?q={urllib.parse.quote(chr(34) + n + chr(34) + ' (site:divar.ir OR site:sheypoor.com)')}"),
        ("Google — LinkedIn", f"https://www.google.com/search?q={urllib.parse.quote(chr(34) + n + chr(34) + ' site:linkedin.com')}"),
        ("Yandex — name", f"https://yandex.com/search/?text={q}"),
        ("Paziresh24 — doctor search", f"https://www.paziresh24.com/search?q={urllib.parse.quote(n)}"),
        ("Aparat — internal search", f"https://www.aparat.com/result/{urllib.parse.quote(n)}"),
        ("Virgool — internal search", f"https://virgool.io/search?q={urllib.parse.quote(n)}"),
    ]
    if print_links:
        print(f"\n{GREEN}[*] NAME MODE — deep-search links for Iranian sites:{RESET}")
        for label, url in links:
            print(f"{CYAN}[*] {label}:{RESET} {url}")
    return links


# ---------------------------------------------------------------------------
# GOVERNMENT / BUSINESS REGISTRY LINKS
# (Iranian gov portals use POST forms + captcha, so automated HTTP checks are
#  impossible; Google already indexed them, so dorks surface the registry data)
# ---------------------------------------------------------------------------
def run_gov_links(name):
    n = name.strip()
    links = [
        ("ENAMAD — نماد اعتماد الکترونیکی (اطلاعات صاحب کسب‌وکار)",
         f"https://www.google.com/search?q={urllib.parse.quote('site:enamad.ir ' + chr(34) + n + chr(34))}"),
        ("Samandehi — نشانه ملی ثبت کسب‌وکارهای مجازی",
         f"https://www.google.com/search?q={urllib.parse.quote('site:samandehi.ir ' + chr(34) + n + chr(34))}"),
        ("Rasmi Newspaper — روزنامه رسمی (ثبت شرکت‌ها و برندها)",
         f"https://www.google.com/search?q={urllib.parse.quote('site:rrk.ir ' + chr(34) + n + chr(34))}"),
        ("Company Registry — سامانه ثبت شرکت‌ها (ssaa)",
         f"https://www.google.com/search?q={urllib.parse.quote('site:ssaa.ir ' + chr(34) + n + chr(34))}"),
        ("Google — brand/business registry data anywhere",
         f"https://www.google.com/search?q={urllib.parse.quote(chr(34) + n + chr(34) + ' (شماره ثبت OR شناسه ملی OR کد اقتصادی)')}"),
    ]
    return links


# ---------------------------------------------------------------------------
# PROBE MODE — calibration from inside Iran
# ---------------------------------------------------------------------------
def run_probe_mode():
    print(BANNER)
    print(f"{YELLOW}PROBE / CALIBRATION MODE{RESET}")
    print(f"{YELLOW}Checks a known handle and a random handle on every platform.{RESET}")
    print(f"{YELLOW}Run this from an IRANIAN IP to calibrate all sites.{RESET}\n")

    KNOWN = "durov"
    RANDOM = "zzqx9v3random7421"

    def one(item):
        name, cfg = item
        _, _, a = check_platform(name, cfg, KNOWN)
        _, _, b = check_platform(name, cfg, RANDOM)
        return name, a, b

    v = {True: "FOUND ", False: "not-fd", None: "UNKNWN"}
    print(f"{'Platform':<14}{'known(durov)':<14}{'random':<9}note")
    print("-" * 55)
    with ThreadPoolExecutor(10) as ex:
        for name, a, b in ex.map(one, IRAN_PLATFORMS.items()):
            note = ""
            if a is None and b is None:
                note = "<- blocked from this network (geo/CDN)"
            if b is True:
                note = "<- CHECK MARKERS (false positive!)"
            print(f"{name:<14}{v[a]:<14}{v[b]:<9}{note}")
    print("\n" + f"{CYAN}[*] Every platform that shows UNKNWN is blocked from this network.{RESET}")
    print(f"{CYAN}[*] Run again from an Iranian IP / home connection for real results.{RESET}")


# ---------------------------------------------------------------------------
# REPORT
# ---------------------------------------------------------------------------
def save_report(query, mode, sections):
    filename = re.sub(r"[^\w\-]", "_", query)[:40] + "_iran_osint.txt"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write("============================================================\n")
            f.write("            SHADOW ACADEMY IRAN OSINT REPORT                \n")
            f.write("                  Channel: @Shadow_Acadmey                  \n")
            f.write("============================================================\n\n")
            f.write(f"Query          : {query}\n")
            f.write(f"Detected Mode  : {mode}\n\n")
            for title, lines in sections:
                f.write(f"{title}\n")
                f.write("-" * 60 + "\n")
                for line in lines:
                    f.write(f"- {line}\n")
                f.write("\n")
            f.write("Report compiled successfully.\n")
        print(f"\n{GREEN}[+] Full report saved to: '{filename}'{RESET}")
    except Exception as e:
        print(f"{RED}[-] Error writing the report file: {e}{RESET}")


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
def detect_mode(query):
    q = query.strip()
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", q):
        return "EMAIL"
    normalized, err = normalize_phone(q)
    if err is None:
        return "PHONE"
    if re.search(r"[\u0600-\u06FF]", q) or " " in q:
        return "NAME"
    return "USERNAME"


def main():
    init_terminal_colors()

    args = [a for a in sys.argv[1:]]
    if "--probe" in args:
        run_probe_mode()
        return

    print(BANNER)

    if args:
        query = args[0].strip()
    else:
        query = input(f"{CYAN}Enter username / ID / name / phone / email: {RESET}").strip()
    if not query:
        print(f"{RED}[-] Error: Input cannot be empty.{RESET}")
        return

    mode = detect_mode(query)
    print(f"\n{GREEN}[*] SHADOW ACADEMY IRAN OSINT — target: '{query}'{RESET}")
    print(f"{GREEN}[*] Detected input type: {mode}{RESET}")

    sections = []

    if mode == "USERNAME":
        found, unknown = run_platform_scan(query)
        sections.append(("VERIFIED PROFILES", [f"{n}: {u}" for n, u in found] or ["None"]))
        if unknown:
            sections.append(("UNVERIFIABLE FROM THIS NETWORK (try from an Iranian IP)",
                             [f"{n}: {u}" for n, u in unknown]))
        links = run_name_mode(query, print_links=False)
        sections.append(("MANUAL DEEP-SEARCH LINKS", [f"{l}: {u}" for l, u in links]))
        gov = run_gov_links(query)
        sections.append(("GOVERNMENT / BUSINESS REGISTRY LINKS", [f"{l}: {u}" for l, u in gov]))

    elif mode == "PHONE":
        auto, links = run_phone_mode(query)
        sections.append(("AUTOMATED CHECKS", auto))
        sections.append(("MANUAL DEEP-SEARCH LINKS", [f"{l}: {u}" for l, u in links]))

    elif mode == "EMAIL":
        auto, found, unknown, links = run_email_mode(query)
        sections.append(("AUTOMATED CHECKS", auto))
        if found:
            sections.append(("SAME-ID PROFILES (username part of the email)",
                             [f"{n}: {u}" for n, u in found]))
        if unknown:
            sections.append(("UNVERIFIABLE FROM THIS NETWORK (try from an Iranian IP)",
                             [f"{n}: {u}" for n, u in unknown]))
        sections.append(("MANUAL DEEP-SEARCH LINKS", [f"{l}: {u}" for l, u in links]))

    else:  # NAME
        links = run_name_mode(query, print_links=True)
        sections.append(("MANUAL DEEP-SEARCH LINKS", [f"{l}: {u}" for l, u in links]))
        gov = run_gov_links(query)
        print(f"\n{GREEN}[*] GOVERNMENT / BUSINESS REGISTRY links:{RESET}")
        for label, url in gov:
            print(f"{CYAN}[*] {label}:{RESET} {url}")
        sections.append(("GOVERNMENT / BUSINESS REGISTRY LINKS", [f"{l}: {u}" for l, u in gov]))

    print("\n" + f"{CYAN}" + "=" * 50 + RESET)
    print(f"{GREEN}[*] Scan complete.{RESET}")
    print(f"{CYAN}" + "=" * 50 + RESET)
    save_report(query, mode, sections)


if __name__ == "__main__":
    main()
