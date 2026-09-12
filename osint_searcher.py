#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSINT-SEARCHER — Username reconnaissance across 30 global & Iranian platforms.
Channel: @Shadow_Acadmey

Fixed & hardened edition:
  * Report-writer crash fixed ("-" * ا60  ->  NameError at runtime)
  * Telegram / TikTok / Steam detection logic corrected (was inverted or wrong)
  * 403 / 429 / login-walls / bot-challenge pages are now reported as
    "unverifiable" instead of being counted as FOUND (anti-false-positive)
  * Facebook support added
"""

import os

import sys

import requests

from concurrent.futures import ThreadPoolExecutor



# ANSI Color Codes for Terminal Styling

GREEN = "\033[1;32m"

CYAN = "\033[1;36m"

RED = "\033[1;31m"

YELLOW = "\033[1;33m"

RESET = "\033[0m"



# Colorful Hacking Banner (Green & Cyan Accent)

BANNER = f"""{GREEN}

  _      _      _      _      _      _      _

 / \\    / \\    / \\    / \\    / \\    / \\    / \\

(  {CYAN}O{GREEN}  )(  {CYAN}S{GREEN}  )(  {CYAN}I{GREEN}  )(  {CYAN}N{GREEN}  )(  {CYAN}T{GREEN}  )(  {CYAN}-{GREEN}  )(  {CYAN}S{GREEN}  )

 \\_/    \\_/    \\_/    \\_/    \\_/    \\_/    \\_/

  _      _      _      _      _      _      _

 / \\    / \\    / \\    / \\    / \\    / \\    / \\

(  {CYAN}E{GREEN}  )(  {CYAN}A{GREEN}  )(  {CYAN}R{GREEN}  )(  {CYAN}C{GREEN}  )(  {CYAN}H{GREEN}  )(  {CYAN}E{GREEN}  )(  {CYAN}R{GREEN}  )

 \\_/    \\_/    \\_/    \\_/    \\_/    \\_/    \\_/



       {CYAN}========================================{GREEN}

                 SHADOW ACADEMY OSINT

             Channel: {YELLOW}@Shadow_Acadmey{GREEN}

       {CYAN}========================================{RESET}

"""



# Completely Hardened Platform database

# Every platform now has custom validation parameters to check status codes, redirect behaviors, and error messages

PLATFORMS = {

    # Global Platforms

    "Instagram": {

        "url": "https://www.instagram.com/{username}/",

        "check_type": "advanced_redirect_or_404",

        "not_found_status": [404],

        # Instagram serves this text on its real "page not available" page

        "error_indicator": ["Sorry, this page isn't available."]

    },

    "Twitter (X)": {

        "url": "https://x.com/{username}",

        "check_type": "advanced_redirect_or_404",

        "not_found_status": [404],

        "error_indicator": ["This account doesn’t exist", "page doesn’t exist", "user-not-found"]

    },

    "GitHub": {

        "url": "https://github.com/{username}",

        "check_type": "status_only",

        "not_found_status": [404]

    },

    "Reddit": {

        "url": "https://www.reddit.com/user/{username}",

        "check_type": "advanced_redirect_or_404",

        "not_found_status": [404],

        "error_indicator": ["Sorry, nobody on Reddit goes by that name", "page not found"]

    },

    "TikTok": {

        "url": "https://www.tiktok.com/@{username}",

        "check_type": "advanced_redirect_or_404",

        "not_found_status": [404],

        # Verified marker: the embedded JSON of a missing account carries statusCode 10221.

        # (The visible text "Couldn't find this account" exists on BOTH pages and must NOT be used.)

        "error_indicator": ["\"statusCode\":10221"]

    },

    "YouTube": {

        "url": "https://www.youtube.com/@{username}",

        "check_type": "status_only",

        "not_found_status": [404]

    },

    "Telegram": {

        "url": "https://t.me/{username}",

        "check_type": "content_analysis",

        # Verified: this raw-HTML phrase appears ONLY on unclaimed/non-existent

        # usernames. Existing profiles show "Telegram: View @user" instead.

        "error_indicator": ["If you have <strong>Telegram</strong>, you can contact"]

    },

    "Pinterest": {

        "url": "https://www.pinterest.com/{username}/",

        "check_type": "status_only",

        "not_found_status": [404]

    },

    "Twitch": {

        "url": "https://www.twitch.tv/{username}",

        "check_type": "status_only",

        "not_found_status": [404]

    },

    "Medium": {

        "url": "https://medium.com/@{username}",

        "check_type": "status_only",

        "not_found_status": [404]

    },

    "Dev.to": {

        "url": "https://dev.to/{username}",

        "check_type": "status_only",

        "not_found_status": [404]

    },

    "SoundCloud": {

        "url": "https://soundcloud.com/{username}",

        "check_type": "status_only",

        "not_found_status": [404]

    },

    "Steam": {

        "url": "https://steamcommunity.com/id/{username}",

        "check_type": "content_analysis",

        # Verified real error text of Steam Community

        "error_indicator": ["The specified profile could not be found"]

    },

    "Vimeo": {

        "url": "https://vimeo.com/{username}",

        "check_type": "status_only",

        # 410 (Gone) is returned for deleted/closed profiles — also "not found"

        "not_found_status": [404, 410]

    },

    "Patreon": {

        "url": "https://www.patreon.com/{username}",

        "check_type": "status_only",

        "not_found_status": [404]

    },

    "Behance": {

        "url": "https://www.behance.net/{username}",

        "check_type": "status_only",

        "not_found_status": [404]

    },

    "Dribbble": {

        "url": "https://dribbble.com/{username}",

        "check_type": "status_only",

        "not_found_status": [404]

    },

    "Flickr": {

        "url": "https://www.flickr.com/people/{username}",

        "check_type": "status_only",

        "not_found_status": [404]

    },

    "SlideShare": {

        "url": "https://www.slideshare.net/{username}",

        # SlideShare serves a JS challenge wall, so content must be inspected

        "check_type": "content_analysis",

        "error_indicator": []

    },

    "Spotify": {

        "url": "https://open.spotify.com/user/{username}",

        "check_type": "content_analysis",

        # Verified: Spotify returns an IDENTICAL 200 SPA shell for existing and

        # missing users (oembed & embed endpoints return 404 for both), so it

        # cannot be verified without executing JavaScript -> reported as unverifiable.

        "unverifiable": True,

        "error_indicator": ["Page not found"]

    },

    "Linktree": {

        "url": "https://linktr.ee/{username}",

        "check_type": "status_only",

        "not_found_status": [404]

    },

    "Facebook": {

        "url": "https://www.facebook.com/{username}/",

        "check_type": "content_analysis",

        # Not-logged-in visitors get the real profile page for existing accounts,

        # and a "content isn't available" page for missing accounts.

        "error_indicator": [

            "This content isn't available right now",

            "The link may have expired",

            "This page isn't available"

        ]

    },



    # Iranian Local Platforms

    "Aparat": {

        "url": "https://www.aparat.com/{username}",

        "check_type": "content_analysis",

        "error_indicator": ["کانالی یافت نشد", "صفحه مورد نظر یافت نشد"]

    },

    "Virgool": {

        "url": "https://virgool.io/@{username}",

        "check_type": "content_analysis",

        # Verified: Virgool returns a real HTTP 404 for missing authors, so the

        # status code is the reliable signal. The old Persian indicators ("۴۰۴",

        # "یافت نشد") ALSO appear inside normal profile pages (embedded UI

        # strings), which wrongly marked real profiles as not-found.

        "error_indicator": []

    },

    "Eitaa": {

        "url": "https://eitaa.com/{username}",

        "check_type": "content_analysis",

        "error_indicator": ["کانالی با این مشخصات یافت نشد", "کاربری با این مشخصات یافت نشد", "مورد یافت نشد"]

    },

    "Rubika": {

        "url": "https://rubika.ir/{username}",

        "check_type": "content_analysis",

        "error_indicator": ["page-not-found", "صفحه مورد نظر یافت نشد", "یافت نشد"]

    },

    "Bale": {

        "url": "https://ble.ir/{username}",

        "check_type": "content_analysis",

        "error_indicator": ["کاربر یافت نشد", "not found", "صفحه مورد نظر پیدا نشد", "یافت نشد"]

    },

    "Soroush": {

        "url": "https://splus.ir/{username}",

        "check_type": "content_analysis",

        "error_indicator": ["یافت نشد", "وجود ندارد"]

    },

    "Gap": {

        "url": "https://gap.im/{username}",

        "check_type": "content_analysis",

        "error_indicator": ["کاربر یافت نشد", "یافت نشد"]

    },

    "iGap": {

        "url": "https://profile.igap.net/{username}",

        "check_type": "content_analysis",

        "error_indicator": ["صفحه مورد نظر یافت نشد", "Not Found", "یافت نشد"]

    }

}



# Fragments that identify an anti-bot wall (Cloudflare, SlideShare challenge, ...).

# Such pages say nothing about the username, so the result must be "unknown".

BOT_WALL_MARKERS = (

    "just a moment",        # Cloudflare challenge (Medium, Patreon, ...)

    "client challenge",     # SlideShare / Scribd wall

    "checking your browser",

    "attention required",   # Cloudflare block page

    "cf-challenge"

)



HEADERS = {

    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",

    "Accept-Language": "fa-IR,fa;q=0.9,en-US;q=0.8,en;q=0.7"

}



def init_terminal_colors():

    """Enables ANSI color support on Windows terminals if needed."""

    if sys.platform == "win32":

        os.system("color")



def _is_bot_wall(html_content):

    """Heuristic: anti-bot walls are small pages whose header contains a challenge phrase."""

    head = html_content[:6000].lower()

    return any(marker in head for marker in BOT_WALL_MARKERS)



def check_platform(name, config, username):

    url = config["url"].format(username=username)

    check_type = config["check_type"]



    # SPA-only platforms (e.g. Spotify) return an identical page for existing

    # and missing users, so no reliable server-side verdict is possible.

    if config.get("unverifiable"):

        return name, url, None



    try:

        with requests.Session() as session:



            # Scenario 1: Platforms that redirect active users, but return 404 ONLY if completely empty.

            if check_type == "advanced_redirect_or_404":

                response = session.get(url, headers=HEADERS, timeout=10, allow_redirects=True)



                # If the platform returns 404, it definitely does not exist.

                if response.status_code in config.get("not_found_status", [404]):

                    return name, url, False



                # 403/429 = blocked or rate-limited, a login-walled redirect or an

                # anti-bot challenge proves NOTHING about the username.

                if response.status_code in (403, 429):

                    return name, url, None

                if "/login" in (response.url or ""):

                    return name, url, None

                if _is_bot_wall(response.text):

                    return name, url, None



                # Check for customized non-existent page keywords inside redirected content

                html_content = response.text

                error_indicators = config.get("error_indicator", [])

                for indicator in error_indicators:

                    if indicator in html_content:

                        return name, url, False



                # Real content was reached and no "not found" indicator matched:

                # the username handle is actively registered/taken.

                return name, url, True



            # Scenario 2: Strict Status Code Check (Sites where 404 means vacant, and 200/302 always means taken)

            elif check_type == "status_only":

                response = session.get(url, headers=HEADERS, timeout=10, allow_redirects=False)

                not_found_list = config.get("not_found_status", [404])



                if response.status_code in not_found_list:

                    return name, url, False

                # A block/rate-limit response must not be reported as "found"

                if response.status_code in (403, 429):

                    return name, url, None

                return name, url, True



            # Scenario 3: Heavy Content-Based Analysis (Telegram, Iranian networks, Facebook, etc.)

            elif check_type == "content_analysis":

                response = session.get(url, headers=HEADERS, timeout=10, allow_redirects=True)



                if response.status_code in (403, 429):

                    return name, url, None

                if response.status_code == 404:

                    return name, url, False

                # Login-wall redirects (e.g. restricted Facebook profiles) prove nothing

                if "/login" in (response.url or ""):

                    return name, url, None

                if _is_bot_wall(response.text):

                    return name, url, None



                html_content = response.text

                error_indicators = config.get("error_indicator", [])



                # Scanning for explicit 'not found' text blocks

                for indicator in error_indicators:

                    if indicator in html_content:

                        return name, url, False



                return name, url, True



    except Exception:

        return name, url, None



    return name, url, None



def main():

    init_terminal_colors()



    # Print the hacker-style colored logo

    print(BANNER)



    # Styled input prompt in green

    username = input(f"{CYAN}Enter target username to scan: {RESET}").strip()

    if not username:

        print(f"{RED}[-] Error: Username cannot be empty.{RESET}")

        return



    print(f"\n{GREEN}[*] Initiating deep OSINT scan for username: '{username}'{RESET}")

    print(f"{GREEN}[*] Checking {len(PLATFORMS)} networks (Ultra-Hardened Anti-False-Positive Engine)...{RESET}\n")



    found_profiles = []



    with ThreadPoolExecutor(max_workers=15) as executor:

        futures = [executor.submit(check_platform, name, config, username) for name, config in PLATFORMS.items()]



        for future in futures:

            name, url, exists = future.result()

            if exists is True:

                print(f"{GREEN}[+] FOUND: {name} -> {url}{RESET}")

                found_profiles.append((name, url))

            elif exists is None:

                print(f"{YELLOW}[!] UNVERIFIABLE / CONNECTION ISSUE: {name}{RESET}")



    filename = f"{username}_social_profiles.txt"



    print("\n" + f"{CYAN}="*50 + RESET)

    print(f"{GREEN}[*] Scan complete.{RESET}")

    print(f"{GREEN}[*] Total verified public profiles discovered: {len(found_profiles)}{RESET}")

    print(f"{CYAN}="*50 + RESET)



    try:

        with open(filename, "w", encoding="utf-8") as f:

            f.write(f"============================================================\n")

            f.write(f"              SHADOW ACADEMY OSINT SCAN REPORT              \n")

            f.write(f"                  Channel: @Shadow_Acadmey                  \n")

            f.write(f"============================================================\n\n")

            f.write(f"Target Username: {username}\n")

            f.write(f"Total Discovered Profiles: {len(found_profiles)}\n\n")

            f.write("Discovered Public Links:\n")

            f.write("-" * 60 + "\n")

            if found_profiles:

                for name, url in found_profiles:

                    f.write(f"- {name}: {url}\n")

            else:

                f.write("No active public profiles were found for this username.\n")

            f.write("-" * 60 + "\n")

            f.write(f"Report compiled successfully.\n")



        print(f"{GREEN}[+] Detailed report exported successfully to: '{filename}'{RESET}")

    except Exception as e:

        print(f"{RED}[-] Error writing the output report file: {e}{RESET}")



if __name__ == "__main__":

    main()
