#!/usr/bin/env python3
"""
OrbitTrace - Username Scanner
Checks 25+ social platforms for username existence via HTTP probing
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utils.helpers import safe_get, sleep_random


# Platform definitions: name -> (url_template, found_indicator, not_found_status_or_text)
# found_indicator: 'status_200' | 'no_redirect' | 'text:<string>'
# Each entry: (url_template, check_type, extra_hint)
PLATFORMS = {
    "GitHub": {
        "url": "https://github.com/{username}",
        "check": "status_200",
        "not_found_text": "Not Found"
    },
    "Twitter/X": {
        "url": "https://twitter.com/{username}",
        "check": "status_200",
        "not_found_text": "This account doesn't exist"
    },
    "Instagram": {
        "url": "https://www.instagram.com/{username}/",
        "check": "status_200",
        "not_found_text": "Sorry, this page"
    },
    "Reddit": {
        "url": "https://www.reddit.com/user/{username}",
        "check": "status_200",
        "not_found_text": "Sorry, nobody on Reddit"
    },
    "TikTok": {
        "url": "https://www.tiktok.com/@{username}",
        "check": "status_200",
        "not_found_text": "Couldn't find this account"
    },
    "LinkedIn": {
        "url": "https://www.linkedin.com/in/{username}",
        "check": "status_200",
        "not_found_text": "Page not found"
    },
    "YouTube": {
        "url": "https://www.youtube.com/@{username}",
        "check": "status_200",
        "not_found_text": "404"
    },
    "Pinterest": {
        "url": "https://www.pinterest.com/{username}/",
        "check": "status_200",
        "not_found_text": "Sorry! We couldn't find that page"
    },
    "Twitch": {
        "url": "https://www.twitch.tv/{username}",
        "check": "status_200",
        "not_found_text": "Sorry. Unless you've got a time machine"
    },
    "Steam": {
        "url": "https://steamcommunity.com/id/{username}",
        "check": "status_200",
        "not_found_text": "The specified profile could not be found"
    },
    "Keybase": {
        "url": "https://keybase.io/{username}",
        "check": "status_200",
        "not_found_text": "404"
    },
    "HackerNews": {
        "url": "https://news.ycombinator.com/user?id={username}",
        "check": "status_200",
        "not_found_text": "No such user"
    },
    "GitLab": {
        "url": "https://gitlab.com/{username}",
        "check": "status_200",
        "not_found_text": "404"
    },
    "Bitbucket": {
        "url": "https://bitbucket.org/{username}/",
        "check": "status_200",
        "not_found_text": "404"
    },
    "Gravatar": {
        "url": "https://en.gravatar.com/{username}",
        "check": "status_200",
        "not_found_text": "404"
    },
    "DeviantArt": {
        "url": "https://www.deviantart.com/{username}",
        "check": "status_200",
        "not_found_text": "404"
    },
    "Medium": {
        "url": "https://medium.com/@{username}",
        "check": "status_200",
        "not_found_text": "404"
    },
    "Pastebin": {
        "url": "https://pastebin.com/u/{username}",
        "check": "status_200",
        "not_found_text": "Not Found"
    },
    "SoundCloud": {
        "url": "https://soundcloud.com/{username}",
        "check": "status_200",
        "not_found_text": "404"
    },
    "Flickr": {
        "url": "https://www.flickr.com/photos/{username}/",
        "check": "status_200",
        "not_found_text": "Page Not Found"
    },
    "Vimeo": {
        "url": "https://vimeo.com/{username}",
        "check": "status_200",
        "not_found_text": "404"
    },
    "Disqus": {
        "url": "https://disqus.com/by/{username}/",
        "check": "status_200",
        "not_found_text": "404"
    },
    "HackerEarth": {
        "url": "https://www.hackerearth.com/@{username}",
        "check": "status_200",
        "not_found_text": "404"
    },
    "DockerHub": {
        "url": "https://hub.docker.com/u/{username}/",
        "check": "status_200",
        "not_found_text": "404"
    },
    "NPM": {
        "url": "https://www.npmjs.com/~{username}",
        "check": "status_200",
        "not_found_text": "Not found"
    },
    "PyPI": {
        "url": "https://pypi.org/user/{username}/",
        "check": "status_200",
        "not_found_text": "404"
    },
}


class UsernameScan:
    """Scans multiple platforms for a given username"""

    def __init__(self, logger=None, verbose=False, max_workers=10):
        self.logger = logger
        self.verbose = verbose
        self.max_workers = max_workers

    def investigate(self, username: str) -> dict:
        """
        Check all platforms for the given username.
        
        Args:
            username: The username to search for
        
        Returns:
            dict: Results with found/not_found platform lists and URLs
        """
        if self.logger:
            self.logger.info(f"Scanning {len(PLATFORMS)} platforms for: "
                             f"{Fore.GREEN}{username}{Style.RESET_ALL}")

        found = {}
        not_found = []
        errors = []
        total = len(PLATFORMS)
        done = 0

        # Use thread pool for concurrent requests
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._check_platform, username, name, cfg): name
                for name, cfg in PLATFORMS.items()
            }

            for future in as_completed(futures):
                platform_name = futures[future]
                done += 1

                try:
                    result = future.result()
                except Exception as e:
                    errors.append({"platform": platform_name, "error": str(e)})
                    not_found.append(platform_name)
                    if self.logger:
                        self.logger.debug(f"Error checking {platform_name}: {e}")
                    continue

                if self.logger:
                    self.logger.progress(done, total, f"Checking {platform_name:<20}")

                if result["found"]:
                    found[platform_name] = {
                        "url": result["url"],
                        "status_code": result.get("status_code")
                    }
                    if self.logger:
                        self.logger.found(platform_name, result["url"])
                else:
                    not_found.append(platform_name)
                    if self.logger:
                        self.logger.not_found(platform_name)

        # Summary
        if self.logger:
            self.logger.section("RESULTS SUMMARY")
            self.logger.data("Username", username)
            self.logger.data("Platforms checked", str(total))
            self.logger.data("Found on", f"{Fore.GREEN}{len(found)}{Style.RESET_ALL} platforms")
            self.logger.data("Not found on", f"{Fore.RED}{len(not_found)}{Style.RESET_ALL} platforms")

            if found:
                self.logger.section("CONFIRMED PROFILES")
                for platform, info in found.items():
                    self.logger.found(platform, info["url"])

        return {
            "username": username,
            "platforms_checked": total,
            "found_count": len(found),
            "found": found,
            "not_found": not_found,
            "errors": errors
        }

    def _check_platform(self, username: str, platform_name: str, config: dict) -> dict:
        """
        Check a single platform for the username.
        
        Returns dict with: found (bool), url (str), status_code (int)
        """
        url = config["url"].format(username=username)
        not_found_text = config.get("not_found_text", "")

        resp = safe_get(url, timeout=10, allow_redirects=True)

        if resp is None:
            return {"found": False, "url": url, "status_code": None}

        status = resp.status_code

        # Status-based check
        if status == 404:
            return {"found": False, "url": url, "status_code": status}

        if status == 200:
            # Check page content for "not found" indicators
            if not_found_text and not_found_text.lower() in resp.text.lower():
                return {"found": False, "url": url, "status_code": status}
            return {"found": True, "url": url, "status_code": status}

        # 301/302 redirects can mean the profile doesn't exist
        if status in (301, 302):
            location = resp.headers.get('Location', '')
            # If redirected to homepage or /404, it's not found
            if any(x in location.lower() for x in ['/404', 'notfound', 'error']):
                return {"found": False, "url": url, "status_code": status}

        # 403/429/503 - can't determine; mark as uncertain
        return {"found": False, "url": url, "status_code": status}
