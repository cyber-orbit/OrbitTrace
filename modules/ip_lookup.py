#!/usr/bin/env python3
"""
OrbitTrace - IP Lookup Module
Geolocation, reverse DNS, WHOIS, ASN, and threat intelligence
"""

import socket
import json
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utils.helpers import safe_get, reverse_dns, is_private_ip
from colorama import Fore, Style


class IPLookup:
    """Full IP address investigation"""

    def __init__(self, logger=None, verbose=False):
        self.logger = logger
        self.verbose = verbose

    def investigate(self, ip: str) -> dict:
        results = {
            "ip": ip,
            "private": False,
            "geolocation": {},
            "reverse_dns": None,
            "asn": {},
            "whois": {},
            "open_ports": [],
            "threat_intel": {},
            "blacklists": {}
        }

        if self.logger:
            self.logger.info(f"Investigating IP: {Fore.GREEN}{ip}{Style.RESET_ALL}")

        # Check if private
        if is_private_ip(ip):
            if self.logger:
                self.logger.warning(f"{ip} is a PRIVATE / reserved IP address")
            results["private"] = True
            results["note"] = "Private IP - limited OSINT data available"

        # 1. Geolocation (ip-api.com - free, no key)
        if self.logger:
            self.logger.section("Geolocation")
        results["geolocation"] = self._get_geolocation(ip)

        # 2. Reverse DNS
        if self.logger:
            self.logger.section("Reverse DNS")
        results["reverse_dns"] = reverse_dns(ip)
        if results["reverse_dns"]:
            if self.logger:
                self.logger.found("PTR Record", results["reverse_dns"])
        else:
            if self.logger:
                self.logger.not_found("No PTR record")

        # 3. ASN / BGP info
        if self.logger:
            self.logger.section("ASN / BGP Info")
        results["asn"] = self._get_asn_info(ip)

        # 4. Shodan-style free check (ipinfo.io)
        if self.logger:
            self.logger.section("IPInfo")
        results["ipinfo"] = self._get_ipinfo(ip)

        # 5. Threat Intelligence (AbuseIPDB free check)
        if self.logger:
            self.logger.section("Threat Intelligence")
        results["threat_intel"] = self._get_threat_intel(ip)

        # 6. DNSBL / Blacklist check
        if self.logger:
            self.logger.section("Blacklist Check")
        results["blacklists"] = self._check_blacklists(ip)

        # Summary
        if self.logger:
            self.logger.section("Summary")
            self.logger.data("IP Address", ip)
            self.logger.data("Private", str(results["private"]))
            geo = results["geolocation"]
            if geo.get("country"):
                self.logger.data("Country", f"{geo.get('country')} ({geo.get('countryCode','')})")
            if geo.get("city"):
                self.logger.data("City", geo["city"])
            if geo.get("isp"):
                self.logger.data("ISP", geo["isp"])
            if geo.get("org"):
                self.logger.data("Organization", geo["org"])
            if results["reverse_dns"]:
                self.logger.data("Hostname", results["reverse_dns"])
            if results["asn"].get("asn"):
                self.logger.data("ASN", f"{results['asn']['asn']} - {results['asn'].get('name','')}")
            bl = results["blacklists"]
            listed = [name for name, listed in bl.items() if listed]
            if listed:
                self.logger.warning(f"Listed on {len(listed)} blacklist(s): {', '.join(listed)}")
            else:
                self.logger.success("Not found on checked blacklists")

        return results

    def _get_geolocation(self, ip: str) -> dict:
        """
        Get geolocation data from ip-api.com (free, no API key required).
        Rate limit: 45 requests/minute for HTTP endpoint.
        """
        url = f"http://ip-api.com/json/{ip}?fields=66846719"
        resp = safe_get(url, timeout=10, verify=False)

        if not resp or resp.status_code != 200:
            if self.logger:
                self.logger.warning("Geolocation lookup failed")
            return {}

        try:
            data = resp.json()
            if data.get("status") == "fail":
                if self.logger:
                    self.logger.warning(f"ip-api: {data.get('message', 'lookup failed')}")
                return {}

            info = {
                "country":       data.get("country"),
                "countryCode":   data.get("countryCode"),
                "region":        data.get("regionName"),
                "city":          data.get("city"),
                "zip":           data.get("zip"),
                "lat":           data.get("lat"),
                "lon":           data.get("lon"),
                "timezone":      data.get("timezone"),
                "isp":           data.get("isp"),
                "org":           data.get("org"),
                "as":            data.get("as"),
                "hosting":       data.get("hosting"),
                "proxy":         data.get("proxy"),
                "mobile":        data.get("mobile"),
            }

            if self.logger:
                for k, v in info.items():
                    if v not in (None, False, ''):
                        self.logger.data(k.replace('_',' ').title(), str(v))

            return info
        except Exception as e:
            if self.logger:
                self.logger.debug(f"Geolocation parse error: {e}")
            return {}

    def _get_asn_info(self, ip: str) -> dict:
        """Get ASN info from bgpview.io (free API)"""
        url = f"https://api.bgpview.io/ip/{ip}"
        resp = safe_get(url, timeout=10)

        if not resp or resp.status_code != 200:
            return {}

        try:
            data = resp.json()
            prefixes = data.get("data", {}).get("prefixes", [])
            asns = data.get("data", {}).get("rir_allocation", {})

            result = {}
            if prefixes:
                first = prefixes[0]
                asn_info = first.get("asn", {})
                result = {
                    "asn":         f"AS{asn_info.get('asn', '')}",
                    "name":        asn_info.get("name", ""),
                    "description": asn_info.get("description", ""),
                    "prefix":      first.get("prefix", ""),
                    "country":     first.get("country_code", ""),
                }
                if self.logger:
                    for k, v in result.items():
                        if v:
                            self.logger.data(k.title(), str(v))
            return result
        except Exception as e:
            if self.logger:
                self.logger.debug(f"ASN lookup error: {e}")
            return {}

    def _get_ipinfo(self, ip: str) -> dict:
        """Get data from ipinfo.io (free tier, no key needed for basic info)"""
        url = f"https://ipinfo.io/{ip}/json"
        resp = safe_get(url, timeout=10)
        if not resp or resp.status_code != 200:
            return {}
        try:
            data = resp.json()
            result = {
                "hostname": data.get("hostname"),
                "org":      data.get("org"),
                "abuse":    data.get("abuse", {}).get("email") if data.get("abuse") else None,
            }
            if self.logger:
                for k, v in result.items():
                    if v:
                        self.logger.data(k.title(), str(v))
            return data
        except Exception:
            return {}

    def _get_threat_intel(self, ip: str) -> dict:
        """
        Check AbuseIPDB for threat intelligence.
        Note: Full data needs API key - we check the public report page.
        """
        result = {
            "note": "Full threat intel requires AbuseIPDB API key (free at abuseipdb.com)",
            "url": f"https://www.abuseipdb.com/check/{ip}"
        }

        if self.logger:
            self.logger.info(f"Manual check: {result['url']}")

        # Check GreyNoise community API (free, no key)
        url = f"https://api.greynoise.io/v3/community/{ip}"
        resp = safe_get(url, timeout=8)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                result["greynoise"] = {
                    "noise":     data.get("noise"),
                    "riot":      data.get("riot"),
                    "name":      data.get("name"),
                    "message":   data.get("message"),
                    "link":      data.get("link")
                }
                if self.logger:
                    self.logger.data("GreyNoise Noise", str(data.get("noise")))
                    self.logger.data("GreyNoise RIOT",  str(data.get("riot")))
                    if data.get("name"):
                        self.logger.data("GreyNoise Name", data["name"])
            except Exception:
                pass

        return result

    def _check_blacklists(self, ip: str) -> dict:
        """
        Check common DNS-based blacklists (DNSBL).
        Reverses the IP and appends each DNSBL zone for lookup.
        """
        dnsbls = {
            "Spamhaus ZEN":      "zen.spamhaus.org",
            "SORBS SPAM":        "spam.sorbs.net",
            "Barracuda":         "b.barracudacentral.org",
            "SpamCop":           "bl.spamcop.net",
            "UCEPROTECT L1":     "dnsbl-1.uceprotect.net",
        }

        # Reverse the IP for DNSBL lookup
        reversed_ip = '.'.join(reversed(ip.split('.')))
        results = {}

        for name, zone in dnsbls.items():
            query = f"{reversed_ip}.{zone}"
            try:
                socket.gethostbyname(query)
                results[name] = True  # Listed!
                if self.logger:
                    self.logger.warning(f"LISTED on {name}")
            except socket.gaierror:
                results[name] = False  # Not listed
                if self.logger:
                    self.logger.not_found(f"Not listed: {name}")

        return results
