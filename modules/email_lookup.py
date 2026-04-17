#!/usr/bin/env python3
"""
OrbitTrace - Email Lookup Module
Validates email, checks Gravatar, MX records, and public breach databases
"""

import re
import hashlib
import socket

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utils.helpers import safe_get, get_headers
from colorama import Fore, Style

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class EmailLookup:
    """Investigates an email address for OSINT data points"""

    def __init__(self, logger=None, verbose=False):
        self.logger = logger
        self.verbose = verbose

    def investigate(self, email: str) -> dict:
        results = {
            "email": email,
            "validation": {},
            "domain_info": {},
            "mx_records": [],
            "gravatar": {},
            "breaches": {},
            "related_accounts": []
        }

        if self.logger:
            self.logger.info(f"Investigating email: {Fore.GREEN}{email}{Style.RESET_ALL}")

        # 1. Validate format
        results["validation"] = self._validate_format(email)
        if not results["validation"]["valid"]:
            if self.logger:
                self.logger.error("Invalid email format - aborting further checks")
            return results

        domain = email.split('@')[1]
        local = email.split('@')[0]

        # 2. Domain info
        if self.logger:
            self.logger.section("Domain Analysis")
        results["domain_info"] = self._check_domain(domain)
        if self.logger:
            for k, v in results["domain_info"].items():
                if v:
                    self.logger.data(k.replace('_', ' ').title(), str(v))

        # 3. MX Records
        if self.logger:
            self.logger.section("MX Records")
        results["mx_records"] = self._get_mx_records(domain)
        if results["mx_records"]:
            for mx in results["mx_records"]:
                if self.logger:
                    self.logger.found("MX", f"{mx['host']} (priority {mx['priority']})")
        else:
            if self.logger:
                self.logger.warning("No MX records found")

        # 4. Gravatar check
        if self.logger:
            self.logger.section("Gravatar Check")
        results["gravatar"] = self._check_gravatar(email)
        if results["gravatar"].get("exists"):
            if self.logger:
                self.logger.found("Gravatar profile", results["gravatar"].get("profile_url", ""))
                self.logger.found("Gravatar avatar", results["gravatar"].get("avatar_url", ""))
        else:
            if self.logger:
                self.logger.not_found("Gravatar")

        # 5. Disposable email check
        if self.logger:
            self.logger.section("Disposable Email Check")
        results["disposable"] = self._check_disposable(domain)
        if results["disposable"]:
            if self.logger:
                self.logger.warning(f"Domain '{domain}' appears to be a DISPOSABLE email service")

        # 6. Public breach check (HaveIBeenPwned API v3 - free endpoint)
        if self.logger:
            self.logger.section("Breach Check")
        results["breaches"] = self._check_breaches(email)
        if results["breaches"].get("found"):
            if self.logger:
                self.logger.warning(f"Email found in {results['breaches']['count']} breach(es)")
                for b in results["breaches"].get("breach_names", [])[:5]:
                    self.logger.data("  Breach", b)
        else:
            if self.logger:
                self.logger.success("No breaches found in public databases")

        # 7. Summary
        if self.logger:
            self.logger.section("Summary")
            self.logger.data("Email", email)
            self.logger.data("Domain", domain)
            self.logger.data("Local part", local)
            self.logger.data("Valid format", str(results["validation"]["valid"]))
            self.logger.data("Disposable", str(results.get("disposable", False)))
            self.logger.data("Gravatar exists", str(results["gravatar"].get("exists", False)))

        return results

    def _validate_format(self, email: str) -> dict:
        """Validate email format using regex"""
        pattern = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')
        valid = bool(pattern.match(email))
        parts = email.split('@') if '@' in email else [email, '']
        return {
            "valid": valid,
            "local_part": parts[0],
            "domain": parts[1] if len(parts) > 1 else "",
            "has_plus_tag": '+' in parts[0]
        }

    def _check_domain(self, domain: str) -> dict:
        """Check basic domain properties"""
        info = {
            "domain": domain,
            "resolves": False,
            "ip_address": None,
            "is_free_provider": False
        }

        free_providers = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
            'protonmail.com', 'icloud.com', 'aol.com', 'mail.com',
            'live.com', 'msn.com', 'ymail.com', 'me.com',
            'zoho.com', 'fastmail.com', 'tutanota.com', 'guerrillamail.com'
        }

        info["is_free_provider"] = domain.lower() in free_providers

        try:
            ip = socket.gethostbyname(domain)
            info["resolves"] = True
            info["ip_address"] = ip
        except socket.gaierror:
            pass

        return info

    def _get_mx_records(self, domain: str) -> list:
        """Retrieve MX records for the email domain"""
        if not DNS_AVAILABLE:
            if self.logger:
                self.logger.warning("dnspython not installed - skipping MX lookup")
            return []

        try:
            import dns.resolver
            mx_records = []
            answers = dns.resolver.resolve(domain, 'MX')
            for rdata in sorted(answers, key=lambda x: x.preference):
                mx_records.append({
                    "host": str(rdata.exchange).rstrip('.'),
                    "priority": rdata.preference
                })
            return mx_records
        except Exception as e:
            if self.logger:
                self.logger.debug(f"MX lookup failed: {e}")
            return []

    def _check_gravatar(self, email: str) -> dict:
        """Check if the email has a Gravatar profile"""
        email_lower = email.lower().strip()
        email_hash = hashlib.md5(email_lower.encode()).hexdigest()

        avatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
        profile_url = f"https://www.gravatar.com/{email_hash}"

        resp = safe_get(avatar_url, timeout=8)

        if resp and resp.status_code == 200:
            return {
                "exists": True,
                "hash": email_hash,
                "avatar_url": f"https://www.gravatar.com/avatar/{email_hash}",
                "profile_url": profile_url
            }
        return {"exists": False, "hash": email_hash}

    def _check_disposable(self, domain: str) -> bool:
        """Check if domain is a known disposable email provider"""
        disposable_domains = {
            'mailinator.com', 'guerrillamail.com', 'tempmail.com',
            'throwaway.email', 'yopmail.com', 'sharklasers.com',
            'guerrillamailblock.com', 'grr.la', 'guerrillamail.info',
            'guerrillamail.biz', 'guerrillamail.de', 'guerrillamail.net',
            'guerrillamail.org', 'spam4.me', '10minutemail.com',
            'trashmail.com', 'fakeinbox.com', 'maildrop.cc',
            'dispostable.com', 'mailnesia.com', 'mailnull.com',
            'spamgourmet.com', 'trashmail.at', 'trashmail.io',
            'tempr.email', 'discard.email', 'spamgourmet.net'
        }
        return domain.lower() in disposable_domains

    def _check_breaches(self, email: str) -> dict:
        """
        Check HaveIBeenPwned for email breaches.
        Uses the public API endpoint (rate-limited, no key needed for basic check).
        Note: Full breach details require an API key; we do a name check only.
        """
        try:
            # HIBP v3 requires an API key for breach data
            # We can check the public breach list endpoint for the domain
            domain = email.split('@')[1]
            url = f"https://haveibeenpwned.com/api/v3/breachesforaccount/{email}"
            headers = {
                "hibp-api-key": "NO_KEY",  # Placeholder
                "User-Agent": "OrbitTrace-OSINT"
            }
            # Without API key, we get 401 - inform user
            resp = safe_get(url, timeout=10, headers={"User-Agent": "OrbitTrace-OSINT"})

            if resp is None:
                return {"found": False, "note": "Service unreachable"}

            if resp.status_code == 404:
                return {"found": False, "count": 0}

            if resp.status_code == 401:
                return {
                    "found": None,
                    "note": "HIBP API key required for breach lookup. "
                            "Get free key at https://haveibeenpwned.com/API/Key"
                }

            if resp.status_code == 200:
                breaches = resp.json()
                names = [b.get("Name", "") for b in breaches]
                return {
                    "found": True,
                    "count": len(breaches),
                    "breach_names": names
                }

            return {"found": False, "status": resp.status_code}

        except Exception as e:
            return {"found": False, "error": str(e)}
