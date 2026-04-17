#!/usr/bin/env python3
"""
OrbitTrace - Domain Lookup Module
WHOIS, DNS records, subdomain enumeration, SSL certificate analysis
"""

import ssl
import socket
import json
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utils.helpers import safe_get, clean_domain, resolve_hostname
from colorama import Fore, Style

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class DomainLookup:
    """Full domain/website investigation: WHOIS, DNS, subdomains, SSL"""

    # Common subdomains to bruteforce
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail',
        'admin', 'administrator', 'portal', 'vpn', 'remote', 'api',
        'dev', 'staging', 'test', 'uat', 'qa', 'prod', 'beta',
        'cdn', 'static', 'media', 'assets', 'img', 'images', 'video',
        'blog', 'shop', 'store', 'app', 'mobile', 'm', 'wap',
        'secure', 'login', 'auth', 'sso', 'oauth', 'accounts',
        'ns1', 'ns2', 'ns3', 'mx', 'mx1', 'mx2',
        'git', 'gitlab', 'github', 'ci', 'jenkins', 'jira', 'confluence',
        'docs', 'help', 'support', 'status', 'monitor',
        'cpanel', 'whm', 'plesk', 'webdisk', 'autoconfig',
        'autodiscover', 'exchange', 'owa',
        'internal', 'intranet', 'extranet', 'private',
    ]

    def __init__(self, logger=None, verbose=False):
        self.logger = logger
        self.verbose = verbose

    def investigate(self, domain: str) -> dict:
        domain = clean_domain(domain)
        results = {
            "domain": domain,
            "whois": {},
            "dns": {},
            "subdomains": [],
            "ssl": {},
            "http_headers": {},
            "technologies": []
        }

        if self.logger:
            self.logger.info(f"Investigating domain: {Fore.GREEN}{domain}{Style.RESET_ALL}")

        # 1. WHOIS
        if self.logger:
            self.logger.section("WHOIS Information")
        results["whois"] = self._get_whois(domain)

        # 2. DNS Records
        if self.logger:
            self.logger.section("DNS Records")
        results["dns"] = self._get_dns_records(domain)

        # 3. Subdomain Enumeration
        if self.logger:
            self.logger.section("Subdomain Enumeration")
        results["subdomains"] = self._enumerate_subdomains(domain)

        # 4. SSL Certificate
        if self.logger:
            self.logger.section("SSL Certificate")
        results["ssl"] = self._get_ssl_info(domain)

        # 5. HTTP Headers
        if self.logger:
            self.logger.section("HTTP Headers & Technology")
        results["http_headers"] = self._get_http_headers(domain)
        results["technologies"] = self._detect_technologies(results["http_headers"])

        # Summary
        if self.logger:
            self.logger.section("Summary")
            self.logger.data("Domain", domain)
            if results["whois"].get("registrar"):
                self.logger.data("Registrar", results["whois"]["registrar"])
            if results["whois"].get("creation_date"):
                self.logger.data("Created", str(results["whois"]["creation_date"]))
            if results["whois"].get("expiration_date"):
                self.logger.data("Expires", str(results["whois"]["expiration_date"]))
            if results["dns"].get("A"):
                self.logger.data("IP (A record)", ", ".join(results["dns"]["A"]))
            self.logger.data("Subdomains found", str(len(results["subdomains"])))
            if results["ssl"].get("issuer"):
                self.logger.data("SSL Issuer", results["ssl"]["issuer"])
            if results["technologies"]:
                self.logger.data("Technologies", ", ".join(results["technologies"]))

        return results

    def _get_whois(self, domain: str) -> dict:
        """Run WHOIS query for the domain"""
        if not WHOIS_AVAILABLE:
            if self.logger:
                self.logger.warning("python-whois not installed")
            return {"error": "python-whois not available"}

        try:
            w = whois.whois(domain)
            info = {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "updated_date": str(w.updated_date) if w.updated_date else None,
                "name_servers": w.name_servers,
                "status": w.status,
                "emails": w.emails,
                "dnssec": w.dnssec,
                "name": w.name,
                "org": w.org,
                "country": w.country,
                "registrant_postal_code": w.registrant_postal_code,
            }

            if self.logger:
                for k, v in info.items():
                    if v:
                        self.logger.data(k.replace('_', ' ').title(), str(v)[:100])

            return info
        except Exception as e:
            if self.logger:
                self.logger.debug(f"WHOIS error: {e}")
            return {"error": str(e)}

    def _get_dns_records(self, domain: str) -> dict:
        """Query various DNS record types"""
        if not DNS_AVAILABLE:
            if self.logger:
                self.logger.warning("dnspython not installed - using socket fallback")
            ip = resolve_hostname(domain)
            return {"A": [ip] if ip else [], "error": "dnspython not available"}

        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        records = {}

        for rtype in record_types:
            try:
                import dns.resolver
                answers = dns.resolver.resolve(domain, rtype, raise_on_no_answer=False)
                if answers:
                    records[rtype] = [str(r) for r in answers]
                    if self.logger:
                        for r in records[rtype]:
                            self.logger.found(rtype, r[:100])
            except dns.resolver.NXDOMAIN:
                if self.logger:
                    self.logger.warning(f"Domain {domain} does not exist (NXDOMAIN)")
                break
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"DNS {rtype} query failed: {e}")

        return records

    def _enumerate_subdomains(self, domain: str) -> list:
        """Enumerate subdomains using wordlist + crt.sh certificate transparency"""
        found = []

        if self.logger:
            self.logger.info(f"Checking {len(self.COMMON_SUBDOMAINS)} common subdomains...")

        # Wordlist-based enumeration
        for sub in self.COMMON_SUBDOMAINS:
            fqdn = f"{sub}.{domain}"
            ip = resolve_hostname(fqdn)
            if ip:
                found.append({"subdomain": fqdn, "ip": ip, "source": "wordlist"})
                if self.logger:
                    self.logger.found(fqdn, ip)

        # Certificate Transparency logs (crt.sh - free, no API key)
        if self.logger:
            self.logger.info("Querying crt.sh certificate transparency logs...")
        ct_subs = self._query_crtsh(domain)
        for sub in ct_subs:
            if not any(f["subdomain"] == sub for f in found):
                ip = resolve_hostname(sub)
                found.append({"subdomain": sub, "ip": ip or "unresolved", "source": "crt.sh"})
                if self.logger:
                    self.logger.found(sub, ip or "unresolved")

        if self.logger:
            self.logger.data("Total subdomains found", str(len(found)))

        return found

    def _query_crtsh(self, domain: str) -> list:
        """Query crt.sh for subdomains via certificate transparency"""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = safe_get(url, timeout=15)
        if not resp or resp.status_code != 200:
            return []

        try:
            data = resp.json()
            subdomains = set()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split('\n'):
                    sub = sub.strip().lstrip('*.')
                    if sub.endswith(f'.{domain}') or sub == domain:
                        subdomains.add(sub)
            return list(subdomains)
        except Exception:
            return []

    def _get_ssl_info(self, domain: str) -> dict:
        """Extract SSL/TLS certificate information"""
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(10)
                s.connect((domain, 443))
                cert = s.getpeercert()

            # Parse subject
            subject = dict(x[0] for x in cert.get('subject', []))
            issuer  = dict(x[0] for x in cert.get('issuer', []))

            # SANs (Subject Alternative Names)
            san = []
            for type_, value in cert.get('subjectAltName', []):
                if type_ == 'DNS':
                    san.append(value)

            info = {
                "subject": subject.get('commonName', 'Unknown'),
                "issuer":  issuer.get('organizationName', 'Unknown'),
                "issued_to": subject.get('commonName'),
                "valid_from": cert.get('notBefore'),
                "valid_until": cert.get('notAfter'),
                "san": san[:20],   # Limit to 20
                "version": cert.get('version'),
                "serial_number": cert.get('serialNumber')
            }

            if self.logger:
                self.logger.data("Subject", info["subject"])
                self.logger.data("Issuer",  info["issuer"])
                self.logger.data("Valid From",  info["valid_from"])
                self.logger.data("Valid Until", info["valid_until"])
                self.logger.data("SANs", str(len(san)))

            return info

        except ssl.SSLError as e:
            if self.logger:
                self.logger.warning(f"SSL error: {e}")
            return {"error": str(e)}
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            if self.logger:
                self.logger.warning(f"Could not connect for SSL: {e}")
            return {"error": str(e)}

    def _get_http_headers(self, domain: str) -> dict:
        """Fetch HTTP response headers from the domain"""
        for scheme in ['https', 'http']:
            url = f"{scheme}://{domain}"
            resp = safe_get(url, timeout=10)
            if resp:
                headers = dict(resp.headers)
                if self.logger:
                    interesting = ['Server', 'X-Powered-By', 'X-Framework',
                                   'CF-RAY', 'X-Varnish', 'Via', 'Strict-Transport-Security']
                    for h in interesting:
                        if h in headers:
                            self.logger.data(h, headers[h][:80])
                return headers
        return {}

    def _detect_technologies(self, headers: dict) -> list:
        """Detect web technologies from HTTP response headers"""
        techs = []
        h = {k.lower(): v.lower() for k, v in headers.items()}

        if 'x-powered-by' in h:
            techs.append(h['x-powered-by'])
        if 'server' in h:
            server = h['server']
            for tech in ['nginx', 'apache', 'iis', 'caddy', 'lighttpd', 'openresty']:
                if tech in server:
                    techs.append(tech.capitalize())

        # CDN detection
        if 'cf-ray' in h:
            techs.append('Cloudflare CDN')
        if 'x-served-by' in h and 'fastly' in h.get('x-served-by', ''):
            techs.append('Fastly CDN')
        if 'x-amz-request-id' in h or 'x-amz-id' in h:
            techs.append('Amazon AWS / S3')
        if 'x-varnish' in h:
            techs.append('Varnish Cache')

        return list(set(techs))
