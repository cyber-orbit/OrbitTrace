#!/usr/bin/env python3
"""
OrbitTrace - Phone Lookup Module
Validates phone numbers, detects carrier, location, and VoIP status
"""

import re
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utils.helpers import safe_get
from colorama import Fore, Style

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone
    PHONENUMBERS_AVAILABLE = True
except ImportError:
    PHONENUMBERS_AVAILABLE = False


class PhoneLookup:
    """Investigates a phone number for carrier, location, and VoIP info"""

    def __init__(self, logger=None, verbose=False):
        self.logger = logger
        self.verbose = verbose

    def investigate(self, phone: str) -> dict:
        results = {
            "input": phone,
            "valid": False,
            "formatted": {},
            "location": {},
            "carrier": {},
            "timezone": [],
            "type": {},
            "additional_checks": {}
        }

        if self.logger:
            self.logger.info(f"Investigating phone: {Fore.GREEN}{phone}{Style.RESET_ALL}")

        if not PHONENUMBERS_AVAILABLE:
            if self.logger:
                self.logger.warning("phonenumbers library not installed. "
                                    "Install with: pip install phonenumbers")
            results["error"] = "phonenumbers library not available"
            # Try basic formatting anyway
            results["formatted"]["cleaned"] = re.sub(r'[^\d+]', '', phone)
            return results

        # Parse the phone number
        parsed = self._parse_number(phone)
        if not parsed:
            if self.logger:
                self.logger.error(f"Could not parse phone number: {phone}")
                self.logger.info("Tip: Include country code (e.g., +1 for US)")
            results["error"] = "Could not parse phone number"
            return results

        results["valid"] = phonenumbers.is_valid_number(parsed)
        results["possible"] = phonenumbers.is_possible_number(parsed)

        if not results["valid"]:
            if self.logger:
                self.logger.warning("Phone number is not valid")

        # Formatted versions
        if self.logger:
            self.logger.section("Number Formats")
        results["formatted"] = {
            "e164":          phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            "international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "national":      phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            "rfc3966":       phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.RFC3966),
            "country_code":  parsed.country_code,
            "national_number": str(parsed.national_number)
        }
        if self.logger:
            for k, v in results["formatted"].items():
                self.logger.data(k.replace('_', ' ').title(), str(v))

        # Geographic location
        if self.logger:
            self.logger.section("Location")
        geo = geocoder.description_for_number(parsed, "en")
        results["location"] = {
            "description": geo if geo else "Unknown",
            "country_code": phonenumbers.region_code_for_number(parsed),
        }
        if self.logger:
            self.logger.data("Location", results["location"]["description"] or "Unknown")
            self.logger.data("Country Code", results["location"]["country_code"] or "Unknown")

        # Carrier information
        if self.logger:
            self.logger.section("Carrier")
        carrier_name = carrier.name_for_number(parsed, "en")
        results["carrier"] = {
            "name": carrier_name if carrier_name else "Unknown",
        }
        if self.logger:
            self.logger.data("Carrier", results["carrier"]["name"])

        # Timezone
        if self.logger:
            self.logger.section("Timezone")
        tz_list = list(timezone.time_zones_for_number(parsed))
        results["timezone"] = tz_list
        if self.logger:
            for tz in tz_list:
                self.logger.data("Timezone", tz)

        # Number type (mobile, fixed, VoIP, etc.)
        if self.logger:
            self.logger.section("Number Type")
        num_type = phonenumbers.number_type(parsed)
        type_map = {
            phonenumbers.PhoneNumberType.MOBILE:          ("MOBILE",     False),
            phonenumbers.PhoneNumberType.FIXED_LINE:      ("FIXED LINE", False),
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: ("FIXED/MOBILE", False),
            phonenumbers.PhoneNumberType.TOLL_FREE:       ("TOLL FREE",  False),
            phonenumbers.PhoneNumberType.PREMIUM_RATE:    ("PREMIUM",    False),
            phonenumbers.PhoneNumberType.SHARED_COST:     ("SHARED COST",False),
            phonenumbers.PhoneNumberType.VOIP:            ("VOIP",       True),
            phonenumbers.PhoneNumberType.PERSONAL_NUMBER: ("PERSONAL",   False),
            phonenumbers.PhoneNumberType.PAGER:           ("PAGER",      False),
            phonenumbers.PhoneNumberType.UAN:             ("UAN",        False),
            phonenumbers.PhoneNumberType.UNKNOWN:         ("UNKNOWN",    False),
        }
        type_name, is_voip = type_map.get(num_type, ("UNKNOWN", False))
        results["type"] = {
            "name": type_name,
            "is_voip": is_voip,
            "is_mobile": type_name in ("MOBILE", "FIXED/MOBILE")
        }
        if self.logger:
            self.logger.data("Type", type_name)
            if is_voip:
                self.logger.warning("Number appears to be VOIP / virtual number")
            self.logger.data("Is Mobile", str(results["type"]["is_mobile"]))
            self.logger.data("Is VoIP", str(is_voip))

        # Additional public lookups
        if self.logger:
            self.logger.section("Public Lookup")
        results["additional_checks"] = self._public_lookup(
            results["formatted"]["e164"],
            results["formatted"]["national"]
        )

        # Summary
        if self.logger:
            self.logger.section("Summary")
            self.logger.data("Input", phone)
            self.logger.data("Valid", str(results["valid"]))
            self.logger.data("E164", results["formatted"].get("e164", "N/A"))
            self.logger.data("Country", results["location"].get("country_code", "Unknown"))
            self.logger.data("Carrier", results["carrier"].get("name", "Unknown"))
            self.logger.data("Type", results["type"].get("name", "Unknown"))

        return results

    def _parse_number(self, phone: str):
        """Attempt to parse number with and without country code"""
        # Clean up input
        cleaned = phone.strip()

        # If no leading +, try to add it for international parsing
        if not cleaned.startswith('+'):
            cleaned_digits = re.sub(r'[^\d]', '', cleaned)
            # Try common default: US (+1) if 10 digits
            if len(cleaned_digits) == 10:
                cleaned = '+1' + cleaned_digits
            elif len(cleaned_digits) == 11 and cleaned_digits.startswith('1'):
                cleaned = '+' + cleaned_digits
            else:
                cleaned = '+' + cleaned_digits

        try:
            return phonenumbers.parse(cleaned, None)
        except phonenumbers.phonenumberutil.NumberParseException:
            try:
                # Last attempt: parse as US number
                return phonenumbers.parse(phone, "US")
            except Exception:
                return None

    def _public_lookup(self, e164: str, national: str) -> dict:
        """
        Check public phone lookup directories for spam/reported status.
        Uses free endpoints that don't require API keys.
        """
        results = {}

        # Check NumVerify (free tier - limited)
        # Note: Full validation needs API key, but we can try basic check
        numverify_url = f"https://api.numlookupapi.com/v1/validate/{e164}"
        resp = safe_get(numverify_url, timeout=8)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                results["numlookupapi"] = {
                    "valid": data.get("valid"),
                    "country": data.get("country_name"),
                    "location": data.get("location"),
                    "carrier": data.get("carrier"),
                    "line_type": data.get("line_type")
                }
            except Exception:
                pass

        return results
