#!/usr/bin/env python3
"""
OrbitTrace - Target Detector
Automatically identifies the type of investigation target from input string
"""

import re
import os


class TargetDetector:
    """
    Detects the type of OSINT target from a given string.
    Uses regex patterns and heuristics to classify:
    - IP addresses (IPv4 / IPv6)
    - Email addresses
    - Phone numbers (international format)
    - Domain names
    - Image files
    - File paths (for metadata scan)
    - Usernames (fallback)
    """

    # File extensions that trigger metadata scan
    METADATA_EXTENSIONS = {
        '.pdf', '.doc', '.docx', '.xls', '.xlsx',
        '.ppt', '.pptx', '.odt', '.ods', '.odp',
        '.mp3', '.mp4', '.jpg', '.jpeg', '.png',
        '.tiff', '.tif', '.gif', '.bmp', '.webp',
        '.wav', '.avi', '.mov', '.mkv'
    }

    # Image extensions that trigger image search / EXIF
    IMAGE_EXTENSIONS = {
        '.jpg', '.jpeg', '.png', '.gif', '.bmp',
        '.tiff', '.tif', '.webp', '.heic', '.raw'
    }

    def __init__(self):
        # Compiled regex patterns for performance
        self._ip_v4 = re.compile(
            r'^(\d{1,3}\.){3}\d{1,3}$'
        )
        self._ip_v6 = re.compile(
            r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
            r'|^(([0-9a-fA-F]{1,4}:){1,7}:)'
            r'|^:(:[0-9a-fA-F]{1,4}){1,7}$'
        )
        self._email = re.compile(
            r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
        )
        self._phone = re.compile(
            r'^\+?[\d\s\-().]{7,20}$'
        )
        self._phone_intl = re.compile(
            r'^\+\d{1,3}[\s\-]?\d+'
        )
        self._domain = re.compile(
            r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
            r'+[a-zA-Z]{2,}$'
        )

    def detect(self, target: str) -> str:
        """
        Main detection method.
        
        Args:
            target: Raw input string from CLI
        
        Returns:
            str: One of: 'ip', 'email', 'phone', 'domain', 'image', 'file', 'username'
        """
        target = target.strip()

        # 1. Check if it's an existing file path
        if os.path.exists(target):
            return self._detect_file_type(target)

        # 2. Check for IPv4
        if self._ip_v4.match(target):
            if self._is_valid_ipv4(target):
                return 'ip'

        # 3. Check for IPv6
        if self._ip_v6.match(target):
            return 'ip'

        # 4. Check for email
        if self._email.match(target):
            return 'email'

        # 5. Check for phone number (must start with + or be numeric-heavy)
        cleaned = re.sub(r'[\s\-().]', '', target)
        if self._phone_intl.match(target) or (cleaned.isdigit() and 7 <= len(cleaned) <= 15):
            return 'phone'

        # 6. Check for domain (contains dot but not email)
        if '.' in target and not '@' in target:
            # Remove protocol if present
            clean_target = re.sub(r'^https?://', '', target)
            clean_target = clean_target.split('/')[0]  # Remove path
            if self._domain.match(clean_target):
                return 'domain'

        # 7. Default to username
        return 'username'

    def _detect_file_type(self, filepath: str) -> str:
        """Determine if file should be treated as image or generic file for metadata"""
        ext = os.path.splitext(filepath)[1].lower()
        if ext in self.IMAGE_EXTENSIONS:
            return 'image'
        if ext in self.METADATA_EXTENSIONS:
            return 'file'
        # Unknown extension - try metadata scan
        return 'file'

    def _is_valid_ipv4(self, ip: str) -> bool:
        """Validate that each octet is in 0-255 range"""
        try:
            parts = ip.split('.')
            return all(0 <= int(p) <= 255 for p in parts)
        except (ValueError, AttributeError):
            return False

    def describe(self, target_type: str) -> str:
        """Return a human-readable description of the target type"""
        descriptions = {
            'username': 'Social media / platform username',
            'email':    'Email address',
            'phone':    'Phone number',
            'domain':   'Domain name / website',
            'ip':       'IP address',
            'image':    'Image file (EXIF + reverse search)',
            'file':     'File (metadata extraction)',
        }
        return descriptions.get(target_type, 'Unknown target type')


if __name__ == "__main__":
    # Quick test
    detector = TargetDetector()
    tests = [
        "johndoe",
        "test@gmail.com",
        "+1-555-867-5309",
        "192.168.1.1",
        "8.8.8.8",
        "example.com",
        "https://google.com",
        "photo.jpg",
        "document.pdf",
        "5551234567"
    ]
    for t in tests:
        result = detector.detect(t)
        print(f"  {t:<30} → {result}")
