#!/usr/bin/env python3
"""
OrbitTrace - Image Search Module
Extracts EXIF/metadata from images and provides reverse image search guidance
"""

import os
import sys
import hashlib
import struct
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utils.helpers import safe_get, format_bytes, md5_hash, sha256_hash
from colorama import Fore, Style

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import exifread
    EXIFREAD_AVAILABLE = True
except ImportError:
    EXIFREAD_AVAILABLE = False


class ImageSearch:
    """Extract EXIF data and provide reverse image search links"""

    def __init__(self, logger=None, verbose=False):
        self.logger = logger
        self.verbose = verbose

    def investigate(self, image_path: str) -> dict:
        results = {
            "file": image_path,
            "exists": False,
            "file_info": {},
            "exif_data": {},
            "gps": {},
            "hashes": {},
            "reverse_search_links": {},
            "suspicious_findings": []
        }

        if self.logger:
            self.logger.info(f"Analyzing image: {Fore.GREEN}{image_path}{Style.RESET_ALL}")

        # Check file exists
        if not os.path.exists(image_path):
            if self.logger:
                self.logger.error(f"File not found: {image_path}")
            results["error"] = f"File not found: {image_path}"
            return results

        results["exists"] = True

        # 1. File info
        if self.logger:
            self.logger.section("File Information")
        results["file_info"] = self._get_file_info(image_path)

        # 2. Compute hashes
        if self.logger:
            self.logger.section("File Hashes")
        results["hashes"] = self._compute_hashes(image_path)

        # 3. EXIF data extraction
        if self.logger:
            self.logger.section("EXIF Data")
        if PIL_AVAILABLE or EXIFREAD_AVAILABLE:
            results["exif_data"] = self._extract_exif(image_path)
        else:
            if self.logger:
                self.logger.warning("Neither Pillow nor exifread is installed")
            results["exif_data"] = {"error": "Install Pillow or exifread"}

        # 4. GPS data
        if self.logger:
            self.logger.section("GPS Location")
        results["gps"] = self._extract_gps(results["exif_data"])
        if results["gps"].get("latitude"):
            if self.logger:
                self.logger.found("GPS coordinates found!")
                self.logger.data("Latitude",  str(results["gps"]["latitude"]))
                self.logger.data("Longitude", str(results["gps"]["longitude"]))
                self.logger.data("Google Maps",
                                 f"https://maps.google.com/?q={results['gps']['latitude']},"
                                 f"{results['gps']['longitude']}")
        else:
            if self.logger:
                self.logger.not_found("No GPS data in EXIF")

        # 5. Reverse image search links
        if self.logger:
            self.logger.section("Reverse Image Search")
        results["reverse_search_links"] = self._get_reverse_search_links(image_path)
        if self.logger:
            for engine, url in results["reverse_search_links"].items():
                self.logger.data(engine, url)

        # 6. Suspicious findings analysis
        results["suspicious_findings"] = self._analyze_suspicious(results)
        if results["suspicious_findings"]:
            if self.logger:
                self.logger.section("Suspicious Findings")
            for finding in results["suspicious_findings"]:
                if self.logger:
                    self.logger.warning(finding)

        # Summary
        if self.logger:
            self.logger.section("Summary")
            self.logger.data("File", os.path.basename(image_path))
            self.logger.data("Size", results["file_info"].get("size_human", "unknown"))
            self.logger.data("Format", results["file_info"].get("format", "unknown"))
            self.logger.data("Dimensions", results["file_info"].get("dimensions", "unknown"))
            self.logger.data("MD5", results["hashes"].get("md5", "unknown"))
            gps_str = "YES ⚠️" if results["gps"].get("latitude") else "No"
            self.logger.data("GPS Data", gps_str)

        return results

    def _get_file_info(self, path: str) -> dict:
        """Get basic file system info about the image"""
        stat = os.stat(path)
        info = {
            "filename":   os.path.basename(path),
            "path":       os.path.abspath(path),
            "size_bytes": stat.st_size,
            "size_human": format_bytes(stat.st_size),
            "extension":  os.path.splitext(path)[1].lower(),
            "format":     "Unknown",
            "dimensions": "Unknown",
            "mode":       "Unknown",
        }

        if PIL_AVAILABLE:
            try:
                with Image.open(path) as img:
                    info["format"]     = img.format or "Unknown"
                    info["mode"]       = img.mode
                    info["dimensions"] = f"{img.width}x{img.height}"
                    info["width"]      = img.width
                    info["height"]     = img.height
            except Exception as e:
                info["pil_error"] = str(e)

        if self.logger:
            for k, v in info.items():
                if k not in ('path', 'size_bytes') and v not in ('Unknown', None):
                    self.logger.data(k.replace('_', ' ').title(), str(v))

        return info

    def _compute_hashes(self, path: str) -> dict:
        """Compute MD5 and SHA256 hashes of the file"""
        hashes = {}
        try:
            with open(path, 'rb') as f:
                data = f.read()
            hashes["md5"]    = hashlib.md5(data).hexdigest()
            hashes["sha1"]   = hashlib.sha1(data).hexdigest()
            hashes["sha256"] = hashlib.sha256(data).hexdigest()

            if self.logger:
                self.logger.data("MD5",    hashes["md5"])
                self.logger.data("SHA1",   hashes["sha1"])
                self.logger.data("SHA256", hashes["sha256"])
        except Exception as e:
            hashes["error"] = str(e)

        return hashes

    def _extract_exif(self, path: str) -> dict:
        """Extract EXIF metadata using Pillow (preferred) or exifread"""
        exif_data = {}

        # Try Pillow first
        if PIL_AVAILABLE:
            try:
                with Image.open(path) as img:
                    raw_exif = img._getexif()
                    if raw_exif:
                        for tag_id, value in raw_exif.items():
                            tag = TAGS.get(tag_id, tag_id)
                            # Convert bytes to string for JSON serialization
                            if isinstance(value, bytes):
                                try:
                                    value = value.decode('utf-8', errors='replace')
                                except Exception:
                                    value = str(value)
                            exif_data[str(tag)] = value
                        if self.logger:
                            interesting_tags = [
                                'Make', 'Model', 'Software', 'DateTime',
                                'DateTimeOriginal', 'DateTimeDigitized',
                                'Artist', 'Copyright', 'ImageDescription',
                                'XResolution', 'YResolution', 'Flash',
                                'FocalLength', 'ExposureTime', 'ISOSpeedRatings'
                            ]
                            for tag in interesting_tags:
                                if tag in exif_data:
                                    self.logger.data(tag, str(exif_data[tag])[:80])
                    else:
                        if self.logger:
                            self.logger.not_found("No EXIF data found in image")
                return exif_data
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"Pillow EXIF error: {e}")

        # Fallback to exifread
        if EXIFREAD_AVAILABLE:
            try:
                with open(path, 'rb') as f:
                    tags = exifread.process_file(f, details=False)
                for tag, value in tags.items():
                    exif_data[tag] = str(value)
                    if self.logger:
                        self.logger.data(tag[:40], str(value)[:60])
                return exif_data
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"exifread error: {e}")

        return exif_data

    def _extract_gps(self, exif_data: dict) -> dict:
        """Extract and decode GPS coordinates from EXIF data"""
        gps = {}

        # Pillow format: GPSInfo is tag 34853
        gps_info = exif_data.get("GPSInfo") or exif_data.get("GPS GPSLatitude")

        if not gps_info:
            return gps

        # Pillow returns GPSInfo as a dict keyed by integer GPS tag IDs
        if isinstance(gps_info, dict):
            gps_tags = {}
            for key, val in gps_info.items():
                name = GPSTAGS.get(key, key) if PIL_AVAILABLE else key
                gps_tags[name] = val

            try:
                lat = self._convert_gps_coord(
                    gps_tags.get("GPSLatitude"),
                    gps_tags.get("GPSLatitudeRef", "N")
                )
                lon = self._convert_gps_coord(
                    gps_tags.get("GPSLongitude"),
                    gps_tags.get("GPSLongitudeRef", "E")
                )
                if lat and lon:
                    gps["latitude"]   = lat
                    gps["longitude"]  = lon
                    gps["maps_url"]   = f"https://maps.google.com/?q={lat},{lon}"
                    gps["altitude"]   = gps_tags.get("GPSAltitude")
                    gps["timestamp"]  = gps_tags.get("GPSTimeStamp")
            except Exception:
                pass

        return gps

    def _convert_gps_coord(self, coord, ref: str) -> float:
        """Convert GPS DMS (degrees, minutes, seconds) to decimal degrees"""
        if not coord:
            return None
        try:
            if hasattr(coord[0], 'numerator'):
                # IFDRational objects from Pillow
                d = float(coord[0])
                m = float(coord[1])
                s = float(coord[2])
            else:
                d, m, s = float(coord[0]), float(coord[1]), float(coord[2])

            decimal = d + (m / 60.0) + (s / 3600.0)
            if ref in ('S', 'W'):
                decimal = -decimal
            return round(decimal, 7)
        except Exception:
            return None

    def _get_reverse_search_links(self, path: str) -> dict:
        """
        Generate reverse image search URLs.
        Note: Most require uploading; we provide the search engine URLs.
        """
        return {
            "Google Lens":   "https://lens.google.com/ (upload manually)",
            "TinEye":        "https://tineye.com/ (upload manually)",
            "Yandex Images": "https://yandex.com/images/ (upload manually)",
            "Bing Visual":   "https://www.bing.com/visualsearch (upload manually)",
            "PimEyes":       "https://pimeyes.com/ (face search - upload manually)"
        }

    def _analyze_suspicious(self, results: dict) -> list:
        """Analyze results for potentially suspicious/interesting findings"""
        findings = []
        exif = results.get("exif_data", {})

        # GPS data is privacy-sensitive
        if results.get("gps", {}).get("latitude"):
            findings.append("⚠️  GPS coordinates found - image reveals physical location")

        # Check for device info
        if exif.get("Make") or exif.get("Model"):
            device = f"{exif.get('Make','')} {exif.get('Model','')}".strip()
            findings.append(f"📱 Device identified: {device}")

        # Check for software/editor info
        if exif.get("Software"):
            findings.append(f"🖥️  Software identified: {exif['Software']}")

        # Check for creation date
        if exif.get("DateTimeOriginal") or exif.get("DateTime"):
            dt = exif.get("DateTimeOriginal") or exif.get("DateTime")
            findings.append(f"📅 Creation timestamp: {dt}")

        # Artist/copyright
        if exif.get("Artist"):
            findings.append(f"👤 Artist/Author in EXIF: {exif['Artist']}")
        if exif.get("Copyright"):
            findings.append(f"©️  Copyright info: {exif['Copyright']}")

        return findings
