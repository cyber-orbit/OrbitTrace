#!/usr/bin/env python3
"""
OrbitTrace - Metadata Scanner
Extracts metadata from PDFs, Office documents, images, audio/video files
"""

import os
import sys
import hashlib
import struct
import xml.etree.ElementTree as ET
from zipfile import ZipFile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utils.helpers import format_bytes
from colorama import Fore, Style

try:
    import PyPDF2
    PYPDF2_AVAILABLE = True
except ImportError:
    try:
        import pypdf as PyPDF2
        PYPDF2_AVAILABLE = True
    except ImportError:
        PYPDF2_AVAILABLE = False

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import exifread
    EXIFREAD_AVAILABLE = True
except ImportError:
    EXIFREAD_AVAILABLE = False


class MetadataScan:
    """Extract metadata from various file types"""

    def __init__(self, logger=None, verbose=False):
        self.logger = logger
        self.verbose = verbose

    def investigate(self, file_path: str) -> dict:
        results = {
            "file": file_path,
            "exists": False,
            "file_info": {},
            "hashes": {},
            "metadata": {},
            "suspicious_findings": []
        }

        if self.logger:
            self.logger.info(f"Scanning file: {Fore.GREEN}{file_path}{Style.RESET_ALL}")

        if not os.path.exists(file_path):
            if self.logger:
                self.logger.error(f"File not found: {file_path}")
            results["error"] = f"File not found: {file_path}"
            return results

        results["exists"] = True

        # 1. File info
        if self.logger:
            self.logger.section("File Information")
        results["file_info"] = self._get_file_info(file_path)

        # 2. File hashes
        if self.logger:
            self.logger.section("File Hashes")
        results["hashes"] = self._compute_hashes(file_path)

        # 3. Type-specific metadata extraction
        ext = os.path.splitext(file_path)[1].lower()
        if self.logger:
            self.logger.section("Metadata Extraction")

        if ext == '.pdf':
            results["metadata"] = self._extract_pdf_metadata(file_path)
        elif ext in ('.docx', '.xlsx', '.pptx', '.odt', '.ods', '.odp'):
            results["metadata"] = self._extract_office_metadata(file_path)
        elif ext in ('.doc', '.xls', '.ppt'):
            results["metadata"] = self._extract_ole_metadata(file_path)
        elif ext in ('.jpg', '.jpeg', '.png', '.tiff', '.tif', '.gif', '.bmp', '.webp'):
            results["metadata"] = self._extract_image_metadata(file_path)
        elif ext in ('.mp3', '.flac', '.ogg', '.wav', '.m4a'):
            results["metadata"] = self._extract_audio_metadata(file_path)
        else:
            # Generic: try to read magic bytes and any embedded strings
            results["metadata"] = self._generic_scan(file_path)

        # 4. Find suspicious data
        results["suspicious_findings"] = self._find_suspicious(results)
        if results["suspicious_findings"]:
            if self.logger:
                self.logger.section("Suspicious Findings")
            for f in results["suspicious_findings"]:
                if self.logger:
                    self.logger.warning(f)

        # Summary
        if self.logger:
            self.logger.section("Summary")
            self.logger.data("File", os.path.basename(file_path))
            self.logger.data("Size", results["file_info"].get("size_human", "?"))
            self.logger.data("Type", results["file_info"].get("extension", "?"))
            self.logger.data("MD5", results["hashes"].get("md5", "?"))
            self.logger.data("Metadata fields", str(len(results.get("metadata", {}))))

        return results

    def _get_file_info(self, path: str) -> dict:
        stat = os.stat(path)
        info = {
            "filename":   os.path.basename(path),
            "path":       os.path.abspath(path),
            "size_bytes": stat.st_size,
            "size_human": format_bytes(stat.st_size),
            "extension":  os.path.splitext(path)[1].lower(),
        }
        if self.logger:
            self.logger.data("Filename", info["filename"])
            self.logger.data("Size",     info["size_human"])
            self.logger.data("Type",     info["extension"])
        return info

    def _compute_hashes(self, path: str) -> dict:
        hashes = {}
        try:
            with open(path, 'rb') as f:
                data = f.read()
            hashes["md5"]    = hashlib.md5(data).hexdigest()
            hashes["sha1"]   = hashlib.sha1(data).hexdigest()
            hashes["sha256"] = hashlib.sha256(data).hexdigest()
            if self.logger:
                self.logger.data("MD5",    hashes["md5"])
                self.logger.data("SHA256", hashes["sha256"])
        except Exception as e:
            hashes["error"] = str(e)
        return hashes

    def _extract_pdf_metadata(self, path: str) -> dict:
        """Extract metadata from PDF using PyPDF2/pypdf"""
        if not PYPDF2_AVAILABLE:
            if self.logger:
                self.logger.warning("PyPDF2/pypdf not installed. Install: pip install pypdf")
            return {"error": "PyPDF2/pypdf not available"}

        try:
            with open(path, 'rb') as f:
                reader = PyPDF2.PdfReader(f)
                info_dict = reader.metadata or {}
                meta = {}
                for k, v in info_dict.items():
                    clean_key = k.lstrip('/')
                    meta[clean_key] = str(v)

                meta["page_count"] = len(reader.pages)
                meta["encrypted"]  = reader.is_encrypted

            if self.logger:
                for k, v in meta.items():
                    if v not in (None, '', 'None'):
                        self.logger.data(k, str(v)[:80])

            return meta
        except Exception as e:
            if self.logger:
                self.logger.debug(f"PDF metadata error: {e}")
            return {"error": str(e)}

    def _extract_office_metadata(self, path: str) -> dict:
        """
        Extract metadata from modern Office files (.docx, .xlsx, .pptx).
        These are ZIP files containing XML - no extra library needed.
        """
        meta = {}
        try:
            with ZipFile(path, 'r') as z:
                # Core properties
                if 'docProps/core.xml' in z.namelist():
                    with z.open('docProps/core.xml') as f:
                        tree = ET.parse(f)
                        root = tree.getroot()
                        ns = {
                            'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties',
                            'dc': 'http://purl.org/dc/elements/1.1/',
                            'dcterms': 'http://purl.org/dc/terms/',
                        }
                        fields = {
                            'title':          './/dc:title',
                            'subject':        './/dc:subject',
                            'creator':        './/dc:creator',
                            'keywords':       './/cp:keywords',
                            'description':    './/dc:description',
                            'lastModifiedBy': './/cp:lastModifiedBy',
                            'revision':       './/cp:revision',
                            'created':        './/dcterms:created',
                            'modified':       './/dcterms:modified',
                        }
                        for field, xpath in fields.items():
                            el = root.find(xpath, ns)
                            if el is not None and el.text:
                                meta[field] = el.text

                # App properties (application name, version, company)
                if 'docProps/app.xml' in z.namelist():
                    with z.open('docProps/app.xml') as f:
                        tree = ET.parse(f)
                        root = tree.getroot()
                        ns = {'ep': 'http://schemas.openxmlformats.org/officeDocument/2006/extended-properties'}
                        for tag in ['Application', 'AppVersion', 'Company', 'Template']:
                            el = root.find(f'.//ep:{tag}', ns)
                            if el is not None and el.text:
                                meta[tag] = el.text

            if self.logger:
                for k, v in meta.items():
                    self.logger.data(k, str(v)[:80])

        except Exception as e:
            meta["error"] = str(e)
            if self.logger:
                self.logger.debug(f"Office metadata error: {e}")

        return meta

    def _extract_ole_metadata(self, path: str) -> dict:
        """Attempt basic metadata extraction from legacy Office files (.doc/.xls/.ppt)"""
        meta = {"note": "Legacy OLE format. Install olefile for full extraction."}
        try:
            import olefile
            ole = olefile.OleFileIO(path)
            meta_stream = ole.get_metadata()
            meta = {
                "author":       meta_stream.author,
                "last_saved_by":meta_stream.last_saved_by,
                "title":        meta_stream.title,
                "subject":      meta_stream.subject,
                "keywords":     meta_stream.keywords,
                "comments":     meta_stream.comments,
                "company":      meta_stream.company,
                "create_time":  str(meta_stream.create_time),
                "last_saved":   str(meta_stream.last_saved_time),
            }
            ole.close()
            if self.logger:
                for k, v in meta.items():
                    if v:
                        self.logger.data(k, str(v)[:80])
        except ImportError:
            pass
        except Exception as e:
            meta["error"] = str(e)
        return meta

    def _extract_image_metadata(self, path: str) -> dict:
        """Extract EXIF and basic metadata from image files"""
        meta = {}
        if PIL_AVAILABLE:
            try:
                with Image.open(path) as img:
                    meta["format"]     = img.format
                    meta["mode"]       = img.mode
                    meta["dimensions"] = f"{img.width}x{img.height}"
                    raw = img._getexif()
                    if raw:
                        for tag_id, value in raw.items():
                            tag = TAGS.get(tag_id, str(tag_id))
                            if isinstance(value, bytes):
                                value = value.decode('utf-8', errors='replace')
                            meta[tag] = value
            except Exception as e:
                meta["error"] = str(e)
        elif EXIFREAD_AVAILABLE:
            with open(path, 'rb') as f:
                tags = exifread.process_file(f)
            for k, v in tags.items():
                meta[k] = str(v)

        if self.logger:
            important = ['Make','Model','Software','DateTimeOriginal','DateTime','Artist','Copyright']
            for k in important:
                if k in meta:
                    self.logger.data(k, str(meta[k])[:80])
        return meta

    def _extract_audio_metadata(self, path: str) -> dict:
        """Extract ID3/audio metadata using mutagen if available"""
        meta = {}
        try:
            import mutagen
            from mutagen import File as MutagenFile
            audio = MutagenFile(path, easy=True)
            if audio:
                for k, v in audio.tags.items():
                    meta[k] = str(v[0]) if isinstance(v, list) else str(v)
                meta["duration_seconds"] = audio.info.length if hasattr(audio, 'info') else None
                if self.logger:
                    for k, v in meta.items():
                        if v:
                            self.logger.data(k, str(v)[:80])
        except ImportError:
            meta["note"] = "Install mutagen for audio metadata: pip install mutagen"
        except Exception as e:
            meta["error"] = str(e)
        return meta

    def _generic_scan(self, path: str) -> dict:
        """Generic scan: magic bytes, file type guess, embedded strings"""
        meta = {}
        try:
            with open(path, 'rb') as f:
                header = f.read(16)

            # Magic byte detection
            magic_map = {
                b'\x25\x50\x44\x46': 'PDF',
                b'\x50\x4B\x03\x04': 'ZIP/Office',
                b'\xFF\xD8\xFF':     'JPEG',
                b'\x89\x50\x4E\x47': 'PNG',
                b'\x47\x49\x46\x38': 'GIF',
                b'\x49\x49\x2A\x00': 'TIFF (little-endian)',
                b'\x4D\x4D\x00\x2A': 'TIFF (big-endian)',
                b'\x1F\x8B':         'GZIP',
                b'\x37\x7A\xBC\xAF': '7-ZIP',
                b'\x52\x61\x72\x21': 'RAR',
            }
            for magic, ftype in magic_map.items():
                if header.startswith(magic):
                    meta["detected_type"] = ftype
                    break

            if self.logger and meta.get("detected_type"):
                self.logger.data("Detected Type", meta["detected_type"])

        except Exception as e:
            meta["error"] = str(e)
        return meta

    def _find_suspicious(self, results: dict) -> list:
        """Identify potentially sensitive metadata"""
        findings = []
        meta = results.get("metadata", {})

        # Author / creator info
        for key in ['creator', 'author', 'Creator', 'Author', 'Artist', 'lastModifiedBy']:
            if meta.get(key):
                findings.append(f"👤 Author/Creator identified: {meta[key]}")

        # Software
        for key in ['Software', 'Application', 'Producer', 'Creator']:
            if meta.get(key) and key != 'creator':
                findings.append(f"🖥️  Software: {meta[key]}")

        # Company
        if meta.get("Company"):
            findings.append(f"🏢 Company: {meta['Company']}")

        # Internal template paths (can reveal internal structure)
        if meta.get("Template"):
            findings.append(f"📄 Template path: {meta['Template']}")

        # Revision history
        if meta.get("revision") and int(meta.get("revision", 0)) > 1:
            findings.append(f"📝 Document revised {meta['revision']} times - may have edit history")

        return findings
