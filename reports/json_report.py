#!/usr/bin/env python3
"""
OrbitTrace - JSON Report Generator
Saves investigation results to timestamped JSON files
"""

import os
import json
import re
from datetime import datetime


class JSONReport:
    """Handles saving and formatting of investigation reports to JSON"""

    def __init__(self, output_dir: str = "output"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def save(self, report: dict, target: str, target_type: str) -> str:
        """
        Save investigation report to a JSON file.
        
        Args:
            report:      Full report dict (meta + results)
            target:      The investigation target string
            target_type: Type of target (username, email, etc.)
        
        Returns:
            str: Path to the saved report file
        """
        # Build a safe filename from target + timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = self._sanitize_filename(target)
        filename = f"{target_type}_{safe_target}_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)

        # Serialise with pretty-print and handle non-serialisable types
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=self._json_serializer,
                      ensure_ascii=False)

        return filepath

    def _sanitize_filename(self, name: str) -> str:
        """
        Remove characters unsafe for filenames.
        Keeps letters, numbers, hyphens, dots, underscores.
        """
        name = re.sub(r'[^\w\-.]', '_', name)
        return name[:64]  # Limit length

    @staticmethod
    def _json_serializer(obj):
        """Handle non-JSON-serialisable Python objects"""
        if hasattr(obj, 'isoformat'):
            # datetime objects
            return obj.isoformat()
        if isinstance(obj, bytes):
            return obj.decode('utf-8', errors='replace')
        if isinstance(obj, set):
            return list(obj)
        # Fallback: convert to string
        return str(obj)
