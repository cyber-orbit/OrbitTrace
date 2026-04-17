#!/usr/bin/env python3
"""
OrbitTrace - OSINT Investigation Framework
Main engine that orchestrates all modules
"""

import sys
import os
import time
import json
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from colorama import init, Fore, Back, Style
init(autoreset=True)

from detector import TargetDetector
from utils.logger import Logger
from reports.json_report import JSONReport

# ASCII Banner
BANNER = f"""
{Fore.CYAN}
  ██████╗ ██████╗ ██████╗ ██╗████████╗████████╗██████╗  █████╗  ██████╗███████╗
 ██╔═══██╗██╔══██╗██╔══██╗██║╚══██╔══╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
 ██║   ██║██████╔╝██████╔╝██║   ██║      ██║   ██████╔╝███████║██║     █████╗  
 ██║   ██║██╔══██╗██╔══██╗██║   ██║      ██║   ██╔══██╗██╔══██║██║     ██╔══╝  
 ╚██████╔╝██║  ██║██████╔╝██║   ██║      ██║   ██║  ██║██║  ██║╚██████╗███████╗
  ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝
{Fore.GREEN}                          [ OSINT Investigation Framework ]
{Fore.YELLOW}                               v1.0.0 | Open Source
{Style.RESET_ALL}"""


class OrbitTrace:
    """Main OrbitTrace engine - routes targets to appropriate modules"""

    def __init__(self, verbose=False, output_dir="output"):
        self.verbose = verbose
        self.output_dir = output_dir
        self.logger = Logger(verbose=verbose)
        self.detector = TargetDetector()
        self.reporter = JSONReport(output_dir=output_dir)
        self.results = {}

        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

    def print_banner(self):
        """Display the OrbitTrace ASCII banner"""
        print(BANNER)
        print(f"{Fore.CYAN}{'─' * 80}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}  Session started: {Fore.YELLOW}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─' * 80}{Style.RESET_ALL}\n")

    def print_section(self, title):
        """Print a styled section header"""
        print(f"\n{Fore.CYAN}┌{'─' * (len(title) + 4)}┐")
        print(f"│  {Fore.WHITE}{Style.BRIGHT}{title}{Fore.CYAN}  │")
        print(f"└{'─' * (len(title) + 4)}┘{Style.RESET_ALL}")

    def investigate(self, target, target_type=None):
        """
        Main investigation method - detects target type and runs appropriate module
        
        Args:
            target: The target string (username, email, IP, etc.)
            target_type: Optional override for target type detection
        
        Returns:
            dict: Investigation results
        """
        self.print_banner()

        # Detect target type if not specified
        if not target_type:
            target_type = self.detector.detect(target)
            self.logger.info(f"Auto-detected target type: {Fore.YELLOW}{target_type.upper()}{Style.RESET_ALL}")
        else:
            self.logger.info(f"Target type: {Fore.YELLOW}{target_type.upper()}{Style.RESET_ALL}")

        self.logger.info(f"Target: {Fore.GREEN}{target}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─' * 80}{Style.RESET_ALL}\n")

        start_time = time.time()

        # Route to appropriate module
        try:
            results = self._run_module(target, target_type)
        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user")
            results = {"error": "Scan interrupted", "partial_results": self.results}
        except Exception as e:
            self.logger.error(f"Fatal error during investigation: {e}")
            results = {"error": str(e)}

        # Calculate elapsed time
        elapsed = time.time() - start_time

        # Build final report
        report = {
            "meta": {
                "target": target,
                "target_type": target_type,
                "timestamp": datetime.now().isoformat(),
                "elapsed_seconds": round(elapsed, 2),
                "tool": "OrbitTrace v1.0.0"
            },
            "results": results
        }

        # Save report
        report_path = self.reporter.save(report, target, target_type)

        print(f"\n{Fore.CYAN}{'─' * 80}{Style.RESET_ALL}")
        self.logger.success(f"Scan completed in {Fore.YELLOW}{elapsed:.2f}s{Style.RESET_ALL}")
        self.logger.success(f"Report saved to: {Fore.GREEN}{report_path}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─' * 80}{Style.RESET_ALL}\n")

        return report

    def _run_module(self, target, target_type):
        """Route to the correct investigation module based on target type"""

        module_map = {
            "username": self._run_username_scan,
            "email":    self._run_email_lookup,
            "phone":    self._run_phone_lookup,
            "domain":   self._run_domain_lookup,
            "ip":       self._run_ip_lookup,
            "image":    self._run_image_search,
            "file":     self._run_metadata_scan,
        }

        if target_type not in module_map:
            self.logger.error(f"Unknown target type: {target_type}")
            self.logger.info(f"Supported types: {', '.join(module_map.keys())}")
            return {"error": f"Unknown target type: {target_type}"}

        return module_map[target_type](target)

    def _run_username_scan(self, username):
        self.print_section(f"USERNAME SCAN: {username}")
        from modules.username_scan import UsernameScan
        scanner = UsernameScan(logger=self.logger, verbose=self.verbose)
        return scanner.investigate(username)

    def _run_email_lookup(self, email):
        self.print_section(f"EMAIL LOOKUP: {email}")
        from modules.email_lookup import EmailLookup
        scanner = EmailLookup(logger=self.logger, verbose=self.verbose)
        return scanner.investigate(email)

    def _run_phone_lookup(self, phone):
        self.print_section(f"PHONE LOOKUP: {phone}")
        from modules.phone_lookup import PhoneLookup
        scanner = PhoneLookup(logger=self.logger, verbose=self.verbose)
        return scanner.investigate(phone)

    def _run_domain_lookup(self, domain):
        self.print_section(f"DOMAIN LOOKUP: {domain}")
        from modules.domain_lookup import DomainLookup
        scanner = DomainLookup(logger=self.logger, verbose=self.verbose)
        return scanner.investigate(domain)

    def _run_ip_lookup(self, ip):
        self.print_section(f"IP LOOKUP: {ip}")
        from modules.ip_lookup import IPLookup
        scanner = IPLookup(logger=self.logger, verbose=self.verbose)
        return scanner.investigate(ip)

    def _run_image_search(self, image_path):
        self.print_section(f"IMAGE SEARCH: {image_path}")
        from modules.image_search import ImageSearch
        scanner = ImageSearch(logger=self.logger, verbose=self.verbose)
        return scanner.investigate(image_path)

    def _run_metadata_scan(self, file_path):
        self.print_section(f"METADATA SCAN: {file_path}")
        from modules.metadata_scan import MetadataScan
        scanner = MetadataScan(logger=self.logger, verbose=self.verbose)
        return scanner.investigate(file_path)


if __name__ == "__main__":
    # If run directly, use CLI
    from cli import main
    main()
