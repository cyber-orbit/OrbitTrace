#!/usr/bin/env python3
"""
OrbitTrace - CLI Interface
Handles command-line argument parsing and dispatching
"""

import argparse
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def build_parser():
    """Build and return the argument parser"""

    parser = argparse.ArgumentParser(
        prog="orbittrace",
        description="OrbitTrace - OSINT Investigation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  orbittrace username johndoe
  orbittrace email target@example.com
  orbittrace phone +15558675309
  orbittrace domain example.com
  orbittrace ip 8.8.8.8
  orbittrace image photo.jpg
  orbittrace file document.pdf
  orbittrace auto 8.8.8.8          # auto-detect type

TARGET TYPES:
  username    Check 20+ social platforms for username
  email       Email validation, MX records, Gravatar, breach check
  phone       Carrier, location, VoIP detection
  domain      WHOIS, DNS, subdomains, SSL certificate
  ip          Geolocation, reverse DNS, WHOIS, threat intel
  image       EXIF data extraction, reverse image search hints
  file        Metadata extraction from PDFs, Office docs, images
  auto        Auto-detect target type (default)
        """
    )

    # Subcommands (one per investigation type)
    subparsers = parser.add_subparsers(dest="command", help="Investigation type")

    # Common arguments shared across subcommands
    def add_common_args(sub):
        sub.add_argument("target", help="Target to investigate")
        sub.add_argument("-v", "--verbose", action="store_true",
                         help="Enable verbose/debug output")
        sub.add_argument("-o", "--output", default="output",
                         help="Output directory for reports (default: output)")
        sub.add_argument("--no-banner", action="store_true",
                         help="Suppress ASCII banner")

    # username subcommand
    p_user = subparsers.add_parser("username", aliases=["user", "u"],
                                    help="Scan social platforms for username")
    add_common_args(p_user)

    # email subcommand
    p_email = subparsers.add_parser("email", aliases=["e"],
                                     help="Email address investigation")
    add_common_args(p_email)

    # phone subcommand
    p_phone = subparsers.add_parser("phone", aliases=["ph"],
                                     help="Phone number lookup")
    add_common_args(p_phone)

    # domain subcommand
    p_domain = subparsers.add_parser("domain", aliases=["d"],
                                      help="Domain/website investigation")
    add_common_args(p_domain)

    # ip subcommand
    p_ip = subparsers.add_parser("ip", help="IP address investigation")
    add_common_args(p_ip)

    # image subcommand
    p_img = subparsers.add_parser("image", aliases=["img"],
                                   help="Image EXIF + reverse search")
    add_common_args(p_img)

    # file subcommand
    p_file = subparsers.add_parser("file", aliases=["f"],
                                    help="File metadata extraction")
    add_common_args(p_file)

    # auto subcommand (detect type)
    p_auto = subparsers.add_parser("auto", aliases=["a"],
                                    help="Auto-detect target type")
    add_common_args(p_auto)

    return parser


# Map aliases/subcommands to canonical type names
COMMAND_TYPE_MAP = {
    "username": "username", "user": "username", "u": "username",
    "email": "email", "e": "email",
    "phone": "phone", "ph": "phone",
    "domain": "domain", "d": "domain",
    "ip": "ip",
    "image": "image", "img": "image",
    "file": "file", "f": "file",
    "auto": None, "a": None,  # None = auto-detect
}


def main():
    """Main CLI entry point"""
    from orbittrace import OrbitTrace

    parser = build_parser()
    args = parser.parse_args()

    # No command given - show help
    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Map command to target type
    target_type = COMMAND_TYPE_MAP.get(args.command)

    # Create engine and run
    engine = OrbitTrace(
        verbose=args.verbose,
        output_dir=args.output
    )

    # Optionally suppress banner
    if hasattr(args, 'no_banner') and args.no_banner:
        pass
    
    engine.investigate(args.target, target_type=target_type)


if __name__ == "__main__":
    main()
