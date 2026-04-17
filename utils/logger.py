#!/usr/bin/env python3
"""
OrbitTrace - Logger Utility
Provides styled terminal output with color-coded log levels
"""

import sys
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)


class Logger:
    """
    Styled logger for OrbitTrace terminal output.
    Provides color-coded messages for different severity levels.
    """

    # Icons for each log level
    ICONS = {
        'info':    f'{Fore.CYAN}[*]{Style.RESET_ALL}',
        'success': f'{Fore.GREEN}[+]{Style.RESET_ALL}',
        'warning': f'{Fore.YELLOW}[!]{Style.RESET_ALL}',
        'error':   f'{Fore.RED}[-]{Style.RESET_ALL}',
        'debug':   f'{Fore.MAGENTA}[D]{Style.RESET_ALL}',
        'found':   f'{Fore.GREEN}[✓]{Style.RESET_ALL}',
        'notfound':f'{Fore.RED}[✗]{Style.RESET_ALL}',
        'data':    f'{Fore.BLUE}[>]{Style.RESET_ALL}',
    }

    def __init__(self, verbose=False):
        self.verbose = verbose

    def _timestamp(self):
        return f"{Fore.CYAN}{datetime.now().strftime('%H:%M:%S')}{Style.RESET_ALL}"

    def _log(self, level, message, show_time=False):
        icon = self.ICONS.get(level, '[?]')
        time_prefix = f"[{self._timestamp()}] " if show_time else ""
        print(f"  {time_prefix}{icon} {message}")

    def info(self, message):
        self._log('info', message)

    def success(self, message):
        self._log('success', message)

    def warning(self, message):
        self._log('warning', message)

    def error(self, message):
        self._log('error', f"{Fore.RED}{message}{Style.RESET_ALL}")

    def debug(self, message):
        if self.verbose:
            self._log('debug', f"{Fore.MAGENTA}{message}{Style.RESET_ALL}")

    def found(self, platform, url=None):
        """Log a found/confirmed result (e.g., username found on platform)"""
        msg = f"{Fore.GREEN}{Style.BRIGHT}{platform}{Style.RESET_ALL}"
        if url:
            msg += f" → {Fore.CYAN}{url}{Style.RESET_ALL}"
        self._log('found', msg)

    def not_found(self, platform):
        """Log a not-found result"""
        if self.verbose:
            self._log('notfound', f"{Fore.RED}{platform}{Style.RESET_ALL}")

    def data(self, key, value):
        """Log a key-value data pair"""
        k = f"{Fore.YELLOW}{Style.BRIGHT}{key}{Style.RESET_ALL}"
        v = f"{Fore.WHITE}{value}{Style.RESET_ALL}"
        self._log('data', f"{k}: {v}")

    def section(self, title):
        """Print a subsection header"""
        print(f"\n  {Fore.CYAN}── {Fore.WHITE}{Style.BRIGHT}{title} {Fore.CYAN}{'─' * (50 - len(title))}{Style.RESET_ALL}")

    def table(self, headers, rows):
        """Print a simple ASCII table"""
        if not rows:
            return

        # Calculate column widths
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    col_widths[i] = max(col_widths[i], len(str(cell)))

        # Header
        header_row = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
        separator = "-+-".join("-" * w for w in col_widths)
        print(f"\n  {Fore.CYAN}{header_row}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}{separator}{Style.RESET_ALL}")

        # Rows
        for row in rows:
            cells = []
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    cells.append(str(cell).ljust(col_widths[i]))
            print(f"  {Fore.WHITE}{'  | '.join(cells)}{Style.RESET_ALL}")
        print()

    def progress(self, current, total, label=""):
        """Print an inline progress indicator"""
        bar_width = 30
        filled = int(bar_width * current / total) if total > 0 else 0
        bar = f"{Fore.GREEN}{'█' * filled}{Fore.WHITE}{'░' * (bar_width - filled)}{Style.RESET_ALL}"
        pct = f"{int(100 * current / total):3d}%" if total > 0 else "  0%"
        sys.stdout.write(f"\r  {Fore.CYAN}[{bar}{Fore.CYAN}] {pct} {label:<30}")
        sys.stdout.flush()
        if current >= total:
            print()  # New line when complete
