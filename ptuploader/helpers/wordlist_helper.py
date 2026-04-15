"""
Wordlist helper – loads the built-in upload path wordlist, expands it with
date-based path suffixes, and optionally merges an additional user-supplied
wordlist file.
"""

import os
from datetime import datetime

_WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "ptwordlist.txt")


def _load_file(path: str) -> list:
    """Reads a wordlist file and returns non-empty, stripped lines."""
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def _generate_date_suffixes() -> list:
    """
    Generates date-based path suffixes from the current date.
    e.g. for 2026-04-15:
      26, 2026, 4, 04, 15,
      26/4, 26/04, 2026/4, 2026/04,
      26/4/15, 26/04/15, 2026/4/15, 2026/04/15,
      264, 2604, 26415, 260415, 20264, 202604, 2026415, 20260415
    """
    now = datetime.now()
    yy   = now.strftime("%y")    # 26
    yyyy = now.strftime("%Y")    # 2026
    m    = str(now.month)        # 4
    mm   = now.strftime("%m")    # 04
    dd   = now.strftime("%d")    # 15

    suffixes = [
        yy, yyyy,
        m, mm,
        dd,
        f"{yy}/{m}", f"{yy}/{mm}",
        f"{yyyy}/{m}", f"{yyyy}/{mm}",
        f"{yy}/{m}/{dd}", f"{yy}/{mm}/{dd}",
        f"{yyyy}/{m}/{dd}", f"{yyyy}/{mm}/{dd}",
        f"{yy}{m}", f"{yy}{mm}",
        f"{yyyy}{m}", f"{yyyy}{mm}",
        f"{yy}{m}{dd}", f"{yy}{mm}{dd}",
        f"{yyyy}{m}{dd}", f"{yyyy}{mm}{dd}",
    ]
    return suffixes


def get_wordlist(extra_wordlist_path: str = None) -> list:
    """
    Returns a deduplicated list of upload paths to probe.

    Starts with the built-in wordlist, expands every base path with
    date suffixes, appends standalone date paths, and optionally merges
    paths from an extra wordlist file.

    Args:
        extra_wordlist_path: Optional path to a user-supplied wordlist file.

    Returns:
        Ordered, deduplicated list of path strings (no leading slash).
    """
    base_paths = _load_file(_WORDLIST_PATH)

    if extra_wordlist_path:
        extra_paths = _load_file(extra_wordlist_path)
        base_paths = list(dict.fromkeys(base_paths + extra_paths))

    date_suffixes = _generate_date_suffixes()

    combined = list(base_paths)

    for base in base_paths:
        for suffix in date_suffixes:
            combined.append(f"{base}/{suffix}")

    for suffix in date_suffixes:
        combined.append(suffix)

    return list(dict.fromkeys(combined))
