"""
Max Size Test – checks if the server enforces a maximum file size limit for uploads.
Uploads files of increasing size and reports at which size the server rejects them,
returns an error, or stops responding.

If -sz is not provided, a built-in list of sizes is used (100KB .. 1GB).
If -sz is provided, those specific sizes are tested.

Contains:
- MaxSize class for performing the max size test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib, http_client, print_lock)
"""

import re

from ptlibs.ptprinthelper import out_if

__TESTLABEL__ = "Max File Size Test:"

# Default sizes to probe (bytes), smallest first
DEFAULT_SIZES = [
    100    * 1024,       # 100 KB
    512    * 1024,       # 512 KB
    1      * 1024**2,    # 1 MB
    5      * 1024**2,    # 5 MB
    10     * 1024**2,    # 10 MB
    25     * 1024**2,    # 25 MB
    50     * 1024**2,    # 50 MB
    100    * 1024**2,    # 100 MB
    250    * 1024**2,    # 250 MB
    500    * 1024**2,    # 500 MB
    1      * 1024**3,    # 1 GB
]


def _format_size(size_bytes: int) -> str:
    """Human-readable file size."""
    if size_bytes >= 1024**3:
        return f"{size_bytes / 1024**3:.1f} GB"
    if size_bytes >= 1024**2:
        return f"{size_bytes / 1024**2:.1f} MB"
    if size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes} B"


def _parse_size(value: str) -> int:
    """
    Parses a human-readable size string into bytes.
    Accepts: '10MB', '10 MB', '10M', '500KB', '1GB', '1024', '1024B'.
    """
    value = value.strip().upper()
    m = re.match(r'^(\d+(?:\.\d+)?)\s*(GB|MB|KB|G|M|K|B)?$', value)
    if not m:
        raise ValueError(f"Cannot parse size: '{value}'")
    num = float(m.group(1))
    unit = m.group(2) or "B"
    multipliers = {
        "B": 1,
        "K": 1024, "KB": 1024,
        "M": 1024**2, "MB": 1024**2,
        "G": 1024**3, "GB": 1024**3,
    }
    return int(num * multipliers[unit])


class MaxSize:
    def __init__(self, args: object, ptjsonlib: object, http_client: object, print_lock: object) -> None:
        self.args        = args
        self.ptjsonlib   = ptjsonlib
        self.http_client = http_client
        self.print_lock  = print_lock
        self.param       = args.parameter or "file"

    def _get_sizes(self) -> list:
        """Returns sorted list of sizes (bytes) to test."""
        if self.args.size:
            parsed = []
            for s in self.args.size.split(","):
                parsed.append(_parse_size(s.strip()))
            return sorted(parsed)
        return list(DEFAULT_SIZES)

    def _get_filename(self) -> str:
        """Returns filename for the test upload."""
        base = self.args.file or "test.txt"
        stem, _, ext = base.rpartition(".")
        stem = stem or base
        ext = ext or "txt"
        return f"{stem}_maxsize.{ext}"

    def _upload_accepted(self, response) -> bool:
        """Returns True if upload response matches -sy/-sn criteria."""
        if response is None:
            return False
        text = response.text
        if self.args.string_yes and self.args.string_yes not in text:
            return False
        if self.args.string_no and self.args.string_no in text:
            return False
        return True

    def _test_size(self, filename: str, size_bytes: int) -> dict:
        """
        Uploads a file of the given size and returns a result dict:
        {accepted: bool, status: int|None, error: str|None, size: int}
        """
        content = b"\x00" * size_bytes
        content_type = getattr(self.args, "content_type", None) or "application/octet-stream"
        files = {self.param: (filename, content, content_type)}
        data = dict(item.split("=", 1) for item in self.args.data.split("&")) if self.args.data else None

        try:
            response = self.http_client.send_request(
                url=self.args.url,
                method="POST",
                files=files,
                data=data,
            )
        except Exception as e:
            return {"accepted": False, "status": None, "error": str(e), "size": size_bytes}

        if response is None:
            return {"accepted": False, "status": None, "error": "No response (timeout/connection error)", "size": size_bytes}

        status = response.status_code
        accepted = self._upload_accepted(response)

        error = None
        if status >= 500:
            error = f"Server error {status}"
        elif not accepted and status >= 400:
            error = f"Client error {status}"

        return {"accepted": accepted, "status": status, "error": error, "size": size_bytes}

    def run(self) -> None:
        self.print_lock.add_string_to_output(
            out_if(__TESTLABEL__, "INFO", not self.args.json)
        )

        sizes = self._get_sizes()
        filename = self._get_filename()
        max_accepted_size = 0
        first_rejected_size = None

        self.print_lock.add_string_to_output(
            out_if(f"Testing {len(sizes)} file sizes up to {_format_size(sizes[-1])}  [{filename}]", "INFO", not self.args.json, indent=4)
        )

        for size_bytes in sizes:
            result = self._test_size(filename, size_bytes)
            size_str = _format_size(size_bytes)

            if result["accepted"]:
                max_accepted_size = size_bytes
                self.print_lock.add_string_to_output(
                    out_if(f"Accepted  [{size_str}]", "OK", not self.args.json, indent=4)
                )
            elif result["error"]:
                if first_rejected_size is None:
                    first_rejected_size = size_bytes
                self.print_lock.add_string_to_output(
                    out_if(f"Error  [{size_str}]  {result['error']}", "WARNING", not self.args.json, indent=4)
                )
                break
            else:
                if first_rejected_size is None:
                    first_rejected_size = size_bytes
                self.print_lock.add_string_to_output(
                    out_if(f"Rejected  [{size_str}]", "OK", not self.args.json, indent=4)
                )

        # Summary
        if max_accepted_size > 0 and first_rejected_size:
            self.print_lock.add_string_to_output(
                out_if(
                    f"Max accepted size: {_format_size(max_accepted_size)} (rejected at {_format_size(first_rejected_size)})",
                    "INFO", not self.args.json, indent=4
                )
            )
        elif max_accepted_size > 0 and not first_rejected_size:
            self.print_lock.add_string_to_output(
                out_if(
                    f"No size limit detected - server accepted all sizes up to {_format_size(max_accepted_size)}",
                    "VULN", not self.args.json, indent=4
                )
            )
            self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-MAXSIZE")
        else:
            self.print_lock.add_string_to_output(
                out_if("Server rejected all tested sizes", "OK", not self.args.json, indent=4)
            )


def run(args, ptjsonlib, http_client, print_lock):
    """Entry point for running the Max File Size Test module."""
    MaxSize(args, ptjsonlib, http_client, print_lock).run()
