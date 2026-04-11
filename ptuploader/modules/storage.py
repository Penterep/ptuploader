"""
Storage Discovery Test – uploads a file and then performs a dictionary attack
to find if the uploaded file is publicly accessible at common storage paths.

Contains:
- Storage class for performing the storage discovery test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib, http_client, print_lock)
"""

import uuid
from datetime import datetime
from urllib.parse import urlparse

from ptlibs.ptprinthelper import out_if

__TESTLABEL__ = "Storage Discovery Test:"

STORAGE_PATHS = [
    "upload",
    "uploads",
    "files",
    "file",
    "media",
    "images",
    "img",
    "assets",
    "static",
    "content",
    "attachments",
    "documents",
    "docs",
    "data",
    "temp",
    "tmp",
    "public",
    "storage",
    "userfiles",
    "user-content",
    "fileupload",
    "uploaded",
    "uploadedfiles",
    "resources",
    "share",
    "shared",
]


def _get_date_paths() -> list:
    """Returns date-based paths for current year and month."""
    now = datetime.now()
    year = now.strftime("%Y")
    month = now.strftime("%m")
    paths = []
    for base in ("upload", "uploads", "files", "media"):
        paths.append(f"{base}/{year}")
        paths.append(f"{base}/{year}/{month}")
    return paths


class Storage:
    def __init__(self, args: object, ptjsonlib: object, http_client: object, print_lock: object) -> None:
        self.args        = args
        self.ptjsonlib   = ptjsonlib
        self.http_client = http_client
        self.print_lock  = print_lock
        self.param       = args.parameter or "file"

    def _get_base_url(self) -> str:
        """Returns base URL (scheme + host) derived from -u."""
        parsed = urlparse(self.args.url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _get_filename(self) -> str:
        """Returns a unique filename with storage module identifier."""
        base = self.args.file or "test.txt"
        stem, _, ext = base.rpartition(".")
        stem = stem or base
        ext = ext or "txt"
        unique = uuid.uuid4().hex[:8]
        return f"{stem}_storage_{unique}.{ext}"

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

    def _check_paths(self, filename: str) -> None:
        """Tries all dictionary paths and reports any accessible locations."""
        base_url = self._get_base_url()
        all_paths = STORAGE_PATHS + _get_date_paths()

        if self.args.storage:
            storage_url = self.args.storage.rstrip("/") + "/" + filename
            check = self.http_client.send_request(url=storage_url, method="GET", allow_redirects=True)
            if check is not None and check.status_code == 200:
                self.print_lock.add_string_to_output(
                    out_if(f"File found at storage URL  [{storage_url}]", "VULN", not self.args.json, indent=4)
                )
                self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-STORAGE")
                return

        found = False
        for path in all_paths:
            url = f"{base_url}/{path}/{filename}"
            check = self.http_client.send_request(url=url, method="GET", allow_redirects=True)
            if check is not None and check.status_code == 200:
                self.print_lock.add_string_to_output(
                    out_if(f"File found at  [{url}]", "VULN", not self.args.json, indent=4)
                )
                self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-STORAGE")
                found = True

        if not found:
            self.print_lock.add_string_to_output(
                out_if("File not found in any common storage path", "OK", not self.args.json, indent=4)
            )

    def run(self) -> None:
        self.print_lock.add_string_to_output(
            out_if(__TESTLABEL__, "INFO", not self.args.json)
        )

        filename = self._get_filename()
        data = dict(item.split("=", 1) for item in self.args.data.split("&")) if self.args.data else None
        files = {self.param: (filename, b"storage discovery test", "application/octet-stream")}

        response = self.http_client.send_request(
            url=self.args.url,
            method="POST",
            files=files,
            data=data,
        )

        if not self._upload_accepted(response):
            self.print_lock.add_string_to_output(
                out_if(f"Upload rejected, cannot perform storage discovery  [{filename}]", "OK", not self.args.json, indent=4)
            )
            return

        self.print_lock.add_string_to_output(
            out_if(f"File uploaded, searching storage paths  [{filename}]", "INFO", not self.args.json, indent=4)
        )
        self._check_paths(filename)


def run(args, ptjsonlib, http_client, print_lock):
    """Entry point for running the Storage Discovery Test module."""
    Storage(args, ptjsonlib, http_client, print_lock).run()
