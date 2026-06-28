"""
Find Storage Test – uploads a file and performs a dictionary attack to discover
publicly accessible upload directories and verify the file is reachable.

Includes:
- False-positive detection (servers that return HTTP 200 for every path)
- File content verification (checks response body, not just status code)
- Built-in wordlist extended with date-based paths + optional custom wordlist

Contains:
- FindStorage class for performing the storage discovery test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib, http_client, print_lock)
"""

import os
import sys
import uuid
from urllib.parse import urlparse

from ptlibs.ptprinthelper import out_if

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from helpers.wordlist_helper import get_wordlist

__TESTLABEL__ = "Find Storage Test:"

_FILE_CONTENT_MARKER = "ptuploader-marker-{uid}"


class FindStorage:
    def __init__(self, args: object, ptjsonlib: object, http_client: object, print_lock: object) -> None:
        self.args        = args
        self.ptjsonlib   = ptjsonlib
        self.http_client = http_client
        self.print_lock  = print_lock
        self.param       = args.parameter or "file"

    def _get_base_url(self) -> str:
        """Returns scheme + host from -u."""
        parsed = urlparse(self.args.url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _get_filename(self) -> tuple:
        """Returns (filename, file_content_bytes) with a unique embedded marker."""
        base = self.args.file or "test.txt"
        stem, _, ext = base.rpartition(".")
        stem = stem or base
        ext  = ext or "txt"
        uid  = uuid.uuid4().hex[:8]
        filename = f"{stem}_findstorage_{uid}.{ext}"
        marker   = _FILE_CONTENT_MARKER.format(uid=uid)
        return filename, marker.encode()

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

    def _get_false_positive_baseline(self, base_url: str) -> tuple:
        """
        Fetches a random non-existent path to establish a baseline for false-positive detection.
        Returns (status_code, content_length).
        """
        random_path = f"{base_url}/{uuid.uuid4().hex}/nonexistent_{uuid.uuid4().hex}.txt"
        response = self.http_client.send_request(url=random_path, method="GET", allow_redirects=True)
        if response is None:
            return (404, -1)
        return (response.status_code, len(response.content))

    def _is_false_positive(self, response, baseline: tuple) -> bool:
        """Returns True if the response looks like a false positive based on the baseline."""
        if response is None:
            return False
        fp_status, fp_length = baseline
        if response.status_code != fp_status:
            return False
        if fp_length >= 0 and abs(len(response.content) - fp_length) < 50:
            return True
        return False

    def _find_directories(self, base_url: str, paths: list, baseline: tuple) -> list:
        """
        Probes each path and returns those that exist (not false positives).
        Returns list of accessible directory URLs.
        """
        found = []
        for path in paths:
            url = f"{base_url}/{path}"
            response = self.http_client.send_request(url=url, method="GET", allow_redirects=True)
            if response is None:
                continue
            if response.status_code in (200, 403) and not self._is_false_positive(response, baseline):
                found.append((url, response.status_code))
        return found

    def _find_file(self, directories: list, filename: str, marker: bytes, base_url: str, baseline: tuple) -> list:
        """
        Looks for the uploaded file in discovered directories and at -s storage URL.
        Verifies file content contains the embedded marker.
        Returns list of accessible file URLs.
        """
        found = []
        candidates = [f"{dir_url}/{filename}" for dir_url, _ in directories]

        if self.args.storage:
            candidates.insert(0, self.args.storage.rstrip("/") + "/" + filename)

        for url in candidates:
            response = self.http_client.send_request(url=url, method="GET", allow_redirects=True)
            if response is None:
                continue
            if response.status_code == 200 and not self._is_false_positive(response, baseline):
                if marker.decode() in response.text:
                    found.append(url)
        return found

    def run(self) -> None:
        self.print_lock.add_string_to_output(
            self.print_lock.add_string_to_output(out_if(__TESTLABEL__, "TITLE", not self.args.json, colortext=True))
        )

        filename, content = self._get_filename()
        marker = content
        content_type = getattr(self.args, "content_type", None) or "application/octet-stream"
        data  = dict(item.split("=", 1) for item in self.args.data.split("&")) if self.args.data else None
        files = {self.param: (filename, content, content_type)}

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
            out_if(f"File uploaded  [{filename}], searching...", "INFO", not self.args.json, indent=4)
        )

        base_url  = self._get_base_url()
        baseline  = self._get_false_positive_baseline(base_url)
        wordlist  = get_wordlist(getattr(self.args, "wordlist", None))

        directories = _find_directories_output = self._find_directories(base_url, wordlist, baseline)

        self.print_lock.add_string_to_output(
            out_if("Discovered directories for uploaded files", "INFO", not self.args.json, indent=4)
        )
        if directories:
            for dir_url, status in directories:
                self.print_lock.add_string_to_output(
                    out_if(f"{dir_url}  [{status}]", "TEXT", not self.args.json, indent=8)
                )
        else:
            self.print_lock.add_string_to_output(
                out_if("No directory for uploads found", "TEXT", not self.args.json, indent=8)
            )

        found_files = self._find_file(directories, filename, marker, base_url, baseline)

        self.print_lock.add_string_to_output(
            out_if("Uploaded file found", "INFO", not self.args.json, indent=4)
        )
        if found_files:
            for url in found_files:
                self.print_lock.add_string_to_output(
                    out_if(url, "VULN", not self.args.json, indent=8)
                )
            self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-FINDSTORAGE")
        else:
            self.print_lock.add_string_to_output(
                out_if("Uploaded file not found", "TEXT", not self.args.json, indent=8)
            )


def run(args, ptjsonlib, http_client, print_lock):
    """Entry point for running the Find Storage Test module."""
    FindStorage(args, ptjsonlib, http_client, print_lock).run()
