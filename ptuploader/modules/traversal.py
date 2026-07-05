"""
Path Traversal Test – checks if the server allows uploading files with traversal sequences in the filename.
Uploads a file with ../ or ..\\ sequences (plain and URL/double encoded) and checks whether the file
lands outside the intended upload directory.

Contains:
- Traversal class for performing the path traversal test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib, http_client, print_lock)
"""

from ptlibs.ptprinthelper import out_if

__TESTLABEL__ = "Path Traversal Test:"

TRAVERSAL_PREFIXES = [
    "../",
    "..\\",
    "%2E%2E%2F",
    "%2E%2E%5C",
    "%252E%252E%252F",
    "%252E%252E%255C",
    "%25252E%25252E%25252F",
    "%25252E%25252E%25255C",
]


class Traversal:
    def __init__(self, args: object, ptjsonlib: object, http_client: object, print_lock: object) -> None:
        self.args        = args
        self.ptjsonlib   = ptjsonlib
        self.http_client = http_client
        self.print_lock  = print_lock
        self.param       = args.parameter or "file"

    def _get_base_filename(self) -> str:
        """Returns base filename with traversal module identifier."""
        base = self.args.file or "test.txt"
        stem, _, ext = base.rpartition(".")
        stem = stem or base
        ext = ext or "txt"
        return f"{stem}_traversal.{ext}"

    def _get_parent_url(self) -> str | None:
        """Returns the parent directory URL of the storage path."""
        if not self.args.storage:
            return None
        storage = self.args.storage.rstrip("/")
        parent = storage.rsplit("/", 1)[0]
        return parent + "/"

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

    def _test_prefix(self, prefix: str, base_filename: str) -> None:
        """Uploads a file with a traversal prefix in the filename and checks the result."""
        traversal_filename = prefix + base_filename
        data = dict(item.split("=", 1) for item in self.args.data.split("&")) if self.args.data else None
        content_type = getattr(self.args, "content_type", None) or "application/octet-stream"
        files = {self.param: (traversal_filename, b"traversal test", content_type)}
        response = self.http_client.send_request(
            url=self.args.url,
            method="POST",
            files=files,
            data=data,
        )

        accepted = self._upload_accepted(response)

        if not accepted:
            self.print_lock.add_string_to_output(
                out_if(f"Upload rejected  [{traversal_filename}]", "OK", not self.args.json, indent=4)
            )
            return

        parent_url = self._get_parent_url()
        if parent_url:
            escaped_url = parent_url + base_filename
            check = self.http_client.send_request(url=escaped_url, method="GET", allow_redirects=True)
            accessible = check is not None and check.status_code == 200

            if accessible:
                self.print_lock.add_string_to_output(
                    out_if(f"File uploaded outside intended directory  [{traversal_filename}]", "VULN", not self.args.json, indent=4)
                )
                self.print_lock.add_string_to_output(
                    out_if(f"File available at: {escaped_url}", "TEXT", not self.args.json, indent=8)
                )
                self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-TRAVERSAL")
            else:
                self.print_lock.add_string_to_output(
                    out_if(f"Upload accepted but file not found in parent directory  [{traversal_filename}]", "WARNING", not self.args.json, indent=4)
                )
        else:
            self.print_lock.add_string_to_output(
                out_if(f"Upload accepted with traversal filename  [{traversal_filename}]", "VULN", not self.args.json, indent=4)
            )
            self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-TRAVERSAL")

    def run(self) -> None:
        self.print_lock.add_string_to_output(
            self.print_lock.add_string_to_output(out_if(__TESTLABEL__, "TITLE", not self.args.json, colortext=True))
        )
        base_filename = self._get_base_filename()
        for prefix in TRAVERSAL_PREFIXES:
            self._test_prefix(prefix, base_filename)


def run(args, ptjsonlib, http_client, print_lock):
    """Entry point for running the Path Traversal Test module."""
    Traversal(args, ptjsonlib, http_client, print_lock).run()
