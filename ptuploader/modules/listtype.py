"""
List Type Test – determines whether the server enforces a whitelist or a
blacklist on uploaded file extensions.

The test uploads files with several nonsensical, non-existent extensions
(e.g. .qwe). The reasoning:

- If such an unknown extension is ACCEPTED, the server cannot be using a
  whitelist (which would only permit known-good extensions); it is therefore
  filtering with a BLACKLIST that blocks a fixed set of dangerous extensions
  and lets everything else through.
- If the unknown extension is REJECTED, the server only permits a fixed set of
  known extensions — a WHITELIST.

Blacklist-based filtering is considered insecure because it is trivially
bypassed by uncommon or newly introduced executable extensions, so a detected
blacklist is reported as a vulnerability.

Contains:
- Listtype class for performing the list-type detection test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib, http_client, print_lock)
"""

from ptlibs.ptprinthelper import out_if

__TESTLABEL__ = "Whitelist/Blacklist Detection Test:"

# Five nonsensical extensions that do not correspond to any real file format.
# Used to probe whether the server allows unknown extensions (blacklist) or
# rejects everything that is not explicitly permitted (whitelist).
NONSENSE_EXTENSIONS = ["qwe", "zxq", "xvk", "jpq", "mzw"]


class Listtype:
    def __init__(self, args: object, ptjsonlib: object, http_client: object, print_lock: object) -> None:
        self.args        = args
        self.ptjsonlib   = ptjsonlib
        self.http_client = http_client
        self.print_lock  = print_lock
        self.param       = args.parameter or "file"

    def _get_extensions(self) -> list:
        """Returns the nonsense extensions to test (overridable via -e)."""
        if self.args.extensions:
            return list(self.args.extensions)
        return list(NONSENSE_EXTENSIONS)

    def _get_stem(self) -> str:
        """Returns filename stem for uploaded files."""
        base = self.args.file or "test.txt"
        stem, _, _ = base.rpartition(".")
        return stem or base

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

    def _upload_file(self, filename: str) -> bool:
        """Uploads a file and returns True if accepted."""
        content_type = getattr(self.args, "content_type", None) or "application/octet-stream"
        files = {self.param: (filename, b"listtype test content", content_type)}
        data = dict(item.split("=", 1) for item in self.args.data.split("&")) if self.args.data else None
        response = self.http_client.send_request(
            url=self.args.url,
            method="POST",
            files=files,
            data=data,
        )
        return self._upload_accepted(response)

    def _check_accessible(self, filename: str) -> str | None:
        """If -s is set, checks if file is accessible. Returns URL or None."""
        if not self.args.storage:
            return None
        url = self.args.storage.rstrip("/") + "/" + filename
        check = self.http_client.send_request(url=url, method="GET", allow_redirects=True)
        if check is not None and check.status_code == 200:
            return url
        return None

    def _test_extension(self, stem: str, ext: str) -> bool:
        """Uploads one nonsense extension and reports the result. Returns True if accepted."""
        filename = f"{stem}_listtype.{ext}"
        accepted = self._upload_file(filename)

        if not accepted:
            self.print_lock.add_string_to_output(
                out_if(f"Rejected  [{filename}]", "OK", not self.args.json, indent=4)
            )
            return False

        accessible_url = self._check_accessible(filename)
        if accessible_url:
            self.print_lock.add_string_to_output(
                out_if(f"Accepted and accessible  [{filename}]", "VULN", not self.args.json, indent=4)
            )
            self.print_lock.add_string_to_output(
                out_if(accessible_url, "TEXT", not self.args.json, indent=8)
            )
        else:
            self.print_lock.add_string_to_output(
                out_if(f"Accepted  [{filename}]", "VULN", not self.args.json, indent=4)
            )
        return True

    def _report_conclusion(self, accepted_count: int, total: int) -> None:
        """Derives and reports whether a blacklist or a whitelist is deployed."""
        if accepted_count == total:
            # Every unknown extension passed → the server is not restricting to
            # known-good extensions, so it must be using a blacklist.
            self.print_lock.add_string_to_output(
                out_if(f"Blacklist detected — all {total} nonsense extensions were accepted. ",
                       "VULN", not self.args.json, indent=4)
            )
            self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-BLACKLIST")
        elif accepted_count == 0:
            # Every unknown extension was rejected → only a fixed set of known
            # extensions is permitted, i.e. a whitelist.
            self.print_lock.add_string_to_output(
                out_if(f"Whitelist detected — all {total} nonsense extensions were rejected. "
                       f"The server permits only a fixed set of known extensions.",
                       "OK", not self.args.json, indent=4)
            )
        else:
            # Mixed results — the decision is not driven purely by the extension.
            self.print_lock.add_string_to_output(
                out_if(f"Inconclusive — {accepted_count}/{total} nonsense extensions were accepted. "
                       f"Filtering may depend on more than the extension (e.g. content or Content-Type).",
                       "WARNING", not self.args.json, indent=4)
            )

    def run(self) -> None:
        self.print_lock.add_string_to_output(
            out_if(__TESTLABEL__, "INFO", not self.args.json)
        )

        stem = self._get_stem()
        extensions = self._get_extensions()

        self.print_lock.add_string_to_output(
            out_if(f"Uploading {len(extensions)} nonsense extensions: "
                   f"{', '.join('.' + e for e in extensions)}",
                   "INFO", not self.args.json, indent=4)
        )

        accepted_count = 0
        for ext in extensions:
            if self._test_extension(stem, ext):
                accepted_count += 1

        self._report_conclusion(accepted_count, len(extensions))


def run(args, ptjsonlib, http_client, print_lock):
    """Entry point for running the Whitelist/Blacklist Detection Test module."""
    Listtype(args, ptjsonlib, http_client, print_lock).run()