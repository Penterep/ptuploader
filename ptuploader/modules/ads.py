"""
Alternate Data Streams Test – checks whether the server is vulnerable to
NTFS Alternate Data Stream (ADS) abuse during file upload.

Uploads files whose names contain ADS syntax (e.g. image.jpg:hidden.php,
file.txt::$DATA) and verifies whether the server accepted the name, where
the file was stored, and whether it is accessible — under the ADS name,
the base name, or the stream name alone.

This can bypass extension filters on Windows/NTFS servers by hiding
executable content inside an alternate stream of an innocent-looking file.

Contains:
- Ads class for performing the ADS test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib, http_client, print_lock)
"""

from ptlibs.ptprinthelper import out_if

__TESTLABEL__ = "Alternate Data Streams Test:"

# (label, filename template)
# {stem} and {ext} are replaced at runtime
ADS_TESTS = [
    # ::$DATA — default data stream, may strip the suffix on NTFS
    ("::$DATA",                      "{stem}.{ext}::$DATA"),
    ("::$DATA (php)",                "{stem}.php::$DATA"),

    # stream:hidden_ext — hide executable inside benign file
    ("stream .php",                  "{stem}.{ext}:{stem}.php"),
    ("stream .asp",                  "{stem}.{ext}:{stem}.asp"),
    ("stream .jsp",                  "{stem}.{ext}:{stem}.jsp"),
    ("stream .cgi",                  "{stem}.{ext}:{stem}.cgi"),
    ("stream generic",               "{stem}.{ext}:payload.txt"),

    # nested ::$DATA on stream
    ("stream .php ::$DATA",          "{stem}.{ext}:{stem}.php:$DATA"),
    ("stream .asp ::$DATA",          "{stem}.{ext}:{stem}.asp:$DATA"),

    # dot-colon trick — some parsers truncate at ':'
    ("colon truncate",               "{stem}.php:.jpg"),
    ("colon truncate asp",           "{stem}.asp:.jpg"),

    # URL-encoded colon (%3a)
    ("url-encoded colon",            "{stem}.{ext}%3a{stem}.php"),
    ("url-encoded ::$DATA",          "{stem}.{ext}%3a%3a%24DATA"),

    # double-encoded colon (%253a)
    ("double-encoded colon",         "{stem}.{ext}%253a{stem}.php"),

    # trailing ::$DATA after dangerous extension
    ("php ::$DATA direct",           "{stem}.php::$DATA"),
    ("asp ::$DATA direct",           "{stem}.asp::$DATA"),
    ("jsp ::$DATA direct",           "{stem}.jsp::$DATA"),

    # stream with null byte
    ("stream null byte",             "{stem}.php%00.jpg:{stem}.txt"),

    # plain colon without stream name
    ("bare colon",                   "{stem}.{ext}:"),
    ("bare double colon",            "{stem}.{ext}::"),
]


class Ads:
    def __init__(self, args: object, ptjsonlib: object, http_client: object, print_lock: object) -> None:
        self.args        = args
        self.ptjsonlib   = ptjsonlib
        self.http_client = http_client
        self.print_lock  = print_lock
        self.param       = args.parameter or "file"

    def _get_stem_and_ext(self) -> tuple:
        base = self.args.file or "test.txt"
        stem, _, ext = base.rpartition(".")
        stem = stem or base
        ext = ext or "txt"
        return stem + "_ads", ext

    def _upload_accepted(self, response) -> bool:
        if response is None:
            return False
        text = response.text
        if self.args.string_yes and self.args.string_yes not in text:
            return False
        if self.args.string_no and self.args.string_no in text:
            return False
        return True

    def _upload_file(self, filename: str) -> bool:
        content_type = getattr(self.args, "content_type", None) or "application/octet-stream"
        files = {self.param: (filename, b"ads test content", content_type)}
        data = dict(item.split("=", 1) for item in self.args.data.split("&")) if self.args.data else None

        response = self.http_client.send_request(
            url=self.args.url,
            method="POST",
            files=files,
            data=data,
        )
        return self._upload_accepted(response)

    def _check_accessible(self, url: str) -> bool:
        response = self.http_client.send_request(url=url, method="GET", allow_redirects=True)
        return response is not None and response.status_code == 200

    def _probe_storage(self, filename: str, stem: str, ext: str) -> list:
        """
        Tries to access the uploaded file under several candidate URLs.
        Returns list of accessible URLs.
        """
        if not self.args.storage:
            return []

        base = self.args.storage.rstrip("/")
        candidates = set()

        # Exact filename as uploaded
        candidates.add(f"{base}/{filename}")

        # Base name without ADS part (server may strip everything after ':')
        base_name = filename.split(":")[0].split("%3a")[0].split("%3A")[0].split("%253a")[0].split("%253A")[0]
        if base_name:
            candidates.add(f"{base}/{base_name}")

        # Stream name alone (part after first ':')
        if ":" in filename:
            stream_part = filename.split(":", 1)[1]
            stream_name = stream_part.split(":")[0].rstrip("$DATA").rstrip("$data")
            if stream_name and not stream_name.startswith("$"):
                candidates.add(f"{base}/{stream_name}")

        # Stem with common extensions (server may normalise)
        candidates.add(f"{base}/{stem}.{ext}")

        accessible = []
        for url in candidates:
            # skip urls with problematic chars that won't resolve
            clean = url.replace("\x00", "").replace("\n", "").replace("\r", "")
            if clean != url:
                url = clean
            try:
                if self._check_accessible(url):
                    accessible.append(url)
            except Exception:
                pass
        return accessible

    def _test_ads(self, label: str, filename: str, stem: str, ext: str) -> None:
        try:
            accepted = self._upload_file(filename)
        except Exception:
            self.print_lock.add_string_to_output(
                out_if(f"Error  [{label}]  {filename}", "WARNING", not self.args.json, indent=4)
            )
            return

        if not accepted:
            self.print_lock.add_string_to_output(
                out_if(f"Rejected  [{label}]  {filename}", "OK", not self.args.json, indent=4)
            )
            return

        # Check accessibility
        accessible_urls = self._probe_storage(filename, stem, ext)

        if accessible_urls:
            self.print_lock.add_string_to_output(
                out_if(f"Accepted and accessible  [{label}]  {filename}", "VULN", not self.args.json, indent=4)
            )
            for url in accessible_urls:
                self.print_lock.add_string_to_output(
                    out_if(url, "TEXT", not self.args.json, indent=8)
                )
            self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-ADS")
        elif self.args.storage:
            self.print_lock.add_string_to_output(
                out_if(f"Accepted but not accessible  [{label}]  {filename}", "WARNING", not self.args.json, indent=4)
            )
        else:
            self.print_lock.add_string_to_output(
                out_if(f"Accepted  [{label}]  {filename}", "VULN", not self.args.json, indent=4)
            )
            self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-ADS")

    def run(self) -> None:
        self.print_lock.add_string_to_output(
            self.print_lock.add_string_to_output(out_if(__TESTLABEL__, "TITLE", not self.args.json, colortext=True))
        )

        stem, ext = self._get_stem_and_ext()

        self.print_lock.add_string_to_output(
            out_if(f"Testing {len(ADS_TESTS)} ADS variants...", "INFO", not self.args.json, indent=4)
        )

        for label, template in ADS_TESTS:
            filename = template.format(stem=stem, ext=ext)
            self._test_ads(label, filename, stem, ext)


def run(args, ptjsonlib, http_client, print_lock):
    """Entry point for running the Alternate Data Streams Test module."""
    Ads(args, ptjsonlib, http_client, print_lock).run()
