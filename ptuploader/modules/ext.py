"""
Extension Test – checks which file extensions the server accepts during upload.
Uploads files with various extensions (including dangerous ones) and bypass
variants, then reports which were accepted and optionally verifies accessibility.

Built-in extension lists are selected by the -l (language) parameter.
If -e is provided, only those extensions are tested (bypass variants still apply).

Contains:
- Ext class for performing the extension test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib, http_client, print_lock)
"""

from ptlibs.ptprinthelper import out_if

__TESTLABEL__ = "Extension Test:"

# ---------------------------------------------------------------------------
# Built-in extension lists per language
# ---------------------------------------------------------------------------

EXTENSIONS_PHP = [
    "php", "php3", "php4", "php5", "php7", "php8",
    "phtml", "phar", "phps", "pht", "phpt", "inc",
]

EXTENSIONS_ASP = [
    "asp", "aspx", "ashx", "asmx", "asa", "asax", "ascx",
    "config", "cer", "cdx",
]

EXTENSIONS_JSP = [
    "jsp", "jspx", "jsw", "jsv", "jspf", "wss",
    "do", "action", "war",
]

EXTENSIONS_NET = [
    "aspx", "ashx", "asmx", "ascx", "config",
    "cs", "cshtml", "vb", "vbhtml",
]

EXTENSIONS_PY = ["py", "pyw", "pyc", "pyo", "wsgi"]

EXTENSIONS_JS = ["js", "mjs", "cjs", "node"]

EXTENSIONS_GENERAL = [
    "exe", "bat", "cmd", "com", "sh", "cgi", "pl",
    "htaccess", "htpasswd", "svg", "html", "htm",
    "shtml", "xml", "xhtml", "ssi", "txt", "jpg",
]

LANGUAGE_MAP = {
    "PHP": EXTENSIONS_PHP,
    "ASP": EXTENSIONS_ASP,
    "JSP": EXTENSIONS_JSP,
    "NET": EXTENSIONS_NET,
    "PY":  EXTENSIONS_PY,
    "JS":  EXTENSIONS_JS,
}


def _generate_bypass_variants(stem: str, ext: str) -> list:
    """
    Generates filter-bypass filename variants for a given extension.
    Returns list of (filename, bypass_description) tuples.
    """
    variants = []

    # Case variations
    if ext.isalpha() and len(ext) >= 2:
        upper = ext.upper()
        mixed = ext[0].upper() + ext[1:].lower()
        reverse_mixed = ext[0].lower() + ext[1:].upper()
        for case_var in dict.fromkeys([upper, mixed, reverse_mixed]):
            if case_var != ext:
                variants.append((f"{stem}.{case_var}", f"case: .{case_var}"))

    # Double extension (dangerous ext first, safe ext last)
    for safe_ext in ("jpg", "png", "gif", "txt"):
        variants.append((f"{stem}.{ext}.{safe_ext}", f"double: .{ext}.{safe_ext}"))

    # Reverse double extension (safe first, dangerous last)
    variants.append((f"{stem}.jpg.{ext}", f"reverse: .jpg.{ext}"))

    # Null byte
    variants.append((f"{stem}.{ext}%00.jpg", f"null byte: .{ext}%00.jpg"))

    # Trailing dot
    variants.append((f"{stem}.{ext}.", f"trailing dot: .{ext}."))

    # Trailing semicolon
    variants.append((f"{stem}.{ext};.jpg", f"semicolon: .{ext};.jpg"))

    # Trailing space
    variants.append((f"{stem}.{ext} ", f"trailing space: .{ext} "))

    return variants


class Ext:
    def __init__(self, args: object, ptjsonlib: object, http_client: object, print_lock: object) -> None:
        self.args        = args
        self.ptjsonlib   = ptjsonlib
        self.http_client = http_client
        self.print_lock  = print_lock
        self.param       = args.parameter or "file"

    def _get_extensions(self) -> list:
        """Returns the list of extensions to test."""
        if self.args.extensions:
            return list(self.args.extensions)

        lang = getattr(self.args, "language", None)
        lang_exts = LANGUAGE_MAP.get(lang, []) if lang else []
        combined = lang_exts + EXTENSIONS_GENERAL
        return list(dict.fromkeys(combined))

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
        files = {self.param: (filename, b"extension test content", content_type)}
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
        """Tests a single extension and reports the result. Returns True if accepted."""
        filename = f"{stem}_ext.{ext}"
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
            self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-EXT")
        elif self.args.storage:
            self.print_lock.add_string_to_output(
                out_if(f"Accepted but not accessible  [{filename}]", "WARNING", not self.args.json, indent=4)
            )
        else:
            self.print_lock.add_string_to_output(
                out_if(f"Accepted  [{filename}]", "VULN", not self.args.json, indent=4)
            )
            self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-EXT")
        return True

    def _test_bypasses(self, stem: str, accepted_exts: list) -> None:
        """Tests bypass variants for extensions that were rejected."""
        extensions = self._get_extensions()
        rejected_exts = [e for e in extensions if e not in accepted_exts]

        if not rejected_exts:
            return

        self.print_lock.add_string_to_output(
            out_if("Bypass attempts:", "INFO", not self.args.json, indent=4)
        )

        for ext in rejected_exts:
            variants = _generate_bypass_variants(f"{stem}_ext", ext)
            for filename, desc in variants:
                accepted = self._upload_file(filename)
                if accepted:
                    accessible_url = self._check_accessible(filename)
                    if accessible_url:
                        self.print_lock.add_string_to_output(
                            out_if(f"Bypass successful and accessible  [{filename}]  ({desc})", "VULN", not self.args.json, indent=8)
                        )
                        self.print_lock.add_string_to_output(
                            out_if(accessible_url, "TEXT", not self.args.json, indent=12)
                        )
                        self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-EXT-BYPASS")
                    elif self.args.storage:
                        self.print_lock.add_string_to_output(
                            out_if(f"Bypass accepted but not accessible  [{filename}]  ({desc})", "WARNING", not self.args.json, indent=8)
                        )
                    else:
                        self.print_lock.add_string_to_output(
                            out_if(f"Bypass successful  [{filename}]  ({desc})", "VULN", not self.args.json, indent=8)
                        )
                        self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-EXT-BYPASS")

    def run(self) -> None:
        self.print_lock.add_string_to_output(
            out_if(__TESTLABEL__, "INFO", not self.args.json)
        )

        stem = self._get_stem()
        extensions = self._get_extensions()

        self.print_lock.add_string_to_output(
            out_if(f"Testing {len(extensions)} extensions...", "INFO", not self.args.json, indent=4)
        )

        accepted_exts = []
        for ext in extensions:
            if self._test_extension(stem, ext):
                accepted_exts.append(ext)

        if accepted_exts:
            self.print_lock.add_string_to_output(
                out_if(f"Summary: {len(accepted_exts)}/{len(extensions)} extensions accepted", "INFO", not self.args.json, indent=4)
            )

        self._test_bypasses(stem, accepted_exts)


def run(args, ptjsonlib, http_client, print_lock):
    """Entry point for running the Extension Test module."""
    Ext(args, ptjsonlib, http_client, print_lock).run()
