"""
Content Validation Test – checks whether the server validates the actual file
content (magic bytes / MIME detection) against the declared extension and
Content-Type header.

Sends files where the content intentionally mismatches the extension — e.g.
PHP code with a .jpg extension, HTML inside a .png, or a valid JPEG header
followed by PHP code (polyglot).

The test reveals whether the server relies only on extension / Content-Type
or actually inspects file content.

Contains:
- Content class for performing the content validation test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib, http_client, print_lock)
"""

from ptlibs.ptprinthelper import out_if

__TESTLABEL__ = "Content Validation Test:"

# ---------------------------------------------------------------------------
# Magic bytes for common file types
# ---------------------------------------------------------------------------

MAGIC_JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00"
MAGIC_PNG  = b"\x89PNG\r\n\x1a\n"
MAGIC_GIF  = b"GIF89a"
MAGIC_PDF  = b"%PDF-1.4"
MAGIC_ZIP  = b"PK\x03\x04"
MAGIC_BMP  = b"BM"

# ---------------------------------------------------------------------------
# Test matrix: (label, filename, content-type, body)
#
# Each entry is a tuple:
#   label         – human-readable description
#   ext           – file extension to use
#   content_type  – Content-Type header sent with the upload
#   body          – raw bytes of the file body
#   category      – grouping for output
# ---------------------------------------------------------------------------

CONTENT_TESTS = [
    # --- Category: wrong content, correct extension & CT ---
    ("PHP code as .jpg (CT image/jpeg)",
     "jpg", "image/jpeg",
     b'<?php echo "CONTENT_TEST"; ?>',
     "mismatch"),

    ("PHP code as .png (CT image/png)",
     "png", "image/png",
     b'<?php echo "CONTENT_TEST"; ?>',
     "mismatch"),

    ("PHP code as .gif (CT image/gif)",
     "gif", "image/gif",
     b'<?php echo "CONTENT_TEST"; ?>',
     "mismatch"),

    ("HTML as .jpg (CT image/jpeg)",
     "jpg", "image/jpeg",
     b'<html><body>CONTENT_TEST</body></html>',
     "mismatch"),

    ("HTML as .png (CT image/png)",
     "png", "image/png",
     b'<html><body>CONTENT_TEST</body></html>',
     "mismatch"),

    ("EXE header as .txt (CT text/plain)",
     "txt", "text/plain",
     b"MZ" + b"\x00" * 50,
     "mismatch"),

    ("SVG (XML) as .jpg (CT image/jpeg)",
     "jpg", "image/jpeg",
     b'<svg xmlns="http://www.w3.org/2000/svg"><text>CONTENT_TEST</text></svg>',
     "mismatch"),

    # --- Category: correct magic bytes, wrong extension ---
    ("JPEG magic as .php (CT application/octet-stream)",
     "php", "application/octet-stream",
     MAGIC_JPEG + b"\x00" * 20,
     "magic_ext"),

    ("PNG magic as .php (CT application/octet-stream)",
     "php", "application/octet-stream",
     MAGIC_PNG + b"\x00" * 20,
     "magic_ext"),

    ("GIF magic as .php (CT application/octet-stream)",
     "php", "application/octet-stream",
     MAGIC_GIF + b"\x00" * 20,
     "magic_ext"),

    ("PDF magic as .php (CT application/octet-stream)",
     "php", "application/octet-stream",
     MAGIC_PDF + b"\x00" * 20,
     "magic_ext"),

    ("JPEG magic as .html (CT application/octet-stream)",
     "html", "application/octet-stream",
     MAGIC_JPEG + b"\x00" * 20,
     "magic_ext"),

    # --- Category: correct magic bytes, wrong Content-Type ---
    ("JPEG magic, .jpg, CT text/html",
     "jpg", "text/html",
     MAGIC_JPEG + b"\x00" * 20,
     "magic_ct"),

    ("PNG magic, .png, CT application/x-php",
     "png", "application/x-php",
     MAGIC_PNG + b"\x00" * 20,
     "magic_ct"),

    ("GIF magic, .gif, CT text/plain",
     "gif", "text/plain",
     MAGIC_GIF + b"\x00" * 20,
     "magic_ct"),

    # --- Category: polyglot — valid magic bytes + embedded code ---
    ("JPEG polyglot + PHP",
     "jpg", "image/jpeg",
     MAGIC_JPEG + b'\xff\xfe<?php echo "CONTENT_TEST"; ?>',
     "polyglot"),

    ("PNG polyglot + PHP",
     "png", "image/png",
     MAGIC_PNG + b'\x00\x00\x00\x0dIHDR<?php echo "CONTENT_TEST"; ?>',
     "polyglot"),

    ("GIF polyglot + PHP",
     "gif", "image/gif",
     MAGIC_GIF + b'<?php echo "CONTENT_TEST"; ?>',
     "polyglot"),

    ("GIF polyglot + HTML",
     "gif", "image/gif",
     MAGIC_GIF + b'<html><body>CONTENT_TEST</body></html>',
     "polyglot"),

    ("BMP polyglot + PHP",
     "bmp", "image/bmp",
     MAGIC_BMP + b'\x00' * 10 + b'<?php echo "CONTENT_TEST"; ?>',
     "polyglot"),

    ("PDF polyglot + JS",
     "pdf", "application/pdf",
     MAGIC_PDF + b'\n1 0 obj<</Type/Catalog>>endobj\n<script>alert("CONTENT_TEST")</script>',
     "polyglot"),

    # --- Category: null byte in filename ---
    ("PHP code as .php%00.jpg (CT image/jpeg)",
     "php%00.jpg", "image/jpeg",
     b'<?php echo "CONTENT_TEST"; ?>',
     "null_byte"),

    ("JPEG polyglot .php%00.png (CT image/png)",
     "php%00.png", "image/png",
     MAGIC_JPEG + b'<?php echo "CONTENT_TEST"; ?>',
     "null_byte"),

    # --- Category: double extension ---
    ("PHP code as .php.jpg (CT image/jpeg)",
     "php.jpg", "image/jpeg",
     b'<?php echo "CONTENT_TEST"; ?>',
     "double_ext"),

    ("PHP code as .jpg.php (CT image/jpeg)",
     "jpg.php", "image/jpeg",
     b'<?php echo "CONTENT_TEST"; ?>',
     "double_ext"),

    ("JPEG polyglot .php.jpg (CT image/jpeg)",
     "php.jpg", "image/jpeg",
     MAGIC_JPEG + b'<?php echo "CONTENT_TEST"; ?>',
     "double_ext_poly"),

    # --- Category: empty / minimal content ---
    ("Empty file as .php (CT image/jpeg)",
     "php", "image/jpeg",
     b"",
     "edge"),

    ("Single null byte as .jpg (CT image/jpeg)",
     "jpg", "image/jpeg",
     b"\x00",
     "edge"),
]

CATEGORY_LABELS = {
    "mismatch":       "Content mismatch (wrong content, benign extension):",
    "magic_ext":      "Magic bytes vs extension mismatch:",
    "magic_ct":       "Magic bytes vs Content-Type mismatch:",
    "polyglot":       "Polyglot files (valid magic + embedded code):",
    "null_byte":      "Null byte in extension:",
    "double_ext":     "Double extension:",
    "double_ext_poly":"Double extension polyglot:",
    "edge":           "Edge cases:",
}


class Content:
    def __init__(self, args: object, ptjsonlib: object, http_client: object, print_lock: object) -> None:
        self.args        = args
        self.ptjsonlib   = ptjsonlib
        self.http_client = http_client
        self.print_lock  = print_lock
        self.param       = args.parameter or "file"

    def _get_stem(self) -> str:
        base = self.args.file or "test.txt"
        stem, _, _ = base.rpartition(".")
        return stem or base

    def _upload_accepted(self, response) -> bool:
        if response is None:
            return False
        text = response.text
        if self.args.string_yes and self.args.string_yes not in text:
            return False
        if self.args.string_no and self.args.string_no in text:
            return False
        return True

    def _test_content(self, label: str, filename: str, content_type: str, body: bytes) -> dict:
        """
        Uploads a file and returns result dict:
        {label, filename, content_type, accepted, accessible, error}
        """
        files = {self.param: (filename, body, content_type)}
        data = dict(item.split("=", 1) for item in self.args.data.split("&")) if self.args.data else None

        try:
            response = self.http_client.send_request(
                url=self.args.url,
                method="POST",
                files=files,
                data=data,
            )
        except Exception:
            return {"label": label, "filename": filename, "content_type": content_type,
                    "accepted": False, "accessible": None, "error": True}

        accepted = self._upload_accepted(response)

        accessible = None
        if accepted and self.args.storage:
            storage_url = self.args.storage.rstrip("/") + "/" + filename
            try:
                check = self.http_client.send_request(url=storage_url, method="GET", allow_redirects=True)
                accessible = check is not None and check.status_code == 200
            except Exception:
                accessible = False

        return {"label": label, "filename": filename, "content_type": content_type,
                "accepted": accepted, "accessible": accessible, "error": False}

    def _report_result(self, result: dict) -> None:
        label = result["label"]
        fname = result["filename"]
        ct = result["content_type"]

        if result["error"]:
            self.print_lock.add_string_to_output(
                out_if(f"Error  [{label}]  {fname}", "WARNING", not self.args.json, indent=8)
            )
            return

        if not result["accepted"]:
            self.print_lock.add_string_to_output(
                out_if(f"Rejected  [{label}]  {fname}  CT={ct}", "OK", not self.args.json, indent=8)
            )
            return

        if result["accessible"] is True:
            self.print_lock.add_string_to_output(
                out_if(f"Accepted and accessible  [{label}]  {fname}  CT={ct}", "VULN", not self.args.json, indent=8)
            )
            if self.args.storage:
                url = self.args.storage.rstrip("/") + "/" + fname
                self.print_lock.add_string_to_output(
                    out_if(url, "TEXT", not self.args.json, indent=12)
                )
            self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-CONTENT")
        elif result["accessible"] is False:
            self.print_lock.add_string_to_output(
                out_if(f"Accepted but not accessible  [{label}]  {fname}  CT={ct}", "WARNING", not self.args.json, indent=8)
            )
        else:
            # No storage URL → can't verify
            self.print_lock.add_string_to_output(
                out_if(f"Accepted  [{label}]  {fname}  CT={ct}", "VULN", not self.args.json, indent=8)
            )
            self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-CONTENT")

    def run(self) -> None:
        self.print_lock.add_string_to_output(
            self.print_lock.add_string_to_output(out_if(__TESTLABEL__, "TITLE", not self.args.json, colortext=True))
        )

        stem = f"{self._get_stem()}_content"

        self.print_lock.add_string_to_output(
            out_if(f"Testing {len(CONTENT_TESTS)} content validation variants...",
                   "INFO", not self.args.json, indent=4)
        )

        # Group tests by category
        categories_seen = []
        tests_by_cat = {}
        for label, ext, ct, body, category in CONTENT_TESTS:
            if category not in tests_by_cat:
                tests_by_cat[category] = []
                categories_seen.append(category)
            tests_by_cat[category].append((label, ext, ct, body))

        accepted_count = 0
        total = len(CONTENT_TESTS)

        for category in categories_seen:
            cat_label = CATEGORY_LABELS.get(category, f"{category}:")
            self.print_lock.add_string_to_output(
                out_if(cat_label, "INFO", not self.args.json, indent=4)
            )

            for label, ext, ct, body in tests_by_cat[category]:
                filename = f"{stem}.{ext}"
                result = self._test_content(label, filename, ct, body)
                self._report_result(result)
                if result["accepted"]:
                    accepted_count += 1

        # Summary
        if accepted_count > 0:
            self.print_lock.add_string_to_output(
                out_if(f"Server accepted {accepted_count}/{total} content validation tests — content is NOT properly validated",
                       "VULN", not self.args.json, indent=4)
            )
        else:
            self.print_lock.add_string_to_output(
                out_if(f"Server rejected all {total} tests — content validation appears effective",
                       "OK", not self.args.json, indent=4)
            )


def run(args, ptjsonlib, http_client, print_lock):
    """Entry point for running the Content Validation Test module."""
    Content(args, ptjsonlib, http_client, print_lock).run()
