"""
Filename Characters Test – checks which special/forbidden characters the server
allows in uploaded file names.

Tests spaces, diacritics, Unicode, null byte, control characters, and
filesystem-forbidden characters (/ \\ : * ? " < > |).  Also tests null-byte
injection as an extension-bypass technique (e.g. file.php%00.jpg).

Contains:
- Chars class for performing the character test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib, http_client, print_lock)
"""

from urllib.parse import quote

from ptlibs.ptprinthelper import out_if

__TESTLABEL__ = "Filename Characters Test:"

# (display label, filename fragment to inject)
CHAR_TESTS = [
    # Spaces & whitespace
    ("space",              "test chars.txt"),
    ("tab",                "test\tchars.txt"),
    ("leading space",      " test_chars.txt"),
    ("trailing space",     "test_chars.txt "),
    ("double space",       "test  chars.txt"),

    # Filesystem-forbidden characters
    ("slash /",            "test/chars.txt"),
    ("backslash \\",       "test\\chars.txt"),
    ("colon :",            "test:chars.txt"),
    ("asterisk *",         "test*chars.txt"),
    ("question ?",         "test?chars.txt"),
    ("double quote \"",    'test"chars.txt'),
    ("less than <",        "test<chars.txt"),
    ("greater than >",     "test>chars.txt"),
    ("pipe |",             "test|chars.txt"),

    # Null byte variants
    ("null byte %00",      "test_chars%00.txt"),
    ("null byte literal",  "test_chars\x00.txt"),

    # Control characters
    ("newline \\n",        "test_chars\n.txt"),
    ("carriage return \\r","test_chars\r.txt"),
    ("bell \\a",           "test_chars\x07.txt"),
    ("backspace \\b",      "test_chars\x08.txt"),
    ("escape \\x1b",       "test_chars\x1b.txt"),

    # Diacritics & Unicode
    ("diacritics",         "test_chářs.txt"),
    ("cyrillic",           "test_чарс.txt"),
    ("chinese",            "test_字符.txt"),
    ("emoji",              "test_chars_😀.txt"),
    ("right-to-left",      "test_chars_\u200f.txt"),
    ("zero-width space",   "test_chars_\u200b.txt"),
    ("zero-width joiner",  "test_chars_\u200d.txt"),

    # Dot / extension tricks
    ("trailing dot",       "test_chars.txt."),
    ("double dot",         "test_chars..txt"),
    ("leading dot",        ".test_chars.txt"),
    ("dotdot",             "..test_chars.txt"),

    # Semicolon & special
    ("semicolon ;",        "test_chars;.txt"),
    ("hash #",             "test_chars#.txt"),
    ("percent %",          "test_chars%.txt"),
    ("ampersand &",        "test_chars&.txt"),
    ("equals =",           "test_chars=.txt"),
    ("plus +",             "test_chars+.txt"),
    ("backtick `",         "test_chars`.txt"),
    ("single quote '",     "test_chars'.txt"),
    ("curly brace {",      "test_chars{.txt"),
    ("curly brace }",      "test_chars}.txt"),
    ("tilde ~",            "test_chars~.txt"),

    # Null byte extension bypass
    ("null ext bypass php",  "test_chars.php%00.jpg"),
    ("null ext bypass exe",  "test_chars.exe%00.jpg"),
    ("null ext bypass asp",  "test_chars.asp%00.jpg"),
]


class Chars:
    def __init__(self, args: object, ptjsonlib: object, http_client: object, print_lock: object) -> None:
        self.args        = args
        self.ptjsonlib   = ptjsonlib
        self.http_client = http_client
        self.print_lock  = print_lock
        self.param       = args.parameter or "file"

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

    def _test_char(self, label: str, filename: str) -> None:
        """Uploads a file with the given filename and reports the result."""
        content_type = getattr(self.args, "content_type", None) or "application/octet-stream"
        files = {self.param: (filename, b"chars test", content_type)}
        data = dict(item.split("=", 1) for item in self.args.data.split("&")) if self.args.data else None

        try:
            response = self.http_client.send_request(
                url=self.args.url,
                method="POST",
                files=files,
                data=data,
            )
        except Exception:
            self.print_lock.add_string_to_output(
                out_if(f"Error during upload  [{label}]", "WARNING", not self.args.json, indent=4)
            )
            return

        accepted = self._upload_accepted(response)

        if not accepted:
            self.print_lock.add_string_to_output(
                out_if(f"Rejected  [{label}]", "OK", not self.args.json, indent=4)
            )
            return

        # Upload accepted — check if accessible in storage
        if self.args.storage:
            # Percent-encode the filename so special characters (spaces, control
            # chars, unicode, '#', '?', ...) produce a valid, clickable link and
            # the accessibility check targets that exact URL. Keep '/' and '%'
            # literal so path separators and %00-style null-byte payloads survive.
            safe_filename = filename.replace("\x00", "").replace("\n", "").replace("\r", "")
            encoded_filename = quote(safe_filename, safe="/%")
            storage_url = self.args.storage.rstrip("/") + "/" + encoded_filename
            check = self.http_client.send_request(url=storage_url, method="GET", allow_redirects=True)
            accessible = check is not None and check.status_code == 200

            if accessible:
                self.print_lock.add_string_to_output(
                    out_if(f"Accepted and accessible  [{label}]", "VULN", not self.args.json, indent=4)
                )
                self.print_lock.add_string_to_output(
                    out_if(f"File available at: {storage_url}", "TEXT", not self.args.json, indent=8)
                )
                self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-CHARS")
            else:
                self.print_lock.add_string_to_output(
                    out_if(f"Accepted but not accessible  [{label}]", "WARNING", not self.args.json, indent=4)
                )
        else:
            self.print_lock.add_string_to_output(
                out_if(f"Accepted  [{label}]", "VULN", not self.args.json, indent=4)
            )
            self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-CHARS")

    def run(self) -> None:
        self.print_lock.add_string_to_output(
            self.print_lock.add_string_to_output(out_if(__TESTLABEL__, "TITLE", not self.args.json, colortext=True))
        )

        for label, filename in CHAR_TESTS:
            self._test_char(label, filename)


def run(args, ptjsonlib, http_client, print_lock):
    """Entry point for running the Filename Characters Test module."""
    Chars(args, ptjsonlib, http_client, print_lock).run()
