"""
Content-Type Bypass Test – checks whether the server relies solely on the
Content-Type header value when validating file uploads.

Uploads files with dangerous extensions and/or dangerous content but with a
spoofed Content-Type header set to a safe value (e.g. image/jpeg). If the
server accepts the file based only on the Content-Type, the upload validation
is insufficient.

The test also checks whether accepted files are accessible and executable
in storage.

Contains:
- Ct class for performing the Content-Type bypass test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib, http_client, print_lock)
"""

from ptlibs.ptprinthelper import out_if

__TESTLABEL__ = "Content-Type Bypass Test:"

EXEC_MARKER = "PTUPLOADER_CT_OK"

# Safe Content-Type values used for spoofing
SAFE_CONTENT_TYPES = [
    "image/jpeg",
    "image/png",
    "image/gif",
    "text/plain",
    "application/pdf",
    "application/octet-stream",
]

# Dangerous extensions to test per language
DANGEROUS_EXTENSIONS = {
    "PHP": ["php", "php5", "phtml", "phar", "pht"],
    "ASP": ["asp", "aspx", "asa", "cer"],
    "JSP": ["jsp", "jspx", "jspf"],
    "PY":  ["py", "cgi"],
    "JS":  ["js", "mjs"],
}

DEFAULT_DANGEROUS = ["php", "php5", "phtml", "phar", "pht"]

# Payloads per language — code that outputs EXEC_MARKER
PAYLOADS = {
    "PHP": f'<?php echo "{EXEC_MARKER}"; ?>'.encode(),
    "ASP": f'<% Response.Write("{EXEC_MARKER}") %>'.encode(),
    "JSP": f'<%= "{EXEC_MARKER}" %>'.encode(),
    "PY":  f'print("{EXEC_MARKER}")'.encode(),
    "JS":  f'console.log("{EXEC_MARKER}")'.encode(),
}

SOURCE_TAGS = {
    "PHP": "<?php",
    "ASP": "<%",
    "JSP": "<%=",
    "PY":  "print(",
    "JS":  "console.log(",
}

DEFAULT_LANGUAGE = "PHP"


class Ct:
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

    def _get_dangerous_extensions(self) -> list:
        if self.args.extensions:
            return list(self.args.extensions)
        lang = self._get_language()
        return list(DANGEROUS_EXTENSIONS.get(lang, DEFAULT_DANGEROUS))

    def _get_spoof_content_types(self) -> list:
        ct = getattr(self.args, "content_type", None)
        if ct:
            return [ct]
        return list(SAFE_CONTENT_TYPES)

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

    def _upload_file(self, filename: str, body: bytes, content_type: str) -> bool:
        files = {self.param: (filename, body, content_type)}
        data = dict(item.split("=", 1) for item in self.args.data.split("&")) if self.args.data else None

        response = self.http_client.send_request(
            url=self.args.url,
            method="POST",
            files=files,
            data=data,
        )
        return self._upload_accepted(response)

    def _check_storage(self, filename: str, source_tag: str) -> str:
        """
        Checks uploaded file in storage.
        Returns: "executed", "source", "accessible", "not_found"
        """
        if not self.args.storage:
            return "no_storage"

        url = self.args.storage.rstrip("/") + "/" + filename
        try:
            response = self.http_client.send_request(url=url, method="GET", allow_redirects=True)
        except Exception:
            return "not_found"

        if response is None or response.status_code != 200:
            return "not_found"

        body = response.text
        if EXEC_MARKER in body:
            if source_tag not in body:
                return "executed"
            return "source"
        return "accessible"

    def _test_variant(self, ext: str, spoof_ct: str, payload: bytes, source_tag: str) -> dict:
        stem = f"{self._get_stem()}_ct"
        filename = f"{stem}.{ext}"

        try:
            accepted = self._upload_file(filename, payload, spoof_ct)
        except Exception:
            return {"ext": ext, "spoof_ct": spoof_ct, "filename": filename,
                    "accepted": False, "storage": None, "error": True}

        storage_status = None
        if accepted:
            storage_status = self._check_storage(filename, source_tag)

        return {"ext": ext, "spoof_ct": spoof_ct, "filename": filename,
                "accepted": accepted, "storage": storage_status, "error": False}

    def _report_result(self, result: dict) -> None:
        ext = result["ext"]
        ct = result["spoof_ct"]
        fname = result["filename"]

        if result.get("error"):
            self.print_lock.add_string_to_output(
                out_if(f"Error  .{ext}  CT={ct}", "WARNING", not self.args.json, indent=8)
            )
            return

        if not result["accepted"]:
            self.print_lock.add_string_to_output(
                out_if(f"Rejected  .{ext}  CT={ct}", "OK", not self.args.json, indent=8)
            )
            return

        storage = result["storage"]

        if storage == "executed":
            self.print_lock.add_string_to_output(
                out_if(f"BYPASS + EXECUTED  .{ext}  CT={ct}  [{fname}]", "VULN", not self.args.json, indent=8)
            )
            if self.args.storage:
                url = self.args.storage.rstrip("/") + "/" + fname
                self.print_lock.add_string_to_output(
                    out_if(url, "TEXT", not self.args.json, indent=12)
                )
            self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-CT-EXEC")
        elif storage == "source":
            self.print_lock.add_string_to_output(
                out_if(f"Bypass (served as source)  .{ext}  CT={ct}  [{fname}]", "WARNING", not self.args.json, indent=8)
            )
            self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-CT")
        elif storage == "accessible":
            self.print_lock.add_string_to_output(
                out_if(f"Bypass (accessible)  .{ext}  CT={ct}  [{fname}]", "VULN", not self.args.json, indent=8)
            )
            self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-CT")
        elif storage == "not_found":
            self.print_lock.add_string_to_output(
                out_if(f"Bypass (not accessible)  .{ext}  CT={ct}  [{fname}]", "WARNING", not self.args.json, indent=8)
            )
        else:
            # no_storage
            self.print_lock.add_string_to_output(
                out_if(f"Bypass (accepted)  .{ext}  CT={ct}  [{fname}]", "VULN", not self.args.json, indent=8)
            )
            self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-CT")

    def run(self) -> None:
        self.print_lock.add_string_to_output(
            self.print_lock.add_string_to_output(out_if(__TESTLABEL__, "TITLE", not self.args.json, colortext=True))
        )

        language = self._get_language()
        extensions = self._get_dangerous_extensions()
        spoof_cts = self._get_spoof_content_types()
        payload = PAYLOADS.get(language, PAYLOADS[DEFAULT_LANGUAGE])
        source_tag = SOURCE_TAGS.get(language, SOURCE_TAGS[DEFAULT_LANGUAGE])

        total = len(extensions) * len(spoof_cts)

        self.print_lock.add_string_to_output(
            out_if(f"Language: {language}  |  {len(extensions)} extensions × {len(spoof_cts)} Content-Types = {total} tests",
                   "INFO", not self.args.json, indent=4)
        )

        bypass_count = 0
        exec_count = 0

        for ext in extensions:
            self.print_lock.add_string_to_output(
                out_if(f"Extension .{ext}:", "INFO", not self.args.json, indent=4)
            )
            for spoof_ct in spoof_cts:
                result = self._test_variant(ext, spoof_ct, payload, source_tag)
                self._report_result(result)
                if result["accepted"]:
                    bypass_count += 1
                    if result.get("storage") == "executed":
                        exec_count += 1

        # Summary
        if exec_count > 0:
            self.print_lock.add_string_to_output(
                out_if(f"CRITICAL: {exec_count}/{total} variants bypassed AND executed! Server relies on Content-Type only.",
                       "VULN", not self.args.json, indent=4)
            )
        elif bypass_count > 0:
            self.print_lock.add_string_to_output(
                out_if(f"{bypass_count}/{total} variants accepted via Content-Type spoofing",
                       "VULN", not self.args.json, indent=4)
            )
        else:
            self.print_lock.add_string_to_output(
                out_if(f"Server rejected all {total} spoofed uploads — Content-Type is not the sole check",
                       "OK", not self.args.json, indent=4)
            )


def run(args, ptjsonlib, http_client, print_lock):
    """Entry point for running the Content-Type Bypass Test module."""
    Ct(args, ptjsonlib, http_client, print_lock).run()
