"""
Zip Bomb Test – checks whether the server automatically extracts uploaded
archives (ZIP, TAR, GZ, etc.) without size limits.

Uploads test archives containing files with unique markers and checks
whether the server extracts them into storage.  Also tests with a mild
zip bomb to detect extraction without protection (slow / timed-out
response).

Contains:
- Zipbomb class for performing the zip bomb test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib, http_client, print_lock)
"""

import io
import time
import uuid
import zipfile
import tarfile

from ptlibs.ptprinthelper import out_if

__TESTLABEL__ = "Zip Bomb Test:"

MARKER_CONTENT = "PTUPLOADER_ZIPBOMB_MARKER"

# Uncompressed size for the zip bomb payload (zeros compress very well)
ZIPBOMB_UNCOMPRESSED_SIZE = 10 * 1024 * 1024  # 10 MB

# Response-time threshold (seconds) above which we suspect server-side extraction
SLOW_RESPONSE_THRESHOLD = 10


# ---------------------------------------------------------------------------
# Archive builders – all produce bytes from (inner_name, content)
# ---------------------------------------------------------------------------

def _make_marker_name(stem: str, tag: str) -> str:
    """Generate a unique marker filename for a specific test."""
    short_id = uuid.uuid4().hex[:8]
    return f"{stem}_zb_{tag}_{short_id}.txt"


def _build_zip(inner_name: str, content: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(inner_name, content)
    return buf.getvalue()


def _build_tar(inner_name: str, content: bytes, compression: str = "") -> bytes:
    buf = io.BytesIO()
    mode = f"w:{compression}" if compression else "w"
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        info = tarfile.TarInfo(name=inner_name)
        info.size = len(content)
        tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _build_zipbomb() -> bytes:
    """Small ZIP that expands to ~10 MB (mild, non-destructive)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.txt", b"\x00" * ZIPBOMB_UNCOMPRESSED_SIZE)
    return buf.getvalue()


def _build_nested_zip(inner_name: str, content: bytes) -> bytes:
    """ZIP containing another ZIP that contains the marker file."""
    inner_zip = _build_zip(inner_name, content)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("inner.zip", inner_zip)
    return buf.getvalue()


# (label, extension, content-type, builder)
ARCHIVE_TESTS = [
    ("ZIP archive",     "zip",     "application/zip",
     lambda name, content: _build_zip(name, content)),
    ("TAR archive",     "tar",     "application/x-tar",
     lambda name, content: _build_tar(name, content)),
    ("TAR.GZ archive",  "tar.gz",  "application/gzip",
     lambda name, content: _build_tar(name, content, "gz")),
    ("TAR.BZ2 archive", "tar.bz2", "application/x-bzip2",
     lambda name, content: _build_tar(name, content, "bz2")),
]


class Zipbomb:
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

    # ------------------------------------------------------------------
    # Upload & storage helpers
    # ------------------------------------------------------------------

    def _upload_archive(self, filename: str, body: bytes, content_type: str) -> tuple:
        """Upload archive.  Returns (accepted, elapsed_seconds, error)."""
        files = {self.param: (filename, body, content_type)}
        data = dict(item.split("=", 1) for item in self.args.data.split("&")) if self.args.data else None

        try:
            start = time.time()
            response = self.http_client.send_request(
                url=self.args.url,
                method="POST",
                files=files,
                data=data,
            )
            elapsed = time.time() - start
            accepted = self._upload_accepted(response)
            return accepted, elapsed, False
        except Exception:
            return False, 0.0, True

    def _check_extracted(self, marker_name: str, archive_stem: str) -> bool:
        """Check if the marker file appeared in storage (root or subdirectory)."""
        if not self.args.storage:
            return False

        base = self.args.storage.rstrip("/")
        candidates = [
            f"{base}/{marker_name}",
            f"{base}/{archive_stem}/{marker_name}",
        ]

        for url in candidates:
            try:
                response = self.http_client.send_request(
                    url=url, method="GET", allow_redirects=True,
                )
                if response and response.status_code == 200:
                    if MARKER_CONTENT in response.text:
                        return True
            except Exception:
                pass
        return False

    # ------------------------------------------------------------------
    # Individual test methods
    # ------------------------------------------------------------------

    def _test_archive(self, label: str, archive_ext: str, content_type: str,
                      builder, stem: str) -> dict:
        tag = archive_ext.replace(".", "")
        marker_name = _make_marker_name(stem, tag)
        marker_content = MARKER_CONTENT.encode()

        filename = f"{stem}_zipbomb.{archive_ext}"
        archive_stem = f"{stem}_zipbomb"
        body = builder(marker_name, marker_content)

        accepted, elapsed, error = self._upload_archive(filename, body, content_type)

        extracted = False
        if accepted and self.args.storage:
            extracted = self._check_extracted(marker_name, archive_stem)

        return {
            "label": label, "filename": filename, "marker": marker_name,
            "accepted": accepted, "extracted": extracted,
            "elapsed": elapsed, "error": error,
        }

    def _test_nested(self, stem: str) -> dict:
        marker_name = _make_marker_name(stem, "nested")
        marker_content = MARKER_CONTENT.encode()

        filename = f"{stem}_zipbomb_nested.zip"
        archive_stem = f"{stem}_zipbomb_nested"
        body = _build_nested_zip(marker_name, marker_content)

        accepted, elapsed, error = self._upload_archive(filename, body, "application/zip")

        extracted = False
        if accepted and self.args.storage:
            extracted = self._check_extracted(marker_name, archive_stem)

        return {
            "label": "Nested ZIP (zip in zip)", "filename": filename,
            "marker": marker_name,
            "accepted": accepted, "extracted": extracted,
            "elapsed": elapsed, "error": error,
        }

    def _test_bomb(self, stem: str) -> dict:
        filename = f"{stem}_zipbomb_bomb.zip"
        body = _build_zipbomb()

        accepted, elapsed, error = self._upload_archive(filename, body, "application/zip")

        return {
            "label": f"Zip bomb (~{ZIPBOMB_UNCOMPRESSED_SIZE // (1024 * 1024)}MB uncompressed)",
            "filename": filename,
            "accepted": accepted, "extracted": False,
            "elapsed": elapsed, "error": error,
            "is_bomb": True,
        }

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def _report_result(self, result: dict) -> None:
        label = result["label"]
        fname = result["filename"]
        elapsed = result.get("elapsed", 0)

        if result["error"]:
            if result.get("is_bomb"):
                self.print_lock.add_string_to_output(
                    out_if(f"Error/timeout — possible extraction  [{label}]  {fname}",
                           "WARNING", not self.args.json, indent=8)
                )
            else:
                self.print_lock.add_string_to_output(
                    out_if(f"Error  [{label}]  {fname}",
                           "WARNING", not self.args.json, indent=8)
                )
            return

        if not result["accepted"]:
            self.print_lock.add_string_to_output(
                out_if(f"Rejected  [{label}]  {fname}",
                       "OK", not self.args.json, indent=8)
            )
            return

        # Zip bomb — judge by response time
        if result.get("is_bomb"):
            if elapsed > SLOW_RESPONSE_THRESHOLD:
                self.print_lock.add_string_to_output(
                    out_if(f"Accepted — slow response ({elapsed:.1f}s) — possible extraction  [{label}]  {fname}",
                           "VULN", not self.args.json, indent=8)
                )
                self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-ZIPBOMB")
            else:
                self.print_lock.add_string_to_output(
                    out_if(f"Accepted ({elapsed:.1f}s)  [{label}]  {fname}",
                           "WARNING", not self.args.json, indent=8)
                )
            return

        # Archive extraction tests
        if result["extracted"]:
            self.print_lock.add_string_to_output(
                out_if(f"EXTRACTED — server unpacks archives!  [{label}]  {fname}",
                       "VULN", not self.args.json, indent=8)
            )
            if self.args.storage:
                self.print_lock.add_string_to_output(
                    out_if("Marker found in storage",
                           "TEXT", not self.args.json, indent=12)
                )
            self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-ZIPBOMB")
        elif self.args.storage:
            self.print_lock.add_string_to_output(
                out_if(f"Accepted, not extracted  [{label}]  {fname}",
                       "OK", not self.args.json, indent=8)
            )
        else:
            self.print_lock.add_string_to_output(
                out_if(f"Accepted (no storage URL to verify extraction)  [{label}]  {fname}",
                       "WARNING", not self.args.json, indent=8)
            )

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run(self) -> None:
        self.print_lock.add_string_to_output(
            out_if(__TESTLABEL__, "INFO", not self.args.json)
        )

        stem = self._get_stem()
        total = len(ARCHIVE_TESTS) + 2  # +nested +bomb

        self.print_lock.add_string_to_output(
            out_if(f"Testing {total} archive variants...",
                   "INFO", not self.args.json, indent=4)
        )

        extracted_count = 0
        accepted_count = 0

        # Phase 1 — archive format tests
        self.print_lock.add_string_to_output(
            out_if("Archive format tests:", "INFO", not self.args.json, indent=4)
        )
        for label, ext, ct, builder in ARCHIVE_TESTS:
            result = self._test_archive(label, ext, ct, builder, stem)
            self._report_result(result)
            if result["accepted"]:
                accepted_count += 1
            if result["extracted"]:
                extracted_count += 1

        # Phase 2 — nested ZIP
        self.print_lock.add_string_to_output(
            out_if("Nested archive test:", "INFO", not self.args.json, indent=4)
        )
        nested = self._test_nested(stem)
        self._report_result(nested)
        if nested["accepted"]:
            accepted_count += 1
        if nested["extracted"]:
            extracted_count += 1

        # Phase 3 — zip bomb
        self.print_lock.add_string_to_output(
            out_if("Zip bomb test:", "INFO", not self.args.json, indent=4)
        )
        bomb = self._test_bomb(stem)
        self._report_result(bomb)
        if bomb["accepted"]:
            accepted_count += 1

        # Summary
        if extracted_count > 0:
            self.print_lock.add_string_to_output(
                out_if(f"CRITICAL: Server extracts archives! {extracted_count} format(s) confirmed — zip bomb attack possible",
                       "VULN", not self.args.json, indent=4)
            )
        elif accepted_count > 0:
            self.print_lock.add_string_to_output(
                out_if(f"Server accepted {accepted_count}/{total} archives but extraction not detected",
                       "WARNING", not self.args.json, indent=4)
            )
        else:
            self.print_lock.add_string_to_output(
                out_if(f"Server rejected all {total} archive uploads",
                       "OK", not self.args.json, indent=4)
            )


def run(args, ptjsonlib, http_client, print_lock):
    """Entry point for running the Zip Bomb Test module."""
    Zipbomb(args, ptjsonlib, http_client, print_lock).run()
