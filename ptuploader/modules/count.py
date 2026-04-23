"""
File Count Test – checks if the server enforces a limit on the number of files
uploaded simultaneously in a single request (e.g. via file[] parameters).

Sends requests with an increasing number of files and reports when the server
starts rejecting them or stops responding.

If -n is not provided, a built-in list of counts is used (1, 5, 10, 50, 100, 500, 1000, 5000, 10000).

Contains:
- Count class for performing the file count test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib, http_client, print_lock)
"""

from ptlibs.ptprinthelper import out_if

__TESTLABEL__ = "File Count Test:"

DEFAULT_COUNTS = [1, 5, 10, 50, 100, 500, 1000, 5000, 10000]


class Count:
    def __init__(self, args: object, ptjsonlib: object, http_client: object, print_lock: object) -> None:
        self.args        = args
        self.ptjsonlib   = ptjsonlib
        self.http_client = http_client
        self.print_lock  = print_lock
        self.param       = args.parameter or "file"

    def _get_counts(self) -> list:
        """Returns sorted list of file counts to test."""
        if self.args.number is not None:
            return [self.args.number]
        return list(DEFAULT_COUNTS)

    def _get_base_filename(self) -> str:
        """Returns base filename for uploaded files."""
        base = self.args.file or "test.txt"
        stem, _, ext = base.rpartition(".")
        stem = stem or base
        ext = ext or "txt"
        return f"{stem}_count.{ext}"

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

    def _test_count(self, base_filename: str, count: int) -> dict:
        """
        Uploads *count* files in a single request.
        Returns {accepted: bool, status: int|None, error: str|None, count: int}.
        """
        stem, _, ext = base_filename.rpartition(".")
        content_type = getattr(self.args, "content_type", None) or "application/octet-stream"
        data = dict(item.split("=", 1) for item in self.args.data.split("&")) if self.args.data else None

        # Build multipart file list
        # For count == 1 use the bare parameter name (baseline check).
        # For count > 1 use param[] array notation so the server sees
        # multiple files — unless the user already supplied "[]".
        if count == 1:
            param_name = self.param
        else:
            param_name = f"{self.param}[]" if not self.param.endswith("[]") else self.param
        file_list = []
        for i in range(count):
            fname = f"{stem}_{i}.{ext}"
            file_list.append((param_name, (fname, b"count test", content_type)))

        try:
            response = self.http_client.send_request(
                url=self.args.url,
                method="POST",
                files=file_list,
                data=data,
            )
        except Exception as e:
            return {"accepted": False, "status": None, "error": str(e), "count": count}

        if response is None:
            return {"accepted": False, "status": None, "error": "No response (timeout/connection error)", "count": count}

        status = response.status_code
        accepted = self._upload_accepted(response)

        error = None
        if status >= 500:
            error = f"Server error {status}"

        return {"accepted": accepted, "status": status, "error": error, "count": count}

    def run(self) -> None:
        self.print_lock.add_string_to_output(
            out_if(__TESTLABEL__, "INFO", not self.args.json)
        )

        counts = self._get_counts()
        filename = self._get_base_filename()
        max_accepted = 0
        first_rejected = None

        self.print_lock.add_string_to_output(
            out_if(f"Testing up to {counts[-1]} files per request  [{filename}]", "INFO", not self.args.json, indent=4)
        )

        for count in counts:
            result = self._test_count(filename, count)

            if result["accepted"]:
                max_accepted = count
                self.print_lock.add_string_to_output(
                    out_if(f"Accepted  [{count} files]", "OK", not self.args.json, indent=4)
                )
            elif result["error"]:
                if first_rejected is None:
                    first_rejected = count
                self.print_lock.add_string_to_output(
                    out_if(f"Error  [{count} files]  {result['error']}", "WARNING", not self.args.json, indent=4)
                )
                break
            else:
                if first_rejected is None:
                    first_rejected = count
                self.print_lock.add_string_to_output(
                    out_if(f"Rejected  [{count} files]", "OK", not self.args.json, indent=4)
                )

        # Summary
        if max_accepted > 0 and first_rejected:
            self.print_lock.add_string_to_output(
                out_if(
                    f"Max accepted count: {max_accepted} files (rejected at {first_rejected})",
                    "INFO", not self.args.json, indent=4
                )
            )
        elif max_accepted > 0 and not first_rejected:
            self.print_lock.add_string_to_output(
                out_if(
                    f"No file count limit detected - server accepted all counts up to {max_accepted}",
                    "VULN", not self.args.json, indent=4
                )
            )
            self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-COUNT")
        else:
            self.print_lock.add_string_to_output(
                out_if("Server rejected all tested counts", "OK", not self.args.json, indent=4)
            )


def run(args, ptjsonlib, http_client, print_lock):
    """Entry point for running the File Count Test module."""
    Count(args, ptjsonlib, http_client, print_lock).run()
