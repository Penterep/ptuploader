"""
Antivirus Detection Test – checks if the server scans uploaded files for malware.
Uploads an EICAR test file and checks whether it is accepted or blocked.

Contains:
- Antivir class for performing the detection test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib, http_client, print_lock)
"""

from ptlibs.ptprinthelper import out_if


__TESTLABEL__ = "Antivirus Detection Test:"

EICAR_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class Antivir:
    def __init__(self, args: object, ptjsonlib: object, http_client: object, print_lock: object) -> None:
        self.args        = args
        self.ptjsonlib   = ptjsonlib
        self.http_client = http_client
        self.print_lock  = print_lock
        self.param       = args.parameter or "file"

    def _get_filenames(self) -> list:
        """Returns list of filenames to test based on -f and -e arguments."""
        base = self.args.file or "eicar.txt"
        stem, _, ext = base.rpartition(".")
        stem = stem or base
        ext = ext or "txt"
        if self.args.extensions:
            return [f"{stem}_antivir.{e}" for e in self.args.extensions]
        return [f"{stem}_antivir.{ext}"]

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

    def _test_file(self, filename: str) -> None:
        """Uploads a single EICAR file and reports the result."""
        content_type = getattr(self.args, "content_type", None) or "application/octet-stream"
        files = {self.param: (filename, EICAR_STRING.encode(), content_type)}
        data = dict(item.split("=", 1) for item in self.args.data.split("&")) if self.args.data else None
        response = self.http_client.send_request(
            url=self.args.url,
            method="POST",
            files=files,
            data=data,
        )

        accepted = self._upload_accepted(response)

        if not accepted:
            self.print_lock.add_string_to_output(
                out_if(f"EICAR file was rejected during upload  [{filename}]", "OK", not self.args.json, indent=4)
            )
            return

        if self.args.storage:
            storage_url = self.args.storage.rstrip("/") + "/" + filename
            check = self.http_client.send_request(url=storage_url, method="GET", allow_redirects=True)
            accessible = check is not None and check.status_code == 200

            if accessible:
                self.print_lock.add_string_to_output(
                    out_if(f"EICAR file uploaded successfully  [{filename}]", "VULN", not self.args.json, indent=4)
                )
                self.print_lock.add_string_to_output(
                    out_if(storage_url, "TEXT", not self.args.json, indent=8)
                )
                self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-ANTIVIR")
            else:
                self.print_lock.add_string_to_output(
                    out_if(f"EICAR file uploaded successfully but is not accessible  [{filename}]", "WARNING", not self.args.json, indent=4)
                )
        else:
            self.print_lock.add_string_to_output(
                out_if(f"EICAR file uploaded successfully  [{filename}]", "VULN", not self.args.json, indent=4)
            )
            self.ptjsonlib.add_vulnerability("PTV-WEB-UPLOAD-ANTIVIR")

    def run(self) -> None:
        self.print_lock.add_string_to_output(out_if(__TESTLABEL__, "TITLE", not self.args.json, colortext=True))
        for filename in self._get_filenames():
            self._test_file(filename)


def run(args, ptjsonlib, http_client, print_lock):
    """Entry point for running the Antivirus Detection Test module."""
    Antivir(args, ptjsonlib, http_client, print_lock).run()
