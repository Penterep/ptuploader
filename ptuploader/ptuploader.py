#!/usr/bin/python3
"""
Copyright (c) 2025 Penterep Security s.r.o.

ptuploader is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

ptuploader is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ptuploader.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import importlib
import os
import threading
import sys; sys.path.append(__file__.rsplit("/", 1)[0])

from types import ModuleType

from ptlibs import ptjsonlib, ptmisclib, ptnethelper
from ptlibs.ptprinthelper import ptprint, print_banner, help_print, get_colored_text
from ptlibs.threads import ptthreads, printlock
from ptlibs.http.http_client import HttpClient

from _version import __version__


class PtUploader:
    def __init__(self, args):
        self.ptjsonlib   = ptjsonlib.PtJsonLib()
        self.ptthreads   = ptthreads.PtThreads()
        self._lock       = threading.Lock()
        self.args        = args
        self.args.headers = ptnethelper.get_request_headers(args)
        self.http_client = HttpClient(args=self.args, ptjsonlib=self.ptjsonlib)

    def fetch(self, url, allow_redirects=False):
        try:
            return self.http_client.send_request(
                url=url,
                method="GET",
                headers=self.args.headers,
                allow_redirects=allow_redirects,
                timeout=self.args.timeout,
            )
        except Exception:
            return None

    def run(self) -> None:
        """Main method"""
        if self.args.upload_type and self.args.upload_type != "MULTIPART":
            ptprint(f"Upload type '{self.args.upload_type}' is currently in development", "WARNING", not self.args.json)
            return

        tests = self.args.tests or _get_all_available_modules()
        self.ptthreads.threads(tests, self.run_single_module, self.args.threads)

        self.ptjsonlib.set_status("finished")
        ptprint(self.ptjsonlib.get_result_json(), "", self.args.json)

    def run_single_module(self, module_name: str) -> None:
        """Safely loads and executes a specified module's `run()` function.

        The method locates the module file in the "modules" directory, imports it dynamically,
        and executes its `run()` method with provided arguments and a shared `ptjsonlib` object.
        Each module call receives a dedicated PrintLock for thread-safe, atomic output.

        If the module or its `run()` method is missing, or if an error occurs during execution,
        it logs appropriate messages to the user.

        Args:
            module_name (str): The name of the module (without `.py` extension) to execute.
        """
        try:
            with self._lock:
                module = _import_module_from_path(module_name)

            if hasattr(module, "run") and callable(module.run):
                print_lock = printlock.PrintLock()
                try:
                    module.run(
                        args=self.args,
                        ptjsonlib=self.ptjsonlib,
                        http_client=self.http_client,
                        print_lock=print_lock,
                    )

                except Exception as e:
                    ptprint(str(e), "ERROR", not self.args.json)
                finally:
                    print_lock.lock_print_output(condition=not self.args.json)
            else:
                ptprint(f"Module '{module_name}' does not have 'run' function", "WARNING", not self.args.json)

        except FileNotFoundError:
            ptprint(f"Module '{module_name}' not found", "ERROR", not self.args.json)
        except Exception as e:
            ptprint(f"Error running module '{module_name}': {e}", "ERROR", not self.args.json)


def _import_module_from_path(module_name: str) -> ModuleType:
    """
    Dynamically imports a Python module from a given file path.

    Args:
        module_name (str): Name under which to register the module.

    Returns:
        ModuleType: The loaded Python module object.

    Raises:
        ImportError: If the module cannot be found or loaded.
    """
    # `-ts` uppercases test names (e.g. EXT) but module files are lowercase
    # (ext.py). Normalize so lookups don't depend on a case-insensitive
    # filesystem — on case-sensitive systems (Linux) the wrong case fails.
    module_name = module_name.lower()
    module_path = os.path.join(os.path.dirname(__file__), "modules", f"{module_name}.py")

    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None:
        raise ImportError(f"Cannot find spec for {module_name} at {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _get_all_available_modules() -> list:
    """
    Returns a list of available Python module names from the 'modules' directory.

    Modules must:
    - Not start with an underscore
    - Have a '.py' extension
    """
    modules_folder = os.path.join(os.path.dirname(__file__), "modules")
    available_modules = [
        f.rsplit(".py", 1)[0]
        for f in sorted(os.listdir(modules_folder))
        if f.endswith(".py") and not f.startswith("_")
    ]
    return available_modules


def _remove_data_field(data: str, field: str) -> str | None:
    """Remove a named field from a urlencoded-style data string (``k=v&k2=v2``).

    Used when ``-P`` selects a parameter that already exists in the request body:
    the selected field becomes the file-upload field, so it must be pulled out of
    the data to avoid being sent twice. Returns the remaining data, or None if no
    fields remain.
    """
    remaining = [
        item for item in data.split("&")
        if item and item.split("=", 1)[0] != field
    ]
    return "&".join(remaining) if remaining else None


def _apply_request_file(args) -> None:
    """Parse the request file and fill in any args fields not already set via CLI.

    The ``-P``/``--parameter`` switch is context-sensitive here: with a request
    file it *selects* which parameter in the request is tested. If the selected
    parameter is an existing form field it is removed from the data so the upload
    field is not duplicated; if ``-P`` is omitted, the file field auto-detected
    from the request is used.
    """
    from helpers.request_parser import parse_request_file

    try:
        parsed = parse_request_file(args.request)
    except ValueError as e:
        ptprint(str(e), "ERROR", not args.json)
        sys.exit(1)

    if not args.url:
        args.url = parsed['url']

    if not args.cookie and parsed['cookie']:
        args.cookie = parsed['cookie']

    # Capture the user-supplied -P before falling back to the auto-detected field.
    user_parameter = args.parameter

    if not args.data and parsed['data']:
        args.data = parsed['data']

    if not args.parameter and parsed.get('parameter'):
        args.parameter = parsed['parameter']

    # If the user explicitly selected a parameter that already exists in the
    # request body, pull it out of the data so it isn't sent in both places.
    if user_parameter and args.data:
        args.data = _remove_data_field(args.data, user_parameter)

    if parsed['headers']:
        existing_lower = set()
        if args.headers:
            existing_lower = {h.split(':')[0].strip().lower() for h in args.headers}
        else:
            args.headers = []

        for name, value in parsed['headers'].items():
            if name.lower() == 'user-agent' and not args.user_agent:
                args.user_agent = value
            elif name.lower() not in existing_lower:
                args.headers.append(f"{name}:{value}")


def get_help():
    """
    Generate structured help content for the CLI tool.

    Returns:
        list: A list of dictionaries representing sections of help content.
    """

    def _get_available_modules_help() -> list:
        rows = []
        available_modules = _get_all_available_modules()
        for module in available_modules:
            mod = _import_module_from_path(module)
            label = getattr(mod, "__TESTLABEL__", f"Test for {module.upper()}")
            row = ["", "", f" {module.upper()}", label.rstrip(':')]
            rows.append(row)
        return sorted(rows, key=lambda x: x[2])

    return [
        {"description": ["Tool for testing file upload vulnerabilities on web servers"]},
        {"usage": ["ptuploader <options>"]},
        {"usage_example": [
            "ptuploader -u https://www.example.com/upload -f file.php",
            "ptuploader -u https://www.example.com/upload -f file.php -ts EXT EXEC",
            "ptuploader -u https://www.example.com/upload -r request.txt -s http://example.com/uploads/",
        ]},
        {"options": [
            ["-u",  "--url",          "<url>",            "Tested URL"],
            ["-f",  "--file",         "<filename>",       "File to upload"],
            ["-sz", "--size",         "<size>",           "Size of uploaded file"],
            ["-n",  "--number",       "<number>",         "Number of uploaded files"],
            ["-e",  "--extensions",   "<extensions>",     "Set extensions of uploaded file"],
            ["-l",  "--language",     "<language>",       "Set app programming language (PHP, ASP, JSP, NET, PY, JS)"],
            ["-T",  "--type",         "<type>",           "Set upload type (multipart)"],
            ["-ct", "--content-type", "<mimetype>",       "Set Content-Type for uploaded file"],
            ["-r",  "--request",      "<request>",        "Set request file or content of request in base64 (headers included)"],
            ["-d",  "--data",         "<data>",           "Set request-data"],
            ["-P",  "--parameter",    "<parameter>",      "Set parameter to test (e.g. GET, POST parameters)"],
            ["-s",  "--storage",      "<url_to_dir>",     "Set URL to directory with upload (http://example.com/uploads/)"],
            ["-w",  "--wordlist",     "<file>",           "Set custom wordlist file for storage discovery"],
            ["-sy", "--string-yes",   "<string>",         "Set the string that must be included in the response to pass the success test"],
            ["-sn", "--string-no",    "<string>",         "Set the string that must not be included in the response to pass the success test"],
            ["-ts", "--tests",        "<test>",           "Specify one or more tests to perform:"],
            *_get_available_modules_help(),
            ["", "", "", ""],
            ["-ua", "--user-agent",   "<user-agent>",     "Set User-Agent header"],
            ["-c",  "--cookie",       "<cookie>",         "Set Cookie(s)"],
            ["-H",  "--headers",      "<header:value>",   "Set custom header(s)"],
            ["-p",  "--proxy",        "<proxy>",          "Set Proxy"],
            ["-t",  "--threads",      "<threads>",        "Set thread count (default 10)"],
            ["-vv", "--verbose",      "",                 "Enable verbose mode"],
            ["-v",  "--version",      "",                 "Show script version and exit"],
            ["-h",  "--help",         "",                 "Show this help message and exit"],
            ["-j",  "--json",         "",                 "Output in JSON format"],
        ]}
    ]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False, description=f"{SCRIPTNAME} <options>")

    # Target
    parser.add_argument("-u",  "--url",          type=str, required=False, default=None)
    parser.add_argument("-f",  "--file",         type=str, default=None)
    parser.add_argument("-sz", "--size",         type=str, default=None)
    parser.add_argument("-n",  "--number",       type=int, default=None)
    parser.add_argument("-e",  "--extensions",   type=str, nargs="+", default=None)
    parser.add_argument("-l",  "--language",     type=lambda s: s.upper(), default=None,
                        choices=["PHP", "ASP", "JSP", "NET", "PY", "JS"])
    parser.add_argument("-T",  "--type",         type=lambda s: s.upper(), default=None,
                        choices=["MULTIPART", "RAW", "JSON", "CHUNKED", "PUT", "WEBDAV", "WEBSOCKET"],
                        dest="upload_type")
    parser.add_argument("-ct", "--content-type", type=str, default=None, dest="content_type")
    parser.add_argument("-r",  "--request",      type=str, default=None)
    parser.add_argument("-d",  "--data",         type=str, default=None)
    parser.add_argument("-P",  "--parameter",    type=str, default=None)
    parser.add_argument("-s",  "--storage",      type=str, default=None)
    parser.add_argument("-w",  "--wordlist",     type=str, default=None)
    parser.add_argument("-sy", "--string-yes",   type=str, default=None, dest="string_yes")
    parser.add_argument("-sn", "--string-no",    type=str, default=None, dest="string_no")

    # Tests
    parser.add_argument("-ts", "--tests",        type=lambda s: s.upper(), nargs="+", default=None,
                        choices=["ANTIVIR", "MAXSIZE", "COUNT", "EXT", "CHARS", "EXEC",
                                 "ADS", "TRAVERSAL", "CONTENT", "CT", "XXE", "ZIPBOMB", "FINDSTORAGE",
                                 "LISTTYPE"])

    # HTTP options
    parser.add_argument("-ua", "--user-agent",   type=str, default=None, dest="user_agent")
    parser.add_argument("-c",  "--cookie",       type=str, default=None)
    parser.add_argument("-H",  "--headers",      type=str, nargs="+", default=None)
    parser.add_argument("-p",  "--proxy",        type=str, default=None)

    # General options
    parser.add_argument("-t",  "--threads",      type=int, default=10)
    parser.add_argument("-vv", "--verbose",      action="store_true")
    parser.add_argument("-j",  "--json",         action="store_true")
    parser.add_argument("-v",  "--version",      action="version", version=f"{SCRIPTNAME} {__version__}")

    parser.add_argument("--socket-address",      type=str, default=None)
    parser.add_argument("--socket-port",         type=str, default=None)
    parser.add_argument("--process-ident",       type=str, default=None)

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprint(help_print(get_help(), SCRIPTNAME, __version__))
        sys.exit(0)

    args = parser.parse_args()

    if not args.url and not args.request:
        parser.error("one of -u/--url or -r/--request is required")

    if args.request:
        _apply_request_file(args)

    if not args.url:
        parser.error("could not determine URL — provide -u/--url or include a Host header in the request file")

    print_banner(SCRIPTNAME, __version__, args.json, 0)
    return args


def main():
    global SCRIPTNAME
    SCRIPTNAME = os.path.splitext(os.path.basename(__file__))[0]
    args = parse_args()
    script = PtUploader(args)
    script.run()


if __name__ == "__main__":
    main()
