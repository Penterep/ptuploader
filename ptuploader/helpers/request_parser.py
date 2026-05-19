"""
HTTP request file parser – parses a raw HTTP request (Burp Suite format)
or a base64-encoded request string and extracts the fields needed to replay it.
"""

import base64
import os
import re

_SKIP_HEADERS = frozenset({
    'host',
    'content-length',
    'transfer-encoding',
    'connection',
    'content-type',  # managed per-upload by each module
})


def _pop_header(headers: dict, name: str):
    """Case-insensitive header pop. Returns value or None."""
    for key in list(headers.keys()):
        if key.lower() == name.lower():
            return headers.pop(key)
    return None


def _get_header(headers: dict, name: str) -> str:
    """Case-insensitive header lookup. Returns value or ''."""
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return ''


def _load_request_text(request: str) -> str:
    """Load raw HTTP request text from a file path or a base64-encoded string."""
    if os.path.isfile(request):
        with open(request, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()
    try:
        decoded = base64.b64decode(request, validate=True).decode('utf-8', errors='replace')
        return decoded
    except Exception:
        raise ValueError(f"Cannot read request: not a valid file path or base64 string")


def _parse_multipart_body(body: str, boundary: str):
    """
    Parse a multipart/form-data body using the given boundary.

    Returns:
        (file_field, form_fields):
            file_field  (str|None)  – name of the part with filename= (the file upload field)
            form_fields (dict)      – {name: value} for non-file parts
    """
    file_field = None
    form_fields = {}

    delimiter = '--' + boundary
    raw_parts = body.split(delimiter)

    for raw_part in raw_parts:
        part = raw_part.lstrip('\n')
        if not part or part.rstrip() == '--':
            continue

        part_head, sep, part_body = part.partition('\n\n')
        if not sep:
            part_head, part_body = part, ''

        cd = ''
        for line in part_head.split('\n'):
            if line.lower().lstrip().startswith('content-disposition:'):
                cd = line.partition(':')[2].strip()
                break
        if not cd:
            continue

        name_match = re.search(r'\bname="([^"]*)"', cd)
        if not name_match:
            continue
        name = name_match.group(1)

        if re.search(r'\bfilename="', cd) is not None:
            file_field = name
        else:
            form_fields[name] = part_body.rstrip('\n')

    return file_field, form_fields


def parse_request_file(request: str, default_scheme: str = 'https') -> dict:
    """
    Parse a raw HTTP request file or base64-encoded request string.

    Extracts: HTTP method, full URL (built from Host header + path),
    remaining headers (dict), Cookie header value, and request body.
    For multipart/form-data bodies, also extracts the file field name
    and the other form fields.

    Args:
        request: File path or base64-encoded raw HTTP request.
        default_scheme: Scheme to prepend when building the URL ('https' by default).

    Returns:
        dict with keys:
            method     (str)       – HTTP method in uppercase
            url        (str)       – reconstructed target URL
            headers    (dict)      – remaining headers (Host/Cookie/skip-list removed)
            cookie     (str|None)  – Cookie header value, or None
            data       (str|None)  – request body, or form-urlencoded non-file fields
            parameter  (str|None)  – name of multipart file field, or None
    """
    text = _load_request_text(request)
    text = text.replace('\r\n', '\n').replace('\r', '\n')

    head, _, body = text.partition('\n\n')
    lines = head.split('\n')

    request_line = next((l.strip() for l in lines if l.strip()), '')
    parts = request_line.split()
    if len(parts) < 2:
        raise ValueError(f"Invalid HTTP request line: {request_line!r}")

    method = parts[0].upper()
    path = parts[1]

    headers = {}
    for line in lines[1:]:
        if not line.strip() or ':' not in line:
            continue
        name, _, value = line.partition(':')
        headers[name.strip()] = value.strip()

    host = _pop_header(headers, 'Host') or ''
    cookie = _pop_header(headers, 'Cookie')

    # Capture Content-Type before skip-headers removes it
    content_type = _get_header(headers, 'Content-Type')

    # Auto-detect scheme from Origin or Referer before removing skip headers
    scheme = default_scheme
    for hint_header in ('Origin', 'Referer'):
        val = headers.get(hint_header, '')
        if val.startswith('http://'):
            scheme = 'http'
            break
        if val.startswith('https://'):
            scheme = 'https'
            break

    for key in list(headers.keys()):
        if key.lower() in _SKIP_HEADERS:
            headers.pop(key)

    url = f"{scheme}://{host}{path}"

    parameter = None
    data = body.strip() or None

    if 'multipart/form-data' in content_type.lower() and body.strip():
        boundary_match = re.search(r'boundary=([^;\s]+)', content_type)
        if boundary_match:
            boundary = boundary_match.group(1).strip().strip('"')
            file_field, form_fields = _parse_multipart_body(body, boundary)
            if file_field:
                parameter = file_field
            if form_fields:
                data = '&'.join(f"{k}={v}" for k, v in form_fields.items())
            elif file_field:
                # Multipart with only a file part — clear the binary body
                data = None

    return {
        'method': method,
        'url': url,
        'headers': headers,
        'cookie': cookie,
        'data': data,
        'parameter': parameter,
    }
