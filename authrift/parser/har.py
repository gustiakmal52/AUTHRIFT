import json
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from authrift.models import ParsedRequest, HttpMethod
from typing import List

STATIC_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico",
    ".svg", ".woff", ".woff2", ".ttf", ".eot", ".map"
}

def parse_har_string(content: str, include_static: bool = False) -> List[ParsedRequest]:
    har_data = json.loads(content)
    requests = []

    entries = har_data.get("log", {}).get("entries", [])

    for entry in entries:
        req = entry.get("request", {})
        if not req:
            continue

        method_str = req.get("method", "").upper()
        if method_str == "CONNECT":
            continue

        url = req.get("url", "")
        if url.startswith("chrome://") or url.startswith("about:"):
            continue

        parsed_url = urlparse(url)
        path = parsed_url.path

        if not include_static and path:
            ext = Path(path).suffix.lower()
            if ext in STATIC_EXTENSIONS:
                continue

        query_params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed_url.query).items()}

        headers_list = req.get("headers", [])
        headers = {h.get("name"): h.get("value") for h in headers_list if h.get("name")}

        post_data = req.get("postData", {})
        body = post_data.get("text")

        cookies_list = req.get("cookies", [])
        cookies = {c.get("name"): c.get("value") for c in cookies_list if c.get("name")}

        content_type = post_data.get("mimeType") or headers.get("Content-Type") or headers.get("content-type")

        if cookies and "Cookie" not in headers:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            headers["Cookie"] = cookie_str

        requests.append(ParsedRequest(
            method=HttpMethod(method_str),
            url=url,
            path=path,
            query_params=query_params,
            headers=headers,
            body=body,
            content_type=content_type,
            source="har"
        ))

    return requests

def parse_har(path: Path, include_static: bool = False) -> List[ParsedRequest]:
    content = path.read_text()
    return parse_har_string(content, include_static=include_static)
