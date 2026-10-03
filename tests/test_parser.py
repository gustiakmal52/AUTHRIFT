"""Tests for raw HTTP and cURL parsing."""
from pathlib import Path

from authrift.parser.raw_http import parse_raw_http, parse_curl, parse_request_file
from authrift.models import HttpMethod


def test_parse_raw_http_basic():
    raw = (
        "GET /api/orders/1832 HTTP/1.1\r\n"
        "Host: target.example\r\n"
        "Authorization: Bearer TOKEN\r\n"
        "Accept: application/json\r\n"
        "\r\n"
    )
    req = parse_raw_http(raw)
    assert req.method == HttpMethod.GET
    assert req.path == "/api/orders/1832"
    assert "target.example" in req.url
    assert req.headers["Authorization"] == "Bearer TOKEN"
    assert req.source == "raw_http"


def test_parse_raw_http_with_body():
    raw = (
        "POST /api/orders HTTP/1.1\n"
        "Host: target.example\n"
        "Content-Type: application/json\n"
        "\n"
        '{"item": "widget", "qty": 2}'
    )
    req = parse_raw_http(raw)
    assert req.method == HttpMethod.POST
    assert req.body is not None
    assert "widget" in req.body
    assert req.content_type == "application/json"


def test_parse_curl_basic():
    cmd = "curl 'https://target.example/api/orders/1832' -H 'Authorization: Bearer TOKEN'"
    req = parse_curl(cmd)
    assert req.method == HttpMethod.GET
    assert req.path == "/api/orders/1832"
    assert req.headers["Authorization"] == "Bearer TOKEN"
    assert req.source == "curl"


def test_parse_curl_post():
    cmd = (
        "curl 'https://target.example/api/orders' "
        "-X POST "
        "-H 'Content-Type: application/json' "
        "-d '{\"item\": \"widget\"}'"
    )
    req = parse_curl(cmd)
    assert req.method == HttpMethod.POST
    assert req.body is not None
    assert "widget" in req.body


def test_parse_curl_implicit_post():
    cmd = "curl 'https://api.example.com/data' -d 'key=value'"
    req = parse_curl(cmd)
    assert req.method == HttpMethod.POST


def test_parse_request_file_multiple(tmp_path: Path):
    content = (
        "GET /api/a HTTP/1.1\n"
        "Host: example.com\n"
        "\n"
        "###\n"
        "GET /api/b HTTP/1.1\n"
        "Host: example.com\n"
    )
    f = tmp_path / "requests.txt"
    f.write_text(content)
    reqs = parse_request_file(f)
    assert len(reqs) == 2
    assert reqs[0].path == "/api/a"
    assert reqs[1].path == "/api/b"
