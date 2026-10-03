"""Tests for identifier detection."""
from authrift.detection.identifiers import (
    looks_like_identifier,
    has_id_param_name,
    detect_url_path_ids,
    detect_query_param_ids,
    detect_body_ids,
    detect_identifiers,
)
from authrift.models import ParsedRequest, HttpMethod, IdentifierLocation


def _make_request(path: str = "/api/test", url: str | None = None, **kwargs) -> ParsedRequest:
    return ParsedRequest(
        method=HttpMethod.GET,
        url=url or f"https://example.com{path}",
        path=path,
        headers={},
        **kwargs,
    )


def test_looks_like_identifier_integer():
    assert looks_like_identifier("1832") == "integer"
    assert looks_like_identifier("0") == "integer"


def test_looks_like_identifier_uuid():
    assert looks_like_identifier("550e8400-e29b-41d4-a716-446655440000") == "uuid"


def test_looks_like_identifier_mongo():
    assert looks_like_identifier("507f1f77bcf86cd799439011") == "mongo_objectid"


def test_looks_like_identifier_not_id():
    assert looks_like_identifier("api") is None
    assert looks_like_identifier("orders") is None
    assert looks_like_identifier("") is None


def test_has_id_param_name():
    assert has_id_param_name("user_id") is True
    assert has_id_param_name("order_id") is True
    assert has_id_param_name("id") is True
    assert has_id_param_name("name") is False
    assert has_id_param_name("description") is False


def test_detect_url_path_ids():
    req = _make_request("/api/orders/1832")
    ids = detect_url_path_ids(req)
    assert len(ids) == 1
    assert ids[0].value == "1832"
    assert ids[0].name == "orders"
    assert ids[0].location == IdentifierLocation.URL_PATH


def test_detect_url_path_multiple_ids():
    req = _make_request("/api/users/42/orders/1832")
    ids = detect_url_path_ids(req)
    assert len(ids) == 2
    values = {i.value for i in ids}
    assert "42" in values
    assert "1832" in values


def test_detect_query_param_ids():
    req = _make_request(
        "/api/search",
        url="https://example.com/api/search?user_id=42&page=1",
        query_params={"user_id": "42", "page": "1"},
    )
    ids = detect_query_param_ids(req)
    assert len(ids) == 1
    assert ids[0].name == "user_id"
    assert ids[0].value == "42"


def test_detect_body_ids():
    req = _make_request(
        "/api/transfer",
        body='{"user_id": 42, "amount": 100}',
        content_type="application/json",
    )
    ids = detect_body_ids(req)
    assert len(ids) == 1
    assert ids[0].name == "user_id"
    assert ids[0].value == "42"


def test_detect_identifiers_combined():
    req = _make_request(
        "/api/orders/1832",
        url="https://example.com/api/orders/1832?tenant_id=99",
        query_params={"tenant_id": "99"},
    )
    ids = detect_identifiers(req)
    assert len(ids) >= 2
    values = {i.value for i in ids}
    assert "1832" in values
    assert "99" in values
