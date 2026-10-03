"""Tests for redaction utilities."""
from authrift.utils.redact import (
    redact_headers,
    is_sensitive_field,
    redact_json_fields,
)


def test_redact_headers():
    headers = {
        "Authorization": "Bearer secret_token",
        "Content-Type": "application/json",
        "Cookie": "session=abc123",
        "Accept": "application/json",
    }
    result = redact_headers(headers)
    assert result["Authorization"] == "[REDACTED]"
    assert result["Cookie"] == "[REDACTED]"
    assert result["Content-Type"] == "application/json"
    assert result["Accept"] == "application/json"


def test_is_sensitive_field():
    assert is_sensitive_field("email") is True
    assert is_sensitive_field("customer_email") is True
    assert is_sensitive_field("password") is True
    assert is_sensitive_field("api_key") is True
    assert is_sensitive_field("name") is False
    assert is_sensitive_field("id") is False


def test_redact_json_fields():
    data = {
        "id": 1,
        "email": "alice@example.com",
        "name": "Alice",
        "nested": {
            "api_key": "secret123",
            "label": "test",
        },
    }
    result = redact_json_fields(data)
    assert result["email"] == "[REDACTED]"
    assert result["name"] == "Alice"
    assert result["id"] == 1
    assert result["nested"]["api_key"] == "[REDACTED]"
    assert result["nested"]["label"] == "test"
