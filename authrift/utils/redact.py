import json
from typing import Any

SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-csrf-token",
    "proxy-authorization",
    "x-auth-token",
}

SENSITIVE_FIELDS = {
    "email",
    "phone",
    "address",
    "token",
    "secret",
    "api_key",
    "apikey",
    "password",
    "balance",
    "invoice",
    "payment",
    "ssn",
    "credit_card",
    "card_number",
}


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    redacted = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADERS or k.lower().endswith("-api-key"):
            redacted[k] = "[REDACTED]"
        else:
            redacted[k] = v
    return redacted


def redact_value(value: str) -> str:
    return "[REDACTED]"


def is_sensitive_field(field_name: str) -> bool:
    normalized = field_name.lower().replace("_", "").replace("-", "")
    for pattern in SENSITIVE_FIELDS:
        if pattern.replace("_", "") in normalized:
            return True
    return False


def redact_json_fields(data: Any) -> Any:
    if isinstance(data, dict):
        return {
            k: redact_value(v) if is_sensitive_field(k) else redact_json_fields(v)
            for k, v in data.items()
        }
    elif isinstance(data, list):
        return [redact_json_fields(item) for item in data]
    return data


def redact_response_body(body: str) -> str:
    """Redacts sensitive fields in JSON response bodies for reporting."""
    if not body:
        return body
    try:
        data = json.loads(body)
        redacted = redact_json_fields(data)
        return json.dumps(redacted, indent=2)
    except (json.JSONDecodeError, TypeError):
        return body
