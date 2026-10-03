import json
from difflib import SequenceMatcher
from typing import Any

from authrift.models import HttpResponse, ResponseDiff, Actor
from authrift.utils.redact import is_sensitive_field

DYNAMIC_FIELDS = {
    "timestamp", "created_at", "updated_at", "modified_at",
    "request_id", "trace_id", "correlation_id",
    "csrf_token", "nonce", "etag",
    "date", "expires",
}

OWNER_FIELD_NAMES = {
    "owner", "owner_id", "ownerid",
    "user_id", "userid", "user", "username",
    "email", "user_email", "customer_email",
    "created_by", "author", "author_id",
    "account_id", "accountid", "account",
    "tenant_id", "tenantid",
    "sub", "login", "handle",
}


def body_similarity(body_a: str, body_b: str) -> float:
    if not body_a and not body_b:
        return 1.0
    if not body_a or not body_b:
        return 0.0
    return SequenceMatcher(None, body_a, body_b).ratio()


def json_structure_keys(obj: Any, prefix: str = "") -> set[str]:
    keys: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else k
            keys.add(path)
            keys.update(json_structure_keys(v, path))
    elif isinstance(obj, list):
        for item in obj:
            keys.update(json_structure_keys(item, prefix))
    return keys


def json_structural_similarity(body_a: str, body_b: str) -> float | None:
    try:
        obj_a = json.loads(body_a)
        obj_b = json.loads(body_b)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None

    keys_a = json_structure_keys(obj_a)
    keys_b = json_structure_keys(obj_b)

    if not keys_a and not keys_b:
        return 1.0

    union = keys_a | keys_b
    if not union:
        return 1.0
    return len(keys_a & keys_b) / len(union)


def find_sensitive_fields(body: str) -> list[str]:
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, TypeError, ValueError):
        return []

    keys = json_structure_keys(obj)
    return [k for k in keys if is_sensitive_field(k.split(".")[-1])]


def detect_authorization_error(response: HttpResponse) -> bool:
    if response.status_code in (401, 403, 407):
        return True
    if not response.body:
        return False
    lower_body = response.body.lower()
    error_strings = [
        "unauthorized", "forbidden", "access denied",
        "not permitted", "insufficient permissions",
    ]
    return any(e in lower_body for e in error_strings)


def check_owner_field_crossover(
    baseline_body: str,
    test_body: str,
    baseline_actor: Actor | str | None = None,
    test_actor: Actor | str | None = None,
) -> tuple[bool, bool]:
    """
    Checks ownership field alignment:
    - Returns (owner_mismatch, owner_matches_test_actor)
    - owner_mismatch: test response explicitly points to baseline actor's ownership
    - owner_matches_test_actor: test response explicitly points to test actor's ownership (isolation confirmed)
    """
    try:
        test_obj = json.loads(test_body)
    except (json.JSONDecodeError, TypeError, ValueError):
        return False, False

    def find_owner_values(obj: Any) -> set[str]:
        values: set[str] = set()
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k.lower() in OWNER_FIELD_NAMES and isinstance(v, (str, int)):
                    values.add(str(v).lower())
                values.update(find_owner_values(v))
        elif isinstance(obj, list):
            for item in obj:
                values.update(find_owner_values(item))
        return values

    def find_all_scalars(obj: Any) -> set[str]:
        values: set[str] = set()
        if isinstance(obj, dict):
            for v in obj.values():
                values.update(find_all_scalars(v))
        elif isinstance(obj, list):
            for item in obj:
                values.update(find_all_scalars(item))
        elif isinstance(obj, (str, int)):
            values.add(str(obj).lower())
        return values

    test_owner_values = find_owner_values(test_obj)
    test_all_values = find_all_scalars(test_obj)
    test_combined = test_owner_values | test_all_values
    if not test_combined:
        return False, False

    baseline_ids: set[str] = set()
    if isinstance(baseline_actor, str):
        baseline_ids.add(baseline_actor.lower())
    elif isinstance(baseline_actor, Actor):
        baseline_ids.add(baseline_actor.name.lower())
        if baseline_actor.owned_objects:
            baseline_ids.update(str(v).lower() for v in baseline_actor.owned_objects.values())
        if baseline_actor.identity_markers:
            baseline_ids.update(str(m).lower() for m in baseline_actor.identity_markers)

    test_ids: set[str] = set()
    if isinstance(test_actor, str):
        test_ids.add(test_actor.lower())
    elif isinstance(test_actor, Actor):
        test_ids.add(test_actor.name.lower())
        if test_actor.owned_objects:
            test_ids.update(str(v).lower() for v in test_actor.owned_objects.values())
        if test_actor.identity_markers:
            test_ids.update(str(m).lower() for m in test_actor.identity_markers)

    owner_matches_test = bool(test_ids & test_combined)
    owner_mismatch = bool((baseline_ids & test_combined) and not (test_ids & test_combined))

    return owner_mismatch, owner_matches_test


def compare_responses(
    baseline: HttpResponse,
    test: HttpResponse,
    baseline_actor: Actor | str | None = None,
    test_actor: Actor | str | None = None,
    control_status: int | None = None,
) -> ResponseDiff:
    sim = body_similarity(baseline.body, test.body)
    json_sim = json_structural_similarity(baseline.body, test.body)
    auth_error = detect_authorization_error(test)
    owner_mismatch, owner_matches_test = check_owner_field_crossover(
        baseline.body, test.body, baseline_actor, test_actor,
    )
    sensitive = find_sensitive_fields(test.body)

    return ResponseDiff(
        status_match=(baseline.status_code == test.status_code),
        baseline_status=baseline.status_code,
        test_status=test.status_code,
        body_similarity=sim,
        json_structure_similarity=json_sim,
        content_length_diff=abs(len(baseline.body) - len(test.body)),
        sensitive_fields_in_response=sensitive,
        owner_field_mismatch=owner_mismatch,
        owner_field_matches_test_actor=owner_matches_test,
        authorization_error_detected=auth_error,
        control_status=control_status,
    )
