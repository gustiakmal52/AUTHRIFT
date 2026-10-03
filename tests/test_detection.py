"""Tests for response comparison and scoring."""
import json

from authrift.models import HttpResponse, ResponseDiff, ScoreSignal, Mutation, MutationType, ParsedRequest, HttpMethod, Actor, ObjectIdentifier, IdentifierLocation
from authrift.detection.response_diff import (
    body_similarity,
    json_structural_similarity,
    find_sensitive_fields,
    detect_authorization_error,
    compare_responses,
)
from authrift.detection.scoring import compute_signals, compute_score, classify
from authrift.models import ConfidenceLevel


def _make_response(status: int = 200, body: str = "", content_type: str | None = None) -> HttpResponse:
    return HttpResponse(
        status_code=status,
        headers={"content-type": content_type or "application/json"},
        body=body,
        elapsed_ms=50.0,
        content_type=content_type or "application/json",
    )


def test_body_similarity_identical():
    assert body_similarity("hello", "hello") == 1.0


def test_body_similarity_empty():
    assert body_similarity("", "") == 1.0


def test_body_similarity_different():
    sim = body_similarity("abcdef", "xyzxyz")
    assert sim < 0.5


def test_json_structural_similarity_identical():
    a = '{"name": "alice", "age": 30}'
    b = '{"name": "bob", "age": 25}'
    sim = json_structural_similarity(a, b)
    assert sim is not None
    assert sim == 1.0


def test_json_structural_similarity_different():
    a = '{"name": "alice"}'
    b = '{"email": "bob@test.com"}'
    sim = json_structural_similarity(a, b)
    assert sim is not None
    assert sim < 1.0


def test_json_structural_similarity_non_json():
    assert json_structural_similarity("not json", "also not") is None


def test_find_sensitive_fields():
    body = json.dumps({
        "id": 1,
        "customer_email": "a@b.com",
        "address": "123 Main",
        "total": 100,
    })
    fields = find_sensitive_fields(body)
    assert "customer_email" in fields
    assert "address" in fields


def test_detect_authorization_error_403():
    resp = _make_response(403, '{"detail": "Forbidden"}')
    assert detect_authorization_error(resp) is True


def test_detect_authorization_error_200():
    resp = _make_response(200, '{"data": "ok"}')
    assert detect_authorization_error(resp) is False


def test_compare_responses_similar():
    baseline = _make_response(200, '{"id": 1, "email": "a@b.com"}')
    test = _make_response(200, '{"id": 1, "email": "a@b.com"}')
    diff = compare_responses(baseline, test)
    assert diff.status_match is True
    assert diff.body_similarity == 1.0


def test_scoring_high_confidence():
    baseline = _make_response(200, json.dumps({
        "id": "1001", "owner_id": "user_a",
        "customer_email": "a@b.com", "total": 100,
    }))
    test = _make_response(200, json.dumps({
        "id": "1001", "owner_id": "user_a",
        "customer_email": "a@b.com", "total": 100,
    }))
    diff = compare_responses(baseline, test, "user_a")

    req = ParsedRequest(
        method=HttpMethod.GET, url="https://x.com/api/orders/1001",
        path="/api/orders/1001", headers={},
    )
    mutation = Mutation(
        mutation_type=MutationType.OBJECT_SUBSTITUTION,
        original_request=req, mutated_request=req,
        actor=Actor(name="user_b"),
        target_actor=Actor(name="user_a"),
        substituted_identifiers=[ObjectIdentifier(
            name="orders", value="1001",
            location=IdentifierLocation.URL_PATH, path_segment_index=2,
        )],
        description="test",
    )

    signals = compute_signals(diff, mutation, baseline, test)
    score = compute_score(signals)
    assert score >= 60
    assert classify(score) in (ConfidenceLevel.LIKELY, ConfidenceLevel.HIGH)


def test_scoring_auth_error():
    baseline = _make_response(200, '{"id": 1}')
    test = _make_response(403, '{"detail": "forbidden"}')
    diff = compare_responses(baseline, test)

    req = ParsedRequest(
        method=HttpMethod.GET, url="https://x.com/api/orders/1",
        path="/api/orders/1", headers={},
    )
    mutation = Mutation(
        mutation_type=MutationType.SESSION_SUBSTITUTION,
        original_request=req, mutated_request=req,
        actor=Actor(name="user_b"),
        description="test",
    )

    signals = compute_signals(diff, mutation, baseline, test)
    score = compute_score(signals)
    assert score < 30
