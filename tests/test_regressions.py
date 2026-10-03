import json
import time
from pathlib import Path

import pytest
import httpx

from authrift.models import (
    ParsedRequest, HttpMethod, Actor, ObjectIdentifier, IdentifierLocation,
    MutationType, ConfidenceLevel, HttpResponse,
)
from authrift.config import ScanConfig
from authrift.actors.actor import apply_actor, swap_actor
from authrift.detection.identifiers import detect_identifiers
from authrift.detection.response_diff import check_owner_field_crossover, compare_responses
from authrift.detection.scoring import compute_signals, compute_score
from authrift.detection.authorization import analyze_authorization, reset_counter
from authrift.engine.mutations import (
    generate_object_substitution,
    generate_session_substitution,
    generate_function_level_test,
    generate_mutations,
)
from authrift.engine.runner import run_scan, RequestPacer
from authrift.reporting.json_report import write_json_report, finding_to_dict
from authrift.reporting.markdown import finding_to_markdown, write_reports

BASE = "http://127.0.0.1:9777"

ACTOR_A = Actor(
    name="user_a",
    headers={"Authorization": "Bearer TOKEN_A"},
    owned_objects={"orders": "1001"},
)
ACTOR_B = Actor(
    name="user_b",
    headers={"Authorization": "Bearer TOKEN_B"},
    owned_objects={"orders": "2001"},
)
ADMIN = Actor(
    name="admin",
    headers={"Authorization": "Bearer ADMIN_TOKEN"},
)
COOKIE_ACTOR_A = Actor(
    name="user_a",
    cookies={"session": "cookie_session_a"},
    owned_objects={"orders": "1001"},
)
COOKIE_ACTOR_B = Actor(
    name="user_b",
    cookies={"session": "cookie_session_b"},
    owned_objects={"orders": "2001"},
)


def _make_req(path: str, method: HttpMethod = HttpMethod.GET, **kwargs) -> ParsedRequest:
    return ParsedRequest(
        method=method,
        url=f"{BASE}{path}",
        path=path,
        headers={"Authorization": "Bearer CAPTURED_TOKEN", "Cookie": "session=captured_old"},
        **kwargs,
    )


def test_profile_endpoint_no_finding_regression():
    reset_counter()
    req = _make_req("/api/profile")
    config = ScanConfig(max_requests=10, timeout_s=5.0)
    result = run_scan([req], ACTOR_A, ACTOR_B, None, config)
    assert len(result.findings) == 0


def test_session_substitution_scoring_isolated_profile():
    baseline = HttpResponse(
        status_code=200,
        headers={"content-type": "application/json"},
        body=json.dumps({"username": "alice", "email": "alice@example.com", "role": "user"}),
        elapsed_ms=10.0,
        content_type="application/json",
    )
    test = HttpResponse(
        status_code=200,
        headers={"content-type": "application/json"},
        body=json.dumps({"username": "bob", "email": "bob@example.com", "role": "user"}),
        elapsed_ms=10.0,
        content_type="application/json",
    )
    req = _make_req("/api/profile")
    mutation = generate_session_substitution(req, ACTOR_A, ACTOR_B)[0]
    diff = compare_responses(baseline, test, baseline_actor=ACTOR_A, test_actor=ACTOR_B)
    signals = compute_signals(diff, mutation, baseline, test)
    score = compute_score(signals)
    assert score < 30


def test_real_object_substitution_tri_state_url_path():
    req = _make_req("/api/orders/1001")
    mutations = generate_object_substitution(req, ACTOR_A, ACTOR_B)
    assert len(mutations) == 1
    m = mutations[0]
    assert m.mutation_type == MutationType.OBJECT_SUBSTITUTION
    assert m.baseline_actor.name == "user_a"
    assert m.test_actor.name == "user_b"
    assert m.control_actor.name == "user_b"
    assert "/api/orders/1001" in m.baseline_request.url
    assert m.baseline_request.headers["Authorization"] == "Bearer TOKEN_A"
    assert "/api/orders/2001" in m.control_request.url
    assert m.control_request.headers["Authorization"] == "Bearer TOKEN_B"
    assert "/api/orders/1001" in m.test_request.url
    assert m.test_request.headers["Authorization"] == "Bearer TOKEN_B"


def test_real_object_substitution_query_param():
    req = ParsedRequest(
        method=HttpMethod.GET,
        url=f"{BASE}/api/orders?order_id=1001",
        path="/api/orders",
        query_params={"order_id": "1001"},
        headers={},
    )
    mutations = generate_object_substitution(req, ACTOR_A, ACTOR_B)
    assert len(mutations) == 1
    m = mutations[0]
    assert m.mutation_type == MutationType.OBJECT_SUBSTITUTION
    assert m.control_request.query_params["order_id"] == "2001"
    assert m.test_request.query_params["order_id"] == "1001"


def test_real_object_substitution_json_body():
    req = ParsedRequest(
        method=HttpMethod.POST,
        url=f"{BASE}/api/orders",
        path="/api/orders",
        headers={"content-type": "application/json"},
        body=json.dumps({"order_id": 1001}),
        content_type="application/json",
    )
    actor_a = Actor(name="user_a", owned_objects={"order_id": "1001"})
    actor_b = Actor(name="user_b", owned_objects={"order_id": "2001"})
    mutations = generate_object_substitution(req, actor_a, actor_b)
    assert len(mutations) == 1
    m = mutations[0]
    assert m.mutation_type == MutationType.OBJECT_SUBSTITUTION
    control_body = json.loads(m.control_request.body)
    assert control_body["order_id"] == 2001
    test_body = json.loads(m.test_request.body)
    assert test_body["order_id"] == 1001


def test_no_owned_objects_not_labeled_object_substitution():
    req = _make_req("/api/feed")
    mutations = generate_mutations(req, ACTOR_A, ACTOR_B, None)
    for m in mutations:
        assert m.mutation_type != MutationType.OBJECT_SUBSTITUTION
        assert m.mutation_type == MutationType.SESSION_SUBSTITUTION


def test_bfla_secure_admin_allowed_user_denied():
    reset_counter()
    req = _make_req("/api/admin/users", method=HttpMethod.POST)
    config = ScanConfig(max_requests=10, timeout_s=5.0, allow_state_changing=True)
    result = run_scan([req], ACTOR_A, ACTOR_B, ADMIN, config)
    bfla_findings = [f for f in result.findings if f.mutation_type == MutationType.FUNCTION_LEVEL]
    assert len(bfla_findings) == 0


def test_bfla_vulnerable_admin_allowed_user_allowed():
    reset_counter()
    req = _make_req("/api/vulnerable/admin/users", method=HttpMethod.POST)
    config = ScanConfig(max_requests=10, timeout_s=5.0, allow_state_changing=True)
    result = run_scan([req], ACTOR_A, ACTOR_B, ADMIN, config)
    bfla_findings = [f for f in result.findings if f.mutation_type == MutationType.FUNCTION_LEVEL]
    assert len(bfla_findings) == 1
    finding = bfla_findings[0]
    assert finding.baseline_actor == "admin"
    assert finding.test_actor == "user_b"
    assert finding.baseline_response.status_code == 200
    assert finding.test_response.status_code == 200
    assert finding.score >= 60


def test_apply_actor_strips_inherited_auth():
    req = ParsedRequest(
        method=HttpMethod.GET,
        url="https://example.com/api/test",
        path="/api/test",
        headers={
            "Authorization": "Bearer OLD_ORIGINAL",
            "Cookie": "session=old_cookie; tracking=xyz",
            "X-Api-Key": "OLD_KEY",
            "Accept": "application/json",
        },
        cookies={"session": "old_cookie"},
    )
    new_actor = Actor(
        name="user_b",
        headers={"Authorization": "Bearer NEW_TOKEN_B"},
        cookies={"session": "new_cookie_b"},
    )
    cleaned = apply_actor(req, new_actor)
    assert cleaned.headers["Authorization"] == "Bearer NEW_TOKEN_B"
    assert "X-Api-Key" not in cleaned.headers
    assert "Cookie" not in cleaned.headers
    assert cleaned.cookies == {"session": "new_cookie_b"}
    assert cleaned.headers["Accept"] == "application/json"


def test_cookie_session_switching_mock_api():
    req = ParsedRequest(
        method=HttpMethod.GET,
        url=f"{BASE}/api/secure/orders/1001",
        path="/api/secure/orders/1001",
        headers={"Authorization": "Bearer LEAKED_HEADER"},
    )
    cleaned = apply_actor(req, COOKIE_ACTOR_A)
    assert "Authorization" not in cleaned.headers
    assert cleaned.cookies == {"session": "cookie_session_a"}
    with httpx.Client(cookies=cleaned.cookies) as client:
        resp = client.get(cleaned.url)
        assert resp.status_code == 200
        assert resp.json()["owner_id"] == "user_a"


def test_json_report_redacts_sensitive_response_bodies(tmp_path: Path):
    finding = _create_mock_finding()
    scan_result = _create_mock_scan_result([finding])
    report_path = write_json_report(scan_result, str(tmp_path), include_raw_evidence=False)
    data = json.loads(report_path.read_text())
    test_body = json.loads(data["findings"][0]["test_response"]["body"])
    assert test_body["customer_email"] == "[REDACTED]"
    assert test_body["address"] == "[REDACTED]"
    assert test_body["id"] == "1001"


def test_json_report_include_raw_evidence_opt_in(tmp_path: Path):
    finding = _create_mock_finding()
    scan_result = _create_mock_scan_result([finding])
    report_path = write_json_report(scan_result, str(tmp_path), include_raw_evidence=True)
    data = json.loads(report_path.read_text())
    test_body = json.loads(data["findings"][0]["test_response"]["body"])
    assert test_body["customer_email"] == "alice@example.com"
    assert test_body["address"] == "123 Main St"


def test_markdown_report_redacts_sensitive_response_bodies(tmp_path: Path):
    finding = _create_mock_finding()
    scan_result = _create_mock_scan_result([finding])
    write_reports(scan_result, str(tmp_path), include_raw_evidence=False)
    finding_md = (tmp_path / "AUTH-001.md").read_text()
    assert "[REDACTED]" in finding_md
    assert "alice@example.com" not in finding_md


def test_check_owner_field_crossover_accuracy():
    baseline_body = json.dumps({"id": "1001", "owner_id": "user_a", "email": "a@x.com"})
    test_body = json.dumps({"id": "1001", "owner_id": "user_a", "email": "a@x.com"})
    mismatch, matches_test = check_owner_field_crossover(baseline_body, test_body, ACTOR_A, ACTOR_B)
    assert mismatch is True
    assert matches_test is False

    alice_profile = json.dumps({"username": "user_a", "email": "alice@x.com", "role": "user"})
    bob_profile = json.dumps({"username": "user_b", "email": "bob@x.com", "role": "user"})
    mismatch, matches_test = check_owner_field_crossover(alice_profile, bob_profile, ACTOR_A, ACTOR_B)
    assert mismatch is False
    assert matches_test is True

    system_a = json.dumps({"item": "A", "created_by": "system"})
    system_b = json.dumps({"item": "B", "created_by": "system"})
    mismatch, matches_test = check_owner_field_crossover(system_a, system_b, ACTOR_A, ACTOR_B)
    assert mismatch is False


def test_request_pacer_rate_limit():
    pacer = RequestPacer(rate_limit_rps=20.0, delay_ms=0)
    t0 = time.monotonic()
    pacer.pace_request()
    pacer.pace_request()
    pacer.pace_request()
    elapsed = time.monotonic() - t0
    assert elapsed >= 0.08


def _create_mock_finding():
    baseline_resp = HttpResponse(
        status_code=200,
        headers={"content-type": "application/json", "Authorization": "Bearer SECRET"},
        body=json.dumps({"id": "1001", "customer_email": "alice@example.com", "address": "123 Main St"}),
        elapsed_ms=15.0,
        content_type="application/json",
    )
    test_resp = HttpResponse(
        status_code=200,
        headers={"content-type": "application/json", "Authorization": "Bearer SECRET"},
        body=json.dumps({"id": "1001", "customer_email": "alice@example.com", "address": "123 Main St"}),
        elapsed_ms=15.0,
        content_type="application/json",
    )
    diff = compare_responses(baseline_resp, test_resp, ACTOR_A, ACTOR_B)
    req = _make_req("/api/vulnerable/orders/1001")
    mutation = generate_object_substitution(req, ACTOR_A, ACTOR_B)[0]
    signals = compute_signals(diff, mutation, baseline_resp, test_resp)
    score = compute_score(signals)

    from authrift.models import Finding
    return Finding(
        finding_id="AUTH-001",
        endpoint="/api/vulnerable/orders/1001",
        method=HttpMethod.GET,
        mutation_type=MutationType.OBJECT_SUBSTITUTION,
        baseline_actor="user_a",
        test_actor="user_b",
        baseline_response=baseline_resp,
        test_response=test_resp,
        diff=diff,
        signals=signals,
        score=score,
        confidence=ConfidenceLevel.HIGH,
    )


def _create_mock_scan_result(findings):
    from authrift.models import ScanResult
    return ScanResult(
        findings=findings,
        total_requests=1,
        total_mutations=1,
        skipped_unsafe=0,
        errors=[],
    )


def test_ordinary_write_endpoint_not_treated_as_privileged():
    reset_counter()
    req = _make_req("/api/orders", method=HttpMethod.POST)
    config = ScanConfig(max_requests=10, timeout_s=5.0, allow_state_changing=True)
    result = run_scan([req], ACTOR_A, ACTOR_B, ADMIN, config)
    bfla_findings = [f for f in result.findings if f.mutation_type == MutationType.FUNCTION_LEVEL]
    assert len(bfla_findings) == 0


def test_ordinary_write_endpoint_explicitly_configured_privileged():
    reset_counter()
    req = _make_req("/api/orders", method=HttpMethod.POST)
    config = ScanConfig(
        max_requests=10,
        timeout_s=5.0,
        allow_state_changing=True,
        privileged_endpoints=[{"method": "POST", "path": "/api/orders"}],
    )
    result = run_scan([req], ACTOR_A, ACTOR_B, ADMIN, config)
    bfla_findings = [f for f in result.findings if f.mutation_type == MutationType.FUNCTION_LEVEL]
    assert len(bfla_findings) == 1
    assert bfla_findings[0].endpoint == "/api/orders"


def test_admin_endpoint_auto_detected_as_privileged():
    reset_counter()
    req = _make_req("/api/admin/users", method=HttpMethod.POST)
    config = ScanConfig(max_requests=10, timeout_s=5.0, allow_state_changing=True)
    result = run_scan([req], ACTOR_A, ACTOR_B, ADMIN, config)
    assert len([f for f in result.findings if f.mutation_type == MutationType.FUNCTION_LEVEL]) == 0

    vulnerable_req = _make_req("/api/vulnerable/admin/users", method=HttpMethod.POST)
    vuln_result = run_scan([vulnerable_req], ACTOR_A, ACTOR_B, ADMIN, config)
    bfla_findings = [f for f in vuln_result.findings if f.mutation_type == MutationType.FUNCTION_LEVEL]
    assert len(bfla_findings) == 1
    assert bfla_findings[0].baseline_actor == "admin"
    assert bfla_findings[0].test_actor == "user_b"


def test_deterministic_identity_markers_correct_isolation():
    reset_counter()
    actor_alice = Actor(
        name="user_a",
        headers={"Authorization": "Bearer TOKEN_A"},
        identity_markers=["alice", "alice@example.com", "user-1001"],
    )
    actor_bob = Actor(
        name="user_b",
        headers={"Authorization": "Bearer TOKEN_B"},
        identity_markers=["bob", "bob@example.com", "user-2001"],
    )
    req = _make_req("/api/profile")
    config = ScanConfig(max_requests=10, timeout_s=5.0)
    result = run_scan([req], actor_alice, actor_bob, None, config)
    assert len(result.findings) == 0


def test_deterministic_identity_markers_cross_session_leakage():
    reset_counter()
    actor_alice = Actor(
        name="user_a",
        headers={"Authorization": "Bearer TOKEN_A"},
        identity_markers=["alice", "alice@example.com", "user-1001"],
    )
    actor_bob = Actor(
        name="user_b",
        headers={"Authorization": "Bearer TOKEN_B"},
        identity_markers=["bob", "bob@example.com", "user-2001"],
    )
    req = _make_req("/api/leaky/profile")
    config = ScanConfig(max_requests=10, timeout_s=5.0)
    result = run_scan([req], actor_alice, actor_bob, None, config)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.mutation_type == MutationType.SESSION_SUBSTITUTION
    assert finding.baseline_actor == "user_a"
    assert finding.test_actor == "user_b"
    assert finding.score >= 60
    for signal in finding.signals:
        assert "alice@example.com" not in signal.description


def test_global_static_endpoint_no_session_finding():
    reset_counter()
    req = _make_req("/api/health")
    config = ScanConfig(max_requests=10, timeout_s=5.0)
    result = run_scan([req], ACTOR_A, ACTOR_B, None, config)
    assert len(result.findings) == 0


def test_hard_request_budget_exact_limit():
    requests = [_make_req(f"/api/vulnerable/orders/{i}") for i in range(1001, 1008)]
    config = ScanConfig(max_requests=3, timeout_s=5.0)
    result = run_scan(requests, ACTOR_A, ACTOR_B, None, config)
    assert result.http_requests_sent <= 3
    assert result.http_requests_sent == 3


def test_hard_request_budget_single_request():
    requests = [_make_req("/api/vulnerable/orders/1001")]
    config = ScanConfig(max_requests=1, timeout_s=5.0)
    result = run_scan(requests, ACTOR_A, ACTOR_B, None, config)
    assert result.http_requests_sent <= 1
    assert result.http_requests_sent == 1
