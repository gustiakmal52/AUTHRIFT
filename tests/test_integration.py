"""
Integration test: runs AUTHRIFT against the mock API to verify it detects
the vulnerable endpoint while correctly handling the secure endpoint.
"""
from authrift.models import ParsedRequest, HttpMethod, Actor, MutationType
from authrift.config import ScanConfig
from authrift.engine.runner import run_scan

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


def _make_request(path: str) -> ParsedRequest:
    return ParsedRequest(
        method=HttpMethod.GET,
        url=f"{BASE}{path}",
        path=path,
        headers={},
    )


def test_detects_vulnerable_endpoint():
    requests = [_make_request("/api/vulnerable/orders/1001")]
    config = ScanConfig(max_requests=10, timeout_s=10.0)

    result = run_scan(requests, ACTOR_A, ACTOR_B, None, config)

    assert len(result.findings) >= 1
    finding = result.findings[0]
    assert finding.score >= 30
    assert finding.diff.body_similarity > 0.8


def test_no_false_positive_on_secure_endpoint():
    requests = [_make_request("/api/secure/orders/1001")]
    config = ScanConfig(max_requests=10, timeout_s=10.0)

    result = run_scan(requests, ACTOR_A, ACTOR_B, None, config)

    high_findings = [f for f in result.findings if f.score >= 60]
    assert len(high_findings) == 0


ADMIN = Actor(
    name="admin",
    headers={"Authorization": "Bearer ADMIN_TOKEN"},
)


def test_profile_endpoint_session_swap():
    requests = [_make_request("/api/profile")]
    config = ScanConfig(max_requests=10, timeout_s=10.0)

    result = run_scan(requests, ACTOR_A, ACTOR_B, None, config)
    assert len(result.findings) == 0


def test_bfla_secure_integration():
    requests = [ParsedRequest(
        method=HttpMethod.POST,
        url=f"{BASE}/api/admin/users",
        path="/api/admin/users",
        headers={},
    )]
    config = ScanConfig(max_requests=10, timeout_s=10.0, allow_state_changing=True)

    result = run_scan(requests, ACTOR_A, ACTOR_B, ADMIN, config)
    assert len(result.findings) == 0


def test_bfla_vulnerable_integration():
    requests = [ParsedRequest(
        method=HttpMethod.POST,
        url=f"{BASE}/api/vulnerable/admin/users",
        path="/api/vulnerable/admin/users",
        headers={},
    )]
    config = ScanConfig(max_requests=10, timeout_s=10.0, allow_state_changing=True)

    result = run_scan(requests, ACTOR_A, ACTOR_B, ADMIN, config)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.mutation_type == MutationType.FUNCTION_LEVEL
    assert finding.baseline_actor == "admin"
    assert finding.test_actor == "user_b"
    assert finding.score >= 60


def test_scan_respects_max_requests():
    requests = [_make_request(f"/api/vulnerable/orders/{i}") for i in range(1001, 1010)]
    config = ScanConfig(max_requests=3, timeout_s=10.0)

    result = run_scan(requests, ACTOR_A, ACTOR_B, None, config)
    assert result.total_requests <= 3
