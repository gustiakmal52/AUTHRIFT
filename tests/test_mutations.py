"""Tests for the mutation engine."""
from authrift.models import ParsedRequest, HttpMethod, Actor, MutationType
from authrift.engine.mutations import (
    generate_object_substitution,
    generate_session_substitution,
    generate_function_level_test,
    generate_mutations,
    substitute_identifier_in_url,
)
from authrift.detection.identifiers import detect_url_path_ids


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


def _make_req(path: str, method: HttpMethod = HttpMethod.GET) -> ParsedRequest:
    return ParsedRequest(
        method=method,
        url=f"https://target.example{path}",
        path=path,
        headers={"Authorization": "Bearer TOKEN_A"},
    )


def test_generate_object_substitution():
    req = _make_req("/api/orders/1001")
    mutations = generate_object_substitution(req, ACTOR_A, ACTOR_B)
    assert len(mutations) >= 1
    m = mutations[0]
    assert m.mutation_type == MutationType.OBJECT_SUBSTITUTION
    assert m.actor.name == "user_b"
    assert m.mutated_request.headers["Authorization"] == "Bearer TOKEN_B"


def test_generate_session_substitution():
    req = _make_req("/api/profile")
    mutations = generate_session_substitution(req, ACTOR_A, ACTOR_B)
    assert len(mutations) == 1
    m = mutations[0]
    assert m.mutation_type == MutationType.SESSION_SUBSTITUTION
    assert m.mutated_request.headers["Authorization"] == "Bearer TOKEN_B"


def test_generate_function_level_test():
    req = _make_req("/api/admin/users", HttpMethod.POST)
    mutations = generate_function_level_test(req, ACTOR_B, ADMIN)
    assert len(mutations) == 1
    assert mutations[0].mutation_type == MutationType.FUNCTION_LEVEL


def test_generate_function_level_skip_normal():
    req = _make_req("/api/orders/1001")
    mutations = generate_function_level_test(req, ACTOR_B, ADMIN)
    assert len(mutations) == 0


def test_generate_mutations_with_ids():
    req = _make_req("/api/orders/1001")
    mutations = generate_mutations(req, ACTOR_A, ACTOR_B, ADMIN)
    types = {m.mutation_type for m in mutations}
    assert MutationType.OBJECT_SUBSTITUTION in types


def test_generate_mutations_without_ids():
    req = _make_req("/api/profile")
    mutations = generate_mutations(req, ACTOR_A, ACTOR_B)
    assert len(mutations) >= 1
    assert mutations[0].mutation_type == MutationType.SESSION_SUBSTITUTION


def test_substitute_identifier_in_url_path():
    req = _make_req("/api/orders/1001")
    ids = detect_url_path_ids(req)
    assert len(ids) >= 1
    new_req = substitute_identifier_in_url(req, ids[0], "9999")
    assert "9999" in new_req.url
    assert "1001" not in new_req.path
