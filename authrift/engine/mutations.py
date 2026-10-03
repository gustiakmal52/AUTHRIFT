import copy
import fnmatch
import json
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl

from authrift.models import (
    ParsedRequest, Actor, Mutation, MutationType, ObjectIdentifier, IdentifierLocation,
)
from authrift.actors.actor import apply_actor
from authrift.detection.identifiers import detect_identifiers


def _rebuild_url(parsed_url, path: str, query_params: dict[str, str]) -> str:
    qs = urlencode(query_params) if query_params else ""
    return urlunparse((parsed_url.scheme, parsed_url.netloc, path, "", qs, ""))


def substitute_identifier_in_url(
    request: ParsedRequest,
    identifier: ObjectIdentifier,
    new_value: str,
) -> ParsedRequest:
    parsed = urlparse(request.url)

    if identifier.location == IdentifierLocation.URL_PATH:
        raw_segments = parsed.path.split("/")
        non_empty_idx = 0
        for i, seg in enumerate(raw_segments):
            if not seg:
                continue
            if non_empty_idx == identifier.path_segment_index:
                raw_segments[i] = str(new_value)
                break
            non_empty_idx += 1
        new_path = "/".join(raw_segments)
        new_qp = dict(request.query_params)
        new_url = _rebuild_url(parsed, new_path, new_qp)
        return request.model_copy(update={"url": new_url, "path": new_path})

    if identifier.location == IdentifierLocation.QUERY_PARAM:
        new_qp = dict(request.query_params)
        new_qp[identifier.name] = str(new_value)
        new_url = _rebuild_url(parsed, parsed.path, new_qp)
        return request.model_copy(update={"url": new_url, "query_params": new_qp})

    return request


def substitute_identifier_in_body(
    request: ParsedRequest,
    identifier: ObjectIdentifier,
    new_value: str,
) -> ParsedRequest:
    if identifier.location != IdentifierLocation.JSON_BODY or not request.body:
        return request

    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, TypeError):
        return request

    parts = identifier.name.split(".")
    obj = data
    for part in parts[:-1]:
        if isinstance(obj, dict) and part in obj:
            obj = obj[part]
        else:
            return request

    last_key = parts[-1]
    if isinstance(obj, dict) and last_key in obj:
        if isinstance(obj[last_key], int) and str(new_value).isdigit():
            obj[last_key] = int(new_value)
        else:
            obj[last_key] = str(new_value)

    return request.model_copy(update={"body": json.dumps(data)})


def substitute_identifier(
    request: ParsedRequest,
    identifier: ObjectIdentifier,
    new_value: str,
) -> ParsedRequest:
    if identifier.location in (IdentifierLocation.URL_PATH, IdentifierLocation.QUERY_PARAM):
        return substitute_identifier_in_url(request, identifier, new_value)
    elif identifier.location == IdentifierLocation.JSON_BODY:
        return substitute_identifier_in_body(request, identifier, new_value)
    return request


def _match_owned_object(ident: ObjectIdentifier, actor: Actor) -> tuple[str, str] | None:
    """Finds an owned object for an identifier matching either exact value or key name."""
    if not actor.owned_objects:
        return None

    for k, v in actor.owned_objects.items():
        if str(v) == ident.value:
            return (k, str(v))

    ident_name_norm = ident.name.lower().replace("_", "").rstrip("s")
    for k, v in actor.owned_objects.items():
        k_norm = k.lower().replace("_", "").rstrip("s")
        if k_norm == ident_name_norm or k_norm in ident_name_norm or ident_name_norm in k_norm:
            return (k, str(v))

    if len(actor.owned_objects) == 1 and ident.name.lower() in ("id", "unknown"):
        k, v = next(iter(actor.owned_objects.items()))
        return (k, str(v))

    return None


def generate_object_substitution(
    request: ParsedRequest,
    actor_a: Actor,
    actor_b: Actor,
) -> list[Mutation]:
    """
    Generates object substitution mutations only when an actual object/identity
    relationship is present and can be tested. Uses tri-state observations:
    1. Owner baseline (Actor A -> Object A)
    2. Test-actor control (Actor B -> Object B)
    3. Cross-object authorization test (Actor B -> Object A)
    """
    identifiers = detect_identifiers(request)
    mutations: list[Mutation] = []

    for ident in identifiers:
        match_a = _match_owned_object(ident, actor_a)
        match_b = _match_owned_object(ident, actor_b)

        if match_a:
            obj_key, val_a = match_a
            val_b = str(actor_b.owned_objects.get(obj_key, "")) if obj_key in actor_b.owned_objects else None

            req_a = substitute_identifier(request, ident, val_a)
            baseline_req = apply_actor(req_a, actor_a)

            control_req = None
            if val_b:
                req_b = substitute_identifier(request, ident, val_b)
                control_req = apply_actor(req_b, actor_b)

            test_req = apply_actor(req_a, actor_b)

            mutations.append(Mutation(
                mutation_type=MutationType.OBJECT_SUBSTITUTION,
                original_request=request,
                baseline_request=baseline_req,
                test_request=test_req,
                baseline_actor=actor_a,
                test_actor=actor_b,
                control_request=control_req,
                control_actor=actor_b if control_req else None,
                substituted_identifiers=[ident],
                description=(
                    f"Cross-object authorization test: Actor '{actor_b.name}' accessing "
                    f"{ident.location.value} '{ident.name}={val_a}' owned by '{actor_a.name}'"
                ),
            ))

        elif match_b:
            obj_key, val_b = match_b
            val_a = str(actor_a.owned_objects.get(obj_key, "")) if obj_key in actor_a.owned_objects else None

            req_b = substitute_identifier(request, ident, val_b)
            baseline_req = apply_actor(req_b, actor_b)

            control_req = None
            if val_a:
                req_a = substitute_identifier(request, ident, val_a)
                control_req = apply_actor(req_a, actor_a)

            test_req = apply_actor(req_b, actor_a)

            mutations.append(Mutation(
                mutation_type=MutationType.OBJECT_SUBSTITUTION,
                original_request=request,
                baseline_request=baseline_req,
                test_request=test_req,
                baseline_actor=actor_b,
                test_actor=actor_a,
                control_request=control_req,
                control_actor=actor_a if control_req else None,
                substituted_identifiers=[ident],
                description=(
                    f"Cross-object authorization test: Actor '{actor_a.name}' accessing "
                    f"{ident.location.value} '{ident.name}={val_b}' owned by '{actor_b.name}'"
                ),
            ))

    return mutations


def generate_session_substitution(
    request: ParsedRequest,
    actor_a: Actor,
    actor_b: Actor,
) -> list[Mutation]:
    """Generates a session-swap mutation comparing Actor A vs Actor B on the exact same request."""
    baseline_req = apply_actor(request, actor_a)
    test_req = apply_actor(request, actor_b)

    return [Mutation(
        mutation_type=MutationType.SESSION_SUBSTITUTION,
        original_request=request,
        baseline_request=baseline_req,
        test_request=test_req,
        baseline_actor=actor_a,
        test_actor=actor_b,
        description=f"Session substitution: Comparing '{actor_b.name}' vs baseline '{actor_a.name}'",
    )]


DEFAULT_PRIVILEGED_PATH_SEGMENTS = {
    "admin", "administrator", "staff", "management", "manage", "internal",
    "superuser", "root", "moderator", "backoffice",
}


def is_privileged_endpoint(
    request: ParsedRequest,
    privileged_path_segments: set[str] | None = None,
    privileged_endpoints: list[dict[str, str]] | None = None,
) -> bool:
    """
    Determines if an endpoint is privileged based on path segments or explicit config.
    Does NOT infer privilege merely because the HTTP method is state-changing.
    """
    if privileged_endpoints:
        req_method = request.method.value.upper()
        for entry in privileged_endpoints:
            entry_method = entry.get("method", "*").upper()
            entry_path = entry.get("path", "")
            method_matches = (entry_method == "*" or entry_method == req_method)
            path_matches = (request.path == entry_path or fnmatch.fnmatch(request.path, entry_path))
            if method_matches and path_matches:
                return True

    segments_to_check = privileged_path_segments if privileged_path_segments is not None else DEFAULT_PRIVILEGED_PATH_SEGMENTS
    raw_segments = {s.lower() for s in request.path.split("/") if s}
    if raw_segments & {s.lower() for s in segments_to_check}:
        return True

    return False


def generate_function_level_test(
    request: ParsedRequest,
    normal_actor: Actor,
    admin_actor: Actor,
    privileged_path_segments: set[str] | None = None,
    privileged_endpoints: list[dict[str, str]] | None = None,
) -> list[Mutation]:
    """
    Generates a Broken Function Level Authorization (BFLA) mutation where
    the privileged user (admin) is the baseline and the unprivileged user is tested.
    Only generated when an endpoint is classified as privileged.
    """
    if not is_privileged_endpoint(
        request,
        privileged_path_segments=privileged_path_segments,
        privileged_endpoints=privileged_endpoints,
    ):
        return []

    baseline_req = apply_actor(request, admin_actor)
    test_req = apply_actor(request, normal_actor)

    return [Mutation(
        mutation_type=MutationType.FUNCTION_LEVEL,
        original_request=request,
        baseline_request=baseline_req,
        test_request=test_req,
        baseline_actor=admin_actor,
        test_actor=normal_actor,
        description=(
            f"BFLA test: Unprivileged actor '{normal_actor.name}' attempting privileged "
            f"endpoint '{request.method.value} {request.path}' against baseline '{admin_actor.name}'"
        ),
    )]


def generate_mutations(
    request: ParsedRequest,
    actor_a: Actor,
    actor_b: Actor,
    admin_actor: Actor | None = None,
    privileged_path_segments: set[str] | None = None,
    privileged_endpoints: list[dict[str, str]] | None = None,
) -> list[Mutation]:
    mutations: list[Mutation] = []

    obj_mutations = generate_object_substitution(request, actor_a, actor_b)
    mutations.extend(obj_mutations)

    if not obj_mutations:
        mutations.extend(generate_session_substitution(request, actor_a, actor_b))

    if admin_actor:
        mutations.extend(generate_function_level_test(
            request,
            actor_b,
            admin_actor,
            privileged_path_segments=privileged_path_segments,
            privileged_endpoints=privileged_endpoints,
        ))

    return mutations
