from authrift.models import Actor, ParsedRequest

DEFAULT_AUTH_HEADERS = {
    "authorization",
    "cookie",
    "x-api-key",
    "proxy-authorization",
    "x-csrf-token",
    "x-auth-token",
    "x-session-id",
    "session-id",
}


def apply_actor(
    request: ParsedRequest,
    actor: Actor,
    auth_headers: set[str] | None = None,
) -> ParsedRequest:
    """
    Applies an actor's credentials to a request after deterministically
    stripping any authentication material inherited from the captured request.
    """
    new_request = request.model_copy(deep=True)
    strip_set = {h.lower() for h in (auth_headers or DEFAULT_AUTH_HEADERS)}

    # 1. Remove existing authentication headers inherited from original request
    cleaned_headers = {}
    for k, v in new_request.headers.items():
        k_lower = k.lower()
        if k_lower in strip_set or k_lower.endswith("-api-key"):
            continue
        cleaned_headers[k] = v
    new_request.headers = cleaned_headers

    # 2. Clear inherited cookies
    new_request.cookies = {}

    # 3. Apply actor's credentials exclusively
    if actor.headers:
        new_request.headers.update(actor.headers)
    if actor.cookies:
        new_request.cookies.update(actor.cookies)

    return new_request


def swap_actor(
    request: ParsedRequest,
    original_actor: Actor,
    new_actor: Actor,
    auth_headers: set[str] | None = None,
) -> ParsedRequest:
    """
    Swaps an actor's credentials deterministically.
    """
    return apply_actor(request, new_actor, auth_headers=auth_headers)
