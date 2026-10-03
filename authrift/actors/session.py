from authrift.models import ParsedRequest, Actor

def extract_auth_info(request: ParsedRequest) -> dict[str, str]:
    auth_info = {}
    for k, v in request.headers.items():
        k_lower = k.lower()
        if k_lower in ("authorization", "cookie", "x-api-key") or "token" in k_lower or "auth" in k_lower:
            auth_info[k] = v
    return auth_info

def requests_share_session(req_a: ParsedRequest, req_b: ParsedRequest) -> bool:
    auth_a = extract_auth_info(req_a)
    auth_b = extract_auth_info(req_b)
    if not auth_a and not auth_b:
        return True
    return auth_a == auth_b
