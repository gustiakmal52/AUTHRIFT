import httpx

from authrift.models import ParsedRequest, HttpResponse, HttpMethod


def send_request_sync(request: ParsedRequest, timeout: float = 30.0) -> HttpResponse:
    method = request.method.value
    with httpx.Client(follow_redirects=False, verify=False, timeout=timeout) as client:
        resp = client.request(
            method=method,
            url=request.url,
            headers=request.headers,
            cookies=request.cookies or None,
            content=request.body.encode() if request.body else None,
        )
        return HttpResponse(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body=resp.text,
            elapsed_ms=resp.elapsed.total_seconds() * 1000,
            content_type=resp.headers.get("content-type"),
        )


async def send_request(request: ParsedRequest, timeout: float = 30.0) -> HttpResponse:
    method = request.method.value
    async with httpx.AsyncClient(follow_redirects=False, verify=False, timeout=timeout) as client:
        resp = await client.request(
            method=method,
            url=request.url,
            headers=request.headers,
            cookies=request.cookies or None,
            content=request.body.encode() if request.body else None,
        )
        return HttpResponse(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body=resp.text,
            elapsed_ms=resp.elapsed.total_seconds() * 1000,
            content_type=resp.headers.get("content-type"),
        )
