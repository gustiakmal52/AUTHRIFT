import shlex
from urllib.parse import urlparse, parse_qs
from pathlib import Path
from typing import List
from authrift.models import ParsedRequest, HttpMethod

def parse_raw_http(text: str) -> ParsedRequest:
    lines = text.replace("
", "
").split("
")
    if not lines:
        raise ValueError("Empty request")
        
    first_line = lines[0].strip().split()
    if len(first_line) < 2:
        raise ValueError("Invalid request line")
        
    method = HttpMethod(first_line[0].upper())
    path = first_line[1]
    
    headers = {}
    body = None
    
    header_end_idx = 1
    for i in range(1, len(lines)):
        line = lines[i]
        if not line.strip():
            header_end_idx = i
            break
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip()] = value.strip()
    else:
        header_end_idx = len(lines)
        
    if header_end_idx < len(lines) - 1:
        body = "
".join(lines[header_end_idx + 1:])
        
    host = headers.get("Host", headers.get("host"))
    
    if not host:
        if path.startswith("http://") or path.startswith("https://"):
            parsed = urlparse(path)
            host = parsed.netloc
        else:
            raise ValueError("Missing Host header and path is not an absolute URL")
            
    if not path.startswith("http"):
        host_name = host.split(":")[0]
        scheme = "http" if host_name in ("localhost", "127.0.0.1", "0.0.0.0") else "https"
        url = f"{scheme}://{host}{path}"
    else:
        url = path

    parsed_url = urlparse(url)
    query_params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed_url.query).items()}
    
    content_type = headers.get("Content-Type", headers.get("content-type"))
    
    return ParsedRequest(
        method=method,
        url=url,
        path=parsed_url.path,
        query_params=query_params,
        headers=headers,
        body=body,
        content_type=content_type,
        source="raw_http"
    )

def parse_curl(command: str) -> ParsedRequest:
    command = command.strip()
    if command.startswith("curl"):
        command = command[4:].strip()
        
    command = command.replace("\
", " ")
    tokens = shlex.split(command)
    
    url = ""
    method_str = "GET"
    headers = {}
    body = None
    
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token in ("-H", "--header"):
            i += 1
            if i < len(tokens):
                h_parts = tokens[i].split(":", 1)
                if len(h_parts) == 2:
                    headers[h_parts[0].strip()] = h_parts[1].strip()
        elif token in ("-X", "--request"):
            i += 1
            if i < len(tokens):
                method_str = tokens[i].upper()
        elif token in ("-d", "--data", "--data-raw"):
            i += 1
            if i < len(tokens):
                body = tokens[i]
                if method_str == "GET":
                    method_str = "POST"
        elif token in ("-b", "--cookie"):
            i += 1
            if i < len(tokens):
                headers["Cookie"] = tokens[i]
        elif not token.startswith("-") and not url:
            url = token
        i += 1
        
    parsed_url = urlparse(url)
    query_params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed_url.query).items()}
    
    content_type = headers.get("Content-Type", headers.get("content-type"))
    
    return ParsedRequest(
        method=HttpMethod(method_str),
        url=url,
        path=parsed_url.path,
        query_params=query_params,
        headers=headers,
        body=body,
        content_type=content_type,
        source="curl"
    )

def parse_request_file(path: Path) -> List[ParsedRequest]:
    content = path.read_text()
    
    delimiters = ["###", "---"]
    parts = [content]
    
    for d in delimiters:
        if d in content:
            parts = [p.strip() for p in content.split(d) if p.strip()]
            break
            
    requests = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
            
        if part.startswith("curl "):
            requests.append(parse_curl(part))
        else:
            requests.append(parse_raw_http(part))
            
    return requests
