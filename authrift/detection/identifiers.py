import re
from urllib.parse import urlparse, parse_qs
import json
from authrift.models import ParsedRequest, ObjectIdentifier, IdentifierLocation

ID_PARAM_PATTERNS = [
    "id", "user_id", "userid", "account_id", "accountid",
    "order_id", "orderid", "document_id", "documentid",
    "tenant_id", "tenantid", "owner_id", "ownerid",
    "project_id", "projectid", "team_id", "teamid",
    "organization_id", "orgid", "org_id",
    "item_id", "itemid", "resource_id", "resourceid",
    "file_id", "fileid", "record_id", "recordid",
    "invoice_id", "invoiceid", "payment_id", "paymentid",
]

ID_VALUE_PATTERNS = {
    "integer": re.compile(r"^d+$"),
    "uuid": re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I),
    "ulid": re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$"),
    "mongo_objectid": re.compile(r"^[0-9a-f]{24}$", re.I),
    "short_hash": re.compile(r"^[0-9a-f]{8,16}$", re.I),
    "generic_alphanum_id": re.compile(r"^[a-zA-Z0-9_-]{4,64}$"),
}

def looks_like_identifier(value: str) -> str | None:
    patterns = ["integer", "uuid", "ulid", "mongo_objectid", "short_hash"]
    for p in patterns:
        if ID_VALUE_PATTERNS[p].match(str(value)):
            return p
    return None

def has_id_param_name(name: str) -> bool:
    lower_name = name.lower()
    return any(lower_name == p or lower_name.endswith(p) for p in ID_PARAM_PATTERNS)

def detect_url_path_ids(request: ParsedRequest) -> list[ObjectIdentifier]:
    ids = []
    parsed_url = urlparse(request.url)
    segments = [s for s in parsed_url.path.split('/') if s]
    for i, segment in enumerate(segments):
        if looks_like_identifier(segment):
            name_hint = segments[i-1] if i > 0 else "unknown"
            ids.append(ObjectIdentifier(
                name=name_hint,
                value=segment,
                location=IdentifierLocation.URL_PATH,
                path_segment_index=i
            ))
    return ids

def detect_query_param_ids(request: ParsedRequest) -> list[ObjectIdentifier]:
    ids = []
    parsed_url = urlparse(request.url)
    qs = parse_qs(parsed_url.query)
    for k, v_list in qs.items():
        if has_id_param_name(k):
            for v in v_list:
                if looks_like_identifier(v):
                    ids.append(ObjectIdentifier(
                        name=k,
                        value=v,
                        location=IdentifierLocation.QUERY_PARAM
                    ))
    return ids

def detect_body_ids(request: ParsedRequest) -> list[ObjectIdentifier]:
    ids = []
    if request.body and request.content_type and "json" in request.content_type.lower():
        try:
            body_data = json.loads(request.body)
        except json.JSONDecodeError:
            return ids
        
        def walk(data, prefix=""):
            if isinstance(data, dict):
                for k, v in data.items():
                    key_path = f"{prefix}.{k}" if prefix else k
                    if isinstance(v, (str, int)):
                        if has_id_param_name(k) and looks_like_identifier(str(v)):
                            ids.append(ObjectIdentifier(
                                name=key_path,
                                value=str(v),
                                location=IdentifierLocation.JSON_BODY
                            ))
                    elif isinstance(v, (dict, list)):
                        walk(v, key_path)
            elif isinstance(data, list):
                for i, v in enumerate(data):
                    key_path = f"{prefix}[{i}]"
                    if isinstance(v, (dict, list)):
                        walk(v, key_path)

        walk(body_data)
    return ids

def detect_identifiers(request: ParsedRequest) -> list[ObjectIdentifier]:
    return detect_url_path_ids(request) + detect_query_param_ids(request) + detect_body_ids(request)
