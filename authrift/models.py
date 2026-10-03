import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class ParsedRequest(BaseModel):
    method: HttpMethod
    url: str
    path: str
    headers: dict[str, str]
    cookies: dict[str, str] = Field(default_factory=dict)
    query_params: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    content_type: str | None = None
    source: str = ""


class HttpResponse(BaseModel):
    status_code: int
    headers: dict[str, str]
    body: str
    elapsed_ms: float
    content_type: str | None = None


class Actor(BaseModel):
    name: str
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    owned_objects: dict[str, str] = Field(default_factory=dict)
    identity_markers: list[str] = Field(default_factory=list)


class IdentifierLocation(str, Enum):
    URL_PATH = "URL_PATH"
    QUERY_PARAM = "QUERY_PARAM"
    JSON_BODY = "JSON_BODY"
    FORM_BODY = "FORM_BODY"
    HEADER = "HEADER"


class ObjectIdentifier(BaseModel):
    name: str
    value: str
    location: IdentifierLocation
    pattern: str = ""
    path_segment_index: int | None = None


class MutationType(str, Enum):
    OBJECT_SUBSTITUTION = "OBJECT_SUBSTITUTION"
    SESSION_SUBSTITUTION = "SESSION_SUBSTITUTION"
    FUNCTION_LEVEL = "FUNCTION_LEVEL"
    TENANT_COMPARISON = "TENANT_COMPARISON"


class Mutation(BaseModel):
    mutation_type: MutationType
    original_request: ParsedRequest
    baseline_request: ParsedRequest
    test_request: ParsedRequest
    baseline_actor: Actor
    test_actor: Actor
    control_request: ParsedRequest | None = None
    control_actor: Actor | None = None
    substituted_identifiers: list[ObjectIdentifier] = Field(default_factory=list)
    description: str

    @model_validator(mode="before")
    @classmethod
    def _compat_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "mutated_request" in data and "test_request" not in data:
                data["test_request"] = data["mutated_request"]
            if "original_request" in data and "baseline_request" not in data:
                data["baseline_request"] = data["original_request"]
            if "actor" in data and "test_actor" not in data:
                data["test_actor"] = data["actor"]
            if "target_actor" in data and "baseline_actor" not in data and data["target_actor"]:
                data["baseline_actor"] = data["target_actor"]
            if "baseline_actor" not in data and "test_actor" in data:
                data["baseline_actor"] = data["test_actor"]
        return data

    @property
    def mutated_request(self) -> ParsedRequest:
        return self.test_request

    @property
    def actor(self) -> Actor:
        return self.test_actor

    @property
    def target_actor(self) -> Actor | None:
        return self.baseline_actor


class ResponseDiff(BaseModel):
    status_match: bool
    baseline_status: int
    test_status: int
    body_similarity: float
    json_structure_similarity: float | None = None
    content_length_diff: int
    sensitive_fields_in_response: list[str] = Field(default_factory=list)
    owner_field_mismatch: bool = False
    owner_field_matches_test_actor: bool = False
    authorization_error_detected: bool = False
    control_status: int | None = None
    matching_json_fields: list[str] = Field(default_factory=list)
    differing_json_fields: list[str] = Field(default_factory=list)


class ScoreSignal(BaseModel):
    description: str
    points: int


class ConfidenceLevel(str, Enum):
    LOW = "Low signal"
    INTERESTING = "Interesting"
    LIKELY = "Likely authorization issue"
    HIGH = "High-confidence candidate"


class Finding(BaseModel):
    finding_id: str
    endpoint: str
    method: HttpMethod
    mutation_type: MutationType
    baseline_actor: str
    test_actor: str
    baseline_response: HttpResponse
    test_response: HttpResponse
    diff: ResponseDiff
    signals: list[ScoreSignal]
    score: int
    confidence: ConfidenceLevel
    timestamp: datetime.datetime = Field(default_factory=datetime.datetime.now)

    @classmethod
    def classify(cls, score: int) -> ConfidenceLevel:
        if score < 30:
            return ConfidenceLevel.LOW
        elif score < 60:
            return ConfidenceLevel.INTERESTING
        elif score < 80:
            return ConfidenceLevel.LIKELY
        else:
            return ConfidenceLevel.HIGH


class ScanResult(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    total_requests: int = 0
    imported_requests_processed: int = 0
    http_requests_sent: int = 0
    total_mutations: int = 0
    mutations_completed: int = 0
    skipped_unsafe: int = 0
    errors: list[str] = Field(default_factory=list)
    started_at: datetime.datetime = Field(default_factory=datetime.datetime.now)
    completed_at: datetime.datetime | None = None
