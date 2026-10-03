from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from authrift.models import Actor

DEFAULT_PRIVILEGED_PATH_SEGMENTS = {
    "admin",
    "administrator",
    "staff",
    "management",
    "manage",
    "internal",
    "superuser",
    "root",
    "moderator",
    "backoffice",
}


class ScanConfig(BaseModel):
    max_requests: int = 100
    delay_ms: int = 0
    timeout_s: float = 30.0
    rate_limit_rps: float = 10.0
    allow_state_changing: bool = False
    include_raw_evidence: bool = False
    safe_methods: set[str] = Field(default_factory=lambda: {"GET", "HEAD", "OPTIONS"})
    report_dir: str = "reports"
    redact_headers: set[str] = Field(
        default_factory=lambda: {"authorization", "cookie", "set-cookie", "x-api-key"}
    )
    privileged_path_segments: set[str] = Field(
        default_factory=lambda: set(DEFAULT_PRIVILEGED_PATH_SEGMENTS)
    )
    privileged_endpoints: list[dict[str, str]] = Field(default_factory=list)


class ActorsConfig(BaseModel):
    actors: dict[str, Actor]


def load_actors(path: Path) -> dict[str, Actor]:
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not data or "actors" not in data:
        return {}

    actors_dict = {}
    for name, config in data["actors"].items():
        actors_dict[name] = Actor(
            name=name,
            headers=config.get("headers", {}),
            cookies=config.get("cookies", {}),
            owned_objects=config.get("owned_objects", {}),
            identity_markers=config.get("identity_markers", []),
        )
    return actors_dict


def load_scan_config(overrides: dict | None = None, config_path: Path | None = None) -> ScanConfig:
    config_dict: dict[str, Any] = {}

    if config_path and config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict):
            if "privileged_endpoints" in data:
                config_dict["privileged_endpoints"] = data["privileged_endpoints"]
            if "privileged_path_segments" in data:
                config_dict["privileged_path_segments"] = set(data["privileged_path_segments"])

    if overrides:
        config_dict.update(overrides)

    config = ScanConfig()
    if config_dict:
        return config.model_copy(update=config_dict)
    return config
