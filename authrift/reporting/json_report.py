import json
from pathlib import Path

from authrift.models import ScanResult, Finding
from authrift.utils.redact import redact_headers, redact_response_body


def finding_to_dict(finding: Finding, include_raw_evidence: bool = False) -> dict:
    data = finding.model_dump()
    data["method"] = finding.method.value
    data["mutation_type"] = finding.mutation_type.value
    data["confidence"] = finding.confidence.value
    data["timestamp"] = finding.timestamp.isoformat()

    if not include_raw_evidence:
        for key in ("baseline_response", "test_response"):
            if key in data and isinstance(data[key], dict):
                if "headers" in data[key]:
                    data[key]["headers"] = redact_headers(data[key]["headers"])
                if "body" in data[key] and data[key]["body"]:
                    data[key]["body"] = redact_response_body(data[key]["body"])

    return data


def write_json_report(
    result: ScanResult,
    output_dir: str = "reports",
    include_raw_evidence: bool = False,
) -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    report = {
        "authrift_version": "0.1.0",
        "scan": {
            "imported_requests_processed": result.imported_requests_processed or result.total_requests,
            "http_requests_sent": result.http_requests_sent,
            "mutations_completed": result.mutations_completed or result.total_mutations,
            "total_requests": result.total_requests,
            "total_mutations": result.total_mutations,
            "skipped_unsafe": result.skipped_unsafe,
            "findings_count": len(result.findings),
            "errors_count": len(result.errors),
            "started_at": result.started_at.isoformat(),
            "completed_at": result.completed_at.isoformat() if result.completed_at else None,
        },
        "findings": [finding_to_dict(f, include_raw_evidence=include_raw_evidence) for f in result.findings],
    }

    path = out / "report.json"
    path.write_text(json.dumps(report, indent=2, default=str))
    return path
