import time
import datetime

from authrift.models import ParsedRequest, Actor, ScanResult, HttpMethod, HttpResponse
from authrift.config import ScanConfig
from authrift.engine.mutations import generate_mutations
from authrift.engine.replay import send_request_sync
from authrift.detection.authorization import analyze_authorization
from authrift.utils.logging import info, warning, success, error, finding_alert


class RequestPacer:
    """Enforces deterministic rate limiting (RPS) and post-mutation delay."""

    def __init__(self, rate_limit_rps: float = 10.0, delay_ms: int = 0):
        self.rate_limit_rps = rate_limit_rps
        self.delay_ms = delay_ms
        self._min_interval = 1.0 / rate_limit_rps if rate_limit_rps > 0 else 0.0
        self._last_request_time = 0.0

    def pace_request(self) -> None:
        """Called immediately before sending any HTTP request to enforce RPS limit."""
        if self._min_interval > 0 and self._last_request_time > 0:
            elapsed = time.monotonic() - self._last_request_time
            if elapsed < self._min_interval:
                time.sleep(self._min_interval - elapsed)
        self._last_request_time = time.monotonic()

    def pace_mutation(self) -> None:
        """Called after completing a mutation iteration to enforce configured delay."""
        if self.delay_ms > 0:
            time.sleep(self.delay_ms / 1000.0)


def run_scan(
    requests: list[ParsedRequest],
    actor_a: Actor,
    actor_b: Actor,
    admin_actor: Actor | None,
    config: ScanConfig,
) -> ScanResult:
    result = ScanResult()
    pacer = RequestPacer(rate_limit_rps=config.rate_limit_rps, delay_ms=config.delay_ms)
    budget_exhausted = False

    def send_budgeted_request(req: ParsedRequest) -> HttpResponse | None:
        nonlocal budget_exhausted
        if result.http_requests_sent >= config.max_requests:
            budget_exhausted = True
            warning(f"HTTP request budget limit ({config.max_requests}) reached")
            return None
        pacer.pace_request()
        resp = send_request_sync(req, timeout=config.timeout_s)
        result.http_requests_sent += 1
        return resp

    for idx, req in enumerate(requests, 1):
        if budget_exhausted or result.http_requests_sent >= config.max_requests:
            break

        method_str = req.method.value.upper()

        if method_str not in config.safe_methods and not config.allow_state_changing:
            result.skipped_unsafe += 1
            warning(f"[{idx}/{len(requests)}] Skipping unsafe {method_str} {req.path}")
            continue

        mutations = generate_mutations(
            req,
            actor_a,
            actor_b,
            admin_actor,
            privileged_path_segments=config.privileged_path_segments,
            privileged_endpoints=config.privileged_endpoints,
        )

        if not mutations:
            info(f"[{idx}/{len(requests)}] {method_str} {req.path} — no mutations generated")
            result.imported_requests_processed += 1
            result.total_requests += 1
            continue

        for mutation in mutations:
            if budget_exhausted or result.http_requests_sent >= config.max_requests:
                break

            try:
                baseline_response = send_budgeted_request(mutation.baseline_request)
                if baseline_response is None:
                    break

                control_response = None
                if mutation.control_request:
                    control_response = send_budgeted_request(mutation.control_request)
                    if control_response is None:
                        break

                test_response = send_budgeted_request(mutation.test_request)
                if test_response is None:
                    break

                log_lines = [
                    f"[{idx}/{len(requests)}] {method_str} {req.path} ({mutation.mutation_type.value})",
                    f"      Baseline ({mutation.baseline_actor.name}): {baseline_response.status_code}  "
                    f"Test ({mutation.test_actor.name}): {test_response.status_code}",
                ]
                if control_response and mutation.control_actor:
                    log_lines.append(
                        f"      Control ({mutation.control_actor.name}): {control_response.status_code}"
                    )
                info("
".join(log_lines))

                finding = analyze_authorization(
                    mutation, baseline_response, test_response, control_response=control_response,
                )
                if finding:
                    result.findings.append(finding)
                    finding_alert(
                        finding.finding_id,
                        f"{finding.method.value} {finding.endpoint}",
                        finding.confidence.value,
                    )
                else:
                    success("      Authorization behavior appears correct")

                result.total_mutations += 1
                result.mutations_completed += 1

            except Exception as exc:
                msg = f"Error testing {method_str} {req.path}: {exc}"
                result.errors.append(msg)
                error(msg)

            pacer.pace_mutation()

        result.imported_requests_processed += 1
        result.total_requests += 1

    result.completed_at = datetime.datetime.now()
    return result
