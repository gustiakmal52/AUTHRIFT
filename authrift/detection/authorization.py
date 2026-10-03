from authrift.models import Finding, Mutation, HttpResponse
from authrift.detection.response_diff import compare_responses
from authrift.detection.scoring import compute_signals, compute_score, classify

_finding_counter = 0


def reset_counter() -> None:
    global _finding_counter
    _finding_counter = 0


def analyze_authorization(
    mutation: Mutation,
    baseline_response: HttpResponse,
    test_response: HttpResponse,
    control_response: HttpResponse | None = None,
) -> Finding | None:
    global _finding_counter

    control_status = control_response.status_code if control_response else None
    diff = compare_responses(
        baseline_response,
        test_response,
        baseline_actor=mutation.baseline_actor,
        test_actor=mutation.test_actor,
        control_status=control_status,
    )
    signals = compute_signals(diff, mutation, baseline_response, test_response)
    score = compute_score(signals)

    if score < 30:
        return None

    confidence = classify(score)
    _finding_counter += 1
    finding_id = f"AUTH-{_finding_counter:03d}"

    return Finding(
        finding_id=finding_id,
        endpoint=mutation.original_request.path,
        method=mutation.original_request.method,
        mutation_type=mutation.mutation_type,
        baseline_actor=mutation.baseline_actor.name,
        test_actor=mutation.test_actor.name,
        baseline_response=baseline_response,
        test_response=test_response,
        diff=diff,
        signals=signals,
        score=score,
        confidence=confidence,
    )
