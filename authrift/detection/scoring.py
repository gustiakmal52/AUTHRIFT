from authrift.models import (
    ResponseDiff, ScoreSignal, ConfidenceLevel, Finding, Mutation, MutationType, HttpResponse,
)


def compute_signals(
    diff: ResponseDiff,
    mutation: Mutation,
    baseline_response: HttpResponse,
    test_response: HttpResponse,
) -> list[ScoreSignal]:
    signals: list[ScoreSignal] = []

    if diff.authorization_error_detected:
        signals.append(ScoreSignal(
            description="Authorization error detected in test response (access control enforced)",
            points=-40,
        ))

    if 400 <= test_response.status_code < 600:
        signals.append(ScoreSignal(
            description=f"Test response returned error status ({test_response.status_code})",
            points=-15,
        ))

    m_type = mutation.mutation_type

    if m_type == MutationType.OBJECT_SUBSTITUTION:
        _score_object_substitution(signals, diff, mutation, baseline_response, test_response)
    elif m_type == MutationType.FUNCTION_LEVEL:
        _score_function_level(signals, diff, mutation, baseline_response, test_response)
    elif m_type == MutationType.SESSION_SUBSTITUTION:
        _score_session_substitution(signals, diff, mutation, baseline_response, test_response)

    return signals


def _score_object_substitution(
    signals: list[ScoreSignal],
    diff: ResponseDiff,
    mutation: Mutation,
    baseline_response: HttpResponse,
    test_response: HttpResponse,
) -> None:
    test_is_2xx = 200 <= test_response.status_code < 300
    baseline_is_2xx = 200 <= baseline_response.status_code < 300

    if test_is_2xx and baseline_is_2xx:
        signals.append(ScoreSignal(
            description="Unauthorized actor received 2xx on target object",
            points=25,
        ))

    for ident in mutation.substituted_identifiers:
        if test_response.body and ident.value in test_response.body:
            signals.append(ScoreSignal(
                description=f"Target object identifier '{ident.value}' returned to unauthorized actor",
                points=25,
            ))
            break

    if diff.owner_field_mismatch:
        signals.append(ScoreSignal(
            description=f"Object owner field points to baseline actor '{mutation.baseline_actor.name}'",
            points=25,
        ))

    if test_is_2xx and diff.sensitive_fields_in_response:
        signals.append(ScoreSignal(
            description=f"Sensitive fields in unauthorized response: {', '.join(diff.sensitive_fields_in_response[:4])}",
            points=15,
        ))

    if diff.json_structure_similarity is not None and diff.json_structure_similarity >= 0.9:
        signals.append(ScoreSignal(description="JSON structure matches baseline object (>= 90%)", points=10))

    if diff.body_similarity >= 0.9:
        signals.append(ScoreSignal(description="Response body similarity with baseline object >= 90%", points=10))

    if diff.control_status is not None:
        if 200 <= diff.control_status < 300 and test_is_2xx:
            signals.append(ScoreSignal(
                description="Control test confirmed: Actor accesses own object (2xx) AND target object (2xx)",
                points=15,
            ))
        elif 200 <= diff.control_status < 300 and (test_response.status_code in (401, 403, 404)):
            signals.append(ScoreSignal(
                description="Tri-state verification confirmed: Actor accesses own object (2xx) but denied target (4xx)",
                points=-40,
            ))

    if diff.body_similarity < 0.2 and not any(i.value in test_response.body for i in mutation.substituted_identifiers):
        signals.append(ScoreSignal(
            description="Sanitized or minimal response (similarity < 20%)",
            points=-25,
        ))


def _score_function_level(
    signals: list[ScoreSignal],
    diff: ResponseDiff,
    mutation: Mutation,
    baseline_response: HttpResponse,
    test_response: HttpResponse,
) -> None:
    test_is_2xx = 200 <= test_response.status_code < 300
    baseline_is_2xx = 200 <= baseline_response.status_code < 300

    if test_is_2xx:
        signals.append(ScoreSignal(
            description=f"Unprivileged actor '{mutation.test_actor.name}' received 2xx on privileged function",
            points=45,
        ))
        if baseline_is_2xx:
            signals.append(ScoreSignal(
                description="Both baseline admin and unprivileged user succeeded on privileged endpoint",
                points=20,
            ))
        if diff.json_structure_similarity is not None and diff.json_structure_similarity >= 0.85:
            signals.append(ScoreSignal(
                description="Unprivileged response structure matches admin execution",
                points=15,
            ))
    elif test_response.status_code in (401, 403):
        signals.append(ScoreSignal(
            description="Privileged function correctly denied to unprivileged user (401/403)",
            points=-40,
        ))


def _score_session_substitution(
    signals: list[ScoreSignal],
    diff: ResponseDiff,
    mutation: Mutation,
    baseline_response: HttpResponse,
    test_response: HttpResponse,
) -> None:
    if diff.owner_field_matches_test_actor:
        signals.append(ScoreSignal(
            description=f"Response reflects test actor '{mutation.test_actor.name}' own identity (proper session isolation)",
            points=-40,
        ))

    has_leak = False

    if diff.owner_field_mismatch:
        signals.append(ScoreSignal(
            description=f"Response contains baseline actor '{mutation.baseline_actor.name}' identity/data",
            points=40,
        ))
        has_leak = True

    baseline_markers = getattr(mutation.baseline_actor, "identity_markers", []) or []
    test_markers = getattr(mutation.test_actor, "identity_markers", []) or []
    if baseline_markers and test_response.body:
        test_body_lower = test_response.body.lower()
        test_has_baseline_marker = any(m.lower() in test_body_lower for m in baseline_markers)
        test_has_own_marker = any(m.lower() in test_body_lower for m in test_markers)

        if test_has_baseline_marker and not test_has_own_marker:
            signals.append(ScoreSignal(
                description="Baseline actor identity marker found in test actor response",
                points=40,
            ))
            has_leak = True

    baseline_name = mutation.baseline_actor.name
    if test_response.body and baseline_name.lower() in test_response.body.lower() and not diff.owner_field_matches_test_actor:
        signals.append(ScoreSignal(
            description=f"Baseline actor identity '{baseline_name}' found in test actor response",
            points=30,
        ))
        has_leak = True

    if has_leak:
        if 200 <= test_response.status_code < 300:
            signals.append(ScoreSignal(
                description="Cross-session leakage: Unauthorized actor received baseline actor protected data",
                points=30,
            ))
    else:
        signals.append(ScoreSignal(
            description="No cross-actor data leakage observed; session isolation maintained",
            points=-20,
        ))


def compute_score(signals: list[ScoreSignal]) -> int:
    return max(0, min(100, sum(s.points for s in signals)))


def classify(score: int) -> ConfidenceLevel:
    return Finding.classify(score)
