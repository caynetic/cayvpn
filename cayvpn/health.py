from __future__ import annotations

from dataclasses import dataclass


FAILURE_THRESHOLD = 3
RECOVERY_THRESHOLD = 2


@dataclass(frozen=True)
class HealthTransition:
    state: str
    failures: int
    successes: int
    changed: bool
    reason: str | None = None


def record_probe(
    current_state: str,
    consecutive_failures: int,
    consecutive_successes: int,
    success: bool,
    reason: str | None = None,
) -> HealthTransition:
    """Apply CayVPN's three-failure/two-success health policy.

    A single missed probe does not move a healthy exit, which prevents a
    transient packet loss event from switching clients.  A blocked runtime is
    kept blocked until a later probe explicitly reports success; callers can
    choose whether installing the runtime should trigger that probe.
    """
    state = current_state or "pending"
    if success:
        successes = max(0, consecutive_successes) + 1
        failures = 0
        if state in {"unhealthy", "blocked", "pending"} and successes >= RECOVERY_THRESHOLD:
            return HealthTransition("healthy", failures, successes, True)
        return HealthTransition(state, failures, successes, False)

    failures = max(0, consecutive_failures) + 1
    successes = 0
    if failures >= FAILURE_THRESHOLD:
        next_state = "unhealthy" if state != "blocked" else "blocked"
        return HealthTransition(next_state, failures, successes, next_state != state, reason)
    return HealthTransition(state, failures, successes, False, reason)


def ordered_healthy_profile_ids(profile_ids: list[int], profiles: dict[int, object], excluded: int | None = None) -> list[int]:
    """Return owner-approved, enabled, healthy profiles in pool order."""
    result: list[int] = []
    for profile_id in profile_ids:
        if excluded is not None and profile_id == excluded:
            continue
        profile = profiles.get(profile_id)
        if profile is None:
            continue
        if getattr(profile, "enabled", False) and getattr(profile, "health_state", "") in {"healthy", "active"}:
            result.append(profile_id)
    return result
