"""Shared latency decomposition helpers for benchmark collection and analysis.

This module centralizes workflow timing formulas so suite aggregation and
analysis stages compute the same derived latency fields.
"""

from datetime import datetime
from typing import Any, Dict, Optional

MIXED_EPSILON_SECONDS = 0.05
WORKFLOW_RESHARE = {"join", "removal"}


def normalize_workflow_base(value: Any) -> str:
    """Return normalized workflow base token."""
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    return raw.split("_", 1)[0]


def parse_timestamp(value: Any) -> Optional[datetime]:
    """Parse timestamp-like values into UTC-aware/naive datetime objects."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    raw = str(value).strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(raw)
    except Exception:
        return None


def duration_seconds(start: Any, end: Any) -> Optional[float]:
    """Return end-start in seconds or None when unavailable/invalid."""
    a = parse_timestamp(start)
    b = parse_timestamp(end)
    if a is None or b is None:
        return None
    value = (b - a).total_seconds()
    if value < 0:
        return None
    return value


def sum_non_null(*values: Optional[float]) -> Optional[float]:
    """Sum present values and return None when all values are missing."""
    present = [v for v in values if v is not None]
    if not present:
        return None
    return float(sum(present))


def derive_latency_components(
    row: Dict[str, Any],
    mixed_epsilon_seconds: float = MIXED_EPSILON_SECONDS,
) -> Dict[str, Optional[float]]:
    """Compute canonical latency decomposition fields from one workflow row."""
    workflow_base = normalize_workflow_base(row.get("workflow_base", "") or row.get("workflow_tag", ""))

    client_duration_s = duration_seconds(row.get("client_start_ts"), row.get("client_end_ts"))
    client_to_submitted_s = duration_seconds(row.get("client_start_ts"), row.get("submitted_observed_ts"))
    submit_to_vote_s = duration_seconds(row.get("submitted_observed_ts"), row.get("voted_ts"))
    vote_to_approved_s = duration_seconds(row.get("voted_ts"), row.get("approved_or_executed_ts"))
    approved_to_cert_registered_s = duration_seconds(row.get("approved_or_executed_ts"), row.get("cert_registered_ts"))
    approved_to_reshare_start_s = duration_seconds(row.get("approved_or_executed_ts"), row.get("reshare_started_ts"))
    approved_to_reshare_completed_s = duration_seconds(row.get("approved_or_executed_ts"), row.get("reshare_completed_ts"))
    reshare_duration_s = duration_seconds(row.get("reshare_started_ts"), row.get("reshare_completed_ts"))
    post_reshare_tail_s = duration_seconds(row.get("reshare_completed_ts"), row.get("client_end_ts"))
    reshare_complete_to_local_idle_s = duration_seconds(row.get("reshare_completed_ts"), row.get("local_key_idle_ts"))
    local_idle_to_operation_end_s = duration_seconds(row.get("local_key_idle_ts"), row.get("client_end_ts"))
    execution_to_operation_end_s = duration_seconds(row.get("approved_or_executed_ts"), row.get("client_end_ts"))
    cert_registered_to_operation_end_s = duration_seconds(row.get("cert_registered_ts"), row.get("client_end_ts"))
    cert_registered_to_signing_idle_s = duration_seconds(row.get("cert_registered_ts"), row.get("local_signing_idle_ts"))
    signing_idle_to_operation_end_s = duration_seconds(row.get("local_signing_idle_ts"), row.get("client_end_ts"))

    if approved_to_reshare_start_s is not None and reshare_duration_s is not None:
        tss_reshare_total_s = approved_to_reshare_start_s + reshare_duration_s
    elif approved_to_reshare_completed_s is not None:
        tss_reshare_total_s = approved_to_reshare_completed_s
    elif reshare_duration_s is not None:
        tss_reshare_total_s = reshare_duration_s
    else:
        tss_reshare_total_s = None

    local_key_idle_wait_s = None
    local_finalize_total_s = None
    if workflow_base == "csr":
        local_finalize_total_s = cert_registered_to_operation_end_s
    elif workflow_base == "revocation":
        local_finalize_total_s = execution_to_operation_end_s
    elif workflow_base in WORKFLOW_RESHARE:
        if reshare_complete_to_local_idle_s is not None:
            local_key_idle_wait_s = reshare_complete_to_local_idle_s
            local_finalize_total_s = local_idle_to_operation_end_s
        else:
            local_finalize_total_s = post_reshare_tail_s

    if local_finalize_total_s is None and execution_to_operation_end_s is not None:
        local_finalize_total_s = execution_to_operation_end_s

    blockchain_total_s = sum_non_null(client_to_submitted_s, submit_to_vote_s, vote_to_approved_s)
    tss_coordination_total_s = sum_non_null(
        approved_to_cert_registered_s,
        tss_reshare_total_s,
        local_key_idle_wait_s,
    )
    blockchain_effective_s = sum_non_null(blockchain_total_s, local_finalize_total_s)
    tss_total_s = sum_non_null(tss_coordination_total_s, local_finalize_total_s)
    decomposed_total_s = sum_non_null(blockchain_effective_s, tss_coordination_total_s)

    decomposition_gap_s = None
    if client_duration_s is not None and decomposed_total_s is not None:
        decomposition_gap_s = client_duration_s - decomposed_total_s

    mixed_transition_s_raw = None
    overlap_correction_s_raw = None
    mixed_transition_s = None
    overlap_correction_s = None
    explained_total_s = None
    if decomposition_gap_s is not None:
        mixed_transition_s_raw = max(decomposition_gap_s, 0.0)
        overlap_correction_s_raw = max(-decomposition_gap_s, 0.0)
        mixed_transition_s = mixed_transition_s_raw if mixed_transition_s_raw >= mixed_epsilon_seconds else 0.0
        overlap_correction_s = overlap_correction_s_raw if overlap_correction_s_raw >= mixed_epsilon_seconds else 0.0
    if decomposed_total_s is not None:
        explained_total_s = decomposed_total_s + (mixed_transition_s or 0.0)

    return {
        "client_duration_s": client_duration_s,
        "client_to_submitted_s": client_to_submitted_s,
        "submit_to_vote_s": submit_to_vote_s,
        "vote_to_approved_s": vote_to_approved_s,
        "approved_to_cert_registered_s": approved_to_cert_registered_s,
        "approved_to_reshare_start_s": approved_to_reshare_start_s,
        "approved_to_reshare_completed_s": approved_to_reshare_completed_s,
        "reshare_duration_s": reshare_duration_s,
        "post_reshare_tail_s": post_reshare_tail_s,
        "reshare_complete_to_local_idle_s": reshare_complete_to_local_idle_s,
        "local_idle_to_operation_end_s": local_idle_to_operation_end_s,
        "execution_to_operation_end_s": execution_to_operation_end_s,
        "cert_registered_to_operation_end_s": cert_registered_to_operation_end_s,
        "cert_registered_to_signing_idle_s": cert_registered_to_signing_idle_s,
        "signing_idle_to_operation_end_s": signing_idle_to_operation_end_s,
        "blockchain_total_s": blockchain_total_s,
        "tss_reshare_total_s": tss_reshare_total_s,
        "local_key_idle_wait_s": local_key_idle_wait_s,
        "tss_coordination_total_s": tss_coordination_total_s,
        "local_finalize_total_s": local_finalize_total_s,
        "blockchain_effective_s": blockchain_effective_s,
        "tss_total_s": tss_total_s,
        "decomposed_total_s": decomposed_total_s,
        "decomposition_gap_s": decomposition_gap_s,
        "mixed_transition_s_raw": mixed_transition_s_raw,
        "mixed_transition_s": mixed_transition_s,
        "overlap_correction_s_raw": overlap_correction_s_raw,
        "overlap_correction_s": overlap_correction_s,
        "explained_total_s": explained_total_s,
    }

