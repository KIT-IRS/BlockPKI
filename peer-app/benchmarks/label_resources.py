#!/usr/bin/env python3
"""label_resources.py maps resource samples to benchmark workflow phases.

Runtime flow: reads resource CSV samples and metric-event logs, infers workflow
context by proposal/epoch/timeline, and writes labeled row + phase summary CSVs.
"""

import argparse
import csv
import json
import os
import re
from datetime import datetime
from datetime import timezone

# label_resources.py maps resource samples to benchmark workflow phases.
# Runtime flow: reads metric-event logs and resource samples, infers workflow
# context per proposal/epoch, labels each sample row, and writes enriched CSV artifacts.

try:
    # Python 3.11+
    from datetime import UTC  # type: ignore
except ImportError:
    # Python 3.10 fallback
    UTC = timezone.utc


MODE_CHOICES = ["auto", "csr", "revocation", "join", "removal", "reshare"]
WORKFLOW_CHOICES = ["csr", "revocation", "join", "removal", "reshare"]
RESHARE_REASON_PREFIX_BY_WORKFLOW = {
    "join": ["member_join_requested", "member_join_bootstrap"],
    "removal": ["member_removed"],
}
RESHARE_EVENT_KEYS = [
    "reshare_acknowledged",
    "reshare_keygen_start",
    "tss_keygen_start",
    "tss_keygen_complete",
    "reshare_complete_submitted",
    "reshare_complete_recorded",
    "reshare_complete_observed",
]
PROPOSAL_PREFIX_BY_WORKFLOW = {
    "csr": ["csr-"],
    "revocation": ["revoke-"],
    "join": ["join-"],
    "removal": ["remove-"],
}


# parse_ts handles parse ts behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def parse_ts(ts):
    """parse_ts helper for benchmark tooling."""
    if not ts:
        return None
    ts = str(ts).strip()
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    # Go RFC3339Nano can emit >6 fractional digits; Python fromisoformat may reject those.
    ts = re.sub(r"(\.\d{6})\d+(?=(?:[+-]\d{2}:\d{2})?$)", r"\1", ts)
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None


# to_z handles to z behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def to_z(dt):
    """to_z helper for benchmark tooling."""
    if not dt:
        return ""
    return dt.isoformat().replace("+00:00", "Z")


# pick handles pick behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def pick(ev, *keys):
    """pick helper for benchmark tooling."""
    for k in keys:
        if k in ev:
            return ev.get(k)
    return None


# parse_operation_timestamp handles parse operation timestamp behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def parse_operation_timestamp(operation):
    """parse_operation_timestamp helper for benchmark tooling."""
    if not operation:
        return None
    m = re.search(r"_(\d{10})$", str(operation).strip())
    if not m:
        return None
    try:
        return datetime.fromtimestamp(int(m.group(1)), UTC)
    except Exception:
        return None


# normalize_workflow_name handles normalize workflow name behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def normalize_workflow_name(name):
    """normalize_workflow_name helper for benchmark tooling."""
    v = str(name or "").strip().lower()
    if v in ("member_removal", "remove", "removal"):
        return "removal"
    if v in ("revoke", "revocation"):
        return "revocation"
    if v in ("join", "join_request"):
        return "join"
    if v in ("reshare",):
        return "reshare"
    if v in ("csr",):
        return "csr"
    return ""


# infer_workflow_from_operation handles infer workflow from operation behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def infer_workflow_from_operation(operation):
    """infer_workflow_from_operation helper for benchmark tooling."""
    if not operation:
        return ""
    prefix = str(operation).strip().split("_", 1)[0]
    return normalize_workflow_name(prefix)


# get_proposal_id handles get proposal id behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def get_proposal_id(e):
    """get_proposal_id helper for benchmark tooling."""
    return (
        e.get("proposal_id")
        or e.get("proposalId")
        or e.get("proposalID")
        or e.get("proposal")
        or ""
    )


# get_epoch handles get epoch behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def get_epoch(e):
    """get_epoch helper for benchmark tooling."""
    return e.get("epoch") or e.get("Epoch") or e.get("epoch_id") or ""

# load_events reads newline-delimited metric-event JSON objects.
# Lifecycle: Labeling input preparation.
# Called by: main.
# Triggered: once at startup before proposal/epoch indexing.
def load_events(paths):
    """load_events helper for benchmark tooling."""
    events = []
    for path in paths:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.lstrip("\ufeff").strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return events


# _normalize_row_keys handles normalize row keys behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def _normalize_row_keys(row):
    """_normalize_row_keys helper for benchmark tooling."""
    out = {}
    for k, v in row.items():
        key = str(k).lstrip("\ufeff")
        out[key] = v
    return out


# _is_earlier_ts handles is earlier ts behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def _is_earlier_ts(ts_a, ts_b):
    """Return True if ts_a should replace ts_b as the earliest timestamp."""
    dt_a = parse_ts(ts_a)
    dt_b = parse_ts(ts_b)
    if dt_a and dt_b:
        return dt_a < dt_b
    if dt_a and not dt_b:
        return True
    if not dt_a and dt_b:
        return False
    return str(ts_a) < str(ts_b)


# _upsert_event handles upsert event behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def _upsert_event(bucket, event_name, event_obj):
    """_upsert_event helper for benchmark tooling."""
    existing = bucket.get(event_name)
    ts = event_obj.get("ts", "")
    if not existing or _is_earlier_ts(ts, existing.get("ts", "")):
        bucket[event_name] = {"ts": ts, "fields": dict(event_obj)}

# build_event_indexes organizes events by proposal and epoch with canonical keys.
# Lifecycle: Labeling context construction.
# Called by: main.
# Triggered: after event loading to support workflow/epoch inference.
def build_event_indexes(events):
    """build_event_indexes helper for benchmark tooling."""
    by_proposal = {}
    by_epoch = {}
    for e in events:
        event_name = str(e.get("event", "")).strip()
        ts = str(e.get("ts", "")).strip()
        if not event_name or not ts:
            continue

        pid = str(get_proposal_id(e)).strip()
        if pid:
            if pid not in by_proposal:
                by_proposal[pid] = {}
            _upsert_event(by_proposal[pid], event_name, e)

        epoch = str(get_epoch(e)).strip()
        if epoch:
            if epoch not in by_epoch:
                by_epoch[epoch] = {}
            _upsert_event(by_epoch[epoch], event_name, e)

    return by_proposal, by_epoch


# event_ts handles event ts behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def event_ts(ev, *keys):
    """event_ts helper for benchmark tooling."""
    for k in keys:
        rec = ev.get(k)
        if rec and rec.get("ts"):
            return rec.get("ts")
    return None


# event_field handles event field behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def event_field(ev, key, *field_names):
    """event_field helper for benchmark tooling."""
    rec = ev.get(key)
    if not rec:
        return ""
    fields = rec.get("fields", {})
    for name in field_names:
        value = fields.get(name)
        if value not in (None, ""):
            return value
    return ""


# epoch_reason handles epoch reason behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def epoch_reason(epoch_ev):
    """epoch_reason helper for benchmark tooling."""
    for key in RESHARE_EVENT_KEYS:
        reason = event_field(epoch_ev, key, "reason")
        if reason:
            return str(reason)
    return ""


# has_reshare_signal handles has reshare signal behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def has_reshare_signal(epoch_ev):
    """has_reshare_signal helper for benchmark tooling."""
    for key in RESHARE_EVENT_KEYS:
        if event_ts(epoch_ev, key):
            return True
    return False


# proposal_anchor_ts handles proposal anchor ts behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def proposal_anchor_ts(workflow, ev):
    """proposal_anchor_ts helper for benchmark tooling."""
    if workflow == "csr":
        return event_ts(
            ev,
            "csr_api_received",
            "csr_submitted",
            "csr_submitted_observed",
            "tss_signing_start",
            "cert_registered",
            "cert_registered_observed",
        )
    if workflow == "revocation":
        return event_ts(
            ev,
            "revocation_proposed",
            "revocation_proposed_observed",
            "revocation_voted",
            "revocation_executed_observed",
        )
    if workflow == "join":
        return event_ts(
            ev,
            "join_request_submitted",
            "join_request_submitted_observed",
            "join_request_voted",
            "join_request_approved_observed",
        )
    if workflow == "removal":
        return event_ts(
            ev,
            "member_removal_proposed",
            "member_removal_proposed_observed",
            "member_removal_voted",
            "member_removal_executed_observed",
        )
    return None


# proposal_timeline_score handles proposal timeline score behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def proposal_timeline_score(workflow, ev):
    """proposal_timeline_score helper for benchmark tooling."""
    keys = []
    if workflow == "csr":
        keys = [
            "csr_api_received",
            "csr_submitted",
            "csr_submitted_observed",
            "csr_voted",
            "signing_session_active",
            "tss_signing_start",
            "partial_signature_submitted",
            "tss_signing_complete",
            "cert_registered",
            "cert_registered_observed",
        ]
    elif workflow == "revocation":
        keys = [
            "revocation_proposed",
            "revocation_proposed_observed",
            "revocation_voted",
            "revocation_executed_observed",
        ]
    elif workflow == "join":
        keys = [
            "join_request_submitted",
            "join_request_submitted_observed",
            "join_request_voted",
            "join_request_approved_observed",
        ]
    elif workflow == "removal":
        keys = [
            "member_removal_proposed",
            "member_removal_proposed_observed",
            "member_removal_voted",
            "member_removal_executed_observed",
        ]
    return sum(1 for k in keys if event_ts(ev, k))


# reshare_timeline_score handles reshare timeline score behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def reshare_timeline_score(ev):
    """reshare_timeline_score helper for benchmark tooling."""
    return sum(1 for k in RESHARE_EVENT_KEYS if event_ts(ev, k))


# proposal_matches_workflow handles proposal matches workflow behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def proposal_matches_workflow(pid, ev, workflow):
    """proposal_matches_workflow helper for benchmark tooling."""
    pid_s = str(pid)
    expected_prefixes = PROPOSAL_PREFIX_BY_WORKFLOW.get(workflow, [])
    if any(pid_s.startswith(p) for p in expected_prefixes):
        return True
    # Prefix-less fallback by event content.
    return proposal_timeline_score(workflow, ev) > 0


# _anchor_from_resource handles anchor from resource behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def _anchor_from_resource(resource_min_ts, operation_hint):
    """_anchor_from_resource helper for benchmark tooling."""
    if resource_min_ts:
        return resource_min_ts
    return parse_operation_timestamp(operation_hint)


# proposal_anchor_diff_s handles proposal anchor diff s behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def proposal_anchor_diff_s(workflow, ev, anchor_dt):
    """proposal_anchor_diff_s helper for benchmark tooling."""
    if not anchor_dt:
        return None
    start_ts = proposal_anchor_ts(workflow, ev)
    dt = parse_ts(start_ts)
    if not dt:
        return None
    return abs((dt - anchor_dt).total_seconds())

# infer_proposal_id selects the most likely proposal ID for a resource sample group.
# Lifecycle: Labeling context inference.
# Called by: _resolve_single_proposal_context.
# Triggered: when proposal ID is not explicitly provided by CLI arguments.
def infer_proposal_id(by_proposal, workflow, resource_min_ts, operation_hint):
    """infer_proposal_id helper for benchmark tooling."""
    anchor = _anchor_from_resource(resource_min_ts, operation_hint)
    best_pid = ""
    best_diff = None
    best_score = -1

    for pid, ev in by_proposal.items():
        if not proposal_matches_workflow(pid, ev, workflow):
            continue
        anchor_ts = proposal_anchor_ts(workflow, ev)
        dt = parse_ts(anchor_ts)
        if not dt:
            continue
        diff = abs((dt - anchor).total_seconds()) if anchor else 0.0
        score = proposal_timeline_score(workflow, ev)
        if best_diff is None or diff < best_diff or (diff == best_diff and score > best_score):
            best_pid = pid
            best_diff = diff
            best_score = score

    if best_pid and best_diff is not None and best_diff <= 3600:
        return best_pid
    return ""


# reason_matches_member handles reason matches member behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def reason_matches_member(reason, prefixes, member_id):
    """reason_matches_member helper for benchmark tooling."""
    reason_s = str(reason or "")
    member_s = str(member_id or "")
    if not reason_s or not member_s:
        return False
    for prefix in prefixes:
        if reason_s == f"{prefix}:{member_s}":
            return True
    return False


# reshare_anchor_ts handles reshare anchor ts behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def reshare_anchor_ts(ev):
    """reshare_anchor_ts helper for benchmark tooling."""
    return event_ts(
        ev,
        "reshare_acknowledged",
        "reshare_keygen_start",
        "tss_keygen_start",
        "tss_keygen_complete",
        "reshare_complete_submitted",
        "reshare_complete_recorded",
        "reshare_complete_observed",
    )


# _select_best_epoch handles select best epoch behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def _select_best_epoch(records, anchor_dt=None, after_dt=None):
    """_select_best_epoch helper for benchmark tooling."""
    if not records:
        return ""

    # rank handles rank behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def rank(item):
        """rank helper for benchmark tooling."""
        # item = (epoch, dt, score)
        _, dt, score = item
        after_penalty = 1
        after_gap = 0.0
        if after_dt:
            delta = (dt - after_dt).total_seconds()
            if delta >= 0:
                after_penalty = 0
                after_gap = delta
            else:
                after_penalty = 1
                after_gap = abs(delta)
        anchor_gap = 0.0
        if anchor_dt:
            anchor_gap = abs((dt - anchor_dt).total_seconds())
        return (after_penalty, after_gap, anchor_gap, -score)

    return sorted(records, key=rank)[0][0]

# infer_reshare_epoch resolves the matching reshare epoch for membership workflows.
# Lifecycle: Labeling context inference.
# Called by: _linked_reshare_epoch_for_membership.
# Triggered: while linking join/removal workflows to associated reshare activity.
def infer_reshare_epoch(
    by_epoch,
    resource_min_ts,
    operation_hint,
    member_id="",
    reason_prefixes=None,
    after_ts="",
):
    """infer_reshare_epoch helper for benchmark tooling."""
    anchor_dt = _anchor_from_resource(resource_min_ts, operation_hint)
    after_dt = parse_ts(after_ts)
    reason_prefixes = reason_prefixes or []

    reason_candidates = []
    fallback_candidates = []
    for epoch, ev in by_epoch.items():
        if not has_reshare_signal(ev):
            continue
        ts = reshare_anchor_ts(ev)
        dt = parse_ts(ts)
        if not dt:
            continue
        score = reshare_timeline_score(ev)
        reason = epoch_reason(ev)
        candidate = (str(epoch), dt, score)
        if reason_matches_member(reason, reason_prefixes, member_id):
            reason_candidates.append(candidate)
        else:
            fallback_candidates.append(candidate)

    chosen = _select_best_epoch(reason_candidates, anchor_dt=anchor_dt, after_dt=after_dt)
    if chosen:
        return chosen
    return _select_best_epoch(fallback_candidates, anchor_dt=anchor_dt, after_dt=after_dt)


# collect_member_id_from_proposal_ev handles collect member id from proposal ev behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def collect_member_id_from_proposal_ev(workflow, ev):
    """collect_member_id_from_proposal_ev helper for benchmark tooling."""
    preferred_keys = {
        "join": [
            "join_request_approved_observed",
            "join_request_submitted",
            "join_request_submitted_observed",
            "join_request_voted",
        ],
        "removal": [
            "member_removal_executed_observed",
            "member_removal_proposed",
            "member_removal_proposed_observed",
            "member_removal_voted",
        ],
    }
    for key in preferred_keys.get(workflow, []):
        member_id = event_field(ev, key, "member_id", "memberId")
        if member_id:
            return str(member_id)
    return ""


# build_phases_from_milestones handles build phases from milestones behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def build_phases_from_milestones(milestones):
    """build_phases_from_milestones helper for benchmark tooling."""
    parsed = []
    for label, ts in milestones:
        dt = parse_ts(ts)
        if not dt:
            continue
        parsed.append((dt, label, ts))
    parsed.sort(key=lambda x: x[0])

    ordered = []
    for item in parsed:
        if ordered and item[0] == ordered[-1][0]:
            # Keep one marker per exact timestamp to avoid zero-length phase segments.
            continue
        ordered.append(item)

    phases = []
    for i in range(len(ordered) - 1):
        phases.append((ordered[i][2], ordered[i + 1][2], ordered[i][1]))

    markers = [(label, ts) for _, label, ts in ordered]
    return phases, markers

# build_phases_for_csr handles build phases for csr behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def build_phases_for_csr(ev, resource_start=None):
    """build_phases_for_csr helper for benchmark tooling."""
    milestones = []
    csr_start = event_ts(ev, "csr_api_received", "csr_submitted", "csr_submitted_observed")
    if csr_start:
        milestones.append(("csr_submit", csr_start))
    elif resource_start:
        milestones.append(("csr_submit_est", resource_start))

    for label, key in [
        ("csr_observed", "csr_submitted_observed"),
        ("csr_vote", "csr_voted"),
        ("signing_session", "signing_session_active"),
        ("tss_signing", "tss_signing_start"),
        ("partial_sig_submit", "partial_signature_submitted"),
        ("tss_complete", "tss_signing_complete"),
        ("bc_register", "cert_registered"),
        ("cert_sync", "cert_registered_observed"),
    ]:
        ts = event_ts(ev, key)
        if ts:
            milestones.append((label, ts))

    phases, markers = build_phases_from_milestones(milestones)
    if phases:
        return phases, markers

    # Coarse fallback for sparse metrics.
    tss_start = event_ts(ev, "tss_signing_start")
    tss_done = event_ts(ev, "tss_signing_complete")
    cert_done = event_ts(ev, "cert_registered_observed", "cert_registered")
    if csr_start and tss_start:
        phases.append((csr_start, tss_start, "csr_consensus"))
    if tss_start and tss_done:
        phases.append((tss_start, tss_done, "tss_signing"))
    if tss_done and cert_done:
        phases.append((tss_done, cert_done, "bc_registration"))
    if not phases and csr_start and cert_done:
        phases.append((csr_start, cert_done, "csr_total"))
    return phases, markers


# build_phases_for_revocation handles build phases for revocation behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def build_phases_for_revocation(ev, resource_start=None):
    """build_phases_for_revocation helper for benchmark tooling."""
    milestones = []
    proposed = event_ts(ev, "revocation_proposed", "revocation_proposed_observed")
    if proposed:
        milestones.append(("revocation_propose", proposed))
    elif resource_start:
        milestones.append(("revocation_propose_est", resource_start))
    for label, key in [
        ("revocation_observed", "revocation_proposed_observed"),
        ("revocation_vote", "revocation_voted"),
        ("revocation_execute", "revocation_executed_observed"),
    ]:
        ts = event_ts(ev, key)
        if ts:
            milestones.append((label, ts))

    phases, markers = build_phases_from_milestones(milestones)
    if phases:
        return phases, markers

    completed = event_ts(ev, "revocation_executed_observed", "revocation_voted")
    if proposed and completed:
        phases.append((proposed, completed, "revocation_total"))
    return phases, markers


# build_phases_for_join handles build phases for join behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def build_phases_for_join(ev, linked_reshare_ev=None, resource_start=None):
    """build_phases_for_join helper for benchmark tooling."""
    milestones = []
    submitted = event_ts(ev, "join_request_submitted", "join_request_submitted_observed")
    if submitted:
        milestones.append(("join_submit", submitted))
    elif resource_start:
        milestones.append(("join_submit_est", resource_start))

    for label, key in [
        ("join_observed", "join_request_submitted_observed"),
        ("join_vote", "join_request_voted"),
        ("join_approved", "join_request_approved_observed"),
    ]:
        ts = event_ts(ev, key)
        if ts:
            milestones.append((label, ts))

    if linked_reshare_ev:
        for label, key in [
            ("reshare_ack", "reshare_acknowledged"),
            ("reshare_keygen_start", "reshare_keygen_start"),
            ("tss_keygen_complete", "tss_keygen_complete"),
            ("reshare_complete", "reshare_complete_observed"),
        ]:
            ts = event_ts(
                linked_reshare_ev,
                key,
                "tss_keygen_start" if key == "reshare_keygen_start" else key,
                "reshare_complete_recorded" if key == "reshare_complete" else key,
            )
            if ts:
                milestones.append((label, ts))

    phases, markers = build_phases_from_milestones(milestones)
    if phases:
        return phases, markers

    approved = event_ts(ev, "join_request_approved_observed", "join_request_voted")
    complete = ""
    if linked_reshare_ev:
        complete = event_ts(linked_reshare_ev, "reshare_complete_observed", "reshare_complete_recorded")
    if submitted and approved:
        phases.append((submitted, approved, "join_consensus"))
    if approved and complete:
        phases.append((approved, complete, "reshare_total"))
    if not phases and submitted and complete:
        phases.append((submitted, complete, "join_total"))
    return phases, markers


# build_phases_for_removal handles build phases for removal behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def build_phases_for_removal(ev, linked_reshare_ev=None, resource_start=None):
    """build_phases_for_removal helper for benchmark tooling."""
    milestones = []
    proposed = event_ts(ev, "member_removal_proposed", "member_removal_proposed_observed")
    if proposed:
        milestones.append(("removal_propose", proposed))
    elif resource_start:
        milestones.append(("removal_propose_est", resource_start))

    for label, key in [
        ("removal_observed", "member_removal_proposed_observed"),
        ("removal_vote", "member_removal_voted"),
        ("removal_executed", "member_removal_executed_observed"),
    ]:
        ts = event_ts(ev, key)
        if ts:
            milestones.append((label, ts))

    if linked_reshare_ev:
        for label, key in [
            ("reshare_ack", "reshare_acknowledged"),
            ("reshare_keygen_start", "reshare_keygen_start"),
            ("tss_keygen_complete", "tss_keygen_complete"),
            ("reshare_complete", "reshare_complete_observed"),
        ]:
            ts = event_ts(
                linked_reshare_ev,
                key,
                "tss_keygen_start" if key == "reshare_keygen_start" else key,
                "reshare_complete_recorded" if key == "reshare_complete" else key,
            )
            if ts:
                milestones.append((label, ts))

    phases, markers = build_phases_from_milestones(milestones)
    if phases:
        return phases, markers

    executed = event_ts(ev, "member_removal_executed_observed", "member_removal_voted")
    complete = ""
    if linked_reshare_ev:
        complete = event_ts(linked_reshare_ev, "reshare_complete_observed", "reshare_complete_recorded")
    if proposed and executed:
        phases.append((proposed, executed, "removal_consensus"))
    if executed and complete:
        phases.append((executed, complete, "reshare_total"))
    if not phases and proposed and complete:
        phases.append((proposed, complete, "removal_total"))
    return phases, markers


# build_phases_for_reshare handles build phases for reshare behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def build_phases_for_reshare(ev):
    """build_phases_for_reshare helper for benchmark tooling."""
    milestones = []
    for label, key in [
        ("reshare_ack", "reshare_acknowledged"),
        ("reshare_keygen_start", "reshare_keygen_start"),
        ("tss_keygen_complete", "tss_keygen_complete"),
        ("reshare_complete", "reshare_complete_observed"),
    ]:
        ts = event_ts(
            ev,
            key,
            "tss_keygen_start" if key == "reshare_keygen_start" else key,
            "reshare_complete_recorded" if key == "reshare_complete" else key,
        )
        if ts:
            milestones.append((label, ts))

    phases, markers = build_phases_from_milestones(milestones)
    if phases:
        return phases, markers

    ack = event_ts(ev, "reshare_acknowledged")
    tss_start = event_ts(ev, "reshare_keygen_start", "tss_keygen_start")
    tss_done = event_ts(ev, "tss_keygen_complete")
    complete = event_ts(ev, "reshare_complete_observed", "reshare_complete_recorded")
    if ack and tss_start:
        phases.append((ack, tss_start, "reshare_consensus"))
    if tss_start and tss_done:
        phases.append((tss_start, tss_done, "tss_keygen"))
    if tss_done and complete:
        phases.append((tss_done, complete, "bc_registration"))
    if not phases and ack and complete:
        phases.append((ack, complete, "reshare_total"))
    return phases, markers


# build_marker_points handles build marker points behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def build_marker_points(markers):
    """build_marker_points helper for benchmark tooling."""
    points = []
    for label, ts in markers:
        t = parse_ts(ts)
        if not t:
            continue
        points.append((t, label, ts))
    points.sort(key=lambda x: x[0])
    return points


# assign_phase_detail handles assign phase detail behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def assign_phase_detail(ts, phases):
    """assign_phase_detail helper for benchmark tooling."""
    if not ts:
        return ("", "", "", "")
    t = parse_ts(ts)
    if not t:
        return ("", "", "", "")
    for start, end, label in phases:
        s = parse_ts(start)
        e = parse_ts(end)
        if s and e and s <= t < e:
            elapsed = (t - s).total_seconds()
            return (label, start, end, f"{elapsed:.3f}")
    if phases:
        first = parse_ts(phases[0][0])
        last = parse_ts(phases[-1][1])
        if first and t < first:
            return ("pre", "", phases[0][0], "")
        if last and t >= last:
            elapsed = (t - last).total_seconds()
            return ("post", phases[-1][1], "", f"{elapsed:.3f}")
    return ("", "", "", "")


# assign_marker_detail handles assign marker detail behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def assign_marker_detail(ts, marker_points):
    """assign_marker_detail helper for benchmark tooling."""
    if not ts:
        return ("", "", "", "", "", "")
    t = parse_ts(ts)
    if not t:
        return ("", "", "", "", "", "")

    prev_point = None
    next_point = None
    for p in marker_points:
        if p[0] <= t:
            prev_point = p
            continue
        next_point = p
        break

    prev_label = prev_point[1] if prev_point else ""
    prev_ts = prev_point[2] if prev_point else ""
    prev_elapsed = f"{(t - prev_point[0]).total_seconds():.3f}" if prev_point else ""
    next_label = next_point[1] if next_point else ""
    next_ts = next_point[2] if next_point else ""
    next_elapsed = f"{(next_point[0] - t).total_seconds():.3f}" if next_point else ""
    return (prev_label, prev_ts, prev_elapsed, next_label, next_ts, next_elapsed)


# to_float handles to float behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def to_float(row, key):
    """to_float helper for benchmark tooling."""
    v = row.get(key, "")
    try:
        return float(v)
    except Exception:
        return None


# avg_max handles avg max behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def avg_max(values):
    """avg_max helper for benchmark tooling."""
    if not values:
        return ("", "")
    avg = sum(values) / len(values)
    return (f"{avg:.3f}", f"{max(values):.3f}")

# write_phase_summary handles write phase summary behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def write_phase_summary(out_path, rows, group_by_workflow=False):
    """write_phase_summary helper for benchmark tooling."""
    groups = {}
    for row in rows:
        phase = row.get("phase_derived", "").strip()
        if not phase:
            phase = row.get("phase", "").strip() or "unlabeled"
        workflow = row.get("workflow_derived", "").strip()
        key = (workflow, phase) if group_by_workflow else phase
        ts = parse_ts(row.get("ts", ""))

        if key not in groups:
            groups[key] = {
                "samples": 0,
                "start": None,
                "end": None,
                "cpu_total_pct": [],
                "mem_used_pct": [],
                "tss_cpu_pct": [],
                "peer_cpu_pct": [],
                "orderer_cpu_pct": [],
                "rx_bytes_delta": [],
                "tx_bytes_delta": [],
                "rx_bytes_interval": [],
                "tx_bytes_interval": [],
                "control_rx_bytes_interval": [],
                "control_tx_bytes_interval": [],
                "control_rx_bytes_delta": [],
                "control_tx_bytes_delta": [],
                "rx_bytes_interval_adjusted": [],
                "tx_bytes_interval_adjusted": [],
                "rx_bytes_delta_adjusted": [],
                "tx_bytes_delta_adjusted": [],
            }

        g = groups[key]
        g["samples"] += 1
        if ts:
            if g["start"] is None or ts < g["start"]:
                g["start"] = ts
            if g["end"] is None or ts > g["end"]:
                g["end"] = ts
        for k in [
            "cpu_total_pct",
            "mem_used_pct",
            "tss_cpu_pct",
            "peer_cpu_pct",
            "orderer_cpu_pct",
            "rx_bytes_interval",
            "tx_bytes_interval",
            "rx_bytes_delta",
            "tx_bytes_delta",
            "control_rx_bytes_interval",
            "control_tx_bytes_interval",
            "control_rx_bytes_delta",
            "control_tx_bytes_delta",
            "rx_bytes_interval_adjusted",
            "tx_bytes_interval_adjusted",
            "rx_bytes_delta_adjusted",
            "tx_bytes_delta_adjusted",
        ]:
            fv = to_float(row, k)
            if fv is not None:
                g[k].append(fv)

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if group_by_workflow:
            writer.writerow(
                [
                    "workflow",
                    "phase",
                    "samples",
                    "phase_start_ts",
                    "phase_end_ts",
                    "phase_span_s",
                    "cpu_total_avg",
                    "cpu_total_max",
                    "mem_used_avg",
                    "mem_used_max",
                    "tss_cpu_avg",
                    "tss_cpu_max",
                    "peer_cpu_avg",
                    "peer_cpu_max",
                    "orderer_cpu_avg",
                    "orderer_cpu_max",
                    "rx_delta_sum",
                    "tx_delta_sum",
                    "control_rx_delta_sum",
                    "control_tx_delta_sum",
                    "rx_delta_adjusted_sum",
                    "tx_delta_adjusted_sum",
                ]
            )
            sorted_keys = sorted(groups.keys(), key=lambda k: (k[0], k[1]))
        else:
            writer.writerow(
                [
                    "phase",
                    "samples",
                    "phase_start_ts",
                    "phase_end_ts",
                    "phase_span_s",
                    "cpu_total_avg",
                    "cpu_total_max",
                    "mem_used_avg",
                    "mem_used_max",
                    "tss_cpu_avg",
                    "tss_cpu_max",
                    "peer_cpu_avg",
                    "peer_cpu_max",
                    "orderer_cpu_avg",
                    "orderer_cpu_max",
                    "rx_delta_sum",
                    "tx_delta_sum",
                    "control_rx_delta_sum",
                    "control_tx_delta_sum",
                    "rx_delta_adjusted_sum",
                    "tx_delta_adjusted_sum",
                ]
            )
            sorted_keys = sorted(groups.keys())

        for key in sorted_keys:
            g = groups[key]
            start = g["start"]
            end = g["end"]
            span_s = f"{(end - start).total_seconds():.3f}" if start and end else ""
            cpu_avg, cpu_max = avg_max(g["cpu_total_pct"])
            mem_avg, mem_max = avg_max(g["mem_used_pct"])
            tss_avg, tss_max = avg_max(g["tss_cpu_pct"])
            peer_avg, peer_max = avg_max(g["peer_cpu_pct"])
            ord_avg, ord_max = avg_max(g["orderer_cpu_pct"])

            # sum_first_available handles sum first available behavior for benchmark tooling.
            # Lifecycle: Benchmark script runtime, aggregation, and analysis.
            # Called by: module-internal callers (see surrounding flow).
            # Triggered: CLI execution and helper orchestration.
            def sum_first_available(keys):
                """sum_first_available helper for benchmark tooling."""
                for key in keys:
                    vals = g.get(key, [])
                    if vals:
                        return f"{sum(vals):.0f}"
                return ""

            # Prefer interval columns when present; fall back to legacy cumulative deltas.
            rx_sum = sum_first_available(["rx_bytes_interval", "rx_bytes_delta"])
            tx_sum = sum_first_available(["tx_bytes_interval", "tx_bytes_delta"])
            control_rx_sum = sum_first_available(["control_rx_bytes_interval", "control_rx_bytes_delta"])
            control_tx_sum = sum_first_available(["control_tx_bytes_interval", "control_tx_bytes_delta"])
            rx_adj_sum = sum_first_available(["rx_bytes_interval_adjusted", "rx_bytes_delta_adjusted"])
            tx_adj_sum = sum_first_available(["tx_bytes_interval_adjusted", "tx_bytes_delta_adjusted"])

            if group_by_workflow:
                workflow, phase = key
                writer.writerow(
                    [
                        workflow,
                        phase,
                        g["samples"],
                        to_z(start),
                        to_z(end),
                        span_s,
                        cpu_avg,
                        cpu_max,
                        mem_avg,
                        mem_max,
                        tss_avg,
                        tss_max,
                        peer_avg,
                        peer_max,
                        ord_avg,
                        ord_max,
                        rx_sum,
                        tx_sum,
                        control_rx_sum,
                        control_tx_sum,
                        rx_adj_sum,
                        tx_adj_sum,
                    ]
                )
            else:
                phase = key
                writer.writerow(
                    [
                        phase,
                        g["samples"],
                        to_z(start),
                        to_z(end),
                        span_s,
                        cpu_avg,
                        cpu_max,
                        mem_avg,
                        mem_max,
                        tss_avg,
                        tss_max,
                        peer_avg,
                        peer_max,
                        ord_avg,
                        ord_max,
                        rx_sum,
                        tx_sum,
                        control_rx_sum,
                        control_tx_sum,
                        rx_adj_sum,
                        tx_adj_sum,
                    ]
                )


# _resolve_workflow handles resolve workflow behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def _resolve_workflow(mode, operation, explicit_proposal_id="", explicit_epoch=""):
    """_resolve_workflow helper for benchmark tooling."""
    if mode != "auto":
        return mode
    inferred = infer_workflow_from_operation(operation)
    if inferred:
        return inferred
    if explicit_epoch:
        return "reshare"
    if explicit_proposal_id:
        pid = str(explicit_proposal_id).strip()
        for workflow, prefixes in PROPOSAL_PREFIX_BY_WORKFLOW.items():
            if any(pid.startswith(p) for p in prefixes):
                return workflow
    return "csr"


# _resolve_single_proposal_context handles resolve single proposal context behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def _resolve_single_proposal_context(
    workflow,
    by_proposal,
    resource_min_ts,
    operation,
    explicit_proposal_id="",
    strict_proposal_id=False,
):
    """_resolve_single_proposal_context helper for benchmark tooling."""
    matched = ""
    explicit = str(explicit_proposal_id).strip()

    if explicit:
        if explicit in by_proposal:
            matched = explicit
            if not strict_proposal_id:
                diff = proposal_anchor_diff_s(workflow, by_proposal[explicit], resource_min_ts)
                score = proposal_timeline_score(workflow, by_proposal[explicit])
                if diff is None or diff > 900 or score < 2:
                    auto = infer_proposal_id(by_proposal, workflow, resource_min_ts, operation)
                    if auto and auto != explicit:
                        print(
                            f"Warning: proposal id {explicit} looks stale "
                            f"(diff={diff if diff is not None else 'n/a'}s, score={score}); "
                            f"using nearest proposal {auto}."
                        )
                        matched = auto
        else:
            if strict_proposal_id:
                raise SystemExit(
                    f"Proposal id {explicit} not found in metrics and --strict-proposal-id is set."
                )
            print(f"Warning: proposal id {explicit} not found in metrics; auto-detecting nearest {workflow} proposal.")

    if not matched:
        matched = infer_proposal_id(by_proposal, workflow, resource_min_ts, operation)

    if not matched:
        raise SystemExit(
            f"No matching {workflow} proposal events found. "
            "Provide a correct --proposal-id and include metrics.jsonl from submitting/signing nodes."
        )

    return matched, by_proposal.get(matched, {})


# _extract_default_fieldnames handles extract default fieldnames behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def _extract_default_fieldnames(rows):
    """_extract_default_fieldnames helper for benchmark tooling."""
    return list(rows[0].keys()) if rows else []


# _default_labeled_path handles default labeled path behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def _default_labeled_path(resource_path):
    """_default_labeled_path helper for benchmark tooling."""
    base_dir = os.path.dirname(resource_path)
    base_name = os.path.basename(resource_path)
    stem, ext = os.path.splitext(base_name)
    ext = ext if ext else ".csv"
    return os.path.join(base_dir, f"{stem}_labeled{ext}")


# _build_group_map handles build group map behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def _build_group_map(rows):
    """_build_group_map helper for benchmark tooling."""
    groups = {}
    for idx, row in enumerate(rows):
        operation = str(row.get("operation", "")).strip()
        key = operation if operation else "__no_operation__"
        groups.setdefault(key, []).append(idx)
    return groups


# _group_min_ts handles group min ts behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def _group_min_ts(rows, indexes):
    """_group_min_ts helper for benchmark tooling."""
    min_dt = None
    for idx in indexes:
        dt = parse_ts(rows[idx].get("ts", ""))
        if dt and (min_dt is None or dt < min_dt):
            min_dt = dt
    return min_dt


# _linked_reshare_epoch_for_membership handles linked reshare epoch for membership behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def _linked_reshare_epoch_for_membership(workflow, proposal_ev, by_epoch, group_min_ts, operation):
    """_linked_reshare_epoch_for_membership helper for benchmark tooling."""
    member_id = collect_member_id_from_proposal_ev(workflow, proposal_ev)
    reason_prefixes = RESHARE_REASON_PREFIX_BY_WORKFLOW.get(workflow, [])
    after_ts = ""
    if workflow == "join":
        after_ts = event_ts(
            proposal_ev,
            "join_request_approved_observed",
            "join_request_voted",
            "join_request_submitted",
            "join_request_submitted_observed",
        )
    elif workflow == "removal":
        after_ts = event_ts(
            proposal_ev,
            "member_removal_executed_observed",
            "member_removal_voted",
            "member_removal_proposed",
            "member_removal_proposed_observed",
        )
    return infer_reshare_epoch(
        by_epoch,
        group_min_ts,
        operation,
        member_id=member_id,
        reason_prefixes=reason_prefixes,
        after_ts=after_ts,
    )


# _build_phases_for_workflow handles build phases for workflow behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def _build_phases_for_workflow(workflow, proposal_ev, epoch_ev, group_start_ts):
    """_build_phases_for_workflow helper for benchmark tooling."""
    if workflow == "csr":
        return build_phases_for_csr(proposal_ev, group_start_ts)
    if workflow == "revocation":
        return build_phases_for_revocation(proposal_ev, group_start_ts)
    if workflow == "join":
        return build_phases_for_join(proposal_ev, linked_reshare_ev=epoch_ev, resource_start=group_start_ts)
    if workflow == "removal":
        return build_phases_for_removal(proposal_ev, linked_reshare_ev=epoch_ev, resource_start=group_start_ts)
    if workflow == "reshare":
        return build_phases_for_reshare(epoch_ev)
    return ([], [])
# label_resource_rows enriches raw resource rows with workflow/phase labels.
# Lifecycle: Labeling transformation stage.
# Called by: main.
# Triggered: for each resource CSV file provided to the script.
def label_resource_rows(rows, args, by_proposal, by_epoch, source_file):
    """label_resource_rows helper for benchmark tooling."""
    groups = _build_group_map(rows)
    output_rows = [dict(r) for r in rows]
    any_group_labeled = False

    for operation, row_indexes in groups.items():
        op_hint = "" if operation == "__no_operation__" else operation
        group_min_ts = _group_min_ts(output_rows, row_indexes)
        group_start_ts = to_z(group_min_ts) if group_min_ts else ""

        workflow = _resolve_workflow(
            args.mode,
            op_hint,
            explicit_proposal_id=args.proposal_id,
            explicit_epoch=args.epoch,
        )

        proposal_id = ""
        epoch_id = ""
        entity_id = ""
        proposal_ev = {}
        epoch_ev = {}

        if workflow in ("csr", "revocation", "join", "removal"):
            explicit_for_workflow = ""
            if args.proposal_id and proposal_matches_workflow(args.proposal_id, by_proposal.get(args.proposal_id, {}), workflow):
                explicit_for_workflow = args.proposal_id
            elif args.mode == workflow and args.proposal_id:
                explicit_for_workflow = args.proposal_id

            proposal_id, proposal_ev = _resolve_single_proposal_context(
                workflow,
                by_proposal,
                group_min_ts,
                op_hint,
                explicit_proposal_id=explicit_for_workflow,
                strict_proposal_id=args.strict_proposal_id,
            )
            entity_id = proposal_id

            if workflow in ("join", "removal"):
                if args.epoch:
                    epoch_id = str(args.epoch)
                else:
                    epoch_id = _linked_reshare_epoch_for_membership(
                        workflow,
                        proposal_ev,
                        by_epoch,
                        group_min_ts,
                        op_hint,
                    )
                if epoch_id:
                    epoch_ev = by_epoch.get(str(epoch_id), {})

        elif workflow == "reshare":
            if args.epoch:
                epoch_id = str(args.epoch)
            else:
                epoch_id = infer_reshare_epoch(by_epoch, group_min_ts, op_hint)
            if not epoch_id:
                raise SystemExit(
                    "No matching reshare epoch events found. Provide --epoch or include metrics.jsonl from reshare participants."
                )
            epoch_ev = by_epoch.get(str(epoch_id), {})
            entity_id = str(epoch_id)
        else:
            # Unknown workflow fallback; keep rows but mark workflow only.
            pass

        phases, markers = _build_phases_for_workflow(workflow, proposal_ev, epoch_ev, group_start_ts)
        marker_points = build_marker_points(markers)
        markers_json = json.dumps(markers)
        if phases:
            any_group_labeled = True

        for idx in row_indexes:
            row = output_rows[idx]
            label, start, end, elapsed = assign_phase_detail(row.get("ts", ""), phases)
            (
                marker_prev,
                marker_prev_ts,
                marker_prev_elapsed_s,
                marker_next,
                marker_next_ts,
                marker_next_elapsed_s,
            ) = assign_marker_detail(row.get("ts", ""), marker_points)

            row["phase_derived"] = label
            row["phase_start_ts"] = start
            row["phase_end_ts"] = end
            row["phase_elapsed_s"] = elapsed
            row["marker_prev"] = marker_prev
            row["marker_prev_ts"] = marker_prev_ts
            row["marker_prev_elapsed_s"] = marker_prev_elapsed_s
            row["marker_next"] = marker_next
            row["marker_next_ts"] = marker_next_ts
            row["marker_next_elapsed_s"] = marker_next_elapsed_s
            row["proposal_id_derived"] = proposal_id
            row["workflow_derived"] = workflow
            row["entity_id_derived"] = entity_id
            row["epoch_derived"] = epoch_id
            row["timeline_markers"] = markers_json

    if not any_group_labeled:
        raise SystemExit(
            f"No matching timeline phases were found for {source_file}. "
            "Check --mode/--proposal-id/--epoch and include metrics.jsonl from relevant nodes."
        )

    return output_rows


# write_csv handles write csv behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def write_csv(out_path, rows, fieldnames):
    """write_csv helper for benchmark tooling."""
    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


# read_resource_rows handles read resource rows behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def read_resource_rows(resource_path):
    """read_resource_rows helper for benchmark tooling."""
    rows = []
    min_ts = None
    with open(resource_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            normalized = _normalize_row_keys(row)
            rows.append(normalized)
            ts = parse_ts(normalized.get("ts", ""))
            if ts and (min_ts is None or ts < min_ts):
                min_ts = ts
    return rows, min_ts


# enrich_fieldnames handles enrich fieldnames behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def enrich_fieldnames(fieldnames):
    """enrich_fieldnames helper for benchmark tooling."""
    out = list(fieldnames)
    for extra in [
        "phase_derived",
        "phase_start_ts",
        "phase_end_ts",
        "phase_elapsed_s",
        "marker_prev",
        "marker_prev_ts",
        "marker_prev_elapsed_s",
        "marker_next",
        "marker_next_ts",
        "marker_next_elapsed_s",
        "proposal_id_derived",
        "workflow_derived",
        "entity_id_derived",
        "epoch_derived",
        "timeline_markers",
    ]:
        if extra not in out:
            out.append(extra)
    return out


# sort_rows_by_ts handles sort rows by ts behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def sort_rows_by_ts(rows):
    """sort_rows_by_ts helper for benchmark tooling."""
    # key handles key behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def key(row):
        """key helper for benchmark tooling."""
        dt = parse_ts(row.get("ts", ""))
        # Preserve deterministic ordering even when timestamp is missing/invalid.
        return (dt is None, dt or datetime.max, str(row.get("source_file", "")), str(row.get("operation", "")))

    return sorted(rows, key=key)

# main orchestrates resource labeling across one or more resource CSV files.
# Lifecycle: Resource labeling entrypoint.
# Called by: module entrypoint (`if __name__ == "__main__"`).
# Triggered: when invoked directly or from suite automation.
def main():
    """main helper for benchmark tooling."""
    parser = argparse.ArgumentParser(
        description="Label resource samples with workflow phases (csr/revocation/join/removal/reshare)."
    )
    parser.add_argument("--resources", nargs="+", required=True, help="Path(s) to resources CSV file(s)")
    parser.add_argument("--metrics", nargs="+", required=True, help="Metrics JSONL paths")
    parser.add_argument("--proposal-id", default="", help="Proposal ID (for csr/revocation/join/removal)")
    parser.add_argument(
        "--strict-proposal-id",
        action="store_true",
        help="Do not auto-correct stale --proposal-id values",
    )
    parser.add_argument("--epoch", default="", help="Epoch (for reshare or linked membership workflows)")
    parser.add_argument("--mode", choices=MODE_CHOICES, default="auto")
    parser.add_argument("--out", default="", help="Output CSV path (single resource mode)")
    parser.add_argument("--outdir", default="", help="Output directory for per-file labeled CSVs (multi-resource mode)")
    parser.add_argument("--merged-out", default="", help="Optional merged labeled CSV output path")
    parser.add_argument("--phase-summary-out", default="", help="Optional per-phase summary CSV path (single resource mode)")
    parser.add_argument(
        "--merged-phase-summary-out",
        default="",
        help="Optional merged per-phase summary CSV path (groups by workflow + phase)",
    )
    args = parser.parse_args()

    resources = [str(r) for r in args.resources if str(r).strip()]
    if not resources:
        raise SystemExit("No --resources files provided.")

    if len(resources) > 1 and args.out:
        raise SystemExit("--out is only supported with a single --resources input.")
    if len(resources) > 1 and args.phase_summary_out:
        raise SystemExit("--phase-summary-out is only supported with a single --resources input.")

    events = load_events(args.metrics)
    events.sort(key=lambda e: e.get("ts", ""))
    by_proposal, by_epoch = build_event_indexes(events)

    per_file_outputs = []
    merged_rows = []

    for resource_path in resources:
        rows, _ = read_resource_rows(resource_path)
        if not rows:
            print(f"Warning: resources file is empty: {resource_path}")
            continue

        labeled_rows = label_resource_rows(rows, args, by_proposal, by_epoch, resource_path)
        fieldnames = enrich_fieldnames(_extract_default_fieldnames(labeled_rows))

        if len(resources) == 1:
            if args.out:
                out_path = args.out
            elif args.outdir:
                os.makedirs(args.outdir, exist_ok=True)
                out_path = os.path.join(args.outdir, os.path.basename(_default_labeled_path(resource_path)))
            else:
                out_path = _default_labeled_path(resource_path)
        else:
            out_dir = args.outdir or os.path.dirname(resource_path) or "."
            os.makedirs(out_dir, exist_ok=True)
            out_path = os.path.join(out_dir, os.path.basename(_default_labeled_path(resource_path)))

        write_csv(out_path, labeled_rows, fieldnames)
        per_file_outputs.append(out_path)
        print(f"Labeled resource file: {out_path}")

        if len(resources) == 1 and args.phase_summary_out:
            write_phase_summary(args.phase_summary_out, labeled_rows, group_by_workflow=False)
            print(f"Phase summary written: {args.phase_summary_out}")

        for row in labeled_rows:
            merged_row = dict(row)
            merged_row["source_file"] = resource_path
            merged_rows.append(merged_row)

    if not per_file_outputs:
        raise SystemExit("No labeled output was produced (all resources files were empty).")

    if args.merged_out or args.merged_phase_summary_out:
        merged_rows = sort_rows_by_ts(merged_rows)
        merged_fields = enrich_fieldnames(_extract_default_fieldnames(merged_rows))
        if "source_file" not in merged_fields:
            merged_fields.append("source_file")

        if args.merged_out:
            write_csv(args.merged_out, merged_rows, merged_fields)
            print(f"Merged labeled file: {args.merged_out}")

        if args.merged_phase_summary_out:
            write_phase_summary(args.merged_phase_summary_out, merged_rows, group_by_workflow=True)
            print(f"Merged phase summary written: {args.merged_phase_summary_out}")


if __name__ == "__main__":
    main()
