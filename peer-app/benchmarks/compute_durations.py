#!/usr/bin/env python3
"""compute_durations.py derives workflow stage durations from metric-event logs.

Runtime flow: run after benchmark execution to convert metric JSONL streams into
`events.csv` and `durations.csv` summary artifacts.
"""

import argparse
import csv
import json
import re
from collections import defaultdict
from datetime import datetime


# parse_ts parses RFC3339/RFC3339Nano-like timestamps into datetime objects.
# Lifecycle: Post-run benchmark metrics reduction.
# Called by: diff.
# Triggered: whenever timestamp deltas are computed during duration extraction.
def parse_ts(ts):
    """parse_ts helper for benchmark tooling."""
    ts = str(ts).strip()
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    ts = re.sub(r"(\.\d{6})\d+(?=(?:[+-]\d{2}:\d{2})?$)", r"\1", ts)
    return datetime.fromisoformat(ts)


# load_events reads newline-delimited JSON metric events from one or more files.
# Lifecycle: Post-run benchmark metrics reduction.
# Called by: main.
# Triggered: at script startup before grouping and duration computation.
def load_events(paths):
    """load_events helper for benchmark tooling."""
    events = []
    for path in paths:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return events


# main builds event and duration CSV artifacts from raw metric logs.
# Lifecycle: Post-run benchmark metrics reduction.
# Called by: module entrypoint (`if __name__ == "__main__"`).
# Triggered: when the script is executed from CLI or suite automation.
def main():
    """main helper for benchmark tooling."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--metrics", nargs="+", required=True)
    parser.add_argument("--outdir", default=".")
    args = parser.parse_args()

    events = load_events(args.metrics)
    events.sort(key=lambda e: e.get("ts", ""))

    # Write raw events CSV
    events_csv = args.outdir.rstrip("/") + "/events.csv"
    fieldnames = sorted({k for e in events for k in e.keys()})
    with open(events_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for e in events:
            writer.writerow(e)

    # Group by proposal_id and epoch
    by_proposal = defaultdict(dict)
    by_epoch = defaultdict(dict)

    for e in events:
        ts = e.get("ts")
        if not ts:
            continue
        if "proposal_id" in e:
            bucket = by_proposal[e["proposal_id"]]
            if e["event"] not in bucket:
                bucket[e["event"]] = ts
        if "epoch" in e:
            bucket = by_epoch[str(e["epoch"])]
            if e["event"] not in bucket:
                bucket[e["event"]] = ts
            if "reason" in e and "reason" not in bucket:
                bucket["reason"] = e["reason"]

    durations = []

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

    # CSR durations
    for proposal_id, ev in by_proposal.items():
        cert_done = pick(ev, "cert_registered_observed", "cert_registered")
        csr_start = pick(ev, "csr_api_received", "csr_submitted", "csr_submitted_observed")
        if csr_start or cert_done:
            row = {
                "type": "csr",
                "id": proposal_id,
                "proposal_s": diff(csr_start, ev.get("signing_session_active")),
                "tss_s": diff(ev.get("tss_signing_start"), ev.get("tss_signing_complete")),
                "registration_s": diff(ev.get("tss_signing_complete"), cert_done),
                "total_s": diff(csr_start, cert_done),
            }
            durations.append(row)

    # Revocation durations (proposal -> vote)
    for proposal_id, ev in by_proposal.items():
        rev_done = pick(ev, "revocation_executed_observed", "revocation_voted")
        rev_start = pick(ev, "revocation_proposed", "revocation_proposed_observed")
        if rev_start or rev_done:
            row = {
                "type": "revocation",
                "id": proposal_id,
                "proposal_s": diff(rev_start, ev.get("revocation_voted")),
                "tss_s": "",
                "registration_s": "",
                "total_s": diff(rev_start, rev_done),
            }
            durations.append(row)

    # Member removal durations (proposal -> vote)
    for proposal_id, ev in by_proposal.items():
        removal_done = pick(ev, "member_removal_executed_observed", "member_removal_voted")
        removal_start = pick(ev, "member_removal_proposed", "member_removal_proposed_observed")
        if removal_start or removal_done:
            row = {
                "type": "member_removal",
                "id": proposal_id,
                "proposal_s": diff(removal_start, ev.get("member_removal_voted")),
                "tss_s": "",
                "registration_s": "",
                "total_s": diff(removal_start, removal_done),
            }
            durations.append(row)

    # Join request durations (proposal -> vote)
    for proposal_id, ev in by_proposal.items():
        join_done = pick(ev, "join_request_approved_observed", "join_request_voted")
        join_start = pick(ev, "join_request_submitted", "join_request_submitted_observed")
        if join_start or join_done:
            row = {
                "type": "join_request",
                "id": proposal_id,
                "proposal_s": diff(join_start, ev.get("join_request_voted")),
                "tss_s": "",
                "registration_s": "",
                "total_s": diff(join_start, join_done),
            }
            durations.append(row)

    # Reshare durations by epoch
    for epoch, ev in by_epoch.items():
        complete = pick(ev, "reshare_complete_observed", "reshare_complete_recorded")
        if any(k in ev for k in ("reshare_acknowledged", "reshare_keygen_start", "reshare_complete_recorded", "reshare_complete_observed")):
            row = {
                "type": "reshare",
                "id": epoch,
                "reason": ev.get("reason", ""),
                "proposal_s": diff(ev.get("reshare_acknowledged"), ev.get("reshare_keygen_start")),
                "tss_s": diff(ev.get("tss_keygen_complete"), complete),
                "registration_s": diff(ev.get("reshare_complete_submitted"), complete),
                "total_s": diff(ev.get("reshare_acknowledged"), complete),
            }
            durations.append(row)

    durations_csv = args.outdir.rstrip("/") + "/durations.csv"
    with open(durations_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["type", "id", "reason", "proposal_s", "tss_s", "registration_s", "total_s"],
        )
        writer.writeheader()
        for row in durations:
            writer.writerow(row)


# diff returns seconds between two timestamp strings (empty string when unavailable).
# Lifecycle: Post-run benchmark metrics reduction.
# Called by: main.
# Triggered: for each workflow segment duration written to `durations.csv`.
def diff(a, b):
    """diff helper for benchmark tooling."""
    if not a or not b:
        return ""
    try:
        return (parse_ts(b) - parse_ts(a)).total_seconds()
    except Exception:
        return ""


if __name__ == "__main__":
    main()
