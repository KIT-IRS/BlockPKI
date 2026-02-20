#!/usr/bin/env python3
import argparse
import csv
import json
from datetime import datetime


def parse_ts(ts):
    if not ts:
        return None
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def load_events(paths):
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


def pick(ev, *keys):
    for k in keys:
        if k in ev:
            return ev.get(k)
    return None


def get_proposal_id(e):
    return (
        e.get("proposal_id")
        or e.get("proposalId")
        or e.get("proposalID")
        or e.get("proposal")
        or ""
    )


def get_epoch(e):
    return e.get("epoch") or e.get("Epoch") or e.get("epoch_id") or ""


def build_phases_for_csr(ev, resource_start=None):
    csr_start = pick(ev, "csr_api_received", "csr_submitted", "csr_submitted_observed")
    tss_start = pick(ev, "tss_signing_start")
    tss_done = pick(ev, "tss_signing_complete")
    cert_done = pick(ev, "cert_registered_observed", "cert_registered")

    phases = []
    consensus_label = "csr_consensus"
    if not csr_start and resource_start and tss_start:
        csr_start = resource_start
        consensus_label = "csr_consensus_est"
    if csr_start and tss_start:
        phases.append((csr_start, tss_start, consensus_label))
    if tss_start and tss_done:
        phases.append((tss_start, tss_done, "tss_signing"))
    if tss_done and cert_done:
        phases.append((tss_done, cert_done, "bc_registration"))
    if not phases and csr_start and cert_done:
        phases.append((csr_start, cert_done, "csr_total"))
    return phases


def build_phases_for_reshare(ev):
    ack = pick(ev, "reshare_acknowledged")
    tss_start = pick(ev, "reshare_keygen_start", "tss_keygen_start")
    tss_done = pick(ev, "tss_keygen_complete")
    complete = pick(ev, "reshare_complete_observed", "reshare_complete_recorded")

    phases = []
    if ack and tss_start:
        phases.append((ack, tss_start, "reshare_consensus"))
    if tss_start and tss_done:
        phases.append((tss_start, tss_done, "tss_keygen"))
    if tss_done and complete:
        phases.append((tss_done, complete, "bc_registration"))
    if not phases and ack and complete:
        phases.append((ack, complete, "reshare_total"))
    return phases


def assign_phase(ts, phases):
    if not ts:
        return ""
    t = parse_ts(ts)
    if not t:
        return ""
    for start, end, label in phases:
        s = parse_ts(start)
        e = parse_ts(end)
        if s and e and s <= t < e:
            return label
    if phases:
        first = parse_ts(phases[0][0])
        last = parse_ts(phases[-1][1])
        if first and t < first:
            return "pre"
        if last and t >= last:
            return "post"
    return ""


def main():
    parser = argparse.ArgumentParser(description="Label resource samples with CSR/reshare phases.")
    parser.add_argument("--resources", required=True, help="Path to resources CSV")
    parser.add_argument("--metrics", nargs="+", required=True, help="Metrics JSONL paths")
    parser.add_argument("--proposal-id", default="", help="Proposal ID (for CSR)")
    parser.add_argument("--epoch", default="", help="Epoch (for reshare)")
    parser.add_argument("--mode", choices=["csr", "reshare"], default="csr")
    parser.add_argument("--out", required=True, help="Output CSV path")
    args = parser.parse_args()

    events = load_events(args.metrics)
    events.sort(key=lambda e: e.get("ts", ""))

    resource_rows = []
    resource_min_ts = None
    with open(args.resources, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            resource_rows.append(row)
            ts = parse_ts(row.get("ts", ""))
            if ts and (resource_min_ts is None or ts < resource_min_ts):
                resource_min_ts = ts

    ev = {}
    if args.mode == "csr":
        if not args.proposal_id:
            raise SystemExit("Missing --proposal-id for CSR mode.")
        target_pid = str(args.proposal_id).strip()
        for e in events:
            pid = get_proposal_id(e)
            if pid is None:
                continue
            if str(pid).strip() == target_pid:
                if e.get("event") and e["event"] not in ev:
                    ev[e["event"]] = e.get("ts")
    else:
        if args.epoch == "":
            raise SystemExit("Missing --epoch for reshare mode.")
        for e in events:
            if str(get_epoch(e)) == str(args.epoch):
                if e.get("event") and e["event"] not in ev:
                    ev[e["event"]] = e.get("ts")

    if args.mode == "csr":
        start_ts = None
        if resource_min_ts:
            start_ts = resource_min_ts.isoformat().replace("+00:00", "Z")
        phases = build_phases_for_csr(ev, start_ts)
    else:
        phases = build_phases_for_reshare(ev)

    fieldnames = list(resource_rows[0].keys()) if resource_rows else []
    out_field = "phase_derived"
    if out_field not in fieldnames:
        fieldnames.append(out_field)
    rows = []
    for row in resource_rows:
        row[out_field] = assign_phase(row.get("ts", ""), phases)
        rows.append(row)

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    main()
