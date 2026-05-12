#!/usr/bin/env python3
"""run_workflows.py executes benchmark workflow operations and captures raw artifacts.

Runtime flow: drives API workflows, observes metric events, samples resources and
storage, and emits per-run raw CSV/JSON outputs for suite aggregation.
"""

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta

DEFAULT_STORAGE_COMPONENT_RULES = (
    "peer=peer0\\.",
    "orderer=orderer\\.",
)
WORKFLOW_RUNS_CANONICAL_FILE = "workflow_runs.csv"
WORKFLOW_RUNS_LEGACY_FILE = "workflow_runs_v2.csv"
PEER_LEDGER_STORE_SIZE_KEYS = [
    "peer_volume_bytes",
    "block_files_bytes",
    "block_index_bytes",
    "leveldb_data_bytes",
    "leveldb_wal_meta_bytes",
    "peer_store_other_bytes",
]
LEVELDB_WAL_META_FILENAME_RE = re.compile(
    r"^(?:LOG(?:\.old)?|\d+\.log|MANIFEST-\d+|CURRENT|LOCK|OPTIONS-\d+|OPTIONS)$",
    re.IGNORECASE,
)


# normalize_path handles normalize path behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def normalize_path(path):
    """normalize_path helper for benchmark tooling."""
    return os.path.normpath(os.path.abspath(str(path))).replace("\\", "/").rstrip("/")


# is_docker_volumes_path handles is docker volumes path behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def is_docker_volumes_path(path):
    """is_docker_volumes_path helper for benchmark tooling."""
    norm = normalize_path(path)
    return norm.endswith("/volumes")


# resolve_docker_root_dir handles resolve docker root dir behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def resolve_docker_root_dir():
    """resolve_docker_root_dir helper for benchmark tooling."""
    try:
        proc = subprocess.run(
            ["docker", "info", "--format", "{{.DockerRootDir}}"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except Exception:
        return ""
    if proc.returncode != 0:
        return ""
    return (proc.stdout or "").strip()


# resolve_default_storage_paths handles resolve default storage paths behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def resolve_default_storage_paths():
    """resolve_default_storage_paths helper for benchmark tooling."""
    docker_root = resolve_docker_root_dir()
    if not docker_root:
        return [], "", "docker info could not resolve DockerRootDir."
    volumes_path = os.path.join(docker_root, "volumes")
    if not os.path.isdir(volumes_path):
        return [], docker_root, f"Docker volumes path not found: {volumes_path}"
    if not os.access(volumes_path, os.R_OK | os.X_OK):
        return [], docker_root, f"Docker volumes path not readable: {volumes_path}"
    return [volumes_path], docker_root, ""


# ensure_storage_paths_readable handles ensure storage paths readable behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def ensure_storage_paths_readable(paths):
    """ensure_storage_paths_readable helper for benchmark tooling."""
    checked = []
    for raw in paths:
        path = str(raw).strip()
        if not path:
            continue
        if not os.path.isdir(path):
            raise RuntimeError(f"storage path does not exist or is not a directory: {path}")
        if not os.access(path, os.R_OK | os.X_OK):
            raise RuntimeError(f"storage path is not readable/executable: {path}")
        checked.append(path)
    return checked


# safe_dir_size handles safe dir size behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def safe_dir_size(path):
    """safe_dir_size helper for benchmark tooling."""
    if not path or not os.path.isdir(path):
        return 0
    size = dir_size(path)
    if size is None:
        return 0
    return int(size)


# sum_leveldb_wal_meta_bytes handles sum leveldb wal meta bytes behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def sum_leveldb_wal_meta_bytes(root_path):
    """sum_leveldb_wal_meta_bytes helper for benchmark tooling."""
    if not root_path or not os.path.isdir(root_path):
        return 0
    total = 0
    try:
        for dirpath, _dirnames, filenames in os.walk(root_path):
            for name in filenames:
                if not LEVELDB_WAL_META_FILENAME_RE.match(str(name)):
                    continue
                fp = os.path.join(dirpath, name)
                try:
                    total += int(os.path.getsize(fp))
                except OSError:
                    continue
    except OSError:
        return 0
    return total


# candidate_peer_production_roots handles candidate peer production roots behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def candidate_peer_production_roots(volume_path):
    """candidate_peer_production_roots helper for benchmark tooling."""
    base = os.path.join(volume_path, "_data")
    candidates = [
        os.path.join(base, "var", "hyperledger", "production"),
        os.path.join(base, "hyperledger", "production"),
        os.path.join(base, "production"),
        base,
    ]
    out = []
    seen = set()
    for candidate in candidates:
        norm = os.path.normpath(candidate)
        if norm in seen:
            continue
        seen.add(norm)
        if os.path.isdir(candidate):
            out.append(candidate)
    return out


# choose_peer_production_root handles choose peer production root behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def choose_peer_production_root(volume_path):
    """choose_peer_production_root helper for benchmark tooling."""
    roots = candidate_peer_production_roots(volume_path)
    if not roots:
        return ""
    preferred_suffixes = [
        os.path.normpath(os.path.join("ledgersData", "chains", "chains")),
        os.path.normpath(os.path.join("ledgersData", "stateLeveldb")),
    ]
    for root in roots:
        for suffix in preferred_suffixes:
            if os.path.isdir(os.path.join(root, suffix)):
                return root
    return roots[0]


# collect_peer_ledger_store_sizes handles collect peer ledger store sizes behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def collect_peer_ledger_store_sizes(volume_path):
    """collect_peer_ledger_store_sizes helper for benchmark tooling."""
    root = choose_peer_production_root(volume_path)
    peer_volume_bytes = safe_dir_size(volume_path)
    if not root:
        return {
            "peer_volume_bytes": peer_volume_bytes,
            "block_files_bytes": 0,
            "block_index_bytes": 0,
            "leveldb_data_bytes": 0,
            "leveldb_wal_meta_bytes": 0,
            "peer_store_other_bytes": peer_volume_bytes,
            "peer_store_root": "",
        }

    block_files_path = os.path.join(root, "ledgersData", "chains", "chains")
    block_index_path = os.path.join(root, "ledgersData", "chains", "index")
    state_leveldb_path = os.path.join(root, "ledgersData", "stateLeveldb")
    history_leveldb_path = os.path.join(root, "ledgersData", "historyLeveldb")
    bookkeeper_leveldb_path = os.path.join(root, "ledgersData", "bookkeeper")
    config_history_leveldb_path = os.path.join(root, "ledgersData", "configHistory")

    block_files_bytes = safe_dir_size(block_files_path)
    block_index_bytes = safe_dir_size(block_index_path)
    leveldb_total_bytes = (
        safe_dir_size(state_leveldb_path)
        + safe_dir_size(history_leveldb_path)
        + safe_dir_size(bookkeeper_leveldb_path)
        + safe_dir_size(config_history_leveldb_path)
    )
    leveldb_wal_meta_bytes = (
        sum_leveldb_wal_meta_bytes(state_leveldb_path)
        + sum_leveldb_wal_meta_bytes(history_leveldb_path)
        + sum_leveldb_wal_meta_bytes(bookkeeper_leveldb_path)
        + sum_leveldb_wal_meta_bytes(config_history_leveldb_path)
    )
    if leveldb_wal_meta_bytes > leveldb_total_bytes:
        leveldb_wal_meta_bytes = leveldb_total_bytes
    leveldb_data_bytes = max(leveldb_total_bytes - leveldb_wal_meta_bytes, 0)

    accounted = block_files_bytes + block_index_bytes + leveldb_data_bytes + leveldb_wal_meta_bytes
    peer_store_other_bytes = max(peer_volume_bytes - accounted, 0)

    return {
        "peer_volume_bytes": peer_volume_bytes,
        "block_files_bytes": block_files_bytes,
        "block_index_bytes": block_index_bytes,
        "leveldb_data_bytes": leveldb_data_bytes,
        "leveldb_wal_meta_bytes": leveldb_wal_meta_bytes,
        "peer_store_other_bytes": peer_store_other_bytes,
        "peer_store_root": root,
    }


# snapshot_peer_ledger_stores handles snapshot peer ledger stores behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def snapshot_peer_ledger_stores(paths, component_rules):
    """snapshot_peer_ledger_stores helper for benchmark tooling."""
    snap = {}
    for p in paths:
        details = {
            "splittable": is_docker_volumes_path(p),
            "volumes": {},
        }
        if not details["splittable"]:
            snap[p] = details
            continue
        try:
            with os.scandir(p) as it:
                for entry in it:
                    try:
                        if not entry.is_dir(follow_symlinks=False):
                            continue
                    except OSError:
                        continue
                    component = "other"
                    for label, matcher in component_rules:
                        if matcher.search(entry.name):
                            component = label
                            break
                    if component != "peer":
                        continue
                    size_map = collect_peer_ledger_store_sizes(entry.path)
                    details["volumes"][entry.name] = {
                        "component": component,
                        **size_map,
                    }
        except OSError:
            pass
        snap[p] = details
    return snap


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
    ts = re.sub(r"(\.\d{6})\d+(?=(?:[+-]\d{2}:\d{2})?$)", r"\1", ts)
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None


# format_ts handles format ts behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def format_ts(ts):
    """format_ts helper for benchmark tooling."""
    if ts is None:
        return ""
    if isinstance(ts, datetime):
        out = ts.isoformat()
        return out.replace("+00:00", "Z")
    return str(ts)


# get_event_value handles get event value behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def get_event_value(event, *keys):
    """get_event_value helper for benchmark tooling."""
    for key in keys:
        if key in event and event.get(key) not in (None, ""):
            return str(event.get(key)).strip()
    return ""


# load_metric_events handles load metric events behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def load_metric_events(metric_paths):
    """load_metric_events helper for benchmark tooling."""
    events = []
    for path in metric_paths:
        if not path or not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except Exception:
                        continue
                    ts = parse_ts(event.get("ts"))
                    if ts is None:
                        continue
                    event["_ts"] = ts
                    events.append(event)
        except Exception:
            continue
    events.sort(key=lambda e: e.get("_ts"))
    return events


# event_name handles event name behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def event_name(event):
    """event_name helper for benchmark tooling."""
    return get_event_value(event, "event")


# event_proposal_id handles event proposal id behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def event_proposal_id(event):
    """event_proposal_id helper for benchmark tooling."""
    return get_event_value(event, "proposal_id", "proposalId", "proposal")


# event_workflow handles event workflow behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def event_workflow(event):
    """event_workflow helper for benchmark tooling."""
    return get_event_value(event, "workflow", "workflow_base", "mode")


# event_tx_id handles event tx id behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def event_tx_id(event):
    """event_tx_id helper for benchmark tooling."""
    return get_event_value(event, "tx_id", "txId")


# event_ledger_ts handles event ledger ts behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def event_ledger_ts(event):
    """event_ledger_ts helper for benchmark tooling."""
    return get_event_value(event, "ledger_tx_ts", "ledgerTxTs")


# event_epoch handles event epoch behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def event_epoch(event):
    """event_epoch helper for benchmark tooling."""
    raw = get_event_value(event, "epoch")
    if raw == "":
        return None
    try:
        return int(float(raw))
    except Exception:
        return None


# matches_event_or_alias handles matches event or alias behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def matches_event_or_alias(event, target_names):
    """matches_event_or_alias helper for benchmark tooling."""
    name = event_name(event)
    if name in target_names:
        return True
    if name == "cc_event_observed":
        cc_name = get_event_value(event, "event_name", "cc_event_name", "chaincode_event")
        return cc_name in target_names
    return False


# first_event_ts_after handles first event ts after behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def first_event_ts_after(
    events,
    predicate,
    min_ts=None,
    preferred_epoch=None,
    require_preferred_epoch=False,
):
    """first_event_ts_after helper for benchmark tooling."""
    candidates = []
    for event in events:
        try:
            if not predicate(event):
                continue
        except Exception:
            continue
        ts = event.get("_ts")
        if ts is None:
            continue
        if min_ts is not None and ts < min_ts:
            continue
        candidates.append(event)
    if not candidates:
        return ""
    if preferred_epoch is not None:
        epoch_matches = [event for event in candidates if event_epoch(event) == preferred_epoch]
        if epoch_matches:
            return format_ts(epoch_matches[0].get("_ts"))
        if require_preferred_epoch:
            return ""
    return format_ts(candidates[0].get("_ts"))

# infer_milestones derives canonical milestone timestamps from observed metric events.
# Lifecycle: Post-submit workflow state interpretation.
# Called by: main.
# Triggered: after each workflow execution to persist normalized latency markers.
def infer_milestones(events, workflow_base, proposal_id, client_start_ts, client_end_ts, epoch=""):
    """infer_milestones helper for benchmark tooling."""
    if not events:
        return {}

    start_dt = parse_ts(client_start_ts)
    end_dt = parse_ts(client_end_ts)
    window_start = start_dt - timedelta(minutes=10) if start_dt else None
    window_end = end_dt + timedelta(minutes=10) if end_dt else None

    windowed = []
    for event in events:
        ts = event.get("_ts")
        if ts is None:
            continue
        if window_start and ts < window_start:
            continue
        if window_end and ts > window_end:
            continue
        windowed.append(event)

    if not windowed:
        return {}

    proposal_matches = []
    if proposal_id:
        for event in windowed:
            if event_proposal_id(event) == proposal_id:
                proposal_matches.append(event)

    target_epoch = None
    try:
        if str(epoch).strip() != "":
            target_epoch = int(float(str(epoch).strip()))
    except Exception:
        target_epoch = None

    epoch_reshare = []
    if target_epoch is not None:
        epoch_reshare = [
            event
            for event in windowed
            if event_epoch(event) == target_epoch
            and event_workflow(event) in ("", "reshare", "dkg", workflow_base)
        ]

    if proposal_matches:
        scoped = proposal_matches
    else:
        scoped = [
            event
            for event in windowed
            if event_workflow(event) in ("", workflow_base)
        ]
        if not scoped:
            scoped = windowed

    if epoch_reshare:
        combined = scoped + epoch_reshare
        deduped = []
        seen = set()
        for event in combined:
            key = (
                format_ts(event.get("_ts")),
                event_name(event),
                get_event_value(event, "tx_id", "event_name", "action", "function"),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(event)
        scoped = sorted(deduped, key=lambda e: e.get("_ts"))

    submit_event_names = {
        "csr": {"csr_api_received", "csr_submitted", "csr_submitted_observed", "CSRSubmitted"},
        "revocation": {"revocation_proposed", "revocation_proposed_observed", "RevocationProposed"},
        "join": {"join_request_submitted", "join_request_submitted_observed", "MemberJoinRequested"},
        "removal": {"member_removal_proposed", "member_removal_proposed_observed", "MemberRemovalProposed"},
    }
    vote_event_names = {
        "csr": {"csr_voted", "CSRVoted"},
        "revocation": {"revocation_voted", "RevocationVoted"},
        "join": {"join_request_voted", "MemberJoinVoted"},
        "removal": {"member_removal_voted", "MemberRemovalVoted"},
    }
    approve_event_names = {
        "csr": {"signing_session_active", "ThresholdReached", "CertificateRegistered", "cert_registered", "certificate_registered_observed"},
        "revocation": {"NodeRevoked", "revocation_observed", "node_revoked_observed"},
        "join": {"MemberJoinApproved", "member_join_approved_observed"},
        "removal": {"MemberRemoved", "member_removed_observed"},
    }
    reshare_start_names = {"reshare_keygen_start", "tss_reshare_start", "ReshareInitiated", "ReshareRequired"}
    reshare_complete_names = {
        "reshare_complete_observed",
        "reshare_complete_submitted",
        "reshare_complete_recorded",
        "tss_reshare_complete",
        "ReshareCompleted",
    }
    cert_registered_names = {"cert_registered", "cert_registered_event_observed", "CertificateRegistered"}

    submitted_observed_ts = first_event_ts_after(
        scoped, lambda e: matches_event_or_alias(e, submit_event_names.get(workflow_base, set()))
    )
    submitted_dt = parse_ts(submitted_observed_ts)
    voted_ts = first_event_ts_after(
        scoped,
        lambda e: matches_event_or_alias(e, vote_event_names.get(workflow_base, set())),
        min_ts=submitted_dt,
    )
    voted_dt = parse_ts(voted_ts)
    approved_or_executed_ts = first_event_ts_after(
        scoped,
        lambda e: matches_event_or_alias(e, approve_event_names.get(workflow_base, set())),
        min_ts=voted_dt,
    )
    approved_dt = parse_ts(approved_or_executed_ts)

    reshare_epoch = target_epoch if workflow_base in {"join", "removal"} else None
    reshare_anchor = approved_dt if workflow_base in {"join", "removal"} else None
    reshare_started_ts = first_event_ts_after(
        scoped,
        lambda e: matches_event_or_alias(e, reshare_start_names),
        min_ts=reshare_anchor,
        preferred_epoch=reshare_epoch,
        require_preferred_epoch=reshare_epoch is not None,
    )
    reshare_started_dt = parse_ts(reshare_started_ts)
    reshare_completed_ts = first_event_ts_after(
        scoped,
        lambda e: matches_event_or_alias(e, reshare_complete_names),
        min_ts=(reshare_started_dt or reshare_anchor),
        preferred_epoch=reshare_epoch,
        require_preferred_epoch=reshare_epoch is not None,
    )
    cert_registered_ts = first_event_ts_after(
        scoped,
        lambda e: matches_event_or_alias(e, cert_registered_names),
        min_ts=approved_dt if workflow_base == "csr" else None,
    )

    submit_functions = {
        "csr": {"SubmitCSR"},
        "revocation": {"ProposeRevocation"},
        "join": {"RequestJoinCA"},
        "removal": {"ProposeRemoveMember"},
    }
    execute_functions = {
        "csr": {"RegisterCombinedCertificateWithSignature", "SubmitPartialSignature"},
        "revocation": {"VoteOnRevocation"},
        "join": {"VoteOnJoinRequest"},
        "removal": {"VoteOnRemoveMember"},
    }

    submit_tx_id = ""
    ledger_tx_ts_submit = ""
    execute_tx_id = ""
    ledger_tx_ts_execute = ""
    for event in scoped:
        name = event_name(event)
        if name not in {"tx_submitted", "tx_committed", "tx_failed"}:
            continue
        fn = get_event_value(event, "function")
        txid = event_tx_id(event)
        ledger_ts = event_ledger_ts(event)
        if not submit_tx_id and fn in submit_functions.get(workflow_base, set()) and txid:
            submit_tx_id = txid
            ledger_tx_ts_submit = ledger_ts
        if not execute_tx_id and fn in execute_functions.get(workflow_base, set()) and txid:
            execute_tx_id = txid
            ledger_tx_ts_execute = ledger_ts
        if submit_tx_id and execute_tx_id:
            break

    return {
        "submitted_observed_ts": submitted_observed_ts,
        "voted_ts": voted_ts,
        "approved_or_executed_ts": approved_or_executed_ts,
        "reshare_started_ts": reshare_started_ts,
        "reshare_completed_ts": reshare_completed_ts,
        "cert_registered_ts": cert_registered_ts,
        "submit_tx_id": submit_tx_id,
        "execute_tx_id": execute_tx_id,
        "ledger_tx_ts_submit": ledger_tx_ts_submit,
        "ledger_tx_ts_execute": ledger_tx_ts_execute,
    }


# infer_v2_milestones derives canonical milestone timestamps from observed metric events.
# Lifecycle: Post-submit workflow state interpretation.
# Called by: legacy callers.
# Triggered: compatibility alias during migration.
def infer_v2_milestones(events, workflow_base, proposal_id, client_start_ts, client_end_ts, epoch=""):
    """infer_v2_milestones helper for benchmark tooling."""
    return infer_milestones(events, workflow_base, proposal_id, client_start_ts, client_end_ts, epoch=epoch)


# http_json handles http json behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def http_json(method, url, body=None):
    """http_json helper for benchmark tooling."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8") if resp.readable() else ""
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8") if e.fp else ""
        try:
            return e.code, json.loads(raw) if raw else {"error": str(e)}
        except Exception:
            return e.code, {"error": raw or str(e)}
    except Exception as e:
        return 0, {"error": str(e)}


# http_text handles http text behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def http_text(url):
    """http_text helper for benchmark tooling."""
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8") if resp.readable() else ""
            return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8") if e.fp else ""
        return e.code, raw
    except Exception as e:
        return 0, str(e)


# _error_blob handles error blob behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def _error_blob(status, data):
    """_error_blob helper for benchmark tooling."""
    try:
        if isinstance(data, dict):
            return json.dumps(data, sort_keys=True).lower()
        return str(data).lower()
    except Exception:
        return str(data).lower()


# is_mvcc_submit_error handles is mvcc submit error behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def is_mvcc_submit_error(status, data):
    """is_mvcc_submit_error helper for benchmark tooling."""
    blob = _error_blob(status, data)
    return ("mvcc_read_conflict" in blob) or ("phantom_read_conflict" in blob)


# classify_transient_submit_error handles classify transient submit error behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def classify_transient_submit_error(status, data):
    """classify_transient_submit_error helper for benchmark tooling."""
    blob = _error_blob(status, data)
    if ("mvcc_read_conflict" in blob) or ("phantom_read_conflict" in blob):
        return "mvcc_conflict"
    if "while dkg session is" in blob:
        return "dkg_session_state"
    if "while reshare epoch" in blob:
        return "reshare_epoch_state"
    if "membership governance is pending" in blob:
        return "governance_pending"
    if "cannot initiate dkg while reshare" in blob:
        return "reshare_lock"
    if "dkg already in progress" in blob:
        return "dkg_in_progress"
    if "timeout" in blob:
        return "timeout"
    if "temporarily unavailable" in blob:
        return "temporarily_unavailable"
    if status == 0:
        return "transport_or_unreachable"
    if status >= 500:
        return "server_error"
    return "transient_other"


# is_transient_submit_error handles is transient submit error behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def is_transient_submit_error(status, data):
    """is_transient_submit_error helper for benchmark tooling."""
    blob = _error_blob(status, data)
    transient_markers = (
        "mvcc_read_conflict",
        "phantom_read_conflict",
        "while dkg session is",
        "while reshare epoch",
        "membership governance is pending",
        "cannot initiate dkg while reshare",
        "dkg already in progress",
        "timeout",
        "temporarily unavailable",
    )
    if status == 0:
        return True
    if status >= 500:
        return True
    return any(marker in blob for marker in transient_markers)

# post_with_retry retries POST requests on transient submit conflicts and timeouts.
# Lifecycle: Active workflow execution.
# Called by: main.
# Triggered: for submit/vote API operations in benchmark workflows.
def post_with_retry(url, body, label, timeout_s, interval_s):
    """post_with_retry helper for benchmark tooling."""
    started = time.time()
    attempt = 0
    last_status, last_data = 0, {"error": "unknown"}
    retry_classes = {}
    retries_total = 0
    retries_mvcc = 0
    retries_non_mvcc = 0
    while True:
        attempt += 1
        status, data = http_json("POST", url, body)
        last_status, last_data = status, data
        if status > 0 and status < 400:
            return status, data, {
                "attempts": attempt,
                "retries_total": retries_total,
                "retries_mvcc": retries_mvcc,
                "retries_non_mvcc": retries_non_mvcc,
                "retry_classes": retry_classes,
            }
        if not is_transient_submit_error(status, data):
            return status, data, {
                "attempts": attempt,
                "retries_total": retries_total,
                "retries_mvcc": retries_mvcc,
                "retries_non_mvcc": retries_non_mvcc,
                "retry_classes": retry_classes,
            }
        retries_total += 1
        if is_mvcc_submit_error(status, data):
            retries_mvcc += 1
        else:
            retries_non_mvcc += 1
        cls = classify_transient_submit_error(status, data)
        retry_classes[cls] = int(retry_classes.get(cls, 0)) + 1
        elapsed = time.time() - started
        if elapsed >= timeout_s:
            return last_status, last_data, {
                "attempts": attempt,
                "retries_total": retries_total,
                "retries_mvcc": retries_mvcc,
                "retries_non_mvcc": retries_non_mvcc,
                "retry_classes": retry_classes,
            }
        print(f"[retry] {label} attempt {attempt} failed with transient error (status={status}); retrying...")
        time.sleep(max(interval_s, 0.5))


# extract_peer_height_from_prom handles extract peer height from prom behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def extract_peer_height_from_prom(raw):
    """extract_peer_height_from_prom helper for benchmark tooling."""
    heights = []
    for line in (raw or "").splitlines():
        token = str(line).strip()
        if not token or token.startswith("#"):
            continue
        parts = token.split()
        if len(parts) < 2:
            continue
        name = parts[0].split("{", 1)[0]
        lname = name.lower()
        if ("blockchain_height" not in lname) and ("ledger_height" not in lname):
            continue
        try:
            val = float(parts[-1])
        except Exception:
            continue
        if not (val == val):  # NaN guard
            continue
        heights.append(val)
    if not heights:
        return None
    try:
        return int(max(heights))
    except Exception:
        return None


# snapshot_peer_heights handles snapshot peer heights behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def snapshot_peer_heights(urls):
    """snapshot_peer_heights helper for benchmark tooling."""
    heights = {}
    for url in urls or []:
        key = str(url).strip()
        if not key:
            continue
        status, raw = http_text(key)
        if status >= 400 or status == 0:
            heights[key] = None
            continue
        heights[key] = extract_peer_height_from_prom(raw)
    return heights


# measure_gossip_convergence handles measure gossip convergence behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def measure_gossip_convergence(urls, heights_before, timeout_s, interval_s):
    """measure_gossip_convergence helper for benchmark tooling."""
    result = {
        "height_before_max": "",
        "height_after_max": "",
        "target_height": "",
        "height_delta": "",
        "peers_observed": 0,
        "peers_converged": 0,
        "convergence_s": "",
        "status": "disabled",
    }
    urls = [str(u).strip() for u in (urls or []) if str(u).strip()]
    if not urls:
        return result

    before_vals = []
    for u in urls:
        val = None
        if isinstance(heights_before, dict):
            val = heights_before.get(u)
        if val is None:
            continue
        try:
            before_vals.append(int(val))
        except Exception:
            continue
    if before_vals:
        result["height_before_max"] = str(max(before_vals))

    initial = snapshot_peer_heights(urls)
    valid_initial = {u: int(v) for u, v in initial.items() if v is not None}
    if not valid_initial:
        result["status"] = "no_height_metric"
        return result

    target_height = max(valid_initial.values())
    result["height_after_max"] = str(target_height)
    result["target_height"] = str(target_height)
    result["peers_observed"] = int(len(valid_initial))

    if before_vals:
        result["height_delta"] = str(max(target_height - max(before_vals), 0))

    if len(valid_initial) == 1:
        result["peers_converged"] = 1
        result["convergence_s"] = "0.0"
        result["status"] = "single_peer_local_only"
        return result

    if result["height_delta"] != "" and int(float(result["height_delta"])) <= 0:
        result["peers_converged"] = int(sum(1 for v in valid_initial.values() if v >= target_height))
        result["convergence_s"] = "0.0"
        result["status"] = "no_height_increase"
        return result

    started = time.time()
    interval = interval_s if interval_s and interval_s > 0 else 1.0
    timeout = timeout_s if timeout_s and timeout_s > 0 else 30.0
    last_valid = valid_initial
    while time.time() - started < timeout:
        snap = snapshot_peer_heights(urls)
        valid = {u: int(v) for u, v in snap.items() if v is not None}
        if valid:
            last_valid = valid
            converged = int(sum(1 for v in valid.values() if v >= target_height))
            observed = int(len(valid))
            result["peers_observed"] = observed
            result["peers_converged"] = converged
            if observed > 0 and converged >= observed:
                result["convergence_s"] = f"{(time.time() - started):.6f}"
                result["status"] = "converged"
                return result
        time.sleep(interval)

    result["peers_observed"] = int(len(last_valid))
    result["peers_converged"] = int(sum(1 for v in last_valid.values() if v >= target_height))
    result["convergence_s"] = ""
    result["status"] = "timeout"
    return result

# wait_until polls a predicate until success or timeout.
# Lifecycle: Active workflow execution.
# Called by: main.
# Triggered: while awaiting governance/session completion milestones.
def wait_until(predicate, timeout_s, interval_s, label, on_tick=None):
    """wait_until helper for benchmark tooling."""
    start = time.time()
    while time.time() - start < timeout_s:
        if on_tick is not None:
            try:
                on_tick()
            except Exception:
                pass
        if predicate():
            return True
        time.sleep(interval_s)
    print(f"Timeout waiting for {label}")
    return False


# to_int handles to int behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def to_int(value, default=0):
    """to_int helper for benchmark tooling."""
    try:
        return int(value)
    except Exception:
        return default


# sum_numeric_present handles sum numeric present behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def sum_numeric_present(*values):
    """sum_numeric_present helper for benchmark tooling."""
    acc = []
    for value in values:
        if value in (None, ""):
            continue
        try:
            num = float(value)
        except Exception:
            continue
        if not (num == num):
            continue
        acc.append(num)
    if not acc:
        return None
    return float(sum(acc))


# ensure_outdir handles ensure outdir behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def ensure_outdir(path):
    """ensure_outdir helper for benchmark tooling."""
    if path:
        os.makedirs(path, exist_ok=True)


# dir_size handles dir size behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def dir_size(path):
    """dir_size helper for benchmark tooling."""
    total = 0
    had_error = False

    # onerror handles onerror behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def onerror(_):
        """onerror helper for benchmark tooling."""
        nonlocal had_error
        had_error = True

    try:
        for root, dirs, files in os.walk(path, onerror=onerror):
            for name in files:
                fp = os.path.join(root, name)
                try:
                    total += os.path.getsize(fp)
                except OSError:
                    had_error = True
                    continue
    except OSError:
        return None

    if had_error:
        return None

    if total == 0:
        # If the directory isn't empty but we saw zero bytes, it's likely a permissions issue.
        try:
            for _ in os.scandir(path):
                return None
        except OSError:
            return None
    return total


# snapshot_storage handles snapshot storage behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def snapshot_storage(paths):
    """snapshot_storage helper for benchmark tooling."""
    snap = {}
    for p in paths:
        snap[p] = dir_size(p)
    return snap


# normalize_storage_component_label handles normalize storage component label behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def normalize_storage_component_label(label):
    """normalize_storage_component_label helper for benchmark tooling."""
    token = re.sub(r"[^a-zA-Z0-9_]+", "_", str(label or "").strip().lower())
    token = re.sub(r"_+", "_", token).strip("_")
    return token


# parse_storage_component_rules handles parse storage component rules behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def parse_storage_component_rules(raw_rules):
    """parse_storage_component_rules helper for benchmark tooling."""
    rules = []
    seen = set()
    for raw in raw_rules or []:
        token = str(raw or "").strip()
        if not token:
            continue
        if "=" not in token:
            raise ValueError(f"invalid matcher '{token}' (expected label=regex)")
        label_raw, pattern = token.split("=", 1)
        label = normalize_storage_component_label(label_raw)
        if not label:
            raise ValueError(f"invalid matcher '{token}' (empty label)")
        if label in seen:
            raise ValueError(f"duplicate matcher label '{label}'")
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"invalid regex for '{label}': {exc}") from exc
        rules.append((label, compiled))
        seen.add(label)
    return rules


# snapshot_storage_components handles snapshot storage components behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def snapshot_storage_components(paths, component_rules):
    """snapshot_storage_components helper for benchmark tooling."""
    snap = {}
    if not component_rules:
        return snap
    for p in paths:
        details = {
            "splittable": is_docker_volumes_path(p),
            "components": {},
            "component_match_counts": {},
            "other": None,
            "other_match_count": None,
        }
        if not details["splittable"]:
            snap[p] = details
            continue
        try:
            volume_dirs = []
            with os.scandir(p) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            volume_dirs.append((entry.name, entry.path))
                    except OSError:
                        continue
        except OSError:
            for label, _ in component_rules:
                details["components"][label] = None
                details["component_match_counts"][label] = None
            details["other"] = None
            details["other_match_count"] = None
            snap[p] = details
            continue

        assignments = {label: [] for label, _ in component_rules}
        other_dirs = []
        for name, vol_path in volume_dirs:
            assigned = False
            for label, matcher in component_rules:
                if matcher.search(name):
                    assignments[label].append(vol_path)
                    assigned = True
                    break
            if not assigned:
                other_dirs.append(vol_path)

        # aggregate_size handles aggregate size behavior for benchmark tooling.
        # Lifecycle: Benchmark script runtime, aggregation, and analysis.
        # Called by: module-internal callers (see surrounding flow).
        # Triggered: CLI execution and helper orchestration.
        def aggregate_size(dir_paths):
            """aggregate_size helper for benchmark tooling."""
            total = 0
            for vol_path in dir_paths:
                size = dir_size(vol_path)
                if size is None:
                    return None
                total += size
            return total

        for label, _ in component_rules:
            matched_dirs = assignments.get(label, [])
            details["component_match_counts"][label] = len(matched_dirs)
            if not matched_dirs:
                details["components"][label] = 0
                continue
            details["components"][label] = aggregate_size(matched_dirs)

        details["other_match_count"] = len(other_dirs)
        details["other"] = aggregate_size(other_dirs) if other_dirs else 0
        snap[p] = details
    return snap


# snapshot_storage_volumes handles snapshot storage volumes behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def snapshot_storage_volumes(paths, component_rules):
    """snapshot_storage_volumes helper for benchmark tooling."""
    snap = {}
    for p in paths:
        details = {
            "splittable": is_docker_volumes_path(p),
            "volumes": {},
        }
        if not details["splittable"]:
            snap[p] = details
            continue
        try:
            with os.scandir(p) as it:
                for entry in it:
                    try:
                        if not entry.is_dir(follow_symlinks=False):
                            continue
                    except OSError:
                        continue
                    size = dir_size(entry.path)
                    component = "other"
                    for label, matcher in component_rules:
                        if matcher.search(entry.name):
                            component = label
                            break
                    details["volumes"][entry.name] = {
                        "size": size,
                        "component": component,
                    }
        except OSError:
            pass
        snap[p] = details
    return snap


# write_storage_metadata handles write storage metadata behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def write_storage_metadata(path, payload):
    """write_storage_metadata helper for benchmark tooling."""
    if not path:
        return
    ensure_outdir(os.path.dirname(path))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


# write_dict_rows handles write dict rows behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def write_dict_rows(out_path, rows, base_fields=None):
    """write_dict_rows helper for benchmark tooling."""
    if not out_path or not rows:
        return
    ensure_outdir(os.path.dirname(out_path))
    base_fields = list(base_fields or [])
    extra_fields = []
    for row in rows:
        for key in row.keys():
            if key not in base_fields and key not in extra_fields:
                extra_fields.append(key)
    fieldnames = base_fields + extra_fields

    write_header = not os.path.exists(out_path)
    if not write_header:
        try:
            with open(out_path, "r", newline="", encoding="utf-8") as existing:
                reader = csv.reader(existing)
                existing_fields = next(reader, [])
            if existing_fields:
                fieldnames = existing_fields + [f for f in fieldnames if f not in existing_fields]
        except Exception:
            pass

    with open(out_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


# write_storage_deltas handles write storage deltas behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def write_storage_deltas(out_path, rows):
    """write_storage_deltas helper for benchmark tooling."""
    if not rows:
        return
    ensure_outdir(os.path.dirname(out_path))
    base_fields = [
        "ts_start",
        "ts_end",
        "workflow",
        "proposal_id",
        "path",
        "bytes_before",
        "bytes_after",
        "delta_bytes",
    ]
    extra_fields = []
    for row in rows:
        for key in row.keys():
            if key not in base_fields and key not in extra_fields:
                extra_fields.append(key)
    fieldnames = base_fields + extra_fields

    write_header = not os.path.exists(out_path)
    if not write_header:
        try:
            with open(out_path, "r", newline="", encoding="utf-8") as existing:
                reader = csv.reader(existing)
                existing_fields = next(reader, [])
            if existing_fields:
                fieldnames = existing_fields + [f for f in fieldnames if f not in existing_fields]
        except Exception:
            pass

    with open(out_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})

# StorageStageRecorder snapshots storage state at workflow stages and computes deltas.
# Lifecycle: Storage instrumentation during workflow execution.
# Called by: main.
# Triggered: initialized per workflow, then marked at stage boundaries.
class StorageStageRecorder:
    # __init__ handles init behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def __init__(self, enabled, paths, component_rules, topk_limit):
        """__init__ helper for benchmark tooling."""
        self.enabled = bool(enabled)
        self.paths = list(paths or [])
        self.component_rules = list(component_rules or [])
        self.component_labels = [label for label, _ in self.component_rules]
        self.topk_limit = max(int(topk_limit or 0), 0)
        self.snapshots = []
        self._seen = set()

    # mark handles mark behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def mark(self, stage_name, ts_iso=""):
        """mark helper for benchmark tooling."""
        if not self.enabled:
            return
        token = str(stage_name or "").strip()
        if not token or token in self._seen:
            return
        now_iso = ts_iso or (datetime.utcnow().isoformat() + "Z")
        self._seen.add(token)
        self.snapshots.append(
            {
                "stage": token,
                "ts": now_iso,
                "total": snapshot_storage(self.paths),
                "components": snapshot_storage_components(self.paths, self.component_rules),
                "volumes": snapshot_storage_volumes(self.paths, self.component_rules),
                "peer_stores": snapshot_peer_ledger_stores(self.paths, self.component_rules),
            }
        )

    # _volume_delta_rows handles volume delta rows behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def _volume_delta_rows(self, before, after):
        """_volume_delta_rows helper for benchmark tooling."""
        out = []
        before_map = (before or {}).get("volumes", {}) if isinstance(before, dict) else {}
        after_map = (after or {}).get("volumes", {}) if isinstance(after, dict) else {}
        names = sorted(set(before_map.keys()) | set(after_map.keys()))
        for name in names:
            b = before_map.get(name, {})
            a = after_map.get(name, {})
            b_size = b.get("size", None)
            a_size = a.get("size", None)
            if b_size is None or a_size is None:
                delta = ""
            else:
                delta = a_size - b_size
            component = a.get("component", "") or b.get("component", "") or "other"
            out.append(
                {
                    "volume_name": name,
                    "component": component,
                    "bytes_before": b_size if b_size is not None else "NA",
                    "bytes_after": a_size if a_size is not None else "NA",
                    "delta_bytes": delta,
                }
            )
        return out

    # _peer_store_delta_rows handles peer store delta rows behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def _peer_store_delta_rows(self, before, after):
        """_peer_store_delta_rows helper for benchmark tooling."""
        out = []
        before_map = (before or {}).get("volumes", {}) if isinstance(before, dict) else {}
        after_map = (after or {}).get("volumes", {}) if isinstance(after, dict) else {}
        names = sorted(set(before_map.keys()) | set(after_map.keys()))
        for name in names:
            b = before_map.get(name, {})
            a = after_map.get(name, {})
            component = str(a.get("component", "") or b.get("component", "") or "").strip()
            if component != "peer":
                continue
            row = {
                "volume_name": name,
                "component": component,
                "peer_store_root": a.get("peer_store_root", "") or b.get("peer_store_root", ""),
            }
            for key in PEER_LEDGER_STORE_SIZE_KEYS:
                b_val = b.get(key, None)
                a_val = a.get(key, None)
                row[f"{key}_before"] = "NA" if b_val is None else b_val
                row[f"{key}_after"] = "NA" if a_val is None else a_val
                if b_val is None or a_val is None:
                    row[f"{key.replace('_bytes', '')}_delta_bytes"] = ""
                else:
                    row[f"{key.replace('_bytes', '')}_delta_bytes"] = int(a_val) - int(b_val)
            out.append(row)
        return out

    # finalize handles finalize behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def finalize(self, workflow, workflow_tag, operation_id, proposal_id, epoch, run_id=""):
        """finalize helper for benchmark tooling."""
        if not self.enabled or len(self.snapshots) < 2:
            return [], [], [], []
        stage_rows = []
        volume_rows = []
        topk_rows = []
        peer_store_rows = []
        for idx in range(len(self.snapshots) - 1):
            left = self.snapshots[idx]
            right = self.snapshots[idx + 1]
            stage_start = left.get("stage", "")
            stage_end = right.get("stage", "")
            ts_start = left.get("ts", "")
            ts_end = right.get("ts", "")
            for path in self.paths:
                before = left.get("total", {}).get(path)
                after = right.get("total", {}).get(path)
                delta = ""
                if before is not None and after is not None:
                    delta = after - before
                row = {
                    "run_id": run_id,
                    "workflow": workflow,
                    "workflow_tag": workflow_tag,
                    "operation_id": operation_id,
                    "proposal_id": proposal_id,
                    "epoch": epoch,
                    "stage_start": stage_start,
                    "stage_end": stage_end,
                    "ts_start": ts_start,
                    "ts_end": ts_end,
                    "path": path,
                    "bytes_before": "NA" if before is None else before,
                    "bytes_after": "NA" if after is None else after,
                    "delta_bytes": delta,
                }
                comp_before = left.get("components", {}).get(path, {})
                comp_after = right.get("components", {}).get(path, {})
                splittable = bool(comp_before.get("splittable")) and bool(comp_after.get("splittable"))
                row["storage_component_splittable"] = "true" if splittable else "false"
                row["storage_component_note"] = "" if splittable else "non_volume_path"
                comps_before = comp_before.get("components", {})
                comps_after = comp_after.get("components", {})
                for label in self.component_labels:
                    b = comps_before.get(label)
                    a = comps_after.get(label)
                    d = ""
                    if b is not None and a is not None:
                        d = a - b
                    row[f"{label}_volume_delta_bytes"] = d
                other_b = comp_before.get("other")
                other_a = comp_after.get("other")
                other_d = ""
                if other_b is not None and other_a is not None:
                    other_d = other_a - other_b
                row["other_volume_delta_bytes"] = other_d
                stage_rows.append(row)

                vol_rows = self._volume_delta_rows(
                    left.get("volumes", {}).get(path, {}),
                    right.get("volumes", {}).get(path, {}),
                )
                for vol in vol_rows:
                    vrow = {
                        "run_id": run_id,
                        "workflow": workflow,
                        "workflow_tag": workflow_tag,
                        "operation_id": operation_id,
                        "proposal_id": proposal_id,
                        "epoch": epoch,
                        "stage_start": stage_start,
                        "stage_end": stage_end,
                        "ts_start": ts_start,
                        "ts_end": ts_end,
                        "path": path,
                    }
                    vrow.update(vol)
                    volume_rows.append(vrow)

                if self.topk_limit > 0 and vol_rows:
                    numeric = [v for v in vol_rows if isinstance(v.get("delta_bytes"), (int, float))]
                    if numeric:
                        denom = sum(abs(v.get("delta_bytes", 0.0)) for v in numeric)
                        ranked = sorted(numeric, key=lambda v: abs(v.get("delta_bytes", 0.0)), reverse=True)
                        for rank, vol in enumerate(ranked[: self.topk_limit], start=1):
                            delta_val = vol.get("delta_bytes", 0.0)
                            share = (abs(delta_val) / denom * 100.0) if denom > 0 else 0.0
                            topk_rows.append(
                                {
                                    "run_id": run_id,
                                    "workflow": workflow,
                                    "workflow_tag": workflow_tag,
                                    "operation_id": operation_id,
                                    "proposal_id": proposal_id,
                                    "epoch": epoch,
                                    "stage_start": stage_start,
                                    "stage_end": stage_end,
                                    "ts_start": ts_start,
                                    "ts_end": ts_end,
                                    "path": path,
                                    "rank": rank,
                                    "volume_name": vol.get("volume_name", ""),
                                    "component": vol.get("component", ""),
                                    "delta_bytes": delta_val,
                                    "share_pct": share,
                                }
                            )
                peer_rows = self._peer_store_delta_rows(
                    left.get("peer_stores", {}).get(path, {}),
                    right.get("peer_stores", {}).get(path, {}),
                )
                for peer_row in peer_rows:
                    prow = {
                        "run_id": run_id,
                        "workflow": workflow,
                        "workflow_tag": workflow_tag,
                        "operation_id": operation_id,
                        "proposal_id": proposal_id,
                        "epoch": epoch,
                        "stage_start": stage_start,
                        "stage_end": stage_end,
                        "ts_start": ts_start,
                        "ts_end": ts_end,
                        "path": path,
                    }
                    prow.update(peer_row)
                    peer_store_rows.append(prow)
        return stage_rows, volume_rows, topk_rows, peer_store_rows


# event_metric_name handles event metric name behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def event_metric_name(event):
    """event_metric_name helper for benchmark tooling."""
    name = get_event_value(event, "event")
    if name == "cc_event_observed":
        cc_name = get_event_value(event, "event_name", "cc_event_name", "chaincode_event")
        if cc_name:
            return cc_name
    return name

# MilestoneEventObserver tails metric logs and records stage markers for one workflow.
# Lifecycle: Metric-event observation during workflow execution.
# Called by: main.
# Triggered: created per workflow run and polled while waiting for completion.
class MilestoneEventObserver:
    # __init__ handles init behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def __init__(self, metric_paths, workflow_base, start_ts, on_mark=None):
        """__init__ helper for benchmark tooling."""
        self.metric_paths = [str(p) for p in (metric_paths or []) if str(p).strip()]
        self.workflow_base = str(workflow_base or "").strip()
        self.start_dt = parse_ts(start_ts)
        self.on_mark = on_mark
        self.proposal_id = ""
        self.target_epoch = None
        self._offsets = {}
        self._marked = set()
        for path in self.metric_paths:
            try:
                self._offsets[path] = os.path.getsize(path)
            except OSError:
                self._offsets[path] = 0

    # set_proposal_id handles set proposal id behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def set_proposal_id(self, proposal_id):
        """set_proposal_id helper for benchmark tooling."""
        self.proposal_id = str(proposal_id or "").strip()

    # set_target_epoch handles set target epoch behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def set_target_epoch(self, epoch):
        """set_target_epoch helper for benchmark tooling."""
        try:
            token = str(epoch).strip()
            self.target_epoch = int(float(token)) if token else None
        except Exception:
            self.target_epoch = None

    # _stage_specs handles stage specs behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def _stage_specs(self):
        """_stage_specs helper for benchmark tooling."""
        vote_event_names = {
            "csr": {"csr_voted", "CSRVoted"},
            "revocation": {"revocation_voted", "RevocationVoted"},
            "join": {"join_request_voted", "MemberJoinVoted"},
            "removal": {"member_removal_voted", "MemberRemovalVoted"},
        }
        approve_event_names = {
            "csr": {"signing_session_active", "ThresholdReached", "CertificateRegistered", "cert_registered", "certificate_registered_observed"},
            "revocation": {"NodeRevoked", "revocation_observed", "node_revoked_observed"},
            "join": {"MemberJoinApproved", "member_join_approved_observed"},
            "removal": {"MemberRemoved", "member_removed_observed"},
        }
        reshare_start_names = {"reshare_keygen_start", "tss_reshare_start", "ReshareInitiated", "ReshareRequired"}
        reshare_complete_names = {
            "reshare_complete_observed",
            "reshare_complete_submitted",
            "reshare_complete_recorded",
            "tss_reshare_complete",
            "ReshareCompleted",
        }
        cert_registered_names = {"cert_registered", "cert_registered_event_observed", "CertificateRegistered"}

        if self.workflow_base == "csr":
            return [
                ("csr_voted", vote_event_names["csr"], False),
                ("csr_approved", approve_event_names["csr"], False),
                ("cert_registered", cert_registered_names, False),
            ]
        if self.workflow_base == "revocation":
            return [
                ("revocation_voted", vote_event_names["revocation"], False),
                ("revocation_executed", approve_event_names["revocation"], False),
            ]
        if self.workflow_base == "join":
            return [
                ("join_voted", vote_event_names["join"], False),
                ("join_approved", approve_event_names["join"], False),
                ("reshare_started", reshare_start_names, True),
                ("reshare_completed", reshare_complete_names, True),
            ]
        if self.workflow_base == "removal":
            return [
                ("removal_voted", vote_event_names["removal"], False),
                ("removal_approved", approve_event_names["removal"], False),
                ("reshare_started", reshare_start_names, True),
                ("reshare_completed", reshare_complete_names, True),
            ]
        return []

    # _is_relevant handles is relevant behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def _is_relevant(self, event, reshare_stage):
        """_is_relevant helper for benchmark tooling."""
        if self.start_dt is not None:
            ts = parse_ts(event.get("ts"))
            if ts is not None and ts < self.start_dt:
                return False
        if self.proposal_id:
            prop = event_proposal_id(event)
            if prop and prop != self.proposal_id:
                return False
        if reshare_stage and self.target_epoch is not None:
            ep = event_epoch(event)
            if ep is not None and ep != self.target_epoch:
                return False
        wf = event_workflow(event)
        if wf and not reshare_stage and self.workflow_base and wf not in ("", self.workflow_base):
            return False
        return True

    # poll handles poll behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def poll(self):
        """poll helper for benchmark tooling."""
        if not self.metric_paths:
            return
        specs = self._stage_specs()
        if not specs:
            return
        for path in self.metric_paths:
            offset = self._offsets.get(path, 0)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    f.seek(offset)
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            event = json.loads(line)
                        except Exception:
                            continue
                        name = event_metric_name(event)
                        if not name:
                            continue
                        event_ts = get_event_value(event, "ts")
                        for stage_name, names, reshare_stage in specs:
                            if stage_name in self._marked:
                                continue
                            if name not in names:
                                continue
                            if not self._is_relevant(event, reshare_stage):
                                continue
                            self._marked.add(stage_name)
                            if self.on_mark is not None:
                                self.on_mark(stage_name, event_ts)
                    self._offsets[path] = f.tell()
            except OSError:
                continue


# write_message_counts handles write message counts behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def write_message_counts(out_path, rows):
    """write_message_counts helper for benchmark tooling."""
    if not rows:
        return
    ensure_outdir(os.path.dirname(out_path))
    write_header = not os.path.exists(out_path)
    with open(out_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(
                [
                    "ts_start",
                    "ts_end",
                    "workflow",
                    "proposal_id",
                    "tss_p2p_sent",
                    "tss_p2p_recv",
                    "tss_p2p_sent_broadcast",
                    "tss_p2p_sent_direct",
                    "tss_p2p_recv_broadcast",
                    "tss_p2p_recv_direct",
                    "tss_p2p_sent_by_type",
                    "tss_p2p_recv_by_type",
                    "gossip_metric_total",
                ]
            )
        writer.writerows(rows)


# parse_prom_metrics handles parse prom metrics behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def parse_prom_metrics(raw):
    """parse_prom_metrics helper for benchmark tooling."""
    metrics = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[0]
        try:
            value = float(parts[-1])
        except ValueError:
            continue
        base = name.split("{", 1)[0]
        metrics[base] = metrics.get(base, 0.0) + value
    return metrics


# sum_metrics handles sum metrics behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def sum_metrics(metrics, prefixes):
    """sum_metrics helper for benchmark tooling."""
    if not metrics:
        return None
    if not prefixes:
        prefixes = ["gossip_"]
    total = 0.0
    matched = False
    for name, val in metrics.items():
        if not any(name.startswith(p) for p in prefixes):
            continue
        if not (name.endswith("_total") or name.endswith("_count")):
            continue
        total += val
        matched = True
    return total if matched else None


# snapshot_peer_metrics handles snapshot peer metrics behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def snapshot_peer_metrics(urls, prefixes):
    """snapshot_peer_metrics helper for benchmark tooling."""
    if not urls:
        return None
    total = 0.0
    any_ok = False
    for url in urls:
        status, raw = http_text(url)
        if status >= 400 or status == 0:
            continue
        metrics = parse_prom_metrics(raw)
        subtotal = sum_metrics(metrics, prefixes)
        if subtotal is None:
            continue
        total += subtotal
        any_ok = True
    return total if any_ok else None

# start_resource_sampler launches the external resource sampling process.
# Lifecycle: Resource instrumentation setup.
# Called by: main.
# Triggered: at workflow start when resource collection is enabled.
def start_resource_sampler(args, tag):
    """start_resource_sampler helper for benchmark tooling."""
    if not args.measure and not args.collect_resources:
        return None, None
    outdir = args.outdir
    ensure_outdir(outdir)
    out_path = args.resources_out or os.path.join(outdir, f"resources_{tag}.csv")
    phase_file = args.phase_file if args.phase_file else ""
    script_path = os.path.join(os.path.dirname(__file__), "collect_resources.py")
    cmd = [
        sys.executable,
        script_path,
        "--interval",
        str(args.resources_interval),
        "--output",
        out_path,
        "--iface",
        args.resources_iface,
        "--tag",
        tag,
    ]
    for port in args.resources_control_exclude_port:
        cmd += ["--control-exclude-port", str(port)]
    if args.phase_tags and phase_file:
        cmd += ["--phase-file", phase_file]
    for matcher in args.proc_match:
        cmd += ["--proc-match", matcher]
    proc = subprocess.Popen(cmd)
    return proc, out_path

# stop_resource_sampler terminates the running resource sampler process.
# Lifecycle: Resource instrumentation teardown.
# Called by: main.
# Triggered: after each workflow or during cleanup on failures/timeouts.
def stop_resource_sampler(proc):
    """stop_resource_sampler helper for benchmark tooling."""
    if not proc:
        return
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        proc.kill()

# summarize_resources reduces sampled resource rows into workflow-level summary stats.
# Lifecycle: Post-workflow artifact generation.
# Called by: main.
# Triggered: after resource sampling stops for a workflow run.
def summarize_resources(outdir, workflow_base, workflow_tag, start_ts, end_ts, resource_path):
    """summarize_resources helper for benchmark tooling."""
    if not resource_path or not os.path.exists(resource_path):
        return
    rows = []
    with open(resource_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    if not rows:
        return

    # agg handles agg behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def agg(col):
        """agg helper for benchmark tooling."""
        values = []
        for row in rows:
            v = row.get(col, "")
            try:
                values.append(float(v))
            except Exception:
                continue
        if not values:
            return ("", "")
        avg = sum(values) / len(values)
        return (f"{avg:.2f}", f"{max(values):.2f}")

    summary_path = os.path.join(outdir, "resources_summary.csv")
    write_header = not os.path.exists(summary_path)
    with open(summary_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(
                [
                    "ts_start",
                    "ts_end",
                    "workflow",
                    "workflow_base",
                    "workflow_tag",
                    "samples",
                    "cpu_avg",
                    "cpu_max",
                    "mem_avg",
                    "mem_max",
                    "tss_cpu_avg",
                    "tss_cpu_max",
                    "tss_mem_avg",
                    "tss_mem_max",
                    "peer_cpu_avg",
                    "peer_cpu_max",
                    "peer_mem_avg",
                    "peer_mem_max",
                    "orderer_cpu_avg",
                    "orderer_cpu_max",
                    "orderer_mem_avg",
                    "orderer_mem_max",
                ]
            )
        cpu_avg, cpu_max = agg("cpu_total_pct")
        mem_avg, mem_max = agg("mem_used_pct")
        tss_cpu_avg, tss_cpu_max = agg("tss_cpu_pct")
        tss_mem_avg, tss_mem_max = agg("tss_mem_pct")
        peer_cpu_avg, peer_cpu_max = agg("peer_cpu_pct")
        peer_mem_avg, peer_mem_max = agg("peer_mem_pct")
        ord_cpu_avg, ord_cpu_max = agg("orderer_cpu_pct")
        ord_mem_avg, ord_mem_max = agg("orderer_mem_pct")
        writer.writerow(
            [
                start_ts,
                end_ts,
                workflow_tag,
                workflow_base,
                workflow_tag,
                str(len(rows)),
                cpu_avg,
                cpu_max,
                mem_avg,
                mem_max,
                tss_cpu_avg,
                tss_cpu_max,
                tss_mem_avg,
                tss_mem_max,
                peer_cpu_avg,
                peer_cpu_max,
                peer_mem_avg,
                peer_mem_max,
                ord_cpu_avg,
                ord_cpu_max,
                ord_mem_avg,
                ord_mem_max,
            ]
        )

# append_workflow_run appends one normalized workflow result row to CSV.
# Lifecycle: Post-workflow artifact generation.
# Called by: main.
# Triggered: once per workflow completion after metrics and durations are resolved.
def append_workflow_run(path, row, legacy_alias_path=""):
    """append_workflow_run helper for benchmark tooling."""
    fieldnames = [
        "workflow_base",
        "workflow_tag",
        "operation_id",
        "proposal_id",
        "epoch",
        "submit_tx_id",
        "execute_tx_id",
        "status",
        "error",
        "client_start_ts",
        "client_end_ts",
        "submitted_observed_ts",
        "voted_ts",
        "approved_or_executed_ts",
        "reshare_started_ts",
        "reshare_completed_ts",
        "cert_registered_ts",
        "local_key_idle_ts",
        "local_signing_idle_ts",
        "ledger_tx_ts_submit",
        "ledger_tx_ts_execute",
        "submit_attempts",
        "submit_retries_total",
        "submit_retries_mvcc",
        "submit_retries_non_mvcc",
        "submit_retry_classes",
        "tss_signing_compute_s",
        "tss_signing_wait_s",
        "tss_reshare_compute_s",
        "tss_reshare_wait_s",
        "tss_key_session_compute_s",
        "tss_key_session_wait_s",
        "tss_compute_proxy_s",
        "tss_wait_proxy_s",
        "gossip_height_before_max",
        "gossip_height_after_max",
        "gossip_target_height",
        "gossip_height_delta",
        "gossip_peers_observed",
        "gossip_peers_converged",
        "gossip_convergence_s",
        "gossip_convergence_status",
    ]
    ensure_outdir(os.path.dirname(path))
    write_header = not os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
        out = {k: row.get(k, "") for k in fieldnames}
        writer.writerow(out)
    if legacy_alias_path and os.path.normpath(path) != os.path.normpath(legacy_alias_path):
        ensure_outdir(os.path.dirname(legacy_alias_path))
        write_legacy_header = not os.path.exists(legacy_alias_path)
        with open(legacy_alias_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if write_legacy_header:
                writer.writeheader()
            out = {k: row.get(k, "") for k in fieldnames}
            writer.writerow(out)


# append_workflow_run_v2 appends one normalized workflow result row to CSV.
# Lifecycle: Post-workflow artifact generation.
# Called by: legacy callers.
# Triggered: backward-compatible alias for migration period.
def append_workflow_run_v2(path, row):
    """append_workflow_run_v2 helper for benchmark tooling."""
    append_workflow_run(path, row, legacy_alias_path="")

# main orchestrates workflow benchmark execution for one run directory.
# Lifecycle: Workflow benchmark entrypoint.
# Called by: module entrypoint (`if __name__ == "__main__"`).
# Triggered: invoked directly or from suite orchestration.
def main():
    """main helper for benchmark tooling."""
    parser = argparse.ArgumentParser(description="Run benchmark workflows via TSS Peer Web API")
    parser.add_argument("--api", default="http://localhost:8080", help="Base API URL (default: http://localhost:8080)")
    parser.add_argument("--workflow", action="append", choices=["csr", "revocation", "join", "removal", "all"], required=True)
    parser.add_argument("--member-id", default="", help="Target member ID for revocation/removal")
    parser.add_argument("--reason", default="benchmark", help="Reason for proposals")
    parser.add_argument("--timeout", type=int, default=600, help="Timeout in seconds")
    parser.add_argument("--poll", type=float, default=2.0, help="Polling interval in seconds")
    parser.add_argument("--no-wait", action="store_true", help="Do not wait for completion")
    parser.add_argument("--cn", default="", help="CSR Common Name")
    parser.add_argument("--o", default="", help="CSR Organization")
    parser.add_argument("--l", default="", help="CSR Locality")
    parser.add_argument("--st", default="", help="CSR State")
    parser.add_argument("--c", default="", help="CSR Country")
    parser.add_argument("--measure", action="store_true", help="Collect storage deltas and resource samples per workflow")
    parser.add_argument("--collect-resources", action="store_true", help="Collect resource samples even without storage")
    parser.add_argument("--collect-messages", action="store_true", help="Collect TSS P2P + optional gossip message counts")
    parser.add_argument("--phase-tags", action="store_true", help="Emit phase tags for resource samples (submit/wait/etc)")
    parser.add_argument("--messages-out", default="", help="Message counts CSV output path")
    parser.add_argument("--peer-metrics-url", action="append", default=[], help="Prometheus metrics URL(s) for Fabric peers")
    parser.add_argument("--peer-metrics-prefix", action="append", default=[], help="Metric name prefixes to count (repeatable)")
    parser.add_argument("--outdir", default="benchmarks/out", help="Output directory for measurement files")
    parser.add_argument("--phase-file", default="", help="Phase tag file path (optional)")
    parser.add_argument("--storage-path", action="append", default=[], help="Path to measure storage (repeatable)")
    parser.add_argument(
        "--storage-component",
        action="append",
        default=[],
        help="Optional storage component matcher label=regex (repeatable, additive)",
    )
    parser.add_argument(
        "--storage-slices",
        action="store_true",
        help="Record additive milestone-level storage deltas for each workflow operation",
    )
    parser.add_argument(
        "--storage-topk",
        type=int,
        default=5,
        help="Top-K volume contributors to record per storage stage (default: 5)",
    )
    parser.add_argument(
        "--storage-meta-out",
        default="",
        help="Storage measurement metadata JSON output path (default: <outdir>/storage_measurement_meta.json)",
    )
    parser.add_argument("--storage-out", default="", help="Storage delta CSV output path")
    parser.add_argument("--storage-stage-out", default="", help="Milestone storage stage CSV output path")
    parser.add_argument("--storage-stage-volume-out", default="", help="Per-volume milestone storage CSV output path")
    parser.add_argument("--storage-stage-topk-out", default="", help="Top-K milestone storage contributors CSV output path")
    parser.add_argument(
        "--storage-stage-peer-store-out",
        default="",
        help="Per-peer-ledger-store milestone storage CSV output path",
    )
    parser.add_argument("--resources-out", default="", help="Resources CSV output path")
    parser.add_argument("--resources-interval", type=float, default=1.0, help="Resource sample interval (seconds)")
    parser.add_argument("--resources-iface", default="eth0", help="Network interface for RX/TX counters")
    parser.add_argument(
        "--resources-control-exclude-port",
        action="append",
        type=int,
        default=[22, 8083, 9446],
        help="TCP port(s) treated as control-plane for RX/TX subtraction (repeatable; default: 22,8083,9446).",
    )
    parser.add_argument(
        "--no-resources-control-subtract",
        action="store_true",
        help="Disable control-plane RX/TX subtraction (uses raw interface bytes only).",
    )
    parser.add_argument(
        "--proc-match",
        action="append",
        default=[],
        help="Process matcher override label=regex (repeatable; labels: tss, peer, orderer)",
    )
    parser.add_argument(
        "--gossip-convergence-timeout",
        type=float,
        default=30.0,
        help="Max seconds to wait for peer height convergence after an operation (default: 30).",
    )
    parser.add_argument(
        "--gossip-convergence-poll",
        type=float,
        default=1.0,
        help="Polling interval seconds for peer height convergence checks (default: 1.0).",
    )
    parser.add_argument("--inter-workflow-sleep", type=float, default=0.0, help="Sleep seconds between workflows")
    parser.add_argument("--measurement", action="store_true", help="Emit additive deterministic workflow measurement outputs")
    parser.add_argument("--measurement-v2", action="store_true", help="Deprecated alias for --measurement")
    parser.add_argument("--operation-id", default="", help="Optional operation ID override for measurement rows")
    parser.add_argument("--metrics", action="append", default=[], help="Metrics JSONL file(s) for milestone extraction")
    parser.add_argument("--workflow-runs-out", default="", help="Workflow runs CSV output path")
    parser.add_argument("--workflow-runs-v2-out", default="", help="Deprecated alias for --workflow-runs-out")
    parser.add_argument("--run-id", default="", help="Optional run ID propagated into additive stage/query outputs")
    parser.add_argument(
        "--artifact-profile",
        choices=["compact", "full", "ultra"],
        default="full",
        help="Artifact retention profile hint for callers (default: full).",
    )
    args = parser.parse_args()
    measurement_enabled = bool(args.measurement or args.measurement_v2)
    if args.measurement_v2:
        print("Warning: --measurement-v2 is deprecated; use --measurement.")
    if args.workflow_runs_v2_out:
        print("Warning: --workflow-runs-v2-out is deprecated; use --workflow-runs-out.")
    if args.workflow_runs_v2_out and not args.workflow_runs_out:
        args.workflow_runs_out = args.workflow_runs_v2_out
    if measurement_enabled and not args.workflow_runs_out:
        args.workflow_runs_out = os.path.join(args.outdir, WORKFLOW_RUNS_CANONICAL_FILE)
    workflow_runs_dir = args.outdir
    if args.workflow_runs_out:
        workflow_runs_dir = os.path.dirname(args.workflow_runs_out) or args.outdir
    args.workflow_runs_legacy_out = os.path.join(workflow_runs_dir, WORKFLOW_RUNS_LEGACY_FILE)

    base = args.api.rstrip("/")

    storage_source_mode = "disabled"
    resolved_docker_root = ""
    storage_warnings = []
    if args.measure and not args.storage_path:
        auto_paths, resolved_docker_root, auto_err = resolve_default_storage_paths()
        if auto_err:
            raise SystemExit(
                "Storage measurement preflight failed: "
                f"{auto_err} "
                "Pass --storage-path explicitly or ensure Docker is installed and accessible."
            )
        args.storage_path.extend(auto_paths)
        storage_source_mode = "docker_volumes_auto"
    elif args.measure:
        storage_source_mode = "explicit"
    if args.measure or args.collect_resources or args.collect_messages or args.peer_metrics_url:
        ensure_outdir(args.outdir)
    if args.measure:
        try:
            args.storage_path = ensure_storage_paths_readable(args.storage_path)
        except RuntimeError as e:
            raise SystemExit(f"Storage measurement preflight failed: {e}")
    if args.measure and not args.storage_out:
        args.storage_out = os.path.join(args.outdir, "storage_deltas.csv")
    if args.no_resources_control_subtract:
        args.resources_control_exclude_port = []
    else:
        args.resources_control_exclude_port = sorted(set(args.resources_control_exclude_port or []))
    for port in args.resources_control_exclude_port:
        if port <= 0 or port > 65535:
            raise SystemExit(f"--resources-control-exclude-port out of range: {port}")
    if args.storage_topk < 0:
        raise SystemExit("--storage-topk must be >= 0")
    if args.gossip_convergence_timeout < 0:
        raise SystemExit("--gossip-convergence-timeout must be >= 0")
    if args.gossip_convergence_poll <= 0:
        raise SystemExit("--gossip-convergence-poll must be > 0")
    if args.measure and args.storage_slices and not args.storage_stage_out:
        args.storage_stage_out = os.path.join(args.outdir, "storage_stage_deltas.csv")
    if args.measure and args.storage_slices and not args.storage_stage_volume_out:
        args.storage_stage_volume_out = os.path.join(args.outdir, "storage_stage_volume_deltas.csv")
    if args.measure and args.storage_slices and not args.storage_stage_topk_out:
        args.storage_stage_topk_out = os.path.join(args.outdir, "storage_stage_topk_volumes.csv")
    if args.measure and args.storage_slices and not args.storage_stage_peer_store_out:
        args.storage_stage_peer_store_out = os.path.join(args.outdir, "storage_stage_peer_ledger_deltas.csv")
    if args.measure and not args.storage_meta_out:
        args.storage_meta_out = os.path.join(args.outdir, "storage_measurement_meta.json")
    if (args.collect_messages or args.peer_metrics_url) and not args.messages_out:
        args.messages_out = os.path.join(args.outdir, "message_counts.csv")
    if args.phase_tags and not args.phase_file:
        args.phase_file = os.path.join(args.outdir, "operation_phase.txt")
    metric_paths = [p for p in args.metrics if p]
    if args.measure and args.storage_slices and not metric_paths:
        storage_warnings.append(
            "Storage slices running without --metrics inputs; only local phase checkpoint fallback will be used."
        )
    try:
        storage_component_rules = parse_storage_component_rules(args.storage_component)
    except ValueError as e:
        raise SystemExit(f"--storage-component error: {e}")
    if args.measure and not storage_component_rules:
        storage_component_rules = parse_storage_component_rules(DEFAULT_STORAGE_COMPONENT_RULES)
    non_splittable_paths = []
    if args.measure:
        for p in args.storage_path:
            if not is_docker_volumes_path(p):
                non_splittable_paths.append(p)
                storage_warnings.append(
                    f"Storage path '{p}' is not a Docker volumes path; component split will be NA for this path."
                )
        storage_meta_payload = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "storage_source_mode": storage_source_mode,
            "resolved_storage_paths": args.storage_path,
            "resolved_docker_root": resolved_docker_root,
            "artifact_profile": args.artifact_profile,
            "storage_slices_enabled": bool(args.storage_slices),
            "storage_topk": int(args.storage_topk),
            "storage_stage_outputs": {
                "storage_stage_deltas": args.storage_stage_out if args.storage_slices else "",
                "storage_stage_volume_deltas": args.storage_stage_volume_out if args.storage_slices else "",
                "storage_stage_topk_volumes": args.storage_stage_topk_out if args.storage_slices else "",
                "storage_stage_peer_ledger_deltas": args.storage_stage_peer_store_out if args.storage_slices else "",
            },
            "storage_component_rules_effective": [
                {"label": label, "regex": pattern.pattern} for label, pattern in storage_component_rules
            ],
            "non_splittable_paths": non_splittable_paths,
            "warnings": storage_warnings,
            "measurement_enabled": measurement_enabled,
            "workflow_runs_out": args.workflow_runs_out if measurement_enabled else "",
            "workflow_runs_legacy_out": args.workflow_runs_legacy_out if measurement_enabled else "",
        }
        write_storage_metadata(args.storage_meta_out, storage_meta_payload)
        for w in storage_warnings:
            print(f"Warning: {w}")

    # get_ca handles get ca behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def get_ca():
        """get_ca helper for benchmark tooling."""
        status, data = http_json("GET", base + "/api/ca")
        if status >= 400 or status == 0:
            raise RuntimeError(f"CA query failed: {data}")
        return data

    # get_reshare_session handles get reshare session behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def get_reshare_session(epoch):
        """get_reshare_session helper for benchmark tooling."""
        status, data = http_json("GET", base + f"/api/reshare/session?epoch={int(epoch)}")
        if status == 404:
            err = ""
            if isinstance(data, dict):
                err = str(data.get("error", ""))
            else:
                err = str(data)
            if "page not found" in err.lower():
                return {"_status": "endpoint_missing", "_error": err}
            return {"_status": "not_found", "_error": err}
        if status >= 400 or status == 0:
            raise RuntimeError(f"Reshare session query failed for epoch {epoch}: {data}")
        return data if isinstance(data, dict) else {}

    # wait_for_reshare_completion handles wait for reshare completion behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def wait_for_reshare_completion(epoch, on_tick=None, on_started=None, timing_out=None):
        """wait_for_reshare_completion helper for benchmark tooling."""
        started = time.time()
        last_status = "unknown"
        started_marked = False
        last_mark_ts = started
        status_durations = {}

        # mark_status handles mark status behavior for benchmark tooling.
        # Lifecycle: Benchmark script runtime, aggregation, and analysis.
        # Called by: module-internal callers (see surrounding flow).
        # Triggered: CLI execution and helper orchestration.
        def mark_status(new_status):
            """mark_status helper for benchmark tooling."""
            nonlocal last_status, last_mark_ts
            now = time.time()
            if last_status:
                status_durations[last_status] = float(status_durations.get(last_status, 0.0)) + max(now - last_mark_ts, 0.0)
            last_status = str(new_status or "unknown")
            last_mark_ts = now

        # finalize_status handles finalize status behavior for benchmark tooling.
        # Lifecycle: Benchmark script runtime, aggregation, and analysis.
        # Called by: module-internal callers (see surrounding flow).
        # Triggered: CLI execution and helper orchestration.
        def finalize_status():
            """finalize_status helper for benchmark tooling."""
            now = time.time()
            if last_status:
                status_durations[last_status] = float(status_durations.get(last_status, 0.0)) + max(now - last_mark_ts, 0.0)
            compute_s = 0.0
            wait_s = 0.0
            for s, dur in status_durations.items():
                ls = str(s).strip().lower()
                if ls in {"completed"}:
                    continue
                if ls in {"initiated", "acknowledged", "proposed", "not_found", "unknown"}:
                    wait_s += float(dur)
                elif ls in {"started", "running", "in_progress", "processing", "keygen", "reshare"}:
                    compute_s += float(dur)
                else:
                    wait_s += float(dur)
            if timing_out is not None:
                timing_out["elapsed_s"] = float(max(time.time() - started, 0.0))
                timing_out["compute_s"] = float(max(compute_s, 0.0))
                timing_out["wait_s"] = float(max(wait_s, 0.0))
                try:
                    timing_out["status_durations_json"] = json.dumps(status_durations, sort_keys=True)
                except Exception:
                    timing_out["status_durations_json"] = "{}"
                timing_out["last_status"] = str(last_status)

        while time.time() - started < args.timeout:
            if on_tick is not None:
                try:
                    on_tick()
                except Exception:
                    pass
            try:
                session = get_reshare_session(epoch)
            except Exception as e:
                mark_status("query_error")
                time.sleep(args.poll)
                continue
            if isinstance(session, dict):
                marker = str(session.get("_status", "")).strip().lower()
                if marker == "endpoint_missing":
                    mark_status("endpoint_missing")
                    print("Warning: /api/reshare/session endpoint not available; falling back to epoch-only wait.")
                    ok = wait_until(
                        lambda: to_int(get_ca().get("epoch", 0), 0) >= int(epoch),
                        args.timeout,
                        args.poll,
                        f"epoch {epoch}",
                        on_tick=on_tick,
                    )
                    finalize_status()
                    return ok
                if marker == "not_found":
                    mark_status("not_found")
                    time.sleep(args.poll)
                    continue
            status = str(session.get("status", "")).strip().lower()
            if status:
                mark_status(status)
            if (not started_marked) and status in {"initiated", "acknowledged", "proposed"}:
                started_marked = True
                if on_started is not None:
                    try:
                        on_started()
                    except Exception:
                        pass
            if status == "completed":
                finalize_status()
                return True
            time.sleep(args.poll)

        finalize_status()
        print(f"Timeout waiting for reshare completion (epoch {epoch}, last status: {last_status})")
        return False

    # wait_for_local_key_session_idle handles wait for local key session idle behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def wait_for_local_key_session_idle(on_tick=None, on_idle=None, timing_out=None):
        """wait_for_local_key_session_idle helper for benchmark tooling."""
        started = time.time()
        saw_key_session_field = False
        active_s = 0.0
        wait_s = 0.0
        last_tick = started

        # step_duration handles step duration behavior for benchmark tooling.
        # Lifecycle: Benchmark script runtime, aggregation, and analysis.
        # Called by: module-internal callers (see surrounding flow).
        # Triggered: CLI execution and helper orchestration.
        def step_duration(is_active, known=True):
            """step_duration helper for benchmark tooling."""
            nonlocal active_s, wait_s, last_tick
            now = time.time()
            dt = max(now - last_tick, 0.0)
            last_tick = now
            if known and is_active:
                active_s += dt
            else:
                wait_s += dt

        while time.time() - started < args.timeout:
            if on_tick is not None:
                try:
                    on_tick()
                except Exception:
                    pass
            try:
                keyinfo = get_keyinfo()
            except Exception:
                step_duration(False, known=False)
                time.sleep(args.poll)
                continue
            if isinstance(keyinfo, dict) and "keySessionInProgress" in keyinfo:
                saw_key_session_field = True
                is_active = bool(keyinfo.get("keySessionInProgress"))
                step_duration(is_active, known=True)
                if not is_active:
                    if on_idle is not None:
                        try:
                            on_idle()
                        except Exception:
                            pass
                    if timing_out is not None:
                        timing_out["elapsed_s"] = float(max(time.time() - started, 0.0))
                        timing_out["active_s"] = float(max(active_s, 0.0))
                        timing_out["wait_s"] = float(max(wait_s, 0.0))
                        timing_out["mode"] = "keySessionInProgress"
                    return True
            elif isinstance(keyinfo, dict) and "keygenInProgress" in keyinfo:
                # Backward compatibility with older peer payloads.
                saw_key_session_field = True
                is_active = bool(keyinfo.get("keygenInProgress"))
                step_duration(is_active, known=True)
                if not is_active:
                    if on_idle is not None:
                        try:
                            on_idle()
                        except Exception:
                            pass
                    if timing_out is not None:
                        timing_out["elapsed_s"] = float(max(time.time() - started, 0.0))
                        timing_out["active_s"] = float(max(active_s, 0.0))
                        timing_out["wait_s"] = float(max(wait_s, 0.0))
                        timing_out["mode"] = "keygenInProgress"
                    return True
            else:
                # Endpoint does not expose session state; do not block legacy runtimes.
                step_duration(False, known=False)
                if on_idle is not None:
                    try:
                        on_idle()
                    except Exception:
                        pass
                if timing_out is not None:
                    timing_out["elapsed_s"] = float(max(time.time() - started, 0.0))
                    timing_out["active_s"] = float(max(active_s, 0.0))
                    timing_out["wait_s"] = float(max(wait_s, 0.0))
                    timing_out["mode"] = "unsupported"
                return True
            time.sleep(args.poll)
        if timing_out is not None:
            timing_out["elapsed_s"] = float(max(time.time() - started, 0.0))
            timing_out["active_s"] = float(max(active_s, 0.0))
            timing_out["wait_s"] = float(max(wait_s, 0.0))
            timing_out["mode"] = "timeout"
        if saw_key_session_field:
            print("Timeout waiting for local key session to become idle.")
        return not saw_key_session_field

    # wait_for_local_signing_idle handles wait for local signing idle behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def wait_for_local_signing_idle(on_tick=None, on_idle=None, timing_out=None):
        """wait_for_local_signing_idle helper for benchmark tooling."""
        started = time.time()
        saw_signing_field = False
        active_s = 0.0
        wait_s = 0.0
        last_tick = started

        # step_duration handles step duration behavior for benchmark tooling.
        # Lifecycle: Benchmark script runtime, aggregation, and analysis.
        # Called by: module-internal callers (see surrounding flow).
        # Triggered: CLI execution and helper orchestration.
        def step_duration(is_active, known=True):
            """step_duration helper for benchmark tooling."""
            nonlocal active_s, wait_s, last_tick
            now = time.time()
            dt = max(now - last_tick, 0.0)
            last_tick = now
            if known and is_active:
                active_s += dt
            else:
                wait_s += dt

        while time.time() - started < args.timeout:
            if on_tick is not None:
                try:
                    on_tick()
                except Exception:
                    pass
            try:
                keyinfo = get_keyinfo()
            except Exception:
                step_duration(False, known=False)
                time.sleep(args.poll)
                continue
            if isinstance(keyinfo, dict) and "signingInProgress" in keyinfo:
                saw_signing_field = True
                is_active = bool(keyinfo.get("signingInProgress"))
                step_duration(is_active, known=True)
                if not is_active:
                    if on_idle is not None:
                        try:
                            on_idle()
                        except Exception:
                            pass
                    if timing_out is not None:
                        timing_out["elapsed_s"] = float(max(time.time() - started, 0.0))
                        timing_out["active_s"] = float(max(active_s, 0.0))
                        timing_out["wait_s"] = float(max(wait_s, 0.0))
                    return True
            else:
                # Endpoint does not expose signing session state; do not block legacy runtimes.
                step_duration(False, known=False)
                if on_idle is not None:
                    try:
                        on_idle()
                    except Exception:
                        pass
                if timing_out is not None:
                    timing_out["elapsed_s"] = float(max(time.time() - started, 0.0))
                    timing_out["active_s"] = float(max(active_s, 0.0))
                    timing_out["wait_s"] = float(max(wait_s, 0.0))
                    timing_out["mode"] = "unsupported"
                return True
            time.sleep(args.poll)
        if timing_out is not None:
            timing_out["elapsed_s"] = float(max(time.time() - started, 0.0))
            timing_out["active_s"] = float(max(active_s, 0.0))
            timing_out["wait_s"] = float(max(wait_s, 0.0))
            timing_out["mode"] = "timeout"
        if saw_signing_field:
            print("Timeout waiting for local signing session to become idle.")
        return not saw_signing_field

    # get_keyinfo handles get keyinfo behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def get_keyinfo():
        """get_keyinfo helper for benchmark tooling."""
        status, data = http_json("GET", base + "/api/keyshare")
        if status >= 400 or status == 0:
            raise RuntimeError(f"Key info query failed: {data}")
        return data

    # get_p2p_stats handles get p2p stats behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def get_p2p_stats(reset=False):
        """get_p2p_stats helper for benchmark tooling."""
        q = "?reset=true" if reset else ""
        status, data = http_json("GET", base + "/api/metrics/p2p" + q)
        if status >= 400 or status == 0:
            return None
        return data if isinstance(data, dict) else None

    # get_certs handles get certs behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def get_certs():
        """get_certs helper for benchmark tooling."""
        status, data = http_json("GET", base + "/api/certificates")
        if status >= 400 or status == 0:
            raise RuntimeError(f"Certificates query failed: {data}")
        return data if isinstance(data, list) else []

    # cert_id handles cert id behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def cert_id(cert):
        """cert_id helper for benchmark tooling."""
        return cert.get("certId") or cert.get("proposalId") or ""

    # find_member_cert handles find member cert behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def find_member_cert(member_id, proposal_id=None, existing_ids=None, issued_after=None):
        """find_member_cert helper for benchmark tooling."""
        certs = [c for c in get_certs() if c.get("memberId") == member_id]
        if proposal_id:
            for cert in certs:
                if cert.get("proposalId") == proposal_id:
                    return cert
                cid = cert.get("certId", "")
                if cid and proposal_id in cid:
                    return cert
            return None
        if existing_ids is not None:
            for cert in certs:
                if cert_id(cert) and cert_id(cert) not in existing_ids:
                    return cert
        if issued_after is not None:
            skew = issued_after.timestamp() - 60
            for cert in certs:
                ts = parse_ts(cert.get("issuedAt", ""))
                if ts and ts.timestamp() >= skew:
                    return cert
        return certs[-1] if certs else None

    workflows = args.workflow
    if "all" in workflows:
        # Keep "all" aligned with suite defaults and operational flow.
        workflows = ["csr", "revocation", "removal", "join"]

    # set_phase handles set phase behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def set_phase(label):
        """set_phase helper for benchmark tooling."""
        if not args.phase_tags or not args.phase_file:
            return
        try:
            with open(args.phase_file, "w", encoding="utf-8") as f:
                f.write(label)
        except Exception:
            pass

    for wf_index, wf in enumerate(workflows):
        workflow_base = wf
        workflow_tag = f"{wf}_{int(time.time())}"
        proposal_id = ""
        operation_id = (args.operation_id or "").strip()
        op_epoch = ""
        op_start_ts = datetime.utcnow().isoformat() + "Z"
        member_id = ""
        idle_marks = {
            "local_key_idle_ts": "",
            "local_signing_idle_ts": "",
        }
        submit_retry_stats = {
            "attempts": 0,
            "retries_total": 0,
            "retries_mvcc": 0,
            "retries_non_mvcc": 0,
            "retry_classes": {},
        }
        signing_timing = {}
        reshare_timing = {}
        key_session_timing = {}
        gossip_convergence = {
            "height_before_max": "",
            "height_after_max": "",
            "target_height": "",
            "height_delta": "",
            "peers_observed": 0,
            "peers_converged": 0,
            "convergence_s": "",
            "status": "disabled",
        }

        # mark_idle handles mark idle behavior for benchmark tooling.
        # Lifecycle: Benchmark script runtime, aggregation, and analysis.
        # Called by: module-internal callers (see surrounding flow).
        # Triggered: CLI execution and helper orchestration.
        def mark_idle(field):
            """mark_idle helper for benchmark tooling."""
            if field not in idle_marks:
                return
            if not idle_marks[field]:
                idle_marks[field] = datetime.utcnow().isoformat() + "Z"

        storage_stage_enabled = bool(args.measure and args.storage_slices)
        storage_stage_recorder = StorageStageRecorder(
            enabled=storage_stage_enabled,
            paths=args.storage_path,
            component_rules=storage_component_rules,
            topk_limit=args.storage_topk,
        )
        if storage_stage_enabled:
            storage_stage_recorder.mark("operation_start", op_start_ts)
        stage_observer = None
        if storage_stage_enabled and metric_paths:
            stage_observer = MilestoneEventObserver(
                metric_paths=metric_paths,
                workflow_base=workflow_base,
                start_ts=op_start_ts,
                on_mark=storage_stage_recorder.mark,
            )

        # poll_stage_events handles poll stage events behavior for benchmark tooling.
        # Lifecycle: Benchmark script runtime, aggregation, and analysis.
        # Called by: module-internal callers (see surrounding flow).
        # Triggered: CLI execution and helper orchestration.
        def poll_stage_events():
            """poll_stage_events helper for benchmark tooling."""
            if stage_observer is None:
                return
            try:
                stage_observer.poll()
            except Exception:
                pass

        if args.phase_tags and args.phase_file:
            set_phase(f"{wf}_start")
        collect_messages = args.collect_messages or bool(args.peer_metrics_url)
        p2p_reset_ok = False
        p2p_stats_start = None
        if collect_messages:
            p2p_stats_start = get_p2p_stats(reset=True)
            p2p_reset_ok = p2p_stats_start is not None
        peer_metrics_before = snapshot_peer_metrics(args.peer_metrics_url, args.peer_metrics_prefix) if args.peer_metrics_url else None
        peer_heights_before = snapshot_peer_heights(args.peer_metrics_url) if args.peer_metrics_url else {}
        storage_before = snapshot_storage(args.storage_path) if args.measure else {}
        storage_components_before = (
            snapshot_storage_components(args.storage_path, storage_component_rules) if args.measure else {}
        )
        res_proc, res_path = start_resource_sampler(args, workflow_tag)
        error = None
        try:
            if wf == "csr":
                keyinfo = get_keyinfo()
                member_id = keyinfo.get("memberId", "")
                if not member_id:
                    error = "Cannot determine memberId for CSR test."
                else:
                    existing_ids = set(
                        c.get("certId") or c.get("proposalId") or ""
                        for c in get_certs()
                        if c.get("memberId") == member_id
                    )
                    start_dt = datetime.utcnow()
                    set_phase("csr_submit")
                    body = {"cn": args.cn, "o": args.o, "l": args.l, "st": args.st, "c": args.c}
                    status, data, retry_meta = post_with_retry(
                        base + "/api/csr/submit",
                        body,
                        "csr_submit",
                        timeout_s=args.timeout,
                        interval_s=args.poll,
                    )
                    submit_retry_stats = retry_meta or submit_retry_stats
                    if status >= 400 or status == 0:
                        error = f"CSR submit failed: {data}"
                    else:
                        proposal_id = data.get("proposalId", "")
                        if proposal_id and not operation_id:
                            operation_id = proposal_id
                        if stage_observer is not None:
                            stage_observer.set_proposal_id(proposal_id)
                            poll_stage_events()
                        if storage_stage_enabled:
                            storage_stage_recorder.mark("csr_submit_done")
                        print(f"CSR submitted (proposal: {proposal_id}).")
                        if not args.no_wait:
                            set_phase("csr_wait_cert")
                            cert_ok = wait_until(
                                lambda: find_member_cert(member_id, proposal_id, existing_ids, start_dt) is not None,
                                args.timeout,
                                args.poll,
                                "certificate registration",
                                on_tick=poll_stage_events,
                            )
                            if not cert_ok:
                                error = "Certificate registration not observed before timeout."
                            else:
                                # Local fallback marks when metrics are sparse.
                                if storage_stage_enabled:
                                    storage_stage_recorder.mark("csr_voted")
                                    storage_stage_recorder.mark("csr_approved")
                                    storage_stage_recorder.mark("cert_registered")
                                set_phase("csr_wait_signing_idle")
                                if not wait_for_local_signing_idle(
                                    on_tick=poll_stage_events,
                                    on_idle=(lambda: mark_idle("local_signing_idle_ts")),
                                    timing_out=signing_timing,
                                ):
                                    error = "Certificate registered but local signing session did not become idle before timeout."
                    set_phase("csr_done")

            elif wf == "revocation":
                member_id = args.member_id
                if not member_id:
                    keyinfo = get_keyinfo()
                    member_id = keyinfo.get("memberId", "")
                if not member_id:
                    print("Skipping revocation (no --member-id provided and memberId unavailable).")
                else:
                    baseline_member_certs = [c for c in get_certs() if c.get("memberId") == member_id]
                    baseline_active_ids = set(
                        cert_id(c)
                        for c in baseline_member_certs
                        if cert_id(c) and not c.get("isRevoked")
                    )
                    baseline_revoked_count = sum(1 for c in baseline_member_certs if c.get("isRevoked"))
                    set_phase("revocation_propose")
                    status, data, retry_meta = post_with_retry(
                        base + "/api/revoke",
                        {"memberId": member_id, "reason": args.reason},
                        "revocation_propose",
                        timeout_s=args.timeout,
                        interval_s=args.poll,
                    )
                    submit_retry_stats = retry_meta or submit_retry_stats
                    if status >= 400 or status == 0:
                        error = f"Revocation proposal failed: {data}"
                    else:
                        proposal_id = data.get("proposalId", "")
                        if proposal_id and not operation_id:
                            operation_id = proposal_id
                        if stage_observer is not None:
                            stage_observer.set_proposal_id(proposal_id)
                            poll_stage_events()
                        if storage_stage_enabled:
                            storage_stage_recorder.mark("revocation_submit_done")
                        print(f"Revocation proposed: {proposal_id}")
                        if not args.no_wait:
                            set_phase("revocation_wait")

                            # revocation_done handles revocation done behavior for benchmark tooling.
                            # Lifecycle: Benchmark script runtime, aggregation, and analysis.
                            # Called by: module-internal callers (see surrounding flow).
                            # Triggered: CLI execution and helper orchestration.
                            def revocation_done():
                                """revocation_done helper for benchmark tooling."""
                                member_certs = [c for c in get_certs() if c.get("memberId") == member_id]
                                if baseline_active_ids:
                                    return any(
                                        c.get("isRevoked") and cert_id(c) in baseline_active_ids
                                        for c in member_certs
                                    )
                                # Fallback: if no active cert snapshot was found, require revoked count increase.
                                revoked_count = sum(1 for c in member_certs if c.get("isRevoked"))
                                return revoked_count > baseline_revoked_count

                            revoked_ok = wait_until(
                                revocation_done,
                                args.timeout,
                                args.poll,
                                "certificate revocation",
                                on_tick=poll_stage_events,
                            )
                            if not revoked_ok:
                                error = "Certificate revocation not observed before timeout."
                            elif storage_stage_enabled:
                                # Local fallback marks when metrics are sparse.
                                storage_stage_recorder.mark("revocation_voted")
                                storage_stage_recorder.mark("revocation_executed")
                    set_phase("revocation_done")

            elif wf == "join":
                ca = get_ca()
                start_epoch = to_int(ca.get("epoch", 0), 0)
                op_epoch = str(start_epoch)
                set_phase("join_submit")
                status, data, retry_meta = post_with_retry(
                    base + "/api/membership/request",
                    {"reason": args.reason},
                    "join_request_submit",
                    timeout_s=args.timeout,
                    interval_s=args.poll,
                )
                submit_retry_stats = retry_meta or submit_retry_stats
                if status >= 400 or status == 0:
                    error = f"Join request failed: {data}"
                else:
                    proposal_id = data.get("proposalId", "")
                    if proposal_id and not operation_id:
                        operation_id = proposal_id
                    if stage_observer is not None:
                        stage_observer.set_proposal_id(proposal_id)
                        poll_stage_events()
                    if storage_stage_enabled:
                        storage_stage_recorder.mark("join_submit_done")
                    print(f"Join request submitted: {proposal_id}")
                    if not args.no_wait:
                        set_phase("join_wait_vote")
                        approved = wait_until(
                            lambda: to_int(get_ca().get("epoch", 0), 0) > start_epoch,
                            args.timeout,
                            args.poll,
                            "join approval",
                            on_tick=poll_stage_events,
                        )
                        if not approved:
                            error = "Join request not approved before timeout."
                        else:
                            target_epoch = to_int(get_ca().get("epoch", 0), start_epoch + 1)
                            op_epoch = str(target_epoch)
                            if stage_observer is not None:
                                stage_observer.set_target_epoch(target_epoch)
                            if storage_stage_enabled:
                                # Local fallback marks when metrics are sparse.
                                storage_stage_recorder.mark("join_voted")
                                storage_stage_recorder.mark("join_approved")
                            set_phase("join_wait_reshare")
                            if not wait_for_reshare_completion(
                                target_epoch,
                                on_tick=poll_stage_events,
                                on_started=(lambda: storage_stage_recorder.mark("reshare_started")) if storage_stage_enabled else None,
                                timing_out=reshare_timing,
                            ):
                                error = f"Join approved but reshare epoch {target_epoch} did not complete before timeout."
                            elif not wait_for_local_key_session_idle(
                                on_tick=poll_stage_events,
                                on_idle=(lambda: mark_idle("local_key_idle_ts")),
                                timing_out=key_session_timing,
                            ):
                                error = f"Join approved and reshare epoch {target_epoch} completed on-chain, but local key session did not become idle before timeout."
                            elif storage_stage_enabled:
                                storage_stage_recorder.mark("reshare_completed")
                set_phase("join_done")

            elif wf == "removal":
                member_id = args.member_id
                if not member_id:
                    print("Skipping removal (provide --member-id to enable).")
                else:
                    ca = get_ca()
                    start_epoch = to_int(ca.get("epoch", 0), 0)
                    op_epoch = str(start_epoch)
                    set_phase("removal_submit")
                    status, data, retry_meta = post_with_retry(
                        base + "/api/membership/remove",
                        {"memberId": member_id, "reason": args.reason},
                        "member_removal_submit",
                        timeout_s=args.timeout,
                        interval_s=args.poll,
                    )
                    submit_retry_stats = retry_meta or submit_retry_stats
                    if status >= 400 or status == 0:
                        error = f"Removal proposal failed: {data}"
                    else:
                        proposal_id = data.get("proposalId", "")
                        if proposal_id and not operation_id:
                            operation_id = proposal_id
                        if stage_observer is not None:
                            stage_observer.set_proposal_id(proposal_id)
                            poll_stage_events()
                        if storage_stage_enabled:
                            storage_stage_recorder.mark("removal_submit_done")
                        print(f"Removal proposed: {proposal_id}")
                        if not args.no_wait:
                            set_phase("removal_wait_vote")

                            # removal_approved handles removal approved behavior for benchmark tooling.
                            # Lifecycle: Benchmark script runtime, aggregation, and analysis.
                            # Called by: module-internal callers (see surrounding flow).
                            # Triggered: CLI execution and helper orchestration.
                            def removal_approved():
                                """removal_approved helper for benchmark tooling."""
                                ca_now = get_ca()
                                members = ca_now.get("members") or []
                                epoch_now = to_int(ca_now.get("epoch", 0), 0)
                                return (member_id not in members) and (epoch_now > start_epoch)

                            approved = wait_until(
                                removal_approved,
                                args.timeout,
                                args.poll,
                                "member removal approval",
                                on_tick=poll_stage_events,
                            )
                            if not approved:
                                error = "Member removal not approved before timeout."
                            else:
                                target_epoch = to_int(get_ca().get("epoch", 0), start_epoch + 1)
                                op_epoch = str(target_epoch)
                                if stage_observer is not None:
                                    stage_observer.set_target_epoch(target_epoch)
                                if storage_stage_enabled:
                                    # Local fallback marks when metrics are sparse.
                                    storage_stage_recorder.mark("removal_voted")
                                    storage_stage_recorder.mark("removal_approved")
                                set_phase("removal_wait_reshare")
                                if not wait_for_reshare_completion(
                                    target_epoch,
                                    on_tick=poll_stage_events,
                                    on_started=(lambda: storage_stage_recorder.mark("reshare_started")) if storage_stage_enabled else None,
                                    timing_out=reshare_timing,
                                ):
                                    error = f"Member removal approved but reshare epoch {target_epoch} did not complete before timeout."
                                elif not wait_for_local_key_session_idle(
                                    on_tick=poll_stage_events,
                                    on_idle=(lambda: mark_idle("local_key_idle_ts")),
                                    timing_out=key_session_timing,
                                ):
                                    error = f"Member removal approved and reshare epoch {target_epoch} completed on-chain, but local key session did not become idle before timeout."
                                elif storage_stage_enabled:
                                    storage_stage_recorder.mark("reshare_completed")
                    set_phase("removal_done")
        finally:
            op_end_ts = datetime.utcnow().isoformat() + "Z"
            poll_stage_events()
            if storage_stage_enabled:
                storage_stage_recorder.mark("operation_end", op_end_ts)
            if args.peer_metrics_url:
                if error:
                    gossip_convergence = {
                        "height_before_max": "",
                        "height_after_max": "",
                        "target_height": "",
                        "height_delta": "",
                        "peers_observed": 0,
                        "peers_converged": 0,
                        "convergence_s": "",
                        "status": "skipped_error",
                    }
                else:
                    gossip_convergence = measure_gossip_convergence(
                        args.peer_metrics_url,
                        peer_heights_before,
                        timeout_s=args.gossip_convergence_timeout,
                        interval_s=args.gossip_convergence_poll,
                    )
            stop_resource_sampler(res_proc)
            summarize_resources(args.outdir, workflow_base, workflow_tag, op_start_ts, op_end_ts, res_path)
            if args.measure:
                storage_after = snapshot_storage(args.storage_path)
                storage_components_after = snapshot_storage_components(args.storage_path, storage_component_rules)
                rows = []
                for path in args.storage_path:
                    before = storage_before.get(path)
                    after = storage_after.get(path)
                    delta = ""
                    if before is not None and after is not None:
                        delta = str(after - before)
                    row = {
                        "ts_start": op_start_ts,
                        "ts_end": op_end_ts,
                        "workflow": wf,
                        "proposal_id": proposal_id,
                        "path": path,
                        "bytes_before": "NA" if before is None else before,
                        "bytes_after": "NA" if after is None else after,
                        "delta_bytes": delta,
                    }
                    comp_before = storage_components_before.get(path, {})
                    comp_after = storage_components_after.get(path, {})
                    splittable = bool(comp_before.get("splittable")) and bool(comp_after.get("splittable"))
                    row["storage_component_splittable"] = "true" if splittable else "false"
                    row["storage_component_note"] = "" if splittable else "non_volume_path"

                    comps_before = comp_before.get("components", {})
                    comps_after = comp_after.get("components", {})
                    counts_before = comp_before.get("component_match_counts", {})
                    counts_after = comp_after.get("component_match_counts", {})
                    for label, _ in storage_component_rules:
                        b = comps_before.get(label)
                        a = comps_after.get(label)
                        d = ""
                        if b is not None and a is not None:
                            d = str(a - b)
                        cb = counts_before.get(label)
                        ca = counts_after.get(label)
                        row[f"{label}_volume_bytes_before"] = "NA" if b is None else b
                        row[f"{label}_volume_bytes_after"] = "NA" if a is None else a
                        row[f"{label}_volume_delta_bytes"] = d
                        row[f"{label}_volume_match_count"] = "NA" if cb is None or ca is None else max(cb, ca)

                    other_before = comp_before.get("other")
                    other_after = comp_after.get("other")
                    other_delta = ""
                    if other_before is not None and other_after is not None:
                        other_delta = str(other_after - other_before)
                    other_count_before = comp_before.get("other_match_count")
                    other_count_after = comp_after.get("other_match_count")
                    row["other_volume_bytes_before"] = "NA" if other_before is None else other_before
                    row["other_volume_bytes_after"] = "NA" if other_after is None else other_after
                    row["other_volume_delta_bytes"] = other_delta
                    row["other_volume_match_count"] = (
                        "NA"
                        if other_count_before is None or other_count_after is None
                        else max(other_count_before, other_count_after)
                    )
                    rows.append(row)
                write_storage_deltas(args.storage_out, rows)
                if storage_stage_enabled:
                    stage_rows, volume_rows, topk_rows, peer_store_rows = storage_stage_recorder.finalize(
                        workflow=wf,
                        workflow_tag=workflow_tag,
                        operation_id=operation_id or proposal_id or workflow_tag,
                        proposal_id=proposal_id,
                        epoch=op_epoch,
                        run_id=args.run_id,
                    )
                    if stage_rows:
                        write_dict_rows(
                            args.storage_stage_out,
                            stage_rows,
                            base_fields=[
                                "run_id",
                                "workflow",
                                "workflow_tag",
                                "operation_id",
                                "proposal_id",
                                "epoch",
                                "stage_start",
                                "stage_end",
                                "ts_start",
                                "ts_end",
                                "path",
                                "bytes_before",
                                "bytes_after",
                                "delta_bytes",
                            ],
                        )
                    if volume_rows:
                        write_dict_rows(
                            args.storage_stage_volume_out,
                            volume_rows,
                            base_fields=[
                                "run_id",
                                "workflow",
                                "workflow_tag",
                                "operation_id",
                                "proposal_id",
                                "epoch",
                                "stage_start",
                                "stage_end",
                                "ts_start",
                                "ts_end",
                                "path",
                                "volume_name",
                                "component",
                                "bytes_before",
                                "bytes_after",
                                "delta_bytes",
                            ],
                        )
                    if topk_rows:
                        write_dict_rows(
                            args.storage_stage_topk_out,
                            topk_rows,
                            base_fields=[
                                "run_id",
                                "workflow",
                                "workflow_tag",
                                "operation_id",
                                "proposal_id",
                                "epoch",
                                "stage_start",
                                "stage_end",
                                "ts_start",
                                "ts_end",
                                "path",
                                "rank",
                                "volume_name",
                                "component",
                                "delta_bytes",
                                "share_pct",
                            ],
                        )
                    if peer_store_rows:
                        write_dict_rows(
                            args.storage_stage_peer_store_out,
                            peer_store_rows,
                            base_fields=[
                                "run_id",
                                "workflow",
                                "workflow_tag",
                                "operation_id",
                                "proposal_id",
                                "epoch",
                                "stage_start",
                                "stage_end",
                                "ts_start",
                                "ts_end",
                                "path",
                                "volume_name",
                                "component",
                                "peer_store_root",
                                "peer_volume_bytes_before",
                                "peer_volume_bytes_after",
                                "peer_volume_delta_bytes",
                                "block_files_bytes_before",
                                "block_files_bytes_after",
                                "block_files_delta_bytes",
                                "block_index_bytes_before",
                                "block_index_bytes_after",
                                "block_index_delta_bytes",
                                "leveldb_data_bytes_before",
                                "leveldb_data_bytes_after",
                                "leveldb_data_delta_bytes",
                                "leveldb_wal_meta_bytes_before",
                                "leveldb_wal_meta_bytes_after",
                                "leveldb_wal_meta_delta_bytes",
                                "peer_store_other_bytes_before",
                                "peer_store_other_bytes_after",
                                "peer_store_other_delta_bytes",
                            ],
                        )
            if collect_messages:
                p2p_stats_end = get_p2p_stats(reset=False)
                p2p_sent = p2p_recv = p2p_sent_bc = p2p_sent_dir = p2p_recv_bc = p2p_recv_dir = "NA"
                p2p_sent_by_type = "NA"
                p2p_recv_by_type = "NA"
                if p2p_reset_ok and p2p_stats_end:
                    p2p_sent = p2p_stats_end.get("sent_total", "NA")
                    p2p_recv = p2p_stats_end.get("recv_total", "NA")
                    p2p_sent_bc = p2p_stats_end.get("sent_broadcast", "NA")
                    p2p_sent_dir = p2p_stats_end.get("sent_direct", "NA")
                    p2p_recv_bc = p2p_stats_end.get("recv_broadcast", "NA")
                    p2p_recv_dir = p2p_stats_end.get("recv_direct", "NA")
                    p2p_sent_by_type = json.dumps(p2p_stats_end.get("sent_by_type", {}))
                    p2p_recv_by_type = json.dumps(p2p_stats_end.get("recv_by_type", {}))

                gossip_delta = "NA"
                if args.peer_metrics_url:
                    peer_metrics_after = snapshot_peer_metrics(args.peer_metrics_url, args.peer_metrics_prefix)
                    if peer_metrics_before is not None and peer_metrics_after is not None:
                        gossip_delta = f"{peer_metrics_after - peer_metrics_before:.0f}"

                write_message_counts(
                    args.messages_out,
                    [
                        [
                            op_start_ts,
                            op_end_ts,
                            wf,
                            proposal_id,
                            p2p_sent,
                            p2p_recv,
                            p2p_sent_bc,
                            p2p_sent_dir,
                            p2p_recv_bc,
                            p2p_recv_dir,
                            p2p_sent_by_type,
                            p2p_recv_by_type,
                            gossip_delta,
                        ]
                    ],
                )

            if measurement_enabled:
                metric_events = load_metric_events(metric_paths) if metric_paths else []
                milestones = infer_milestones(
                    metric_events,
                    workflow_base=workflow_base,
                    proposal_id=proposal_id,
                    client_start_ts=op_start_ts,
                    client_end_ts=op_end_ts,
                    epoch=op_epoch,
                )
                tss_compute_proxy = sum_numeric_present(
                    signing_timing.get("active_s"),
                    reshare_timing.get("compute_s"),
                    key_session_timing.get("active_s"),
                )
                tss_wait_proxy = sum_numeric_present(
                    signing_timing.get("wait_s"),
                    reshare_timing.get("wait_s"),
                    key_session_timing.get("wait_s"),
                )
                retry_classes_json = "{}"
                try:
                    retry_classes_json = json.dumps(submit_retry_stats.get("retry_classes", {}), sort_keys=True)
                except Exception:
                    retry_classes_json = "{}"
                row = {
                    "workflow_base": workflow_base,
                    "workflow_tag": workflow_tag,
                    "operation_id": operation_id or proposal_id or workflow_tag,
                    "proposal_id": proposal_id,
                    "epoch": op_epoch,
                    "submit_tx_id": milestones.get("submit_tx_id", ""),
                    "execute_tx_id": milestones.get("execute_tx_id", ""),
                    "status": "failed" if error else "success",
                    "error": error or "",
                    "client_start_ts": op_start_ts,
                    "client_end_ts": op_end_ts,
                    "submitted_observed_ts": milestones.get("submitted_observed_ts", ""),
                    "voted_ts": milestones.get("voted_ts", ""),
                    "approved_or_executed_ts": milestones.get("approved_or_executed_ts", ""),
                    "reshare_started_ts": milestones.get("reshare_started_ts", ""),
                    "reshare_completed_ts": milestones.get("reshare_completed_ts", ""),
                    "cert_registered_ts": milestones.get("cert_registered_ts", ""),
                    "local_key_idle_ts": idle_marks.get("local_key_idle_ts", ""),
                    "local_signing_idle_ts": idle_marks.get("local_signing_idle_ts", ""),
                    "ledger_tx_ts_submit": milestones.get("ledger_tx_ts_submit", ""),
                    "ledger_tx_ts_execute": milestones.get("ledger_tx_ts_execute", ""),
                    "submit_attempts": int(submit_retry_stats.get("attempts", 0) or 0),
                    "submit_retries_total": int(submit_retry_stats.get("retries_total", 0) or 0),
                    "submit_retries_mvcc": int(submit_retry_stats.get("retries_mvcc", 0) or 0),
                    "submit_retries_non_mvcc": int(submit_retry_stats.get("retries_non_mvcc", 0) or 0),
                    "submit_retry_classes": retry_classes_json,
                    "tss_signing_compute_s": signing_timing.get("active_s", ""),
                    "tss_signing_wait_s": signing_timing.get("wait_s", ""),
                    "tss_reshare_compute_s": reshare_timing.get("compute_s", ""),
                    "tss_reshare_wait_s": reshare_timing.get("wait_s", ""),
                    "tss_key_session_compute_s": key_session_timing.get("active_s", ""),
                    "tss_key_session_wait_s": key_session_timing.get("wait_s", ""),
                    "tss_compute_proxy_s": tss_compute_proxy if tss_compute_proxy is not None else "",
                    "tss_wait_proxy_s": tss_wait_proxy if tss_wait_proxy is not None else "",
                    "gossip_height_before_max": gossip_convergence.get("height_before_max", ""),
                    "gossip_height_after_max": gossip_convergence.get("height_after_max", ""),
                    "gossip_target_height": gossip_convergence.get("target_height", ""),
                    "gossip_height_delta": gossip_convergence.get("height_delta", ""),
                    "gossip_peers_observed": gossip_convergence.get("peers_observed", 0),
                    "gossip_peers_converged": gossip_convergence.get("peers_converged", 0),
                    "gossip_convergence_s": gossip_convergence.get("convergence_s", ""),
                    "gossip_convergence_status": gossip_convergence.get("status", ""),
                }
                append_workflow_run(
                    args.workflow_runs_out,
                    row,
                    legacy_alias_path=args.workflow_runs_legacy_out,
                )

        if error:
            print(error)
            sys.exit(1)
        if wf_index < len(workflows) - 1 and args.inter_workflow_sleep > 0:
            time.sleep(args.inter_workflow_sleep)

    print("Done.")


if __name__ == "__main__":
    main()
