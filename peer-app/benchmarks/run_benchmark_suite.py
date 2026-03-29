#!/usr/bin/env python3
"""run_benchmark_suite.py orchestrates repeated workflow benchmark suites.

Runtime flow: executes per-run workflow scripts, optional query benchmarks, and
then aggregates all run artifacts into suite-level CSV summaries and manifest data.
"""

import argparse
import csv
import json
import shlex
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

if __package__:
    from .latency_model import MIXED_EPSILON_SECONDS, derive_latency_components
else:
    from latency_model import MIXED_EPSILON_SECONDS, derive_latency_components

VALID_WORKFLOWS = ("csr", "revocation", "removal", "join")
WORKFLOW_RUNS_CANONICAL_FILE = "workflow_runs.csv"
WORKFLOW_RUNS_LEGACY_FILE = "workflow_runs_v2.csv"
SUITE_WORKFLOW_RUNS_CANONICAL_FILE = "suite_workflow_runs_all.csv"
SUITE_WORKFLOW_RUNS_LEGACY_FILE = "suite_workflow_runs_v2_all.csv"
SUITE_WORKFLOW_LATENCY_CANONICAL_FILE = "suite_workflow_latency_averages.csv"
SUITE_WORKFLOW_LATENCY_LEGACY_FILE = "suite_workflow_latency_v2_averages.csv"


# utc_now_iso handles utc now iso behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def utc_now_iso():
    """utc_now_iso helper for benchmark tooling."""
    return datetime.utcnow().isoformat() + "Z"


# parse_iso_ts handles parse iso ts behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def parse_iso_ts(value):
    """parse_iso_ts helper for benchmark tooling."""
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(raw)
    except Exception:
        return None


# canonical_workflow_name handles canonical workflow name behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def canonical_workflow_name(value):
    """canonical_workflow_name helper for benchmark tooling."""
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    if raw in VALID_WORKFLOWS:
        return raw
    token = raw.split("_", 1)[0]
    if token in VALID_WORKFLOWS:
        return token
    return raw


# ensure_dir handles ensure dir behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def ensure_dir(path):
    """ensure_dir helper for benchmark tooling."""
    path.mkdir(parents=True, exist_ok=True)


# parse_workflows handles parse workflows behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def parse_workflows(raw):
    """parse_workflows helper for benchmark tooling."""
    parts = []
    for token in str(raw).split(","):
        token = token.strip().lower()
        if token:
            parts.append(token)
    if not parts:
        return list(VALID_WORKFLOWS)
    if "all" in parts:
        return list(VALID_WORKFLOWS)
    bad = [w for w in parts if w not in VALID_WORKFLOWS]
    if bad:
        raise ValueError(f"Unsupported workflow(s): {', '.join(bad)}")
    return parts


# command_to_string handles command to string behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def command_to_string(cmd):
    """command_to_string helper for benchmark tooling."""
    return " ".join(shlex.quote(str(c)) for c in cmd)

# run_command executes a command and stores combined stdout/stderr in a log file.
# Lifecycle: Suite run orchestration.
# Called by: main, execute_query_benchmark_for_run.
# Triggered: whenever a workflow/query/analyzer subprocess is launched.
def run_command(cmd, log_path):
    """run_command helper for benchmark tooling."""
    ensure_dir(log_path.parent)
    with open(log_path, "w", encoding="utf-8") as log_f:
        log_f.write(f"$ {command_to_string(cmd)}\n\n")
        log_f.flush()
        proc = subprocess.run(cmd, stdout=log_f, stderr=subprocess.STDOUT, text=True)
        return proc.returncode


# read_csv_rows handles read csv rows behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def read_csv_rows(path):
    """read_csv_rows helper for benchmark tooling."""
    if not path.exists():
        return [], []
    with open(path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fields = reader.fieldnames or []
    return fields, rows


# read_json_file handles read json file behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def read_json_file(path):
    """read_json_file helper for benchmark tooling."""
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


# write_csv_rows handles write csv rows behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def write_csv_rows(path, fieldnames, rows):
    """write_csv_rows helper for benchmark tooling."""
    ensure_dir(path.parent)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            out = {k: row.get(k, "") for k in fieldnames}
            writer.writerow(out)


# resolve_run_workflow_runs_path resolves canonical/legacy workflow run CSV path for a run.
# Lifecycle: Suite run orchestration.
# Called by: execute_query_benchmark_for_run, main.
# Triggered: while reading per-run workflow measurement rows.
def resolve_run_workflow_runs_path(raw_dir: Path):
    """resolve_run_workflow_runs_path helper for benchmark tooling."""
    canonical = raw_dir / WORKFLOW_RUNS_CANONICAL_FILE
    legacy = raw_dir / WORKFLOW_RUNS_LEGACY_FILE
    if canonical.exists():
        return canonical, "canonical"
    if legacy.exists():
        return legacy, "legacy"
    return canonical, "missing"


# write_csv_with_legacy_alias writes canonical output and mirrors legacy alias.
# Lifecycle: Suite-level artifact generation.
# Called by: main.
# Triggered: when emitting workflow measurement outputs during compatibility window.
def write_csv_with_legacy_alias(canonical_path: Path, legacy_path: Path, fieldnames, rows):
    """write_csv_with_legacy_alias helper for benchmark tooling."""
    write_csv_rows(canonical_path, fieldnames, rows)
    if canonical_path != legacy_path:
        write_csv_rows(legacy_path, fieldnames, rows)


# union_fields handles union fields behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def union_fields(base, extra):
    """union_fields helper for benchmark tooling."""
    for key in extra:
        if key not in base:
            base.append(key)


# file_size_bytes handles file size bytes behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def file_size_bytes(path: Path):
    """file_size_bytes helper for benchmark tooling."""
    try:
        if path.is_file():
            return path.stat().st_size
    except Exception:
        return 0
    return 0


# remove_file handles remove file behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def remove_file(path: Path):
    """remove_file helper for benchmark tooling."""
    if not path.exists() or not path.is_file():
        return 0
    size = file_size_bytes(path)
    try:
        path.unlink()
        return size
    except Exception:
        return 0


# remove_dir handles remove dir behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def remove_dir(path: Path):
    """remove_dir helper for benchmark tooling."""
    if not path.exists() or not path.is_dir():
        return 0
    total = 0
    try:
        for item in path.rglob("*"):
            if item.is_file():
                total += file_size_bytes(item)
    except Exception:
        pass
    try:
        shutil.rmtree(path)
        return total
    except Exception:
        return 0

# apply_run_artifact_profile prunes or retains run artifacts by profile.
# Lifecycle: Post-run artifact lifecycle management.
# Called by: main.
# Triggered: after each run when compact/ultra retention profiles are selected.
def apply_run_artifact_profile(run_manifest, artifact_profile):
    """apply_run_artifact_profile helper for benchmark tooling."""
    run_dir = Path(run_manifest.get("paths", {}).get("run_dir", ""))
    if not run_dir.exists():
        return {"files_removed": 0, "bytes_freed": 0, "run_dir_removed": False}

    removed_files = 0
    bytes_freed = 0

    # delete_file handles delete file behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def delete_file(path: Path):
        """delete_file helper for benchmark tooling."""
        nonlocal removed_files, bytes_freed
        freed = remove_file(path)
        if freed > 0:
            removed_files += 1
            bytes_freed += freed

    if artifact_profile in {"compact", "ultra"}:
        raw_dir = run_dir / "raw"
        labeled_dir = run_dir / "labeled"
        logs_dir = run_dir / "logs"
        query_dir = run_dir / "query"

        for p in raw_dir.glob("resources_*.csv"):
            delete_file(p)

        for name in ("resources_all_labeled.csv", "resources_all_phase_summary.csv"):
            delete_file(labeled_dir / name)

        delete_file(query_dir / "query_bench_iterations.csv")

        workflows = run_manifest.get("workflows", [])
        if isinstance(workflows, list):
            for wf in workflows:
                if not isinstance(wf, dict):
                    continue
                if str(wf.get("status", "")).strip().lower() != "success":
                    continue
                log_file = str(wf.get("log_file", "")).strip()
                if log_file:
                    delete_file(Path(log_file))

        query_meta = run_manifest.get("query_benchmark", {})
        if isinstance(query_meta, dict):
            if str(query_meta.get("status", "")).strip().lower() == "success":
                log_file = str(query_meta.get("log_file", "")).strip()
                if log_file:
                    delete_file(Path(log_file))
                out = query_meta.get("outputs", {})
                if isinstance(out, dict):
                    q_iter = str(out.get("query_bench_iterations", "")).strip()
                    if q_iter:
                        delete_file(Path(q_iter))

        label_meta = run_manifest.get("labeling", {})
        if isinstance(label_meta, dict) and str(label_meta.get("status", "")).strip().lower() == "success":
            log_file = str(label_meta.get("log_file", "")).strip()
            if log_file:
                delete_file(Path(log_file))
            outputs = label_meta.get("outputs", {})
            if isinstance(outputs, dict):
                merged_labeled = str(outputs.get("merged_labeled", "")).strip()
                merged_phase = str(outputs.get("merged_phase_summary", "")).strip()
                if merged_labeled:
                    delete_file(Path(merged_labeled))
                if merged_phase:
                    delete_file(Path(merged_phase))

        for d in (raw_dir, labeled_dir, logs_dir, query_dir):
            if d.exists():
                try:
                    next(d.iterdir())
                except StopIteration:
                    try:
                        d.rmdir()
                    except Exception:
                        pass

    if artifact_profile == "ultra":
        bytes_freed += remove_dir(run_dir)
        return {"files_removed": removed_files, "bytes_freed": bytes_freed, "run_dir_removed": True}

    return {"files_removed": removed_files, "bytes_freed": bytes_freed, "run_dir_removed": False}


# to_float handles to float behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def to_float(value):
    """to_float helper for benchmark tooling."""
    if value is None:
        return None
    raw = str(value).strip()
    if raw == "" or raw.upper() in {"NA", "N/A", "NONE", "NULL"}:
        return None
    try:
        return float(raw)
    except Exception:
        return None


# fmt_num handles fmt num behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def fmt_num(value):
    """fmt_num helper for benchmark tooling."""
    if value is None:
        return ""
    if abs(value - round(value)) < 1e-9:
        return str(int(round(value)))
    text = f"{value:.6f}"
    text = text.rstrip("0").rstrip(".")
    return text if text else "0"


# find_numeric_columns handles find numeric columns behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def find_numeric_columns(rows, excluded):
    """find_numeric_columns helper for benchmark tooling."""
    numeric_cols = []
    if not rows:
        return numeric_cols
    all_cols = []
    seen = set()
    for row in rows:
        for col in row.keys():
            if col not in seen:
                seen.add(col)
                all_cols.append(col)
    for col in all_cols:
        if col in excluded:
            continue
        has_numeric = False
        has_text = False
        for row in rows:
            raw = row.get(col, "")
            if str(raw).strip() == "":
                continue
            val = to_float(raw)
            if val is None:
                has_text = True
                break
            has_numeric = True
        if has_numeric and not has_text:
            numeric_cols.append(col)
    return numeric_cols

# aggregate_rows groups rows and computes aggregate statistics for numeric columns.
# Lifecycle: Suite-level aggregation.
# Called by: main.
# Triggered: while producing averaged per-workflow and global summary CSVs.
def aggregate_rows(rows, group_keys, excluded_numeric=None):
    """aggregate_rows helper for benchmark tooling."""
    excluded_numeric = set(excluded_numeric or [])
    if not rows:
        return [], []

    groups = defaultdict(list)
    for row in rows:
        key = tuple(str(row.get(k, "")) for k in group_keys)
        groups[key].append(row)

    numeric_cols = find_numeric_columns(rows, set(group_keys) | excluded_numeric)
    out_rows = []
    out_fields = list(group_keys) + ["rows"]
    for col in numeric_cols:
        out_fields.extend([f"{col}_avg", f"{col}_min", f"{col}_max", f"{col}_sum"])

    for key, members in groups.items():
        out = {k: key[idx] for idx, k in enumerate(group_keys)}
        out["rows"] = str(len(members))
        for col in numeric_cols:
            vals = []
            for row in members:
                val = to_float(row.get(col, ""))
                if val is not None:
                    vals.append(val)
            if vals:
                out[f"{col}_avg"] = fmt_num(sum(vals) / len(vals))
                out[f"{col}_min"] = fmt_num(min(vals))
                out[f"{col}_max"] = fmt_num(max(vals))
                out[f"{col}_sum"] = fmt_num(sum(vals))
            else:
                out[f"{col}_avg"] = ""
                out[f"{col}_min"] = ""
                out[f"{col}_max"] = ""
                out[f"{col}_sum"] = ""
        out_rows.append(out)

    out_rows.sort(key=lambda r: tuple(str(r.get(k, "")) for k in group_keys))
    return out_fields, out_rows


# extract_tx_block_size_rows handles extract tx block size rows behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def extract_tx_block_size_rows(tx_event_rows):
    """extract_tx_block_size_rows helper for benchmark tooling."""
    if not tx_event_rows:
        return [], []

    numeric_cols = [
        "tx_envelope_bytes",
        "tx_payload_bytes",
        "block_bytes",
        "block_data_bytes",
        "block_overhead_bytes",
        "block_tx_count",
        "block_shared_overhead_per_tx_bytes",
        "tx_index_in_block",
    ]
    base_fields = [
        "run_id",
        "workflow_base",
        "operation_id",
        "proposal_id",
        "action",
        "event_name",
        "tx_id",
        "block_number",
    ]

    rows = []
    seen = set()
    for row in tx_event_rows:
        event_name = str(row.get("event_name", "")).strip()
        event_kind = str(row.get("event", "")).strip()
        if event_kind and event_kind != "cc_event_observed":
            continue
        if event_name and event_name.lower() == "storageattribution":
            continue

        parsed_numeric = {}
        has_size = False
        for col in numeric_cols:
            val = to_float(row.get(col, ""))
            parsed_numeric[col] = val
            if val is not None:
                has_size = True
        if not has_size:
            continue

        run_id = str(row.get("run_id", "")).strip()
        workflow = canonical_workflow_name(row.get("workflow_base", "") or row.get("workflow", ""))
        op_id = str(row.get("operation_id", "")).strip()
        proposal_id = str(row.get("proposal_id", "")).strip()
        action = str(row.get("action", "")).strip()
        tx_id = str(row.get("tx_id", "")).strip()
        block_number = str(row.get("block_number", "")).strip()

        dedupe_key = (
            run_id,
            workflow,
            op_id,
            proposal_id,
            action,
            tx_id,
            block_number,
            parsed_numeric.get("tx_envelope_bytes"),
            parsed_numeric.get("block_bytes"),
            parsed_numeric.get("block_tx_count"),
        )
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        out = {
            "run_id": run_id,
            "workflow_base": workflow,
            "operation_id": op_id,
            "proposal_id": proposal_id,
            "action": action,
            "event_name": event_name,
            "tx_id": tx_id,
            "block_number": block_number,
        }
        for col in numeric_cols:
            out[col] = fmt_num(parsed_numeric[col]) if parsed_numeric[col] is not None else ""
        rows.append(out)

    fieldnames = base_fields + numeric_cols
    return fieldnames, rows


# raw_resource_files handles raw resource files behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def raw_resource_files(raw_dir):
    """raw_resource_files helper for benchmark tooling."""
    files = []
    for p in sorted(raw_dir.glob("resources_*.csv")):
        name = p.name
        if name == "resources_summary.csv":
            continue
        if name.endswith("_labeled.csv") or name.endswith("_phase_summary.csv"):
            continue
        if name.startswith("resources_all_"):
            continue
        files.append(p)
    return files


# add_common_workflow_args handles add common workflow args behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def add_common_workflow_args(cmd, args):
    """add_common_workflow_args helper for benchmark tooling."""
    cmd.extend(["--reason", args.reason])
    cmd.extend(["--timeout", str(args.timeout)])
    cmd.extend(["--poll", str(args.poll)])
    if args.no_wait:
        cmd.append("--no-wait")
    if args.measure:
        cmd.append("--measure")
    if args.collect_resources:
        cmd.append("--collect-resources")
    if args.collect_messages:
        cmd.append("--collect-messages")
    if args.phase_tags:
        cmd.append("--phase-tags")
    for url in args.peer_metrics_url:
        cmd.extend(["--peer-metrics-url", url])
    for prefix in args.peer_metrics_prefix:
        cmd.extend(["--peer-metrics-prefix", prefix])
    for path in args.storage_path:
        cmd.extend(["--storage-path", path])
    for matcher in args.storage_component:
        cmd.extend(["--storage-component", matcher])
    if args.storage_slices:
        cmd.append("--storage-slices")
        cmd.extend(["--storage-topk", str(args.storage_topk)])
    for matcher in args.proc_match:
        cmd.extend(["--proc-match", matcher])
    cmd.extend(["--resources-interval", str(args.resources_interval)])
    cmd.extend(["--resources-iface", args.resources_iface])
    if args.no_resources_control_subtract:
        cmd.append("--no-resources-control-subtract")
    for port in args.resources_control_exclude_port:
        cmd.extend(["--resources-control-exclude-port", str(port)])
    cmd.extend(["--gossip-convergence-timeout", str(args.gossip_convergence_timeout)])
    cmd.extend(["--gossip-convergence-poll", str(args.gossip_convergence_poll)])


# resolve_query_cert_target handles resolve query cert target behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def resolve_query_cert_target(workflow_rows, source_mode, explicit_cert_id, member_id):
    """resolve_query_cert_target helper for benchmark tooling."""
    source = str(source_mode or "auto_csr").strip().lower()
    explicit = str(explicit_cert_id or "").strip()
    member = str(member_id or "").strip()

    if source == "explicit":
        if explicit:
            return explicit, "explicit"
        return "", "missing_explicit_cert_id"
    if source == "member_id":
        if member:
            return member, "member_id"
        return "", "missing_member_id"

    candidates = []
    for row in workflow_rows or []:
        wf = canonical_workflow_name(row.get("workflow_base", "") or row.get("workflow_tag", ""))
        if wf != "csr":
            continue
        status = str(row.get("status", "")).strip().lower()
        if status and status != "success":
            continue
        proposal_id = str(row.get("proposal_id", "")).strip()
        operation_id = str(row.get("operation_id", "")).strip()
        candidate = proposal_id or operation_id
        if not candidate:
            continue
        ended = parse_iso_ts(row.get("client_end_ts"))
        started = parse_iso_ts(row.get("client_start_ts"))
        ts = ended or started
        candidates.append((ts, candidate))

    if not candidates:
        return "", "missing_successful_csr_target"

    candidates.sort(key=lambda item: (item[0] is None, item[0]))
    _, chosen = candidates[-1]
    return chosen, "auto_csr"


# first_non_empty handles first non empty behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def first_non_empty(data, keys):
    """first_non_empty helper for benchmark tooling."""
    if not isinstance(data, dict):
        return ""
    for key in keys:
        val = data.get(key)
        if val is None:
            continue
        token = str(val).strip()
        if token:
            return token
    return ""

# execute_query_benchmark_for_run executes query-latency benchmarking for one run.
# Lifecycle: Optional query benchmark stage.
# Called by: main.
# Triggered: after workflow execution when query benchmark mode is enabled.
def execute_query_benchmark_for_run(run_id, run_manifest, raw_dir, run_dir, logs_dir, args, query_bench_script, trigger):
    """execute_query_benchmark_for_run helper for benchmark tooling."""
    query_dir = run_dir / "query"
    query_log = logs_dir / "query_bench.log"
    run_workflow_path, workflow_source = resolve_run_workflow_runs_path(raw_dir)
    if workflow_source == "legacy":
        print(f"[{run_id}] Warning: using legacy workflow runs file {WORKFLOW_RUNS_LEGACY_FILE}; prefer {WORKFLOW_RUNS_CANONICAL_FILE}.")
    run_workflow_fields, run_workflow_rows = read_csv_rows(run_workflow_path)
    query_cert_id, query_cert_source = resolve_query_cert_target(
        run_workflow_rows,
        args.query_cert_source,
        args.query_cert_id,
        args.member_id,
    )

    # _set_manifest handles set manifest behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def _set_manifest(status, return_code, reason="", command="", cert_id="", out_enabled=False):
        """_set_manifest helper for benchmark tooling."""
        run_manifest["query_benchmark"] = {
            "enabled": True,
            "status": status,
            "reason": reason,
            "trigger": trigger,
            "return_code": return_code,
            "log_file": str(query_log),
            "command": command,
            "query_cert_id": cert_id,
            "query_cert_source": args.query_cert_source,
            "resolved_query_cert_source": query_cert_source,
            "workflow_runs_rows": len(run_workflow_rows),
            "workflow_runs_fields": run_workflow_fields,
            "workflow_runs_source": workflow_source,
            "workflow_runs_v2_rows": len(run_workflow_rows),
            "workflow_runs_v2_fields": run_workflow_fields,
            "require_status_success": bool(args.strict_measurement_quality),
            "require_proof_success": bool(args.strict_measurement_quality),
            "outputs": {
                "query_bench_iterations": str(query_dir / "query_bench_iterations.csv")
                if out_enabled and (query_dir / "query_bench_iterations.csv").exists()
                else "",
                "query_bench_summary": str(query_dir / "query_bench_summary.csv")
                if out_enabled and (query_dir / "query_bench_summary.csv").exists()
                else "",
            },
        }

    if not query_cert_id:
        if args.strict_measurement_quality:
            _set_manifest(
                status="failed",
                return_code=2,
                reason=query_cert_source,
                command="",
                cert_id="",
                out_enabled=False,
            )
            print(f"[{run_id}] query benchmark: failed (no valid query target: {query_cert_source})")
            return "failed", 2
        _set_manifest(
            status="skipped",
            return_code=0,
            reason=query_cert_source,
            command="",
            cert_id="",
            out_enabled=False,
        )
        print(f"[{run_id}] query benchmark: skipped ({query_cert_source})")
        return "skipped", 0

    ensure_dir(query_dir)
    query_cmd = [
        sys.executable,
        str(query_bench_script),
        "--api",
        args.api,
        "--cert-id",
        query_cert_id,
        "--iters",
        str(args.query_iters),
        "--warmup",
        str(args.query_warmup),
        "--timeout",
        str(args.query_timeout),
        "--outdir",
        str(query_dir),
        "--run-id",
        run_id,
    ]
    if args.strict_measurement_quality:
        query_cmd.append("--require-status-success")
        query_cmd.append("--require-proof-success")
    else:
        query_cmd.append("--no-require-status-success")
        query_cmd.append("--no-require-proof-success")

    query_rc = run_command(query_cmd, query_log)
    query_status = "success" if query_rc == 0 else "failed"
    _set_manifest(
        status=query_status,
        return_code=query_rc,
        reason="",
        command=command_to_string(query_cmd),
        cert_id=query_cert_id,
        out_enabled=True,
    )
    if query_rc == 0:
        print(f"[{run_id}] query benchmark: success")
    else:
        print(f"[{run_id}] query benchmark: failed (rc={query_rc})")
    return query_status, query_rc

# main drives multi-run benchmark suite execution and cross-run aggregation.
# Lifecycle: Benchmark suite entrypoint.
# Called by: module entrypoint (`if __name__ == "__main__"`).
# Triggered: when invoked from CLI to create a suite output directory.
def main():
    """main helper for benchmark tooling."""
    parser = argparse.ArgumentParser(
        description="Run multi-workflow benchmark suites and auto-label resources across repeated runs."
    )
    parser.add_argument("--api", default="http://localhost:8080", help="TSS Web API base URL")
    parser.add_argument("--runs", type=int, default=1, help="Number of full benchmark runs")
    parser.add_argument("--member-id", default="", help="Target member ID for revocation/removal")
    parser.add_argument(
        "--outroot",
        default="",
        help="Suite output root directory (default: benchmarks/out/suite_<utc_ts>)",
    )
    parser.add_argument("--metrics", nargs="+", required=True, help="Metrics JSONL path(s) used for labeling")
    parser.add_argument(
        "--workflows",
        default="csr,revocation,removal,join",
        help="Comma-separated workflow order (default: csr,revocation,removal,join)",
    )
    parser.add_argument(
        "--inter-workflow-sleep",
        type=float,
        default=5.0,
        help="Sleep seconds between workflows",
    )
    parser.set_defaults(continue_on_error=True)
    parser.add_argument(
        "--continue-on-error",
        dest="continue_on_error",
        action="store_true",
        help="Continue when a workflow step fails (default)",
    )
    parser.add_argument(
        "--fail-fast",
        dest="continue_on_error",
        action="store_false",
        help="Stop at first failed workflow step",
    )

    # Pass-through knobs for run_workflows.py
    parser.add_argument("--reason", default="benchmark", help="Reason string for proposals")
    parser.add_argument("--timeout", type=int, default=600, help="Timeout for each workflow execution")
    parser.add_argument("--poll", type=float, default=2.0, help="Polling interval for workflow completion")
    parser.add_argument("--no-wait", action="store_true", help="Submit only, do not wait for completion")
    parser.add_argument("--cn", default="", help="CSR Common Name override")
    parser.add_argument("--o", default="", help="CSR Organization override")
    parser.add_argument("--l", default="", help="CSR Locality override")
    parser.add_argument("--st", default="", help="CSR State override")
    parser.add_argument("--c", default="", help="CSR Country override")
    parser.add_argument("--measure", action="store_true", help="Collect storage + resource samples")
    parser.add_argument("--collect-resources", action="store_true", help="Collect resource samples")
    parser.add_argument("--collect-messages", action="store_true", help="Collect P2P/gossip message counts")
    parser.add_argument("--phase-tags", action="store_true", help="Enable phase tagging")
    parser.add_argument("--peer-metrics-url", action="append", default=[], help="Peer metrics URL(s)")
    parser.add_argument("--peer-metrics-prefix", action="append", default=[], help="Peer metric prefixes")
    parser.add_argument("--storage-path", action="append", default=[], help="Storage path(s) to measure")
    parser.add_argument(
        "--storage-component",
        action="append",
        default=[],
        help="Storage component matcher label=regex (repeatable, passed to run_workflows.py)",
    )
    parser.add_argument(
        "--storage-slices",
        action="store_true",
        help="Enable milestone-level storage slice recording (passed to run_workflows.py)",
    )
    parser.add_argument(
        "--storage-topk",
        type=int,
        default=5,
        help="Top-K volume contributors per milestone stage (default: 5)",
    )
    parser.add_argument(
        "--proc-match",
        action="append",
        default=[],
        help="Process matcher label=regex (repeatable, passed to collect_resources.py via run_workflows.py)",
    )
    parser.add_argument("--resources-interval", type=float, default=1.0, help="Resource sample interval")
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
        "--gossip-convergence-timeout",
        type=float,
        default=30.0,
        help="Max seconds to wait for peer height convergence after each workflow operation (default: 30).",
    )
    parser.add_argument(
        "--gossip-convergence-poll",
        type=float,
        default=1.0,
        help="Polling interval seconds for peer height convergence checks (default: 1.0).",
    )
    parser.add_argument("--measurement", action="store_true", help="Enable additive workflow measurement outputs")
    parser.add_argument("--measurement-v2", action="store_true", help="Deprecated alias for --measurement")
    parser.add_argument("--operation-id", default="", help="Optional operation-id override passed to workflow runner")
    parser.add_argument("--query-bench", action="store_true", help="Run query latency micro-benchmark after each run")
    parser.add_argument("--query-iters", type=int, default=30, help="Query benchmark measured iterations per run")
    parser.add_argument("--query-warmup", type=int, default=5, help="Query benchmark warmup iterations per run")
    parser.add_argument("--query-timeout", type=float, default=10.0, help="Query benchmark HTTP timeout in seconds")
    parser.add_argument(
        "--query-cert-source",
        choices=["auto_csr", "explicit", "member_id"],
        default="auto_csr",
        help="Query benchmark cert-id source mode (default: auto_csr)",
    )
    parser.add_argument(
        "--query-cert-id",
        default="",
        help="Certificate status lookup id for query benchmark (default: --member-id when provided)",
    )
    parser.add_argument(
        "--strict-measurement-quality",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Enable strict measurement quality gating (default: false)",
    )
    parser.add_argument(
        "--tx-event-unmapped-policy",
        choices=["drop", "keep", "warn", "fail"],
        default="warn",
        help="Policy for tx events that cannot be mapped to a run (default: warn)",
    )
    parser.add_argument(
        "--tx-event-window-skew-sec",
        type=int,
        default=120,
        help="Timestamp window skew in seconds for tx-event run mapping fallback (default: 120)",
    )
    parser.add_argument(
        "--artifact-profile",
        choices=["compact", "full", "ultra"],
        default="compact",
        help="Artifact retention profile (default: compact)",
    )
    args = parser.parse_args()
    measurement_enabled = bool(args.measurement or args.measurement_v2)
    if args.measurement_v2:
        print("Warning: --measurement-v2 is deprecated; use --measurement.")

    if args.runs < 1:
        parser.error("--runs must be >= 1")
    if args.inter_workflow_sleep < 0:
        parser.error("--inter-workflow-sleep must be >= 0")
    if args.storage_topk < 0:
        parser.error("--storage-topk must be >= 0")
    if args.query_iters < 1:
        parser.error("--query-iters must be >= 1")
    if args.query_warmup < 0:
        parser.error("--query-warmup must be >= 0")
    if args.query_timeout <= 0:
        parser.error("--query-timeout must be > 0")
    if args.tx_event_window_skew_sec < 0:
        parser.error("--tx-event-window-skew-sec must be >= 0")
    if args.gossip_convergence_timeout < 0:
        parser.error("--gossip-convergence-timeout must be >= 0")
    if args.gossip_convergence_poll <= 0:
        parser.error("--gossip-convergence-poll must be > 0")
    if args.no_resources_control_subtract:
        args.resources_control_exclude_port = []
    else:
        args.resources_control_exclude_port = sorted(set(args.resources_control_exclude_port or []))
    for port in args.resources_control_exclude_port:
        if port <= 0 or port > 65535:
            parser.error(f"--resources-control-exclude-port out of range: {port}")

    try:
        workflows = parse_workflows(args.workflows)
    except ValueError as exc:
        parser.error(str(exc))

    metric_paths = [Path(m) for m in args.metrics]
    missing_metrics = [str(p) for p in metric_paths if not p.exists()]
    if missing_metrics:
        parser.error("Missing --metrics file(s): " + ", ".join(missing_metrics))

    script_dir = Path(__file__).resolve().parent
    run_workflows_script = script_dir / "run_workflows.py"
    label_resources_script = script_dir / "label_resources.py"
    query_bench_script = script_dir / "benchmark_queries.py"
    if not run_workflows_script.exists():
        parser.error(f"Missing runner script: {run_workflows_script}")
    if not label_resources_script.exists():
        parser.error(f"Missing labeler script: {label_resources_script}")
    if args.query_bench and not query_bench_script.exists():
        parser.error(f"Missing query benchmark script: {query_bench_script}")

    if args.outroot.strip():
        outroot = Path(args.outroot).expanduser()
    else:
        suffix = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        outroot = Path("benchmarks/out") / f"suite_{suffix}"
    ensure_dir(outroot)

    print(f"Suite output root: {outroot}")
    print(f"Workflows: {', '.join(workflows)}")
    print(f"Runs: {args.runs}")

    width = max(3, len(str(args.runs)))
    suite_started_at = utc_now_iso()
    run_manifests = []
    workflow_steps_succeeded = 0
    workflow_steps_failed = 0
    labeling_steps_succeeded = 0
    labeling_steps_failed = 0
    query_steps_succeeded = 0
    query_steps_failed = 0
    query_steps_skipped = 0
    stop_early = False

    for idx in range(1, args.runs + 1):
        run_id = f"run_{idx:0{width}d}"
        run_dir = outroot / run_id
        raw_dir = run_dir / "raw"
        labeled_dir = run_dir / "labeled"
        logs_dir = run_dir / "logs"
        ensure_dir(raw_dir)
        ensure_dir(labeled_dir)
        ensure_dir(logs_dir)

        print(f"[{run_id}] starting")
        run_started_at = utc_now_iso()
        run_manifest = {
            "run_id": run_id,
            "started_at": run_started_at,
            "ended_at": "",
            "paths": {
                "run_dir": str(run_dir),
                "raw_dir": str(raw_dir),
                "labeled_dir": str(labeled_dir),
                "logs_dir": str(logs_dir),
            },
            "workflows": [],
            "generated_raw_resource_files": [],
            "labeling": {},
            "measurement": {},
            "measurement_v2": {},
            "query_benchmark": {},
            "artifact_profile": {
                "selected": args.artifact_profile,
                "files_removed": 0,
                "bytes_freed": 0,
                "run_dir_removed": False,
            },
        }
        query_bench_done = False

        for wf_idx, wf in enumerate(workflows):
            wf_start = utc_now_iso()
            log_path = logs_dir / f"{wf}.log"

            cmd = [
                sys.executable,
                str(run_workflows_script),
                "--api",
                args.api,
                "--workflow",
                wf,
                "--outdir",
                str(raw_dir),
                "--run-id",
                run_id,
                "--artifact-profile",
                args.artifact_profile,
            ]
            add_common_workflow_args(cmd, args)
            if measurement_enabled:
                cmd.append("--measurement")
                if args.operation_id:
                    cmd.extend(["--operation-id", args.operation_id])
                for metric_path in metric_paths:
                    cmd.extend(["--metrics", str(metric_path)])

            if args.member_id and wf in {"revocation", "removal"}:
                cmd.extend(["--member-id", args.member_id])
            if wf == "csr":
                if args.cn:
                    cmd.extend(["--cn", args.cn])
                if args.o:
                    cmd.extend(["--o", args.o])
                if args.l:
                    cmd.extend(["--l", args.l])
                if args.st:
                    cmd.extend(["--st", args.st])
                if args.c:
                    cmd.extend(["--c", args.c])

            rc = run_command(cmd, log_path)
            status = "success" if rc == 0 else "failed"
            if rc == 0:
                workflow_steps_succeeded += 1
                print(f"[{run_id}] {wf}: success")
            else:
                workflow_steps_failed += 1
                print(f"[{run_id}] {wf}: failed (rc={rc})")

            run_manifest["workflows"].append(
                {
                    "workflow": wf,
                    "status": status,
                    "return_code": rc,
                    "started_at": wf_start,
                    "ended_at": utc_now_iso(),
                    "log_file": str(log_path),
                    "command": command_to_string(cmd),
                }
            )

            if rc == 0 and wf == "csr" and args.query_bench and not query_bench_done:
                query_status, query_rc = execute_query_benchmark_for_run(
                    run_id=run_id,
                    run_manifest=run_manifest,
                    raw_dir=raw_dir,
                    run_dir=run_dir,
                    logs_dir=logs_dir,
                    args=args,
                    query_bench_script=query_bench_script,
                    trigger="post_csr",
                )
                query_bench_done = True
                if query_status == "success":
                    query_steps_succeeded += 1
                elif query_status == "failed":
                    query_steps_failed += 1
                else:
                    query_steps_skipped += 1
                if query_status == "failed" and not args.continue_on_error:
                    stop_early = True
                    break

            if rc != 0 and not args.continue_on_error:
                stop_early = True
                break

            if wf_idx < len(workflows) - 1 and args.inter_workflow_sleep > 0:
                time.sleep(args.inter_workflow_sleep)

        generated_raw = raw_resource_files(raw_dir)
        run_manifest["generated_raw_resource_files"] = [str(p) for p in generated_raw]
        run_workflow_path, run_workflow_source = resolve_run_workflow_runs_path(raw_dir)
        run_storage_path = raw_dir / "storage_deltas.csv"
        run_storage_meta_path = raw_dir / "storage_measurement_meta.json"
        run_manifest["measurement"] = {
            "enabled": measurement_enabled,
            "workflow_runs_file": str(run_workflow_path) if run_workflow_path.exists() else "",
            "workflow_runs_source": run_workflow_source,
            "event_source": "event_first_with_poll_fallback" if measurement_enabled else "v1_only",
        }
        run_manifest["measurement_v2"] = dict(run_manifest["measurement"])
        run_message_counts_path = raw_dir / "message_counts.csv"
        run_msg_fields, run_msg_rows = read_csv_rows(run_message_counts_path)
        run_manifest["communication_measurement"] = {
            "enabled": bool(args.collect_messages or args.peer_metrics_url),
            "message_counts_file": str(run_message_counts_path) if run_message_counts_path.exists() else "",
            "message_rows": len(run_msg_rows),
            "message_fields": run_msg_fields,
        }
        storage_meta = read_json_file(run_storage_meta_path)
        sd_fields_run, sd_rows_run = read_csv_rows(run_storage_path)
        rows_per_path = {}
        paths_recorded = []
        if sd_rows_run:
            for row in sd_rows_run:
                p = str(row.get("path", "")).strip()
                if not p:
                    continue
                rows_per_path[p] = rows_per_path.get(p, 0) + 1
            paths_recorded = sorted(rows_per_path.keys())
        component_delta_cols = [c for c in sd_fields_run if c.endswith("_volume_delta_bytes") and c != "delta_bytes"]

        # _is_non_empty handles is non empty behavior for benchmark tooling.
        # Lifecycle: Benchmark script runtime, aggregation, and analysis.
        # Called by: module-internal callers (see surrounding flow).
        # Triggered: CLI execution and helper orchestration.
        def _is_non_empty(value):
            """_is_non_empty helper for benchmark tooling."""
            token = str(value).strip().upper()
            return token not in {"", "NA", "N/A", "NONE", "NULL"}

        component_split_populated = False
        if component_delta_cols and sd_rows_run:
            for row in sd_rows_run:
                if any(_is_non_empty(row.get(c, "")) for c in component_delta_cols):
                    component_split_populated = True
                    break

        run_manifest["storage_measurement"] = {
            "enabled": args.measure,
            "storage_source_mode": storage_meta.get("storage_source_mode", "disabled"),
            "resolved_storage_paths": storage_meta.get("resolved_storage_paths", []),
            "storage_slices_enabled": bool(storage_meta.get("storage_slices_enabled", False)),
            "storage_topk": storage_meta.get("storage_topk", args.storage_topk),
            "storage_component_rules_effective": storage_meta.get("storage_component_rules_effective", []),
            "non_splittable_paths": storage_meta.get("non_splittable_paths", []),
            "warnings": storage_meta.get("warnings", []),
            "meta_file": str(run_storage_meta_path) if run_storage_meta_path.exists() else "",
            "storage_rows": len(sd_rows_run),
            "paths_recorded": paths_recorded,
            "rows_per_path": rows_per_path,
            "component_split_populated": component_split_populated,
        }

        run_storage_stage_path = raw_dir / "storage_stage_deltas.csv"
        run_storage_stage_vol_path = raw_dir / "storage_stage_volume_deltas.csv"
        run_storage_stage_topk_path = raw_dir / "storage_stage_topk_volumes.csv"
        run_storage_stage_peer_store_path = raw_dir / "storage_stage_peer_ledger_deltas.csv"
        ssd_fields, ssd_rows = read_csv_rows(run_storage_stage_path)
        ssv_fields, ssv_rows = read_csv_rows(run_storage_stage_vol_path)
        sst_fields, sst_rows = read_csv_rows(run_storage_stage_topk_path)
        ssps_fields, ssps_rows = read_csv_rows(run_storage_stage_peer_store_path)
        run_manifest["storage_measurement"]["storage_stage_files"] = {
            "storage_stage_deltas": str(run_storage_stage_path) if run_storage_stage_path.exists() else "",
            "storage_stage_volume_deltas": str(run_storage_stage_vol_path) if run_storage_stage_vol_path.exists() else "",
            "storage_stage_topk_volumes": str(run_storage_stage_topk_path) if run_storage_stage_topk_path.exists() else "",
            "storage_stage_peer_ledger_deltas": str(run_storage_stage_peer_store_path)
            if run_storage_stage_peer_store_path.exists()
            else "",
        }
        run_manifest["storage_measurement"]["storage_stage_rows"] = {
            "storage_stage_deltas": len(ssd_rows),
            "storage_stage_volume_deltas": len(ssv_rows),
            "storage_stage_topk_volumes": len(sst_rows),
            "storage_stage_peer_ledger_deltas": len(ssps_rows),
        }
        run_manifest["storage_measurement"]["storage_stage_fields"] = {
            "storage_stage_deltas": ssd_fields,
            "storage_stage_volume_deltas": ssv_fields,
            "storage_stage_topk_volumes": sst_fields,
            "storage_stage_peer_ledger_deltas": ssps_fields,
        }

        if args.query_bench and not query_bench_done:
            query_status, query_rc = execute_query_benchmark_for_run(
                run_id=run_id,
                run_manifest=run_manifest,
                raw_dir=raw_dir,
                run_dir=run_dir,
                logs_dir=logs_dir,
                args=args,
                query_bench_script=query_bench_script,
                trigger="post_run",
            )
            query_bench_done = True
            if query_status == "success":
                query_steps_succeeded += 1
            elif query_status == "failed":
                query_steps_failed += 1
            else:
                query_steps_skipped += 1
            if query_status == "failed" and not args.continue_on_error:
                stop_early = True
        elif not args.query_bench:
            run_manifest["query_benchmark"] = {
                "enabled": False,
                "status": "disabled",
                "reason": "",
                "trigger": "disabled",
                "return_code": 0,
                "log_file": str(logs_dir / "query_bench.log"),
                "command": "",
                "query_cert_source": args.query_cert_source,
                "resolved_query_cert_source": "disabled",
                "query_cert_id": "",
                "require_status_success": bool(args.strict_measurement_quality),
                "require_proof_success": bool(args.strict_measurement_quality),
                "outputs": {
                    "query_bench_iterations": "",
                    "query_bench_summary": "",
                },
            }

        labeling_log = logs_dir / "labeling.log"
        merged_labeled = labeled_dir / "resources_all_labeled.csv"
        merged_phase = labeled_dir / "resources_all_phase_summary.csv"
        if generated_raw:
            label_cmd = [
                sys.executable,
                str(label_resources_script),
                "--resources",
                *[str(p) for p in generated_raw],
                "--metrics",
                *[str(p) for p in metric_paths],
                "--mode",
                "auto",
                "--outdir",
                str(labeled_dir),
                "--merged-out",
                str(merged_labeled),
                "--merged-phase-summary-out",
                str(merged_phase),
            ]
            label_rc = run_command(label_cmd, labeling_log)
            label_status = "success" if label_rc == 0 else "failed"
            if label_rc == 0:
                labeling_steps_succeeded += 1
                print(f"[{run_id}] labeling: success")
            else:
                labeling_steps_failed += 1
                print(f"[{run_id}] labeling: failed (rc={label_rc})")
            run_manifest["labeling"] = {
                "status": label_status,
                "return_code": label_rc,
                "log_file": str(labeling_log),
                "command": command_to_string(label_cmd),
                "outputs": {
                    "merged_labeled": str(merged_labeled) if merged_labeled.exists() else "",
                    "merged_phase_summary": str(merged_phase) if merged_phase.exists() else "",
                },
            }
            if label_rc != 0 and not args.continue_on_error:
                stop_early = True
        else:
            run_manifest["labeling"] = {
                "status": "skipped",
                "return_code": 0,
                "log_file": str(labeling_log),
                "command": "",
                "outputs": {
                    "merged_labeled": "",
                    "merged_phase_summary": "",
                },
                "reason": "No raw resources_*.csv files were generated",
            }
            print(f"[{run_id}] labeling: skipped (no raw resources files)")

        run_manifest["ended_at"] = utc_now_iso()
        run_manifest_path = run_dir / "manifest.json"
        with open(run_manifest_path, "w", encoding="utf-8") as f:
            json.dump(run_manifest, f, indent=2)
        run_manifests.append(run_manifest)
        print(f"[{run_id}] manifest: {run_manifest_path}")

        if stop_early:
            break

    # Global aggregation across runs
    resources_summary_rows = []
    resources_summary_fields = ["run_id"]
    storage_rows = []
    storage_fields = ["run_id"]
    storage_stage_rows = []
    storage_stage_fields = ["run_id"]
    storage_stage_volume_rows = []
    storage_stage_volume_fields = ["run_id"]
    storage_stage_topk_rows = []
    storage_stage_topk_fields = ["run_id"]
    storage_stage_peer_store_rows = []
    storage_stage_peer_store_fields = ["run_id"]
    phase_rows = []
    phase_fields = ["run_id"]
    labeled_rows = []
    labeled_fields = ["run_id"]
    workflow_runs_rows = []
    workflow_runs_fields = ["run_id"]
    message_rows = []
    message_fields = ["run_id"]
    tx_event_rows = []
    tx_event_fields = ["run_id"]
    query_iter_rows = []
    query_iter_fields = ["run_id"]
    query_summary_rows = []
    query_summary_fields = ["run_id"]

    for run_manifest in run_manifests:
        run_id = run_manifest.get("run_id", "")
        run_dir = Path(run_manifest["paths"]["run_dir"])
        raw_dir = run_dir / "raw"
        labeled_dir = run_dir / "labeled"

        rs_path = raw_dir / "resources_summary.csv"
        rs_fields, rs_rows = read_csv_rows(rs_path)
        if rs_rows:
            union_fields(resources_summary_fields, rs_fields)
            for row in rs_rows:
                merged = {"run_id": run_id}
                merged.update(row)
                resources_summary_rows.append(merged)

        sd_path = raw_dir / "storage_deltas.csv"
        sd_fields, sd_rows = read_csv_rows(sd_path)
        if sd_rows:
            union_fields(storage_fields, sd_fields)
            for row in sd_rows:
                merged = {"run_id": run_id}
                merged.update(row)
                storage_rows.append(merged)

        ssd_path = raw_dir / "storage_stage_deltas.csv"
        ssd_fields, ssd_rows = read_csv_rows(ssd_path)
        if ssd_rows:
            union_fields(storage_stage_fields, ssd_fields)
            for row in ssd_rows:
                merged = {"run_id": run_id}
                merged.update(row)
                storage_stage_rows.append(merged)

        ssv_path = raw_dir / "storage_stage_volume_deltas.csv"
        ssv_fields, ssv_rows = read_csv_rows(ssv_path)
        if ssv_rows:
            union_fields(storage_stage_volume_fields, ssv_fields)
            for row in ssv_rows:
                merged = {"run_id": run_id}
                merged.update(row)
                storage_stage_volume_rows.append(merged)

        sst_path = raw_dir / "storage_stage_topk_volumes.csv"
        sst_fields, sst_rows = read_csv_rows(sst_path)
        if sst_rows:
            union_fields(storage_stage_topk_fields, sst_fields)
            for row in sst_rows:
                merged = {"run_id": run_id}
                merged.update(row)
                storage_stage_topk_rows.append(merged)

        ssps_path = raw_dir / "storage_stage_peer_ledger_deltas.csv"
        ssps_fields, ssps_rows = read_csv_rows(ssps_path)
        if ssps_rows:
            union_fields(storage_stage_peer_store_fields, ssps_fields)
            for row in ssps_rows:
                merged = {"run_id": run_id}
                merged.update(row)
                storage_stage_peer_store_rows.append(merged)

        ph_path = labeled_dir / "resources_all_phase_summary.csv"
        ph_fields, ph_rows = read_csv_rows(ph_path)
        if ph_rows:
            union_fields(phase_fields, ph_fields)
            for row in ph_rows:
                merged = {"run_id": run_id}
                merged.update(row)
                phase_rows.append(merged)

        la_path = labeled_dir / "resources_all_labeled.csv"
        la_fields, la_rows = read_csv_rows(la_path)
        if la_rows:
            union_fields(labeled_fields, la_fields)
            for row in la_rows:
                merged = {"run_id": run_id}
                merged.update(row)
                labeled_rows.append(merged)

        workflow_path, workflow_rows_source = resolve_run_workflow_runs_path(raw_dir)
        if workflow_rows_source == "legacy":
            print(f"[{run_id}] Warning: using legacy workflow runs file {WORKFLOW_RUNS_LEGACY_FILE}; prefer {WORKFLOW_RUNS_CANONICAL_FILE}.")
        workflow_fields_run, workflow_rows_run = read_csv_rows(workflow_path)
        if workflow_rows_run:
            union_fields(workflow_runs_fields, workflow_fields_run)
            for row in workflow_rows_run:
                merged = {"run_id": run_id}
                merged.update(row)
                workflow_runs_rows.append(merged)

        msg_path = raw_dir / "message_counts.csv"
        msg_fields, msg_rows = read_csv_rows(msg_path)
        if msg_rows:
            union_fields(message_fields, msg_fields)
            for row in msg_rows:
                merged = {"run_id": run_id}
                merged.update(row)
                message_rows.append(merged)

        query_dir = run_dir / "query"
        q_iter_path = query_dir / "query_bench_iterations.csv"
        q_iter_fields, q_iter_rows = read_csv_rows(q_iter_path)
        if q_iter_rows:
            union_fields(query_iter_fields, q_iter_fields)
            for row in q_iter_rows:
                merged = {"run_id": run_id}
                merged.update(row)
                query_iter_rows.append(merged)

        q_sum_path = query_dir / "query_bench_summary.csv"
        q_sum_fields, q_sum_rows = read_csv_rows(q_sum_path)
        if q_sum_rows:
            union_fields(query_summary_fields, q_sum_fields)
            for row in q_sum_rows:
                merged = {"run_id": run_id}
                merged.update(row)
                query_summary_rows.append(merged)

    run_windows = []
    run_tx_event_stats = {}
    run_by_id = {}
    for run_manifest in run_manifests:
        rid = run_manifest.get("run_id", "")
        run_by_id[rid] = run_manifest
        run_tx_event_stats[rid] = {
            "tx_events_total": 0,
            "tx_events_mapped": 0,
            "tx_events_unmapped": 0,
            "tx_events_mapped_committed": 0,
            "tx_events_mapping_mode": "",
        }
        started = parse_iso_ts(run_manifest.get("started_at"))
        ended = parse_iso_ts(run_manifest.get("ended_at"))
        if rid and started and ended:
            skew = timedelta(seconds=args.tx_event_window_skew_sec)
            run_windows.append((rid, started-skew, ended+skew))
    run_windows.sort(key=lambda item: item[1])

    tx_events_total = 0
    tx_events_mapped = 0
    tx_events_unmapped = 0
    tx_events_mapped_committed = 0
    tx_block_size_row_count = 0
    tx_events_mapping_mode = "run_operation_id_primary_with_timestamp_fallback"
    tx_events_unmapped_policy_triggered = False

    if measurement_enabled:
        op_to_run = {}
        proposal_to_run = {}
        event_workflow_hints = {}

        # register_ref handles register ref behavior for benchmark tooling.
        # Lifecycle: Benchmark script runtime, aggregation, and analysis.
        # Called by: module-internal callers (see surrounding flow).
        # Triggered: CLI execution and helper orchestration.
        def register_ref(mapping, key, value):
            """register_ref helper for benchmark tooling."""
            token = str(key or "").strip()
            if not token:
                return
            existing = mapping.get(token)
            if existing is None:
                mapping[token] = value
            elif existing != value:
                mapping[token] = ("", "")

        for row in workflow_runs_rows:
            rid = str(row.get("run_id", "")).strip()
            if not rid:
                continue
            wf = canonical_workflow_name(row.get("workflow_base", "") or row.get("workflow_tag", ""))
            op_id = str(row.get("operation_id", "")).strip()
            proposal_id = str(row.get("proposal_id", "")).strip()
            register_ref(op_to_run, op_id, (rid, wf))
            register_ref(proposal_to_run, proposal_id, (rid, wf))
            if op_id and wf:
                event_workflow_hints[(rid, op_id)] = wf
            if proposal_id and wf:
                event_workflow_hints[(rid, proposal_id)] = wf

        keep_events = {
            "tx_submit_started",
            "tx_submitted",
            "tx_committed",
            "tx_failed",
            "cc_event_observed",
        }
        for metric_path in metric_paths:
            if not metric_path.exists():
                continue
            try:
                with open(metric_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            event = json.loads(line)
                        except Exception:
                            continue
                        ev_name = str(event.get("event", "")).strip()
                        if ev_name not in keep_events:
                            continue

                        tx_events_total += 1
                        op_id = first_non_empty(event, ["operation_id", "operationId"])
                        proposal_id = first_non_empty(event, ["proposal_id", "proposalId", "proposalID"])
                        matched_run = ""
                        mapped_workflow = ""
                        mapping_mode = ""

                        if op_id:
                            ref = op_to_run.get(op_id)
                            if ref and ref[0]:
                                matched_run, mapped_workflow = ref
                                mapping_mode = "operation_id"
                        if not matched_run and proposal_id:
                            ref = proposal_to_run.get(proposal_id)
                            if ref and ref[0]:
                                matched_run, mapped_workflow = ref
                                mapping_mode = "proposal_id"

                        ev_ts = parse_iso_ts(event.get("ts"))
                        if not matched_run and ev_ts is not None:
                            for rid, started, ended in run_windows:
                                if started <= ev_ts <= ended:
                                    matched_run = rid
                                    mapping_mode = "timestamp_window"
                                    break

                        if matched_run and not mapped_workflow:
                            if op_id:
                                mapped_workflow = event_workflow_hints.get((matched_run, op_id), "")
                            if (not mapped_workflow) and proposal_id:
                                mapped_workflow = event_workflow_hints.get((matched_run, proposal_id), "")
                        if not mapped_workflow:
                            mapped_workflow = canonical_workflow_name(first_non_empty(event, ["workflow", "workflow_base"]))

                        if not matched_run:
                            tx_events_unmapped += 1
                            tx_events_unmapped_policy_triggered = True
                            if args.tx_event_unmapped_policy in {"drop", "fail"}:
                                continue
                        else:
                            tx_events_mapped += 1
                            if ev_name == "tx_committed":
                                tx_events_mapped_committed += 1

                        merged = {
                            "run_id": matched_run,
                            "workflow_base": mapped_workflow,
                            "event_mapping_mode": mapping_mode if mapping_mode else "unmapped",
                        }
                        merged.update(event)
                        union_fields(tx_event_fields, list(merged.keys()))
                        tx_event_rows.append(merged)

                        if matched_run in run_tx_event_stats:
                            run_tx_event_stats[matched_run]["tx_events_total"] += 1
                            run_tx_event_stats[matched_run]["tx_events_mapped"] += 1
                            if ev_name == "tx_committed":
                                run_tx_event_stats[matched_run]["tx_events_mapped_committed"] += 1
                            run_tx_event_stats[matched_run]["tx_events_mapping_mode"] = tx_events_mapping_mode
            except Exception:
                continue

    for run_manifest in run_manifests:
        rid = run_manifest.get("run_id", "")
        stats = run_tx_event_stats.get(rid, {})
        run_manifest.setdefault("measurement", {})
        run_manifest["measurement"]["tx_events_total"] = stats.get("tx_events_total", 0)
        run_manifest["measurement"]["tx_events_mapped"] = stats.get("tx_events_mapped", 0)
        run_manifest["measurement"]["tx_events_unmapped"] = max(
            stats.get("tx_events_total", 0)-stats.get("tx_events_mapped", 0),
            0,
        )
        run_manifest["measurement"]["tx_events_mapped_committed"] = stats.get("tx_events_mapped_committed", 0)
        run_manifest["measurement"]["tx_events_mapping_mode"] = stats.get("tx_events_mapping_mode", tx_events_mapping_mode)
        # Backward-compatible manifest alias.
        run_manifest["measurement_v2"] = dict(run_manifest["measurement"])

    aggregate_outputs = {}

    resources_all_runs_path = outroot / "suite_resources_summary_all_runs.csv"
    if resources_summary_rows:
        write_csv_rows(resources_all_runs_path, resources_summary_fields, resources_summary_rows)
        aggregate_outputs["suite_resources_summary_all_runs"] = str(resources_all_runs_path)
        avg_fields, avg_rows = aggregate_rows(
            resources_summary_rows,
            group_keys=["workflow"],
            excluded_numeric={"run_id", "ts_start", "ts_end"},
        )
        resources_avg_path = outroot / "suite_resources_summary_averages.csv"
        write_csv_rows(resources_avg_path, avg_fields, avg_rows)
        aggregate_outputs["suite_resources_summary_averages"] = str(resources_avg_path)

    storage_all_runs_path = outroot / "suite_storage_deltas_all_runs.csv"
    if storage_rows:
        write_csv_rows(storage_all_runs_path, storage_fields, storage_rows)
        aggregate_outputs["suite_storage_deltas_all_runs"] = str(storage_all_runs_path)
        storage_avg_fields, storage_avg_rows = aggregate_rows(
            storage_rows,
            group_keys=["workflow", "path"],
            excluded_numeric={"run_id", "ts_start", "ts_end", "proposal_id"},
        )
        storage_avg_path = outroot / "suite_storage_deltas_averages.csv"
        write_csv_rows(storage_avg_path, storage_avg_fields, storage_avg_rows)
        aggregate_outputs["suite_storage_deltas_averages"] = str(storage_avg_path)

    storage_stage_all_runs_path = outroot / "suite_storage_stage_deltas_all_runs.csv"
    if storage_stage_rows:
        write_csv_rows(storage_stage_all_runs_path, storage_stage_fields, storage_stage_rows)
        aggregate_outputs["suite_storage_stage_deltas_all_runs"] = str(storage_stage_all_runs_path)
        storage_stage_avg_fields, storage_stage_avg_rows = aggregate_rows(
            storage_stage_rows,
            group_keys=["workflow", "stage_start", "stage_end", "path"],
            excluded_numeric={
                "run_id",
                "ts_start",
                "ts_end",
                "proposal_id",
                "operation_id",
                "workflow_tag",
                "epoch",
            },
        )
        storage_stage_avg_path = outroot / "suite_storage_stage_deltas_averages.csv"
        write_csv_rows(storage_stage_avg_path, storage_stage_avg_fields, storage_stage_avg_rows)
        aggregate_outputs["suite_storage_stage_deltas_averages"] = str(storage_stage_avg_path)

    storage_stage_volume_all_runs_path = outroot / "suite_storage_stage_volume_deltas_all_runs.csv"
    if storage_stage_volume_rows:
        write_csv_rows(storage_stage_volume_all_runs_path, storage_stage_volume_fields, storage_stage_volume_rows)
        aggregate_outputs["suite_storage_stage_volume_deltas_all_runs"] = str(storage_stage_volume_all_runs_path)

    storage_stage_topk_all_runs_path = outroot / "suite_storage_stage_topk_volumes_all_runs.csv"
    if storage_stage_topk_rows:
        write_csv_rows(storage_stage_topk_all_runs_path, storage_stage_topk_fields, storage_stage_topk_rows)
        aggregate_outputs["suite_storage_stage_topk_volumes_all_runs"] = str(storage_stage_topk_all_runs_path)

    storage_stage_peer_store_all_runs_path = outroot / "suite_storage_stage_peer_ledger_deltas_all_runs.csv"
    if storage_stage_peer_store_rows:
        write_csv_rows(
            storage_stage_peer_store_all_runs_path,
            storage_stage_peer_store_fields,
            storage_stage_peer_store_rows,
        )
        aggregate_outputs["suite_storage_stage_peer_ledger_deltas_all_runs"] = str(
            storage_stage_peer_store_all_runs_path
        )

    phase_all_runs_path = outroot / "suite_phase_summary_all_runs.csv"
    if phase_rows:
        write_csv_rows(phase_all_runs_path, phase_fields, phase_rows)
        aggregate_outputs["suite_phase_summary_all_runs"] = str(phase_all_runs_path)
        phase_avg_fields, phase_avg_rows = aggregate_rows(
            phase_rows,
            group_keys=["workflow", "phase"],
            excluded_numeric={"run_id", "phase_start_ts", "phase_end_ts"},
        )
        phase_avg_path = outroot / "suite_phase_summary_averages.csv"
        write_csv_rows(phase_avg_path, phase_avg_fields, phase_avg_rows)
        aggregate_outputs["suite_phase_summary_averages"] = str(phase_avg_path)

    labeled_all_runs_path = outroot / "suite_resources_labeled_all_runs.csv"
    if labeled_rows and args.artifact_profile == "full":
        write_csv_rows(labeled_all_runs_path, labeled_fields, labeled_rows)
        aggregate_outputs["suite_resources_labeled_all_runs"] = str(labeled_all_runs_path)

    workflow_runs_all_path = outroot / SUITE_WORKFLOW_RUNS_CANONICAL_FILE
    workflow_runs_legacy_all_path = outroot / SUITE_WORKFLOW_RUNS_LEGACY_FILE
    if workflow_runs_rows:
        for row in workflow_runs_rows:
            base = row.get("workflow_base", "")
            if not str(base).strip():
                base = canonical_workflow_name(row.get("workflow_tag", "") or row.get("workflow", ""))
            row["workflow_base"] = base
        write_csv_with_legacy_alias(
            workflow_runs_all_path,
            workflow_runs_legacy_all_path,
            workflow_runs_fields,
            workflow_runs_rows,
        )
        aggregate_outputs["suite_workflow_runs_all"] = str(workflow_runs_all_path)
        aggregate_outputs["suite_workflow_runs_v2_all"] = str(workflow_runs_legacy_all_path)

        latency_rows = []
        for row in workflow_runs_rows:
            workflow_base = canonical_workflow_name(row.get("workflow_base", ""))
            if not workflow_base:
                continue
            components = derive_latency_components(row, mixed_epsilon_seconds=MIXED_EPSILON_SECONDS)

            latency_rows.append(
                {
                    "run_id": row.get("run_id", ""),
                    "workflow_base": workflow_base,
                    "client_duration_s": components.get("client_duration_s"),
                    "client_to_submitted_s": components.get("client_to_submitted_s"),
                    "submit_to_vote_s": components.get("submit_to_vote_s"),
                    "vote_to_approved_s": components.get("vote_to_approved_s"),
                    "approved_to_cert_registered_s": components.get("approved_to_cert_registered_s"),
                    "approved_to_reshare_start_s": components.get("approved_to_reshare_start_s"),
                    "approved_to_reshare_completed_s": components.get("approved_to_reshare_completed_s"),
                    "reshare_duration_s": components.get("reshare_duration_s"),
                    "post_reshare_tail_s": components.get("post_reshare_tail_s"),
                    "blockchain_total_s": components.get("blockchain_total_s"),
                    "tss_reshare_total_s": components.get("tss_reshare_total_s"),
                    "tss_total_s": components.get("tss_total_s"),
                    "decomposed_total_s": components.get("decomposed_total_s"),
                    "decomposition_gap_s": components.get("decomposition_gap_s"),
                    "mixed_transition_s": components.get("mixed_transition_s"),
                    "overlap_correction_s": components.get("overlap_correction_s"),
                    "explained_total_s": components.get("explained_total_s"),
                }
            )
        latency_avg_fields, latency_avg_rows = aggregate_rows(
            latency_rows,
            group_keys=["workflow_base"],
            excluded_numeric={"run_id"},
        )
        latency_avg_path = outroot / SUITE_WORKFLOW_LATENCY_CANONICAL_FILE
        latency_avg_legacy_path = outroot / SUITE_WORKFLOW_LATENCY_LEGACY_FILE
        write_csv_with_legacy_alias(latency_avg_path, latency_avg_legacy_path, latency_avg_fields, latency_avg_rows)
        aggregate_outputs["suite_workflow_latency_averages"] = str(latency_avg_path)
        aggregate_outputs["suite_workflow_latency_v2_averages"] = str(latency_avg_legacy_path)

    messages_all_runs_path = outroot / "suite_message_counts_all_runs.csv"
    if message_rows:
        for row in message_rows:
            base = row.get("workflow_base", "")
            if not str(base).strip():
                base = canonical_workflow_name(row.get("workflow", ""))
            row["workflow_base"] = base
        union_fields(message_fields, ["workflow_base"])
        write_csv_rows(messages_all_runs_path, message_fields, message_rows)
        aggregate_outputs["suite_message_counts_all_runs"] = str(messages_all_runs_path)
        msg_avg_fields, msg_avg_rows = aggregate_rows(
            message_rows,
            group_keys=["workflow_base"],
            excluded_numeric={"run_id", "ts_start", "ts_end", "proposal_id", "workflow", "workflow_base"},
        )
        msg_avg_path = outroot / "suite_message_counts_averages.csv"
        write_csv_rows(msg_avg_path, msg_avg_fields, msg_avg_rows)
        aggregate_outputs["suite_message_counts_averages"] = str(msg_avg_path)

    tx_events_all_path = outroot / "suite_tx_events_all_runs.csv"
    if tx_event_rows:
        write_csv_rows(tx_events_all_path, tx_event_fields, tx_event_rows)
        aggregate_outputs["suite_tx_events_all_runs"] = str(tx_events_all_path)

        tx_block_size_fields, tx_block_size_rows = extract_tx_block_size_rows(tx_event_rows)
        if tx_block_size_rows:
            tx_block_sizes_all_path = outroot / "suite_tx_block_sizes_all_runs.csv"
            write_csv_rows(tx_block_sizes_all_path, tx_block_size_fields, tx_block_size_rows)
            aggregate_outputs["suite_tx_block_sizes_all_runs"] = str(tx_block_sizes_all_path)
            tx_block_size_row_count = len(tx_block_size_rows)

    query_all_runs_path = outroot / "suite_query_bench_all_runs.csv"
    if query_iter_rows:
        write_csv_rows(query_all_runs_path, query_iter_fields, query_iter_rows)
        aggregate_outputs["suite_query_bench_all_runs"] = str(query_all_runs_path)

    query_avg_path = outroot / "suite_query_bench_averages.csv"
    query_metric_rows = []
    if query_iter_rows:
        metric_cols = [
            "status_ms",
            "merkle_root_ms",
            "merkle_proof_ms",
            "proof_verify_ms",
            "end_to_end_ms",
        ]
        for row in query_iter_rows:
            run_id = str(row.get("run_id", ""))
            for metric in metric_cols:
                val = row.get(metric, "")
                if to_float(val) is None:
                    continue
                query_metric_rows.append(
                    {
                        "run_id": run_id,
                        "metric": metric,
                        "latency_ms": val,
                    }
                )
    if query_metric_rows:
        q_avg_fields, q_avg_rows = aggregate_rows(
            query_metric_rows,
            group_keys=["metric"],
            excluded_numeric={"run_id"},
        )
        write_csv_rows(query_avg_path, q_avg_fields, q_avg_rows)
        aggregate_outputs["suite_query_bench_averages"] = str(query_avg_path)
    elif query_summary_rows:
        q_avg_fields, q_avg_rows = aggregate_rows(
            query_summary_rows,
            group_keys=["metric"],
            excluded_numeric={"run_id"},
        )
        write_csv_rows(query_avg_path, q_avg_fields, q_avg_rows)
        aggregate_outputs["suite_query_bench_averages"] = str(query_avg_path)

    storage_modes = []
    resolved_storage_paths = set()
    component_rules_effective = []
    per_run_storage_coverage = {}
    for run_manifest in run_manifests:
        run_id = run_manifest.get("run_id", "")
        sm = run_manifest.get("storage_measurement", {}) if isinstance(run_manifest, dict) else {}
        mode = str(sm.get("storage_source_mode", "")).strip()
        if mode:
            storage_modes.append(mode)
        for p in sm.get("resolved_storage_paths", []) or []:
            if str(p).strip():
                resolved_storage_paths.add(str(p).strip())
        rules = sm.get("storage_component_rules_effective", []) or []
        for rule in rules:
            if rule not in component_rules_effective:
                component_rules_effective.append(rule)
        per_run_storage_coverage[run_id] = {
            "storage_rows": sm.get("storage_rows", 0),
            "paths_recorded": sm.get("paths_recorded", []),
            "rows_per_path": sm.get("rows_per_path", {}),
            "component_split_populated": bool(sm.get("component_split_populated", False)),
            "storage_stage_rows": sm.get("storage_stage_rows", {}),
        }
    if storage_modes:
        if len(set(storage_modes)) == 1:
            suite_storage_mode = storage_modes[0]
        else:
            suite_storage_mode = "mixed"
    else:
        suite_storage_mode = "disabled"

    measurement_quality_failures = []
    if args.strict_measurement_quality and args.query_bench and query_steps_failed > 0:
        measurement_quality_failures.append("query_benchmark_failed")
    if (
        measurement_enabled
        and args.strict_measurement_quality
        and args.tx_event_unmapped_policy == "fail"
        and tx_events_unmapped_policy_triggered
        and tx_events_unmapped > 0
    ):
        measurement_quality_failures.append("tx_event_unmapped_policy_fail")
    if measurement_enabled and args.strict_measurement_quality and tx_events_mapped_committed == 0:
        measurement_quality_failures.append("mapped_committed_tx_coverage_zero")

    if (
        measurement_enabled
        and args.tx_event_unmapped_policy == "warn"
        and tx_events_unmapped > 0
    ):
        print(
            f"Warning: {tx_events_unmapped} tx-event rows could not be mapped to benchmark operations; "
            "continuing because --tx-event-unmapped-policy=warn."
        )

    any_failures = (
        workflow_steps_failed > 0
        or labeling_steps_failed > 0
        or len(measurement_quality_failures) > 0
    )
    for run_manifest in run_manifests:
        rid = run_manifest.get("run_id", "")
        stats = run_tx_event_stats.get(rid, {})
        run_quality_failures = []
        if args.strict_measurement_quality and args.query_bench:
            if str(run_manifest.get("query_benchmark", {}).get("status", "")).strip().lower() == "failed":
                run_quality_failures.append("query_benchmark_failed")
        if measurement_enabled and args.strict_measurement_quality:
            if int(stats.get("tx_events_mapped_committed", 0)) == 0:
                run_quality_failures.append("mapped_committed_tx_coverage_zero")
        run_manifest["measurement_quality"] = {
            "strict": bool(args.strict_measurement_quality),
            "failures": run_quality_failures,
            "ok": len(run_quality_failures) == 0,
        }
        run_manifest_path = Path(run_manifest["paths"]["run_dir"]) / "manifest.json"
        with open(run_manifest_path, "w", encoding="utf-8") as f:
            json.dump(run_manifest, f, indent=2)

    artifact_retention = {
        "profile": args.artifact_profile,
        "files_removed": 0,
        "bytes_freed": 0,
        "run_dirs_removed": 0,
    }
    if args.artifact_profile != "full":
        for run_manifest in run_manifests:
            profile_result = apply_run_artifact_profile(run_manifest, args.artifact_profile)
            run_manifest.setdefault("artifact_profile", {})
            run_manifest["artifact_profile"]["selected"] = args.artifact_profile
            run_manifest["artifact_profile"]["files_removed"] = int(profile_result.get("files_removed", 0))
            run_manifest["artifact_profile"]["bytes_freed"] = int(profile_result.get("bytes_freed", 0))
            run_manifest["artifact_profile"]["run_dir_removed"] = bool(profile_result.get("run_dir_removed", False))
            artifact_retention["files_removed"] += int(profile_result.get("files_removed", 0))
            artifact_retention["bytes_freed"] += int(profile_result.get("bytes_freed", 0))
            if profile_result.get("run_dir_removed"):
                artifact_retention["run_dirs_removed"] += 1
            if not profile_result.get("run_dir_removed"):
                run_manifest_path = Path(run_manifest["paths"]["run_dir"]) / "manifest.json"
                with open(run_manifest_path, "w", encoding="utf-8") as f:
                    json.dump(run_manifest, f, indent=2)

    run_manifest_paths = [str(Path(r["paths"]["run_dir"]) / "manifest.json") for r in run_manifests]
    if args.artifact_profile == "ultra":
        run_manifest_paths = []

    suite_manifest = {
        "started_at": suite_started_at,
        "ended_at": utc_now_iso(),
        "config": {
            "api": args.api,
            "runs_requested": args.runs,
            "runs_executed": len(run_manifests),
            "workflows": workflows,
            "member_id": args.member_id,
            "inter_workflow_sleep": args.inter_workflow_sleep,
            "continue_on_error": args.continue_on_error,
            "artifact_profile": args.artifact_profile,
            "metrics": [str(p) for p in metric_paths],
            "run_workflows_pass_through": {
                "reason": args.reason,
                "timeout": args.timeout,
                "poll": args.poll,
                "no_wait": args.no_wait,
                "cn": args.cn,
                "o": args.o,
                "l": args.l,
                "st": args.st,
                "c": args.c,
                "measure": args.measure,
                "collect_resources": args.collect_resources,
                "collect_messages": args.collect_messages,
                "phase_tags": args.phase_tags,
                "peer_metrics_url": args.peer_metrics_url,
                "peer_metrics_prefix": args.peer_metrics_prefix,
                "storage_path": args.storage_path,
                "storage_component": args.storage_component,
                "storage_slices": args.storage_slices,
                "storage_topk": args.storage_topk,
                "resources_interval": args.resources_interval,
                "resources_iface": args.resources_iface,
                "no_resources_control_subtract": args.no_resources_control_subtract,
                "resources_control_exclude_port": args.resources_control_exclude_port,
                "measurement": measurement_enabled,
                "measurement_v2": args.measurement_v2,
                "operation_id": args.operation_id,
                "artifact_profile": args.artifact_profile,
                "query_bench": args.query_bench,
                "query_iters": args.query_iters,
                "query_warmup": args.query_warmup,
                "query_timeout": args.query_timeout,
                "query_cert_source": args.query_cert_source,
                "query_cert_id": args.query_cert_id,
                "strict_measurement_quality": args.strict_measurement_quality,
                "tx_event_unmapped_policy": args.tx_event_unmapped_policy,
                "tx_event_window_skew_sec": args.tx_event_window_skew_sec,
                "gossip_convergence_timeout": args.gossip_convergence_timeout,
                "gossip_convergence_poll": args.gossip_convergence_poll,
            },
        },
        "storage_measurement": {
            "storage_source_mode": suite_storage_mode,
            "resolved_storage_paths": sorted(resolved_storage_paths),
            "storage_component_rules_effective": component_rules_effective,
            "storage_slices_enabled": bool(args.storage_slices),
            "storage_topk": args.storage_topk,
            "per_run_coverage": per_run_storage_coverage,
        },
        "workflow_steps": {
            "succeeded": workflow_steps_succeeded,
            "failed": workflow_steps_failed,
            "total": workflow_steps_succeeded + workflow_steps_failed,
        },
        "labeling_steps": {
            "succeeded": labeling_steps_succeeded,
            "failed": labeling_steps_failed,
            "total": labeling_steps_succeeded + labeling_steps_failed,
        },
        "any_failures": any_failures,
        "measurement": {
            "enabled": measurement_enabled,
            "event_primary": measurement_enabled,
            "fallback_mode": "poll_fallback",
            "workflow_runs_rows": len(workflow_runs_rows),
            "tx_event_rows": len(tx_event_rows),
            "tx_block_size_rows": tx_block_size_row_count,
            "tx_events_total": tx_events_total,
            "tx_events_mapped": tx_events_mapped,
            "tx_events_unmapped": tx_events_unmapped,
            "tx_events_mapped_committed": tx_events_mapped_committed,
            "tx_events_mapping_mode": tx_events_mapping_mode,
            "tx_event_unmapped_policy": args.tx_event_unmapped_policy,
        },
        "communication_measurement": {
            "enabled": bool(args.collect_messages or args.peer_metrics_url),
            "suite_message_rows": len(message_rows),
        },
        "query_benchmark": {
            "enabled": bool(args.query_bench),
            "query_cert_source": args.query_cert_source,
            "requested_cert_id": str(args.query_cert_id or ""),
            "fallback_member_id": str(args.member_id or ""),
            "iterations_per_run": args.query_iters,
            "warmup_per_run": args.query_warmup,
            "timeout_s": args.query_timeout,
            "strict_measurement_quality": bool(args.strict_measurement_quality),
            "steps": {
                "succeeded": query_steps_succeeded,
                "failed": query_steps_failed,
                "skipped": query_steps_skipped,
                "total": query_steps_succeeded + query_steps_failed + query_steps_skipped,
            },
            "suite_query_iteration_rows": len(query_iter_rows),
            "suite_query_summary_rows": len(query_summary_rows),
        },
        "measurement_quality": {
            "strict": bool(args.strict_measurement_quality),
            "failures": measurement_quality_failures,
            "ok": len(measurement_quality_failures) == 0,
        },
        "artifact_retention": artifact_retention,
        "run_manifests": run_manifest_paths,
        "aggregate_outputs": aggregate_outputs,
    }
    suite_manifest["measurement_v2"] = {
        "enabled": measurement_enabled,
        "event_primary": measurement_enabled,
        "fallback_mode": suite_manifest["measurement"]["fallback_mode"],
        "workflow_runs_v2_rows": suite_manifest["measurement"]["workflow_runs_rows"],
        "tx_event_rows": suite_manifest["measurement"]["tx_event_rows"],
        "tx_block_size_rows": suite_manifest["measurement"]["tx_block_size_rows"],
        "tx_events_total": suite_manifest["measurement"]["tx_events_total"],
        "tx_events_mapped": suite_manifest["measurement"]["tx_events_mapped"],
        "tx_events_unmapped": suite_manifest["measurement"]["tx_events_unmapped"],
        "tx_events_mapped_committed": suite_manifest["measurement"]["tx_events_mapped_committed"],
        "tx_events_mapping_mode": suite_manifest["measurement"]["tx_events_mapping_mode"],
        "tx_event_unmapped_policy": suite_manifest["measurement"]["tx_event_unmapped_policy"],
    }
    suite_manifest_path = outroot / "suite_manifest.json"
    with open(suite_manifest_path, "w", encoding="utf-8") as f:
        json.dump(suite_manifest, f, indent=2)

    print(f"Suite manifest: {suite_manifest_path}")
    if aggregate_outputs:
        print("Aggregate outputs:")
        for key, value in aggregate_outputs.items():
            print(f"  {key}: {value}")
    if args.artifact_profile != "full":
        print(
            f"Artifact retention ({args.artifact_profile}): "
            f"files_removed={artifact_retention['files_removed']}, "
            f"bytes_freed={artifact_retention['bytes_freed']}, "
            f"run_dirs_removed={artifact_retention['run_dirs_removed']}"
        )

    return 1 if any_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
