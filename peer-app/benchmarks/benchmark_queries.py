#!/usr/bin/env python3
"""benchmark_queries.py measures query-path latency for certificate and Merkle APIs.

Runtime flow: executed standalone or from suite automation to produce per-iteration
and summarized latency CSV artifacts for status/root/proof/verification steps.
"""

import argparse
import csv
import hashlib
import json
import math
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime


# ensure_outdir creates the output directory when it does not exist.
# Lifecycle: Query benchmark artifact preparation.
# Called by: main.
# Triggered: once before writing iteration/summary CSV outputs.
def ensure_outdir(path):
    """ensure_outdir helper for benchmark tooling."""
    if path:
        os.makedirs(path, exist_ok=True)


# now_iso returns the current UTC timestamp in ISO-8601 format with `Z` suffix.
# Lifecycle: Query benchmark sampling.
# Called by: main.
# Triggered: for each measured iteration row that is persisted.
def now_iso():
    """now_iso helper for benchmark tooling."""
    return datetime.utcnow().isoformat() + "Z"


# http_get_json executes a GET request and returns status, JSON payload, error text, and payload byte size.
# Lifecycle: Query benchmark request execution.
# Called by: run_once.
# Triggered: for each status/root/proof API call in every benchmark iteration.
def http_get_json(url, timeout_s):
    """http_get_json helper for benchmark tooling."""
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            raw_bytes = resp.read() if resp.readable() else b""
            raw = raw_bytes.decode("utf-8")
            payload = json.loads(raw) if raw else {}
            return resp.status, payload, "", len(raw_bytes)
    except urllib.error.HTTPError as e:
        raw_bytes = e.read() if e.fp else b""
        raw = raw_bytes.decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw) if raw else {}
        except Exception:
            payload = {"error": raw or str(e)}
        return e.code, payload, str(e), len(raw_bytes)
    except Exception as e:
        return 0, {"error": str(e)}, str(e), 0


# as_bytes_hash normalizes a hash token into raw bytes (hex decode first, then SHA-256 fallback).
# Lifecycle: Query benchmark Merkle verification helper.
# Called by: verify_merkle_proof.
# Triggered: while reconstructing proof paths from API payload nodes.
def as_bytes_hash(token):
    """as_bytes_hash helper for benchmark tooling."""
    value = str(token or "").strip()
    if not value:
        return b""
    try:
        return bytes.fromhex(value)
    except Exception:
        return hashlib.sha256(value.encode("utf-8")).digest()


# verify_merkle_proof verifies the Merkle proof payload against a certificate hash.
# Lifecycle: Query benchmark quality validation.
# Called by: run_once.
# Triggered: after successful proof retrieval when Merkle mode is enabled.
def verify_merkle_proof(cert_hash, proof_payload):
    """verify_merkle_proof helper for benchmark tooling."""
    if not isinstance(proof_payload, dict):
        return False, "proof payload is not an object"
    root = str(proof_payload.get("merkleRoot", "")).strip().lower()
    if not root:
        return False, "missing merkleRoot"
    proof = proof_payload.get("proof", [])
    if proof is None:
        proof = []
    if not isinstance(proof, list):
        return False, "proof is not a list"

    current = as_bytes_hash(cert_hash)
    if not current:
        return False, "empty certificate hash"

    for node in proof:
        if not isinstance(node, dict):
            return False, "invalid proof node"
        sibling = as_bytes_hash(node.get("hash", ""))
        if not sibling:
            return False, "invalid proof sibling hash"
        position = str(node.get("position", "")).strip().lower()
        if position == "left":
            current = hashlib.sha256(sibling + current).digest()
        elif position == "right":
            current = hashlib.sha256(current + sibling).digest()
        else:
            return False, f"invalid proof position '{position}'"

    computed = current.hex().lower()
    return computed == root, ""


# best_effort_tree_size extracts a numeric tree-size field from mixed API payload variants.
# Lifecycle: Query benchmark payload normalization.
# Called by: run_once.
# Triggered: while collecting Merkle root metadata for each iteration.
def best_effort_tree_size(payload):
    """best_effort_tree_size helper for benchmark tooling."""
    if not isinstance(payload, dict):
        return ""
    for key in ("treeSize", "tree_size", "leafCount", "leaf_count", "size", "count"):
        val = payload.get(key)
        if val is None:
            continue
        try:
            num = int(float(val))
        except Exception:
            continue
        if num >= 0:
            return str(num)
    return ""


# percentile computes a linear-interpolated percentile for a numeric sample list.
# Lifecycle: Query benchmark statistics aggregation.
# Called by: summarize_metric.
# Triggered: when building p50/p95/p99 summary statistics.
def percentile(values, p):
    """percentile helper for benchmark tooling."""
    if not values:
        return None
    xs = sorted(values)
    if len(xs) == 1:
        return xs[0]
    rank = (len(xs) - 1) * (float(p) / 100.0)
    low = int(math.floor(rank))
    high = int(math.ceil(rank))
    if low == high:
        return xs[low]
    frac = rank - low
    return xs[low] + (xs[high] - xs[low]) * frac


# summarize_metric builds summary statistics for one latency metric.
# Lifecycle: Query benchmark statistics aggregation.
# Called by: main.
# Triggered: once per metric after measured iterations are collected.
def summarize_metric(values):
    """summarize_metric helper for benchmark tooling."""
    if not values:
        return {
            "count": 0,
            "mean_ms": "",
            "std_ms": "",
            "p50_ms": "",
            "p95_ms": "",
            "p99_ms": "",
            "min_ms": "",
            "max_ms": "",
        }
    count = len(values)
    mean = sum(values) / count
    variance = sum((v - mean) ** 2 for v in values) / count
    std = math.sqrt(variance)
    return {
        "count": count,
        "mean_ms": f"{mean:.6f}",
        "std_ms": f"{std:.6f}",
        "p50_ms": f"{percentile(values, 50):.6f}",
        "p95_ms": f"{percentile(values, 95):.6f}",
        "p99_ms": f"{percentile(values, 99):.6f}",
        "min_ms": f"{min(values):.6f}",
        "max_ms": f"{max(values):.6f}",
    }


# run_once executes one full status/root/proof/verification benchmark cycle.
# Lifecycle: Query benchmark iteration execution.
# Called by: main.
# Triggered: for each warmup and measured iteration requested by CLI options.
def run_once(base_api, cert_id, timeout_s):
    """run_once helper for benchmark tooling."""
    row = {
        "status_ms": "",
        "merkle_root_ms": "",
        "merkle_proof_ms": "",
        "proof_verify_ms": "",
        "end_to_end_ms": "",
        "merkle_enabled": "",
        "http_status_status": "",
        "http_status_merkle_root": "",
        "http_status_merkle_proof": "",
        "status_ok": "false",
        "merkle_root_ok": "false",
        "merkle_proof_ok": "false",
        "proof_verify_ok": "false",
        "error": "",
        "certificateHash": "",
        "merkleRoot": "",
        "proof_nodes": "",
        "merkle_tree_size": "",
        "merkle_root_payload_bytes": "",
        "merkle_proof_payload_bytes": "",
        "merkle_proof_only_bytes": "",
        "quality_ok": "false",
        "quality_reason": "",
    }

    started = time.perf_counter()
    encoded_id = urllib.parse.quote(cert_id, safe="")
    status_url = f"{base_api}/api/certificate/status?id={encoded_id}"
    t0 = time.perf_counter()
    code_status, payload_status, err_status, _ = http_get_json(status_url, timeout_s)
    t1 = time.perf_counter()
    row["status_ms"] = f"{(t1 - t0) * 1000.0:.6f}"
    row["http_status_status"] = str(code_status)
    if 200 <= code_status < 300:
        row["status_ok"] = "true"
        cert_hash = str(payload_status.get("certificateHash", "")).strip()
        row["certificateHash"] = cert_hash
    else:
        cert_hash = ""
        row["error"] = f"status query failed: {payload_status if payload_status else err_status}"

    merkle_url = f"{base_api}/api/merkle"
    t2 = time.perf_counter()
    code_root, payload_root, err_root, root_payload_bytes = http_get_json(merkle_url, timeout_s)
    t3 = time.perf_counter()
    row["merkle_root_ms"] = f"{(t3 - t2) * 1000.0:.6f}"
    row["http_status_merkle_root"] = str(code_root)
    row["merkle_root_payload_bytes"] = str(root_payload_bytes)
    merkle_enabled = True
    if 200 <= code_root < 300:
        if isinstance(payload_root, dict) and ("enabled" in payload_root):
            try:
                merkle_enabled = bool(payload_root.get("enabled"))
            except Exception:
                merkle_enabled = True
        row["merkle_enabled"] = "true" if merkle_enabled else "false"
        root = str(payload_root.get("merkleRoot", "")).strip()
        row["merkleRoot"] = root
        row["merkle_tree_size"] = best_effort_tree_size(payload_root)
        row["merkle_root_ok"] = "true" if (root or not merkle_enabled) else "false"
    else:
        root = ""
        row["merkle_enabled"] = ""
        if not row["error"]:
            row["error"] = f"merkle root query failed: {payload_root if payload_root else err_root}"

    if cert_hash and merkle_enabled:
        encoded_hash = urllib.parse.quote(cert_hash, safe="")
        proof_url = f"{base_api}/api/merkle/proof?hash={encoded_hash}"
        t4 = time.perf_counter()
        code_proof, payload_proof, err_proof, proof_payload_bytes = http_get_json(proof_url, timeout_s)
        t5 = time.perf_counter()
        row["merkle_proof_ms"] = f"{(t5 - t4) * 1000.0:.6f}"
        row["http_status_merkle_proof"] = str(code_proof)
        row["merkle_proof_payload_bytes"] = str(proof_payload_bytes)
        if 200 <= code_proof < 300 and isinstance(payload_proof, dict):
            row["merkle_proof_ok"] = "true"
            proof_nodes = payload_proof.get("proof", [])
            if isinstance(proof_nodes, list):
                row["proof_nodes"] = str(len(proof_nodes))
            try:
                proof_only = json.dumps(payload_proof.get("proof", []), separators=(",", ":"), sort_keys=True)
                row["merkle_proof_only_bytes"] = str(len(proof_only.encode("utf-8")))
            except Exception:
                row["merkle_proof_only_bytes"] = ""
            t6 = time.perf_counter()
            verified, verify_err = verify_merkle_proof(cert_hash, payload_proof)
            t7 = time.perf_counter()
            row["proof_verify_ms"] = f"{(t7 - t6) * 1000.0:.6f}"
            row["proof_verify_ok"] = "true" if verified else "false"
            if (not verified) and (not row["error"]):
                row["error"] = f"proof verification failed: {verify_err}"
        else:
            row["merkle_proof_ok"] = "false"
            if not row["error"]:
                row["error"] = f"merkle proof query failed: {payload_proof if payload_proof else err_proof}"
    else:
        row["http_status_merkle_proof"] = ""
        if not merkle_enabled:
            row["merkle_proof_ok"] = "true"
            row["proof_verify_ok"] = "true"
        elif not row["error"]:
            row["error"] = "certificateHash missing from status endpoint response"

    ended = time.perf_counter()
    row["end_to_end_ms"] = f"{(ended - started) * 1000.0:.6f}"
    quality_reasons = []
    if row.get("status_ok") != "true":
        quality_reasons.append("status_not_success")
    if merkle_enabled and row.get("merkle_root_ok") != "true":
        quality_reasons.append("merkle_root_not_success")
    if cert_hash and merkle_enabled and row.get("merkle_proof_ok") != "true":
        quality_reasons.append("merkle_proof_not_success")
    if cert_hash and merkle_enabled and row.get("proof_verify_ok") != "true":
        quality_reasons.append("proof_verify_not_success")
    if quality_reasons:
        row["quality_ok"] = "false"
        row["quality_reason"] = ";".join(quality_reasons)
    else:
        row["quality_ok"] = "true"
        row["quality_reason"] = ""
    return row


# main parses CLI arguments, runs benchmark iterations, and writes CSV outputs.
# Lifecycle: Query benchmark orchestration entrypoint.
# Called by: module entrypoint (`if __name__ == "__main__"`).
# Triggered: when the script is run directly or by suite orchestration.
def main():
    """main helper for benchmark tooling."""
    parser = argparse.ArgumentParser(description="Benchmark query latencies for cert status + Merkle APIs.")
    parser.add_argument("--api", default="http://127.0.0.1:8083", help="Base API URL (default: http://127.0.0.1:8083)")
    parser.add_argument("--cert-id", required=True, help="Certificate lookup ID (member ID or proposal/cert ID)")
    parser.add_argument("--iters", type=int, default=30, help="Measured iterations (default: 30)")
    parser.add_argument("--warmup", type=int, default=5, help="Warmup iterations excluded from outputs (default: 5)")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds (default: 10)")
    parser.add_argument("--outdir", default="benchmarks/out", help="Output directory")
    parser.add_argument("--run-id", default="", help="Optional run ID for suite integration")
    parser.add_argument(
        "--require-status-success",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Require successful /api/certificate/status responses across measured iterations (default: true)",
    )
    parser.add_argument(
        "--require-proof-success",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Require successful Merkle proof + local verification when certificateHash is present (default: true)",
    )
    args = parser.parse_args()

    if args.iters < 1:
        raise SystemExit("--iters must be >= 1")
    if args.warmup < 0:
        raise SystemExit("--warmup must be >= 0")
    if args.timeout <= 0:
        raise SystemExit("--timeout must be > 0")

    outdir = os.path.abspath(args.outdir)
    ensure_outdir(outdir)
    iter_path = os.path.join(outdir, "query_bench_iterations.csv")
    summary_path = os.path.join(outdir, "query_bench_summary.csv")

    base_api = str(args.api).rstrip("/")
    total_iters = args.warmup + args.iters
    measured = []
    for idx in range(total_iters):
        row = run_once(base_api, args.cert_id, args.timeout)
        if idx >= args.warmup:
            row["run_id"] = args.run_id
            row["iteration"] = str(idx - args.warmup + 1)
            row["ts"] = now_iso()
            measured.append(row)

    iter_fields = [
        "run_id",
        "iteration",
        "ts",
        "status_ms",
        "merkle_root_ms",
        "merkle_proof_ms",
        "proof_verify_ms",
        "end_to_end_ms",
        "merkle_enabled",
        "http_status_status",
        "http_status_merkle_root",
        "http_status_merkle_proof",
        "status_ok",
        "merkle_root_ok",
        "merkle_proof_ok",
        "proof_verify_ok",
        "error",
        "certificateHash",
        "merkleRoot",
        "proof_nodes",
        "merkle_tree_size",
        "merkle_root_payload_bytes",
        "merkle_proof_payload_bytes",
        "merkle_proof_only_bytes",
        "quality_ok",
        "quality_reason",
    ]
    with open(iter_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=iter_fields)
        writer.writeheader()
        for row in measured:
            writer.writerow({k: row.get(k, "") for k in iter_fields})

    metrics = [
        "status_ms",
        "merkle_root_ms",
        "merkle_proof_ms",
        "proof_verify_ms",
        "end_to_end_ms",
    ]
    summary_rows = []
    for metric in metrics:
        vals = []
        for row in measured:
            raw = str(row.get(metric, "")).strip()
            if not raw:
                continue
            try:
                vals.append(float(raw))
            except Exception:
                continue
        s = summarize_metric(vals)
        summary_rows.append(
            {
                "run_id": args.run_id,
                "metric": metric,
                **s,
            }
        )

    summary_fields = [
        "run_id",
        "metric",
        "count",
        "mean_ms",
        "std_ms",
        "p50_ms",
        "p95_ms",
        "p99_ms",
        "min_ms",
        "max_ms",
    ]
    with open(summary_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=summary_fields)
        writer.writeheader()
        for row in summary_rows:
            writer.writerow({k: row.get(k, "") for k in summary_fields})

    print(f"Wrote: {iter_path}")
    print(f"Wrote: {summary_path}")
    measured_count = len(measured)
    status_ok_count = sum(1 for row in measured if str(row.get("status_ok", "")).strip().lower() == "true")
    proof_required_count = sum(
        1
        for row in measured
        if str(row.get("certificateHash", "")).strip() != ""
        and str(row.get("merkle_enabled", "")).strip().lower() != "false"
    )
    proof_ok_count = sum(
        1
        for row in measured
        if str(row.get("merkle_proof_ok", "")).strip().lower() == "true"
        and str(row.get("proof_verify_ok", "")).strip().lower() == "true"
    )

    quality_errors = []
    if args.require_status_success and status_ok_count < measured_count:
        quality_errors.append(
            f"status success ratio {status_ok_count}/{measured_count} below required {measured_count}/{measured_count}"
        )
    if args.require_proof_success and proof_required_count > 0 and proof_ok_count < proof_required_count:
        quality_errors.append(
            f"proof success ratio {proof_ok_count}/{proof_required_count} below required {proof_required_count}/{proof_required_count}"
        )
    if args.require_proof_success and proof_required_count == 0:
        quality_errors.append("no proof-required iterations observed (missing certificateHash or Merkle disabled)")

    if quality_errors:
        for msg in quality_errors:
            print(f"QUALITY ERROR: {msg}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
