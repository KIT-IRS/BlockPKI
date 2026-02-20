#!/usr/bin/env python3
import argparse
import csv
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
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


def http_json(method, url, body=None):
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


def http_text(url):
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


def wait_until(predicate, timeout_s, interval_s, label):
    start = time.time()
    while time.time() - start < timeout_s:
        if predicate():
            return True
        time.sleep(interval_s)
    print(f"Timeout waiting for {label}")
    return False


def ensure_outdir(path):
    if path:
        os.makedirs(path, exist_ok=True)


def dir_size(path):
    total = 0
    had_error = False

    def onerror(_):
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


def snapshot_storage(paths):
    snap = {}
    for p in paths:
        snap[p] = dir_size(p)
    return snap


def write_storage_deltas(out_path, rows):
    if not rows:
        return
    ensure_outdir(os.path.dirname(out_path))
    write_header = not os.path.exists(out_path)
    with open(out_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(
                ["ts_start", "ts_end", "workflow", "proposal_id", "path", "bytes_before", "bytes_after", "delta_bytes"]
            )
        writer.writerows(rows)


def write_message_counts(out_path, rows):
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


def parse_prom_metrics(raw):
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


def sum_metrics(metrics, prefixes):
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


def snapshot_peer_metrics(urls, prefixes):
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


def start_resource_sampler(args, tag):
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
    if args.phase_tags and phase_file:
        cmd += ["--phase-file", phase_file]
    proc = subprocess.Popen(cmd)
    return proc, out_path


def stop_resource_sampler(proc):
    if not proc:
        return
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        proc.kill()


def summarize_resources(outdir, tag, start_ts, end_ts, resource_path):
    if not resource_path or not os.path.exists(resource_path):
        return
    rows = []
    with open(resource_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    if not rows:
        return

    def agg(col):
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
                tag,
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


def main():
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
    parser.add_argument("--storage-out", default="", help="Storage delta CSV output path")
    parser.add_argument("--resources-out", default="", help="Resources CSV output path")
    parser.add_argument("--resources-interval", type=float, default=1.0, help="Resource sample interval (seconds)")
    parser.add_argument("--resources-iface", default="eth0", help="Network interface for RX/TX counters")
    args = parser.parse_args()

    base = args.api.rstrip("/")

    if args.measure and not args.storage_path:
        for p in ("/var/lib/docker/volumes", "/opt/fabric"):
            if os.path.exists(p):
                args.storage_path.append(p)
    if args.measure or args.collect_resources or args.collect_messages or args.peer_metrics_url:
        ensure_outdir(args.outdir)
    if args.measure and not args.storage_out:
        args.storage_out = os.path.join(args.outdir, "storage_deltas.csv")
    if (args.collect_messages or args.peer_metrics_url) and not args.messages_out:
        args.messages_out = os.path.join(args.outdir, "message_counts.csv")
    if args.phase_tags and not args.phase_file:
        args.phase_file = os.path.join(args.outdir, "operation_phase.txt")

    def get_ca():
        status, data = http_json("GET", base + "/api/ca")
        if status >= 400 or status == 0:
            raise RuntimeError(f"CA query failed: {data}")
        return data

    def get_keyinfo():
        status, data = http_json("GET", base + "/api/keyshare")
        if status >= 400 or status == 0:
            raise RuntimeError(f"Key info query failed: {data}")
        return data

    def get_p2p_stats(reset=False):
        q = "?reset=true" if reset else ""
        status, data = http_json("GET", base + "/api/metrics/p2p" + q)
        if status >= 400 or status == 0:
            return None
        return data if isinstance(data, dict) else None

    def get_certs():
        status, data = http_json("GET", base + "/api/certificates")
        if status >= 400 or status == 0:
            raise RuntimeError(f"Certificates query failed: {data}")
        return data if isinstance(data, list) else []

    def cert_id(cert):
        return cert.get("certId") or cert.get("proposalId") or ""

    def find_member_cert(member_id, proposal_id=None, existing_ids=None, issued_after=None):
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
        workflows = ["csr", "revocation", "join", "removal"]

    def set_phase(label):
        if not args.phase_tags or not args.phase_file:
            return
        try:
            with open(args.phase_file, "w", encoding="utf-8") as f:
                f.write(label)
        except Exception:
            pass

    for wf in workflows:
        op_tag = f"{wf}_{int(time.time())}"
        proposal_id = ""
        op_start_ts = datetime.utcnow().isoformat() + "Z"
        if args.phase_tags and args.phase_file:
            set_phase(f"{wf}_start")
        collect_messages = args.collect_messages or bool(args.peer_metrics_url)
        p2p_reset_ok = False
        p2p_stats_start = None
        if collect_messages:
            p2p_stats_start = get_p2p_stats(reset=True)
            p2p_reset_ok = p2p_stats_start is not None
        peer_metrics_before = snapshot_peer_metrics(args.peer_metrics_url, args.peer_metrics_prefix) if args.peer_metrics_url else None
        storage_before = snapshot_storage(args.storage_path) if args.measure else {}
        res_proc, res_path = start_resource_sampler(args, op_tag)
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
                    status, data = http_json("POST", base + "/api/csr/submit", body)
                    if status >= 400 or status == 0:
                        error = f"CSR submit failed: {data}"
                    else:
                        proposal_id = data.get("proposalId", "")
                        print(f"CSR submitted (proposal: {proposal_id}).")
                        if not args.no_wait:
                            set_phase("csr_wait_cert")
                            wait_until(
                                lambda: find_member_cert(member_id, proposal_id, existing_ids, start_dt) is not None,
                                args.timeout,
                                args.poll,
                                "certificate registration",
                            )
                    set_phase("csr_done")

            elif wf == "revocation":
                member_id = args.member_id
                if not member_id:
                    keyinfo = get_keyinfo()
                    member_id = keyinfo.get("memberId", "")
                if not member_id:
                    print("Skipping revocation (no --member-id provided and memberId unavailable).")
                else:
                    set_phase("revocation_propose")
                    status, data = http_json("POST", base + "/api/revoke", {"memberId": member_id, "reason": args.reason})
                    if status >= 400 or status == 0:
                        error = f"Revocation proposal failed: {data}"
                    else:
                        proposal_id = data.get("proposalId", "")
                        print(f"Revocation proposed: {proposal_id}")
                        if not args.no_wait:
                            set_phase("revocation_wait")
                            wait_until(
                                lambda: any(
                                    c.get("memberId") == member_id and c.get("isRevoked")
                                    for c in get_certs()
                                ),
                                args.timeout,
                                args.poll,
                                "certificate revocation",
                            )
                    set_phase("revocation_done")

            elif wf == "join":
                ca = get_ca()
                start_epoch = ca.get("epoch", 0)
                set_phase("join_request")
                status, data = http_json("POST", base + "/api/membership/request", {"reason": args.reason})
                if status >= 400 or status == 0:
                    error = f"Join request failed: {data}"
                else:
                    proposal_id = data.get("proposalId", "")
                    print(f"Join request submitted: {proposal_id}")
                    if not args.no_wait:
                        set_phase("join_wait_reshare")
                        wait_until(
                            lambda: (get_ca().get("epoch", 0) > start_epoch),
                            args.timeout,
                            args.poll,
                            "reshare completion",
                        )
                set_phase("join_done")

            elif wf == "removal":
                member_id = args.member_id
                if not member_id:
                    print("Skipping removal (provide --member-id to enable).")
                else:
                    ca = get_ca()
                    start_epoch = ca.get("epoch", 0)
                    set_phase("removal_propose")
                    status, data = http_json("POST", base + "/api/membership/remove", {"memberId": member_id, "reason": args.reason})
                    if status >= 400 or status == 0:
                        error = f"Removal proposal failed: {data}"
                    else:
                        proposal_id = data.get("proposalId", "")
                        print(f"Removal proposed: {proposal_id}")
                        if not args.no_wait:
                            set_phase("removal_wait_reshare")
                            wait_until(
                                lambda: (member_id not in (get_ca().get("members") or [])) and (get_ca().get("epoch", 0) > start_epoch),
                                args.timeout,
                                args.poll,
                                "member removal + reshare",
                            )
                    set_phase("removal_done")
        finally:
            op_end_ts = datetime.utcnow().isoformat() + "Z"
            stop_resource_sampler(res_proc)
            summarize_resources(args.outdir, op_tag, op_start_ts, op_end_ts, res_path)
            if args.measure:
                storage_after = snapshot_storage(args.storage_path)
                rows = []
                for path in args.storage_path:
                    before = storage_before.get(path)
                    after = storage_after.get(path)
                    delta = ""
                    if before is not None and after is not None:
                        delta = str(after - before)
                    rows.append(
                        [
                            op_start_ts,
                            op_end_ts,
                            wf,
                            proposal_id,
                            path,
                            "NA" if before is None else before,
                            "NA" if after is None else after,
                            delta,
                        ]
                    )
                write_storage_deltas(args.storage_out, rows)
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
        if error:
            print(error)
            sys.exit(1)

    print("Done.")


if __name__ == "__main__":
    main()
