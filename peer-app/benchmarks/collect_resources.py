#!/usr/bin/env python3
"""collect_resources.py samples host/network/process resource usage during workflows.

Runtime flow: launched as a background sampler by workflow benchmarks to emit
time-series CSV rows with host metrics, process-group utilization, and adjusted
traffic counters.
"""

import argparse
import csv
import os
import re
import subprocess
import time
from datetime import datetime


DEFAULT_PROC_MATCH = {
    "tss": r"tss_peer",
    "peer": r"peer node start",
    "orderer": r"orderer",
}


# read_cpu_times reads total and idle CPU jiffies from `/proc/stat`.
# Lifecycle: Live resource sampling loop.
# Called by: main.
# Triggered: on each sampling tick to compute host CPU utilization.
def read_cpu_times():
    """read_cpu_times helper for benchmark tooling."""
    with open("/proc/stat", "r", encoding="utf-8") as f:
        parts = f.readline().strip().split()
    # cpu user nice system idle iowait irq softirq steal guest guest_nice
    values = [int(p) for p in parts[1:]]
    idle = values[3] + values[4]
    total = sum(values)
    return total, idle


# read_mem_usage computes host memory usage percent from `/proc/meminfo`.
# Lifecycle: Live resource sampling loop.
# Called by: main.
# Triggered: on each sampling tick while writing a resource row.
def read_mem_usage():
    """read_mem_usage helper for benchmark tooling."""
    total = 0
    available = 0
    with open("/proc/meminfo", "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("MemTotal:"):
                total = int(line.split()[1])
            elif line.startswith("MemAvailable:"):
                available = int(line.split()[1])
    if total == 0:
        return 0.0
    used = total - available
    return (used / total) * 100.0


# read_mem_total_bytes returns host total memory in bytes.
# Lifecycle: Sampler initialization.
# Called by: main.
# Triggered: once at startup to normalize process memory percentages.
def read_mem_total_bytes():
    """read_mem_total_bytes helper for benchmark tooling."""
    with open("/proc/meminfo", "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    return 0


# read_net_bytes returns interface RX/TX byte counters from `/proc/net/dev`.
# Lifecycle: Live resource sampling loop.
# Called by: main.
# Triggered: on each sampling tick to compute interval and delta traffic.
def read_net_bytes(iface):
    """read_net_bytes helper for benchmark tooling."""
    with open("/proc/net/dev", "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or ":" not in line:
                continue
            name, data = line.split(":", 1)
            name = name.strip()
            if name == iface:
                fields = data.split()
                rx = int(fields[0])
                tx = int(fields[8])
                return rx, tx
    return 0, 0


# parse_endpoint_port extracts a TCP port from an endpoint token.
# Lifecycle: Control-plane traffic subtraction helper.
# Called by: sample_control_tcp_bytes_ss.
# Triggered: while parsing `ss` endpoint columns for monitored ports.
def parse_endpoint_port(token):
    """parse_endpoint_port helper for benchmark tooling."""
    text = str(token or "").strip()
    if not text or text in {"*", "-", ""}:
        return None
    port_token = ""
    if text.startswith("[") and "]" in text:
        idx = text.rfind("]")
        if idx >= 0 and idx + 1 < len(text) and text[idx + 1] == ":":
            port_token = text[idx + 2 :]
    else:
        if ":" in text:
            port_token = text.rsplit(":", 1)[-1]
    if not port_token:
        return None
    try:
        port = int(port_token)
    except Exception:
        return None
    if port <= 0 or port > 65535:
        return None
    return port


_RE_BYTES_RECEIVED = re.compile(r"bytes_received:(\d+)")
_RE_BYTES_ACKED = re.compile(r"bytes_acked:(\d+)")
_RE_BYTES_SENT = re.compile(r"bytes_sent:(\d+)")


# sample_control_tcp_bytes_ss samples TCP byte counters for specified control ports via `ss`.
# Lifecycle: Live resource sampling loop.
# Called by: main.
# Triggered: on each sampling tick when control-plane subtraction is enabled.
def sample_control_tcp_bytes_ss(control_ports):
    """sample_control_tcp_bytes_ss helper for benchmark tooling."""
    ports = set(int(p) for p in (control_ports or []) if int(p) > 0)
    if not ports:
        return {}, True, "disabled"
    try:
        proc = subprocess.run(
            ["ss", "-tinHn"],
            capture_output=True,
            text=True,
            timeout=2.0,
            check=False,
        )
    except Exception as exc:
        return {}, False, f"ss_exec_failed:{exc}"
    if proc.returncode != 0 and not (proc.stdout or "").strip():
        return {}, False, f"ss_rc_{proc.returncode}"

    totals = {}
    current_key = None
    for raw_line in (proc.stdout or "").splitlines():
        line = raw_line.rstrip("\n")
        if not line.strip():
            continue
        if line[:1].isspace():
            if current_key is None:
                continue
            rx_match = _RE_BYTES_RECEIVED.search(line)
            tx_match = _RE_BYTES_ACKED.search(line) or _RE_BYTES_SENT.search(line)
            if not rx_match and not tx_match:
                continue
            cur = totals.get(current_key, {"rx": 0, "tx": 0})
            if rx_match:
                try:
                    cur["rx"] = max(cur.get("rx", 0), int(rx_match.group(1)))
                except Exception:
                    pass
            if tx_match:
                try:
                    cur["tx"] = max(cur.get("tx", 0), int(tx_match.group(1)))
                except Exception:
                    pass
            totals[current_key] = cur
            continue

        parts = line.split()
        if len(parts) < 5:
            current_key = None
            continue
        local_ep = parts[3]
        peer_ep = parts[4]
        local_port = parse_endpoint_port(local_ep)
        peer_port = parse_endpoint_port(peer_ep)
        if local_port not in ports and peer_port not in ports:
            current_key = None
            continue
        current_key = (local_ep, peer_ep)

    return totals, True, f"ok:{len(totals)}"


# compute_control_interval computes interval byte deltas from consecutive control snapshots.
# Lifecycle: Control-plane traffic subtraction helper.
# Called by: main.
# Triggered: after each successful `ss` sample to derive adjusted traffic.
def compute_control_interval(prev_totals, curr_totals, initialized):
    """compute_control_interval helper for benchmark tooling."""
    if not initialized:
        return 0, 0
    rx_delta = 0
    tx_delta = 0
    for key, cur in curr_totals.items():
        prev = prev_totals.get(key)
        if prev is None:
            drx = cur.get("rx", 0)
            dtx = cur.get("tx", 0)
        else:
            drx = cur.get("rx", 0) - prev.get("rx", 0)
            dtx = cur.get("tx", 0) - prev.get("tx", 0)
            if drx < 0:
                drx = cur.get("rx", 0)
            if dtx < 0:
                dtx = cur.get("tx", 0)
        if drx > 0:
            rx_delta += drx
        if dtx > 0:
            tx_delta += dtx
    return rx_delta, tx_delta


# parse_proc_match parses and compiles process label regex overrides.
# Lifecycle: Sampler configuration parsing.
# Called by: main.
# Triggered: once during CLI argument initialization.
def parse_proc_match(values):
    """parse_proc_match helper for benchmark tooling."""
    mapping = dict(DEFAULT_PROC_MATCH)
    for raw in values:
        token = str(raw).strip()
        if not token:
            continue
        if "=" not in token:
            raise ValueError(f"Invalid --proc-match value '{token}' (expected label=regex)")
        label, pattern = token.split("=", 1)
        label = label.strip()
        pattern = pattern.strip()
        if not label:
            raise ValueError(f"Invalid --proc-match value '{token}' (empty label)")
        if label not in {"tss", "peer", "orderer"}:
            raise ValueError(
                f"Invalid --proc-match label '{label}' (allowed: tss, peer, orderer)"
            )
        if not pattern:
            raise ValueError(f"Invalid --proc-match value '{token}' (empty regex)")
        mapping[label] = pattern
    compiled = {}
    for label, pattern in mapping.items():
        compiled[label] = re.compile(pattern)
    return compiled


# iter_pids yields numeric process IDs from `/proc`.
# Lifecycle: Process scan helper.
# Called by: scan_process_group.
# Triggered: each time a process group snapshot is collected.
def iter_pids():
    """iter_pids helper for benchmark tooling."""
    for name in os.listdir("/proc"):
        if name.isdigit():
            yield int(name)


# read_cmdline reads a process command line for regex matching.
# Lifecycle: Process scan helper.
# Called by: scan_process_group.
# Triggered: per PID during group discovery.
def read_cmdline(pid):
    """read_cmdline helper for benchmark tooling."""
    path = f"/proc/{pid}/cmdline"
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except Exception:
        return ""
    if not raw:
        return ""
    return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()


# read_proc_stat reads CPU tick and RSS values for one process from `/proc/<pid>/stat`.
# Lifecycle: Process scan helper.
# Called by: scan_process_group.
# Triggered: for each matched PID while building process-group snapshots.
def read_proc_stat(pid):
    """read_proc_stat helper for benchmark tooling."""
    path = f"/proc/{pid}/stat"
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()
    except Exception:
        return None
    if not content:
        return None

    rpar = content.rfind(")")
    if rpar < 0 or rpar + 2 >= len(content):
        return None
    rest = content[rpar + 2 :].split()
    # rest[0] is state, fields are shifted by 3 from man proc(5)
    if len(rest) <= 21:
        return None
    try:
        utime = int(rest[11])  # field 14
        stime = int(rest[12])  # field 15
        rss_pages = int(rest[21])  # field 24
    except Exception:
        return None

    page_size = os.sysconf("SC_PAGE_SIZE")
    return {
        "ticks": utime + stime,
        "rss_bytes": rss_pages * page_size,
    }


# scan_process_group returns per-PID CPU/RSS stats for processes matching a regex.
# Lifecycle: Live resource sampling loop.
# Called by: main.
# Triggered: on each sampling tick for tss/peer/orderer process groups.
def scan_process_group(regex):
    """scan_process_group helper for benchmark tooling."""
    stats = {}
    for pid in iter_pids():
        cmd = read_cmdline(pid)
        if not cmd or regex.search(cmd) is None:
            continue
        pstat = read_proc_stat(pid)
        if pstat is None:
            continue
        stats[pid] = pstat
    return stats


# compute_proc_metrics computes CPU%, memory%, and process count for a process snapshot.
# Lifecycle: Live resource sampling loop.
# Called by: main.
# Triggered: on each sampling tick after process snapshots are collected.
def compute_proc_metrics(current, previous, host_total_diff, mem_total_bytes):
    """compute_proc_metrics helper for benchmark tooling."""
    cpu_ticks_delta = 0
    rss_bytes_sum = 0
    for pid, stat in current.items():
        rss_bytes_sum += stat["rss_bytes"]
        prev = previous.get(pid)
        if prev is None:
            continue
        dt = stat["ticks"] - prev["ticks"]
        if dt > 0:
            cpu_ticks_delta += dt

    cpu_pct = 0.0
    if host_total_diff > 0:
        cpu_pct = (cpu_ticks_delta / host_total_diff) * 100.0
    mem_pct = 0.0
    if mem_total_bytes > 0:
        mem_pct = (rss_bytes_sum / mem_total_bytes) * 100.0

    return cpu_pct, mem_pct, len(current)


# main runs the periodic sampler and writes resource metrics rows to CSV.
# Lifecycle: Resource collection entrypoint.
# Called by: module entrypoint (`if __name__ == "__main__"`).
# Triggered: started directly or spawned by workflow benchmark orchestration.
def main():
    """main helper for benchmark tooling."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--duration", type=float, default=0.0)
    parser.add_argument("--output", default="resources.csv")
    parser.add_argument("--iface", default="eth0")
    parser.add_argument("--tag", default="")
    parser.add_argument("--phase", default="")
    parser.add_argument("--phase-file", default="")
    parser.add_argument(
        "--control-exclude-port",
        action="append",
        type=int,
        default=[],
        help="TCP control-plane port to subtract from RX/TX (repeatable).",
    )
    parser.add_argument(
        "--proc-match",
        action="append",
        default=[],
        help="Process matcher override in form label=regex (labels: tss, peer, orderer). Repeatable.",
    )
    args = parser.parse_args()

    proc_match = parse_proc_match(args.proc_match)
    mem_total_bytes = read_mem_total_bytes()
    if mem_total_bytes <= 0:
        mem_total_bytes = 1

    control_ports = sorted(
        set(p for p in (args.control_exclude_port or []) if isinstance(p, int) and p > 0 and p <= 65535)
    )

    header = [
        "ts",
        "operation",
        "phase",
        "cpu_total_pct",
        "mem_used_pct",
        "rx_bytes",
        "tx_bytes",
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
        "control_sampling_ok",
        "control_sampling_note",
        "tss_cpu_pct",
        "tss_mem_pct",
        "peer_cpu_pct",
        "peer_mem_pct",
        "orderer_cpu_pct",
        "orderer_mem_pct",
        "tss_pid_count",
        "peer_pid_count",
        "orderer_pid_count",
    ]

    prev_total, prev_idle = read_cpu_times()
    prev_proc = {"tss": {}, "peer": {}, "orderer": {}}
    start = time.time()
    base_rx = None
    base_tx = None
    prev_rx = None
    prev_tx = None
    control_prev_totals = {}
    control_initialized = False
    control_rx_delta_total = 0
    control_tx_delta_total = 0

    # read_phase handles read phase behavior for benchmark tooling.
    # Lifecycle: Benchmark script runtime, aggregation, and analysis.
    # Called by: module-internal callers (see surrounding flow).
    # Triggered: CLI execution and helper orchestration.
    def read_phase():
        """read_phase helper for benchmark tooling."""
        if not args.phase_file:
            return args.phase
        try:
            with open(args.phase_file, "r", encoding="utf-8") as f:
                val = f.read().strip()
                if val:
                    return val
        except Exception:
            pass
        return args.phase

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)

        while True:
            now = time.time()
            total, idle = read_cpu_times()
            total_diff = total - prev_total
            idle_diff = idle - prev_idle
            cpu_pct = 0.0
            if total_diff > 0:
                cpu_pct = (total_diff - idle_diff) / total_diff * 100.0
            prev_total, prev_idle = total, idle

            mem_pct = read_mem_usage()
            rx, tx = read_net_bytes(args.iface)
            if base_rx is None:
                base_rx = rx
            if base_tx is None:
                base_tx = tx
            raw_rx_interval = 0 if prev_rx is None else max(rx - prev_rx, 0)
            raw_tx_interval = 0 if prev_tx is None else max(tx - prev_tx, 0)

            control_ok = True
            control_note = "disabled"
            control_rx_interval = 0
            control_tx_interval = 0
            if control_ports:
                current_control_totals, control_ok, control_note = sample_control_tcp_bytes_ss(control_ports)
                if control_ok:
                    control_rx_interval, control_tx_interval = compute_control_interval(
                        control_prev_totals,
                        current_control_totals,
                        control_initialized,
                    )
                    control_prev_totals = current_control_totals
                    if not control_initialized:
                        control_initialized = True
                        control_rx_interval = 0
                        control_tx_interval = 0
                else:
                    control_rx_interval = 0
                    control_tx_interval = 0
            control_rx_delta_total += max(control_rx_interval, 0)
            control_tx_delta_total += max(control_tx_interval, 0)

            raw_rx_delta = max(rx - base_rx, 0)
            raw_tx_delta = max(tx - base_tx, 0)
            adjusted_rx_interval = max(raw_rx_interval - control_rx_interval, 0)
            adjusted_tx_interval = max(raw_tx_interval - control_tx_interval, 0)
            adjusted_rx_delta = max(raw_rx_delta - control_rx_delta_total, 0)
            adjusted_tx_delta = max(raw_tx_delta - control_tx_delta_total, 0)

            current_proc = {
                "tss": scan_process_group(proc_match["tss"]),
                "peer": scan_process_group(proc_match["peer"]),
                "orderer": scan_process_group(proc_match["orderer"]),
            }
            tss_cpu, tss_mem, tss_count = compute_proc_metrics(
                current_proc["tss"], prev_proc["tss"], total_diff, mem_total_bytes
            )
            peer_cpu, peer_mem, peer_count = compute_proc_metrics(
                current_proc["peer"], prev_proc["peer"], total_diff, mem_total_bytes
            )
            orderer_cpu, orderer_mem, orderer_count = compute_proc_metrics(
                current_proc["orderer"], prev_proc["orderer"], total_diff, mem_total_bytes
            )
            prev_proc = current_proc

            writer.writerow(
                [
                    datetime.utcnow().isoformat() + "Z",
                    args.tag,
                    read_phase(),
                    f"{cpu_pct:.2f}",
                    f"{mem_pct:.2f}",
                    rx,
                    tx,
                    raw_rx_interval,
                    raw_tx_interval,
                    raw_rx_delta,
                    raw_tx_delta,
                    control_rx_interval,
                    control_tx_interval,
                    control_rx_delta_total,
                    control_tx_delta_total,
                    adjusted_rx_interval,
                    adjusted_tx_interval,
                    adjusted_rx_delta,
                    adjusted_tx_delta,
                    "1" if control_ok else "0",
                    control_note,
                    f"{tss_cpu:.2f}",
                    f"{tss_mem:.2f}",
                    f"{peer_cpu:.2f}",
                    f"{peer_mem:.2f}",
                    f"{orderer_cpu:.2f}",
                    f"{orderer_mem:.2f}",
                    str(tss_count),
                    str(peer_count),
                    str(orderer_count),
                ]
            )
            f.flush()
            prev_rx = rx
            prev_tx = tx

            if args.duration > 0 and (now - start) >= args.duration:
                break
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
