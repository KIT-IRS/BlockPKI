#!/usr/bin/env python3
import argparse
import csv
import subprocess
import time
from datetime import datetime


def read_cpu_times():
    with open("/proc/stat", "r", encoding="utf-8") as f:
        parts = f.readline().strip().split()
    # cpu user nice system idle iowait irq softirq steal guest guest_nice
    values = [int(p) for p in parts[1:]]
    idle = values[3] + values[4]
    total = sum(values)
    return total, idle


def read_mem_usage():
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


def read_net_bytes(iface):
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


def read_proc_stats(name):
    try:
        out = subprocess.check_output(
            ["ps", "-C", name, "-o", "%cpu,%mem", "--no-headers"],
            text=True,
        ).strip()
    except subprocess.CalledProcessError:
        return 0.0, 0.0
    if not out:
        return 0.0, 0.0
    cpu = 0.0
    mem = 0.0
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            cpu += float(parts[0])
            mem += float(parts[1])
    return cpu, mem


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--duration", type=float, default=0.0)
    parser.add_argument("--output", default="resources.csv")
    parser.add_argument("--iface", default="eth0")
    parser.add_argument("--tag", default="")
    parser.add_argument("--phase", default="")
    parser.add_argument("--phase-file", default="")
    args = parser.parse_args()

    header = [
        "ts",
        "operation",
        "phase",
        "cpu_total_pct",
        "mem_used_pct",
        "rx_bytes",
        "tx_bytes",
        "rx_bytes_delta",
        "tx_bytes_delta",
        "tss_cpu_pct",
        "tss_mem_pct",
        "peer_cpu_pct",
        "peer_mem_pct",
        "orderer_cpu_pct",
        "orderer_mem_pct",
    ]

    prev_total, prev_idle = read_cpu_times()
    start = time.time()
    base_rx = None
    base_tx = None

    def read_phase():
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

            tss_cpu, tss_mem = read_proc_stats("tss_peer")
            peer_cpu, peer_mem = read_proc_stats("peer")
            orderer_cpu, orderer_mem = read_proc_stats("orderer")

            writer.writerow(
                [
                    datetime.utcnow().isoformat() + "Z",
                    args.tag,
                    read_phase(),
                    f"{cpu_pct:.2f}",
                    f"{mem_pct:.2f}",
                    rx,
                    tx,
                    rx - base_rx,
                    tx - base_tx,
                    f"{tss_cpu:.2f}",
                    f"{tss_mem:.2f}",
                    f"{peer_cpu:.2f}",
                    f"{peer_mem:.2f}",
                    f"{orderer_cpu:.2f}",
                    f"{orderer_mem:.2f}",
                ]
            )
            f.flush()

            if args.duration > 0 and (now - start) >= args.duration:
                break
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
