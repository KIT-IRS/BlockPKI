#!/usr/bin/env python3
"""
Measure idle network communication load and generate suite-style plots.

Outputs:
- idle_network_samples.csv
- idle_network_rates_per_min.csv
- idle_network_summary.csv
- idle_bytes_per_minute.(png|tex)
- idle_packets_per_minute.(png|tex)
- idle_control_bytes_per_minute.(png|tex)  # only when control subtraction is enabled
- idle_peer_orderer_gossip_per_minute.(png|tex)  # when peer/orderer ports or peer metrics are configured
"""

import argparse
import csv
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
import urllib.error
import urllib.request

import matplotlib
import numpy as np
import pandas as pd

if not matplotlib.get_backend() or matplotlib.get_backend().lower() == "agg" or not matplotlib.is_interactive():
    # Keep CLI-safe behavior on headless hosts.
    matplotlib.use("Agg")

import matplotlib.pyplot as plt
from cycler import cycler
from matplotlib.legend import Legend
from matplotlib.lines import Line2D
from matplotlib.text import Text
from matplotlib.ticker import FuncFormatter


KIT_COLORS_RGB = {
    "kit_green": (0, 150, 130),
    "kit_blue": (70, 100, 170),
    "brown": (167, 130, 46),
    "purple": (163, 16, 124),
    "cyan": (35, 161, 224),
    "may_green": (140, 182, 60),
    "yellow": (252, 229, 0),
    "orange": (223, 155, 27),
    "red": (162, 34, 35),
    "black": (0, 0, 0),
    "gray_20": (51, 51, 51),
    "gray_40": (102, 102, 102),
    "gray_60": (153, 153, 153),
    "gray_80": (204, 204, 204),
    "white": (255, 255, 255),
}


# _rgb01 handles rgb01 behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def _rgb01(name: str):
    """_rgb01 helper for benchmark tooling."""
    r, g, b = KIT_COLORS_RGB[name]
    return (r / 255.0, g / 255.0, b / 255.0)


# apply_kit_plot_theme handles apply kit plot theme behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def apply_kit_plot_theme():
    """apply_kit_plot_theme helper for benchmark tooling."""
    cycle = [
        _rgb01("kit_green"),
        _rgb01("kit_blue"),
        _rgb01("brown"),
        _rgb01("purple"),
        _rgb01("cyan"),
        _rgb01("may_green"),
        _rgb01("orange"),
        _rgb01("red"),
        _rgb01("gray_40"),
        _rgb01("gray_60"),
    ]
    plt.rcParams["axes.prop_cycle"] = cycler(color=cycle)
    plt.rcParams["text.color"] = _rgb01("black")
    plt.rcParams["axes.labelcolor"] = _rgb01("black")
    plt.rcParams["axes.edgecolor"] = _rgb01("gray_40")
    plt.rcParams["xtick.color"] = _rgb01("gray_20")
    plt.rcParams["ytick.color"] = _rgb01("gray_20")
    plt.rcParams["grid.color"] = _rgb01("gray_80")
    plt.rcParams["legend.edgecolor"] = _rgb01("gray_80")
    plt.rcParams["legend.facecolor"] = _rgb01("white")
    plt.rcParams["figure.facecolor"] = _rgb01("white")
    plt.rcParams["axes.facecolor"] = _rgb01("white")


# apply_tikz_compat_patch handles apply tikz compat patch behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def apply_tikz_compat_patch():
    """apply_tikz_compat_patch helper for benchmark tooling."""
    # tikzplotlib compatibility for newer matplotlib internals.
    try:
        if not hasattr(Line2D, "_us_dashSeq"):
            Line2D._us_dashSeq = property(  # type: ignore[attr-defined]
                lambda self: (
                    self._dash_pattern[1]
                    if hasattr(self, "_dash_pattern") and len(self._dash_pattern) > 1
                    else []
                )
            )
        if not hasattr(Line2D, "_us_dashOffset"):
            Line2D._us_dashOffset = property(  # type: ignore[attr-defined]
                lambda self: (
                    self._dash_pattern[0]
                    if hasattr(self, "_dash_pattern") and len(self._dash_pattern) > 0
                    else 0
                )
            )
        if not hasattr(Legend, "_ncol"):
            Legend._ncol = property(  # type: ignore[attr-defined]
                lambda self: getattr(self, "_ncols", 1)
            )
    except Exception:
        pass


# sanitize_figure_labels handles sanitize figure labels behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def sanitize_figure_labels(fig):
    """sanitize_figure_labels helper for benchmark tooling."""
    # TikZ/LaTeX treats "_" as a subscript marker.
    try:
        text_nodes = fig.findobj(match=Text)
    except Exception:
        text_nodes = []
    for node in text_nodes:
        try:
            text = node.get_text()
        except Exception:
            continue
        if isinstance(text, str) and "_" in text:
            try:
                node.set_text(text.replace("_", " "))
            except Exception:
                pass


# human_bytes handles human bytes behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def human_bytes(value) -> str:
    """human_bytes helper for benchmark tooling."""
    try:
        v = float(value)
    except Exception:
        return str(value)
    sign = "-" if v < 0 else ""
    v = abs(v)
    for unit, scale in [("GB", 1e9), ("MB", 1e6), ("KB", 1e3)]:
        if v >= scale:
            return f"{sign}{v / scale:.1f} {unit}"
    return f"{sign}{v:.0f} B"


# apply_bytes_axis handles apply bytes axis behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def apply_bytes_axis(ax, axis: str = "y"):
    """apply_bytes_axis helper for benchmark tooling."""
    fmt = FuncFormatter(lambda x, _pos: human_bytes(x))
    if axis in {"y", "both"}:
        ax.yaxis.set_major_formatter(fmt)
    if axis in {"x", "both"}:
        ax.xaxis.set_major_formatter(fmt)


# apply_nonnegative_baseline handles apply nonnegative baseline behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def apply_nonnegative_baseline(ax, values, axis: str = "y"):
    """apply_nonnegative_baseline helper for benchmark tooling."""
    try:
        arr = np.asarray(values, dtype=float).reshape(-1)
    except Exception:
        arr = np.array([], dtype=float)
    arr = arr[np.isfinite(arr)]
    if arr.size and np.nanmin(arr) >= 0:
        if axis in {"y", "both"}:
            ax.set_ylim(bottom=0)
        if axis in {"x", "both"}:
            ax.set_xlim(left=0)


# ensure_outdir handles ensure outdir behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def ensure_outdir(path: Path):
    """ensure_outdir helper for benchmark tooling."""
    path.mkdir(parents=True, exist_ok=True)


# read_net_counters handles read net counters behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def read_net_counters(iface: str):
    """read_net_counters helper for benchmark tooling."""
    with open("/proc/net/dev", "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or ":" not in line:
                continue
            name, data = line.split(":", 1)
            if name.strip() != iface:
                continue
            fields = data.split()
            if len(fields) < 10:
                break
            rx_bytes = int(fields[0])
            rx_packets = int(fields[1])
            tx_bytes = int(fields[8])
            tx_packets = int(fields[9])
            return rx_bytes, tx_bytes, rx_packets, tx_packets
    raise RuntimeError(f"Network interface '{iface}' not found in /proc/net/dev")


# http_text handles http text behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def http_text(url):
    """http_text helper for benchmark tooling."""
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return int(getattr(resp, "status", 200)), raw
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read().decode("utf-8", errors="replace")
        except Exception:
            raw = str(exc)
        return int(getattr(exc, "code", 0) or 0), raw
    except Exception as exc:
        return 0, str(exc)


# parse_prom_metrics handles parse prom metrics behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def parse_prom_metrics(raw):
    """parse_prom_metrics helper for benchmark tooling."""
    metrics = {}
    for line in (raw or "").splitlines():
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


# sum_metrics_by_prefix handles sum metrics by prefix behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def sum_metrics_by_prefix(metrics, prefixes):
    """sum_metrics_by_prefix helper for benchmark tooling."""
    if not metrics:
        return None
    effective_prefixes = [str(p).strip() for p in (prefixes or []) if str(p).strip()]
    if not effective_prefixes:
        effective_prefixes = ["gossip_"]
    total = 0.0
    matched = False
    for name, val in metrics.items():
        if not any(name.startswith(p) for p in effective_prefixes):
            continue
        if not (name.endswith("_total") or name.endswith("_count")):
            continue
        total += float(val)
        matched = True
    return total if matched else None


# snapshot_peer_metrics_total handles snapshot peer metrics total behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def snapshot_peer_metrics_total(urls, prefixes):
    """snapshot_peer_metrics_total helper for benchmark tooling."""
    if not urls:
        return None, False, "disabled"
    grand_total = 0.0
    ok_count = 0
    notes = []
    for url in urls:
        status, raw = http_text(url)
        if status >= 400 or status == 0:
            notes.append(f"{url}:status={status}")
            continue
        metrics = parse_prom_metrics(raw)
        subtotal = sum_metrics_by_prefix(metrics, prefixes)
        if subtotal is None:
            notes.append(f"{url}:no_matching_metrics")
            continue
        grand_total += subtotal
        ok_count += 1
    if ok_count == 0:
        note = ";".join(notes) if notes else "no_metrics"
        return None, False, note
    return grand_total, True, f"ok:{ok_count}"


# parse_endpoint_port handles parse endpoint port behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
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
    elif ":" in text:
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


# sample_tcp_bytes_ss handles sample tcp bytes ss behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def sample_tcp_bytes_ss(ports):
    """sample_tcp_bytes_ss helper for benchmark tooling."""
    ports = set(int(p) for p in (ports or []) if int(p) > 0)
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


# compute_tcp_interval handles compute tcp interval behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def compute_tcp_interval(prev_totals, curr_totals, initialized):
    """compute_tcp_interval helper for benchmark tooling."""
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

# collect_idle_samples gathers time-series idle network and optional control-plane metrics.
# Lifecycle: Idle baseline sampling stage.
# Called by: main.
# Triggered: once per benchmark execution after CLI arguments are parsed.
def collect_idle_samples(
    csv_path: Path,
    iface: str,
    interval_s: float,
    duration_s: float,
    control_ports,
    peer_ports,
    orderer_ports,
    peer_metrics_urls,
    peer_metrics_prefixes,
):
    """collect_idle_samples helper for benchmark tooling."""
    header = [
        "ts",
        "elapsed_s",
        "sample_interval_s",
        "rx_bytes",
        "tx_bytes",
        "rx_packets",
        "tx_packets",
        "rx_bytes_interval",
        "tx_bytes_interval",
        "rx_packets_interval",
        "tx_packets_interval",
        "control_rx_bytes_interval",
        "control_tx_bytes_interval",
        "rx_bytes_interval_adjusted",
        "tx_bytes_interval_adjusted",
        "rx_bytes_delta",
        "tx_bytes_delta",
        "rx_packets_delta",
        "tx_packets_delta",
        "control_rx_bytes_delta",
        "control_tx_bytes_delta",
        "rx_bytes_delta_adjusted",
        "tx_bytes_delta_adjusted",
        "control_sampling_ok",
        "control_sampling_note",
        "peer_rx_bytes_interval",
        "peer_tx_bytes_interval",
        "peer_rx_bytes_delta",
        "peer_tx_bytes_delta",
        "peer_sampling_ok",
        "peer_sampling_note",
        "orderer_rx_bytes_interval",
        "orderer_tx_bytes_interval",
        "orderer_rx_bytes_delta",
        "orderer_tx_bytes_delta",
        "orderer_sampling_ok",
        "orderer_sampling_note",
        "gossip_metric_total",
        "gossip_metric_interval",
        "gossip_metric_delta",
        "gossip_sampling_ok",
        "gossip_sampling_note",
    ]

    start_t = time.time()
    prev_t = None

    base_rx_b = None
    base_tx_b = None
    base_rx_p = None
    base_tx_p = None

    prev_rx_b = None
    prev_tx_b = None
    prev_rx_p = None
    prev_tx_p = None

    control_prev_totals = {}
    control_initialized = False
    control_rx_delta_total = 0
    control_tx_delta_total = 0
    peer_prev_totals = {}
    peer_initialized = False
    peer_rx_delta_total = 0
    peer_tx_delta_total = 0
    orderer_prev_totals = {}
    orderer_initialized = False
    orderer_rx_delta_total = 0
    orderer_tx_delta_total = 0
    gossip_prev_total = None
    gossip_delta_total = 0.0

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)

        while True:
            now = time.time()
            elapsed = max(now - start_t, 0.0)
            sample_interval = 0.0 if prev_t is None else max(now - prev_t, 0.0)

            rx_b, tx_b, rx_p, tx_p = read_net_counters(iface)

            if base_rx_b is None:
                base_rx_b = rx_b
            if base_tx_b is None:
                base_tx_b = tx_b
            if base_rx_p is None:
                base_rx_p = rx_p
            if base_tx_p is None:
                base_tx_p = tx_p

            raw_rx_b_interval = 0 if prev_rx_b is None else max(rx_b - prev_rx_b, 0)
            raw_tx_b_interval = 0 if prev_tx_b is None else max(tx_b - prev_tx_b, 0)
            raw_rx_p_interval = 0 if prev_rx_p is None else max(rx_p - prev_rx_p, 0)
            raw_tx_p_interval = 0 if prev_tx_p is None else max(tx_p - prev_tx_p, 0)

            control_ok = True
            control_note = "disabled"
            control_rx_interval = 0
            control_tx_interval = 0
            if control_ports:
                current_control_totals, control_ok, control_note = sample_tcp_bytes_ss(control_ports)
                if control_ok:
                    control_rx_interval, control_tx_interval = compute_tcp_interval(
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

            peer_ok = True
            peer_note = "disabled"
            peer_rx_interval = 0
            peer_tx_interval = 0
            if peer_ports:
                current_peer_totals, peer_ok, peer_note = sample_tcp_bytes_ss(peer_ports)
                if peer_ok:
                    peer_rx_interval, peer_tx_interval = compute_tcp_interval(
                        peer_prev_totals,
                        current_peer_totals,
                        peer_initialized,
                    )
                    peer_prev_totals = current_peer_totals
                    if not peer_initialized:
                        peer_initialized = True
                        peer_rx_interval = 0
                        peer_tx_interval = 0
                else:
                    peer_rx_interval = 0
                    peer_tx_interval = 0
            peer_rx_delta_total += max(peer_rx_interval, 0)
            peer_tx_delta_total += max(peer_tx_interval, 0)

            orderer_ok = True
            orderer_note = "disabled"
            orderer_rx_interval = 0
            orderer_tx_interval = 0
            if orderer_ports:
                current_orderer_totals, orderer_ok, orderer_note = sample_tcp_bytes_ss(orderer_ports)
                if orderer_ok:
                    orderer_rx_interval, orderer_tx_interval = compute_tcp_interval(
                        orderer_prev_totals,
                        current_orderer_totals,
                        orderer_initialized,
                    )
                    orderer_prev_totals = current_orderer_totals
                    if not orderer_initialized:
                        orderer_initialized = True
                        orderer_rx_interval = 0
                        orderer_tx_interval = 0
                else:
                    orderer_rx_interval = 0
                    orderer_tx_interval = 0
            orderer_rx_delta_total += max(orderer_rx_interval, 0)
            orderer_tx_delta_total += max(orderer_tx_interval, 0)

            gossip_ok = True
            gossip_note = "disabled"
            gossip_total = np.nan
            gossip_interval = 0.0
            if peer_metrics_urls:
                gossip_total_val, gossip_ok, gossip_note = snapshot_peer_metrics_total(
                    peer_metrics_urls,
                    peer_metrics_prefixes,
                )
                if gossip_total_val is None:
                    gossip_total = np.nan
                    gossip_interval = 0.0
                else:
                    gossip_total = float(gossip_total_val)
                    if gossip_prev_total is None:
                        gossip_interval = 0.0
                    else:
                        dg = gossip_total - float(gossip_prev_total)
                        if dg < 0:
                            dg = gossip_total
                        gossip_interval = max(float(dg), 0.0)
                    gossip_prev_total = gossip_total
                    gossip_delta_total += gossip_interval

            raw_rx_b_delta = max(rx_b - base_rx_b, 0)
            raw_tx_b_delta = max(tx_b - base_tx_b, 0)
            raw_rx_p_delta = max(rx_p - base_rx_p, 0)
            raw_tx_p_delta = max(tx_p - base_tx_p, 0)
            adj_rx_b_interval = max(raw_rx_b_interval - control_rx_interval, 0)
            adj_tx_b_interval = max(raw_tx_b_interval - control_tx_interval, 0)
            adj_rx_b_delta = max(raw_rx_b_delta - control_rx_delta_total, 0)
            adj_tx_b_delta = max(raw_tx_b_delta - control_tx_delta_total, 0)

            writer.writerow(
                [
                    datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    f"{elapsed:.6f}",
                    f"{sample_interval:.6f}",
                    rx_b,
                    tx_b,
                    rx_p,
                    tx_p,
                    raw_rx_b_interval,
                    raw_tx_b_interval,
                    raw_rx_p_interval,
                    raw_tx_p_interval,
                    control_rx_interval,
                    control_tx_interval,
                    adj_rx_b_interval,
                    adj_tx_b_interval,
                    raw_rx_b_delta,
                    raw_tx_b_delta,
                    raw_rx_p_delta,
                    raw_tx_p_delta,
                    control_rx_delta_total,
                    control_tx_delta_total,
                    adj_rx_b_delta,
                    adj_tx_b_delta,
                    "1" if control_ok else "0",
                    control_note,
                    peer_rx_interval,
                    peer_tx_interval,
                    peer_rx_delta_total,
                    peer_tx_delta_total,
                    "1" if peer_ok else "0",
                    peer_note,
                    orderer_rx_interval,
                    orderer_tx_interval,
                    orderer_rx_delta_total,
                    orderer_tx_delta_total,
                    "1" if orderer_ok else "0",
                    orderer_note,
                    gossip_total,
                    gossip_interval,
                    gossip_delta_total,
                    "1" if gossip_ok else "0",
                    gossip_note,
                ]
            )
            f.flush()

            prev_t = now
            prev_rx_b = rx_b
            prev_tx_b = tx_b
            prev_rx_p = rx_p
            prev_tx_p = tx_p

            if duration_s > 0 and elapsed >= duration_s:
                break
            time.sleep(interval_s)


# safe_to_numeric handles safe to numeric behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def safe_to_numeric(df: pd.DataFrame, col: str):
    """safe_to_numeric helper for benchmark tooling."""
    if col in df.columns:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    else:
        df[col] = np.nan

# build_rate_table converts cumulative counters into per-minute rate metrics.
# Lifecycle: Idle baseline post-processing.
# Called by: main.
# Triggered: after sample capture before summaries and plotting.
def build_rate_table(samples: pd.DataFrame):
    """build_rate_table helper for benchmark tooling."""
    df = samples.copy()
    for col in [
        "elapsed_s",
        "sample_interval_s",
        "rx_bytes_interval",
        "tx_bytes_interval",
        "rx_packets_interval",
        "tx_packets_interval",
        "control_rx_bytes_interval",
        "control_tx_bytes_interval",
        "rx_bytes_interval_adjusted",
        "tx_bytes_interval_adjusted",
        "peer_rx_bytes_interval",
        "peer_tx_bytes_interval",
        "orderer_rx_bytes_interval",
        "orderer_tx_bytes_interval",
        "gossip_metric_interval",
    ]:
        safe_to_numeric(df, col)

    df = df[df["sample_interval_s"] > 0].copy()
    if df.empty:
        return df

    scale = 60.0 / df["sample_interval_s"]
    df["rx_bytes_per_min_raw"] = df["rx_bytes_interval"] * scale
    df["tx_bytes_per_min_raw"] = df["tx_bytes_interval"] * scale
    df["rx_bytes_per_min_adjusted"] = df["rx_bytes_interval_adjusted"] * scale
    df["tx_bytes_per_min_adjusted"] = df["tx_bytes_interval_adjusted"] * scale
    df["control_rx_bytes_per_min"] = df["control_rx_bytes_interval"] * scale
    df["control_tx_bytes_per_min"] = df["control_tx_bytes_interval"] * scale
    df["rx_packets_per_min"] = df["rx_packets_interval"] * scale
    df["tx_packets_per_min"] = df["tx_packets_interval"] * scale
    df["peer_rx_bytes_per_min"] = df["peer_rx_bytes_interval"] * scale
    df["peer_tx_bytes_per_min"] = df["peer_tx_bytes_interval"] * scale
    df["peer_total_bytes_per_min"] = df["peer_rx_bytes_per_min"] + df["peer_tx_bytes_per_min"]
    df["orderer_rx_bytes_per_min"] = df["orderer_rx_bytes_interval"] * scale
    df["orderer_tx_bytes_per_min"] = df["orderer_tx_bytes_interval"] * scale
    df["orderer_total_bytes_per_min"] = df["orderer_rx_bytes_per_min"] + df["orderer_tx_bytes_per_min"]
    df["gossip_metric_rate_per_min"] = df["gossip_metric_interval"] * scale
    df["elapsed_min"] = df["elapsed_s"] / 60.0
    return df


# metric_stats handles metric stats behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def metric_stats(series: pd.Series):
    """metric_stats helper for benchmark tooling."""
    s = pd.to_numeric(series, errors="coerce").dropna()
    if s.empty:
        return {"mean": np.nan, "p50": np.nan, "p95": np.nan, "max": np.nan}
    return {
        "mean": float(s.mean()),
        "p50": float(s.quantile(0.5)),
        "p95": float(s.quantile(0.95)),
        "max": float(s.max()),
    }

# write_summary_csv writes aggregate idle communication statistics to CSV.
# Lifecycle: Idle baseline artifact generation.
# Called by: main.
# Triggered: after rate table construction for benchmark outputs.
def write_summary_csv(rate_df: pd.DataFrame, out_path: Path):
    """write_summary_csv helper for benchmark tooling."""
    metric_cols = [
        "tx_packets_per_min",
        "rx_packets_per_min",
        "tx_bytes_per_min_adjusted",
        "rx_bytes_per_min_adjusted",
        "tx_bytes_per_min_raw",
        "rx_bytes_per_min_raw",
        "control_tx_bytes_per_min",
        "control_rx_bytes_per_min",
        "peer_total_bytes_per_min",
        "orderer_total_bytes_per_min",
        "gossip_metric_rate_per_min",
    ]
    rows = []
    for col in metric_cols:
        stats = metric_stats(rate_df[col] if col in rate_df.columns else pd.Series(dtype=float))
        rows.append(
            {
                "metric": col,
                "mean": stats["mean"],
                "p50": stats["p50"],
                "p95": stats["p95"],
                "max": stats["max"],
            }
        )
    pd.DataFrame(rows).to_csv(out_path, index=False)


# save_plot handles save plot behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def save_plot(fig, out_path: Path, export_tikz: bool, tikz_available: bool, tikz_error: str):
    """save_plot helper for benchmark tooling."""
    sanitize_figure_labels(fig)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    if export_tikz:
        tikz_path = out_path.with_suffix(".tex")
        if tikz_available:
            import tikzplotlib  # type: ignore

            try:
                tikzplotlib.save(str(tikz_path))
            except Exception as exc:
                print(f"Warning: failed to export TikZ for {out_path.name}: {exc}")
        else:
            print(
                "Warning: --export-tikz requested but tikzplotlib is unavailable "
                f"({tikz_error}). Skipping TikZ export for {out_path.name}."
            )
    plt.close(fig)

# plot_bytes renders idle byte-rate plots and exports image/TikZ artifacts.
# Lifecycle: Idle baseline visualization.
# Called by: main.
# Triggered: after summary generation when plotting is enabled.
def plot_bytes(rate_df: pd.DataFrame, outdir: Path, export_tikz: bool, tikz_available: bool, tikz_error: str):
    """plot_bytes helper for benchmark tooling."""
    fig, ax = plt.subplots(figsize=(10.5, 5.2))
    x = pd.to_numeric(rate_df["elapsed_min"], errors="coerce")
    ax.plot(x, rate_df["tx_bytes_per_min_adjusted"], marker="o", linewidth=1.6, label="TX bytes per min (adjusted)")
    ax.plot(x, rate_df["rx_bytes_per_min_adjusted"], marker="o", linewidth=1.6, label="RX bytes per min (adjusted)")
    ax.plot(
        x,
        rate_df["tx_bytes_per_min_raw"],
        linewidth=1.2,
        linestyle="--",
        alpha=0.7,
        label="TX bytes per min (raw)",
    )
    ax.plot(
        x,
        rate_df["rx_bytes_per_min_raw"],
        linewidth=1.2,
        linestyle="--",
        alpha=0.7,
        label="RX bytes per min (raw)",
    )
    ax.set_title("Idle communication bytes per minute")
    ax.set_xlabel("Elapsed time (min)")
    ax.set_ylabel("Bytes per minute")
    ax.grid(True, alpha=0.3)
    apply_bytes_axis(ax, "y")
    apply_nonnegative_baseline(
        ax,
        np.concatenate(
            [
                pd.to_numeric(rate_df["tx_bytes_per_min_adjusted"], errors="coerce").fillna(0).to_numpy(),
                pd.to_numeric(rate_df["rx_bytes_per_min_adjusted"], errors="coerce").fillna(0).to_numpy(),
                pd.to_numeric(rate_df["tx_bytes_per_min_raw"], errors="coerce").fillna(0).to_numpy(),
                pd.to_numeric(rate_df["rx_bytes_per_min_raw"], errors="coerce").fillna(0).to_numpy(),
            ]
        ),
    )
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, 1.24), ncol=2, frameon=True)
    fig.subplots_adjust(top=0.78)
    save_plot(fig, outdir / "idle_bytes_per_minute.png", export_tikz, tikz_available, tikz_error)

# plot_packets renders idle packet-rate plots and exports image/TikZ artifacts.
# Lifecycle: Idle baseline visualization.
# Called by: main.
# Triggered: after summary generation when plotting is enabled.
def plot_packets(rate_df: pd.DataFrame, outdir: Path, export_tikz: bool, tikz_available: bool, tikz_error: str):
    """plot_packets helper for benchmark tooling."""
    fig, ax = plt.subplots(figsize=(10.0, 5.2))
    x = pd.to_numeric(rate_df["elapsed_min"], errors="coerce")
    ax.plot(x, rate_df["tx_packets_per_min"], marker="o", linewidth=1.6, label="TX packets per min")
    ax.plot(x, rate_df["rx_packets_per_min"], marker="o", linewidth=1.6, label="RX packets per min")
    ax.set_title("Idle communication packets per minute")
    ax.set_xlabel("Elapsed time (min)")
    ax.set_ylabel("Packets per minute")
    ax.grid(True, alpha=0.3)
    apply_nonnegative_baseline(
        ax,
        np.concatenate(
            [
                pd.to_numeric(rate_df["tx_packets_per_min"], errors="coerce").fillna(0).to_numpy(),
                pd.to_numeric(rate_df["rx_packets_per_min"], errors="coerce").fillna(0).to_numpy(),
            ]
        ),
    )
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, 1.20), ncol=2, frameon=True)
    fig.subplots_adjust(top=0.80)
    save_plot(fig, outdir / "idle_packets_per_minute.png", export_tikz, tikz_available, tikz_error)

# plot_control_bytes renders control-plane adjusted byte-rate plots.
# Lifecycle: Idle baseline visualization.
# Called by: main.
# Triggered: when control subtraction metrics are available.
def plot_control_bytes(rate_df: pd.DataFrame, outdir: Path, export_tikz: bool, tikz_available: bool, tikz_error: str):
    """plot_control_bytes helper for benchmark tooling."""
    control_vals = np.concatenate(
        [
            pd.to_numeric(rate_df["control_tx_bytes_per_min"], errors="coerce").fillna(0).to_numpy(),
            pd.to_numeric(rate_df["control_rx_bytes_per_min"], errors="coerce").fillna(0).to_numpy(),
        ]
    )
    if not np.any(control_vals > 0):
        return

    fig, ax = plt.subplots(figsize=(10.0, 5.2))
    x = pd.to_numeric(rate_df["elapsed_min"], errors="coerce")
    ax.plot(x, rate_df["control_tx_bytes_per_min"], marker="o", linewidth=1.6, label="Control TX bytes per min")
    ax.plot(x, rate_df["control_rx_bytes_per_min"], marker="o", linewidth=1.6, label="Control RX bytes per min")
    ax.set_title("Subtracted control-plane bytes per minute")
    ax.set_xlabel("Elapsed time (min)")
    ax.set_ylabel("Bytes per minute")
    ax.grid(True, alpha=0.3)
    apply_bytes_axis(ax, "y")
    apply_nonnegative_baseline(ax, control_vals)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, 1.20), ncol=2, frameon=True)
    fig.subplots_adjust(top=0.80)
    save_plot(fig, outdir / "idle_control_bytes_per_minute.png", export_tikz, tikz_available, tikz_error)

# plot_peer_orderer_gossip renders gossip/control metric rates from peer/orderer signals.
# Lifecycle: Idle baseline visualization.
# Called by: main.
# Triggered: when peer/orderer metrics or endpoint ports are configured.
def plot_peer_orderer_gossip(
    rate_df: pd.DataFrame,
    outdir: Path,
    export_tikz: bool,
    tikz_available: bool,
    tikz_error: str,
):
    """plot_peer_orderer_gossip helper for benchmark tooling."""
    peer_vals = pd.to_numeric(rate_df["peer_total_bytes_per_min"], errors="coerce").fillna(0).to_numpy()
    orderer_vals = pd.to_numeric(rate_df["orderer_total_bytes_per_min"], errors="coerce").fillna(0).to_numpy()
    gossip_vals = pd.to_numeric(rate_df["gossip_metric_rate_per_min"], errors="coerce").fillna(0).to_numpy()
    if not (np.any(peer_vals > 0) or np.any(orderer_vals > 0) or np.any(gossip_vals > 0)):
        return

    fig, ax_left = plt.subplots(figsize=(10.8, 5.4))
    x = pd.to_numeric(rate_df["elapsed_min"], errors="coerce")

    line_peer = ax_left.plot(
        x,
        peer_vals,
        marker="o",
        linewidth=1.7,
        label="Peer port bytes per min",
    )[0]
    line_orderer = ax_left.plot(
        x,
        orderer_vals,
        marker="o",
        linewidth=1.7,
        label="Orderer port bytes per min",
    )[0]
    ax_left.set_title("Idle peer/orderer bytes and gossip rate per minute")
    ax_left.set_xlabel("Elapsed time (min)")
    ax_left.set_ylabel("Bytes per minute")
    ax_left.grid(True, alpha=0.3)
    apply_bytes_axis(ax_left, "y")
    apply_nonnegative_baseline(ax_left, np.concatenate([peer_vals, orderer_vals]))

    ax_right = ax_left.twinx()
    line_gossip = ax_right.plot(
        x,
        gossip_vals,
        marker="s",
        linewidth=1.5,
        linestyle="--",
        label="Gossip counters per min",
        color=_rgb01("red"),
    )[0]
    ax_right.set_ylabel("Counter increments per minute")
    apply_nonnegative_baseline(ax_right, gossip_vals)

    lines = [line_peer, line_orderer, line_gossip]
    labels = [l.get_label() for l in lines]
    ax_left.legend(lines, labels, loc="upper center", bbox_to_anchor=(0.5, 1.22), ncol=2, frameon=True)
    fig.subplots_adjust(top=0.80)
    save_plot(fig, outdir / "idle_peer_orderer_gossip_per_minute.png", export_tikz, tikz_available, tikz_error)


# parse_args handles parse args behavior for benchmark tooling.
# Lifecycle: Benchmark script runtime, aggregation, and analysis.
# Called by: module-internal callers (see surrounding flow).
# Triggered: CLI execution and helper orchestration.
def parse_args():
    """parse_args helper for benchmark tooling."""
    parser = argparse.ArgumentParser(
        description="Collect idle network communication baseline and generate per-minute plots."
    )
    parser.add_argument(
        "--outdir",
        default="",
        help="Output directory. Default: benchmarks/out/idle_<timestamp>",
    )
    parser.add_argument(
        "--input-csv",
        default="",
        help="Analyze an existing idle_network_samples.csv and skip collection.",
    )
    parser.add_argument("--duration", type=float, default=600.0, help="Collection duration in seconds.")
    parser.add_argument("--interval", type=float, default=3.0, help="Sampling interval in seconds.")
    parser.add_argument("--iface", default="eth0", help="Network interface to sample from /proc/net/dev.")
    parser.add_argument(
        "--control-exclude-port",
        action="append",
        type=int,
        default=[],
        help="TCP control-plane port to subtract from RX/TX (repeatable).",
    )
    parser.add_argument(
        "--no-default-control-ports",
        action="store_true",
        help="Do not auto-add default control ports (22, 8083, 9446).",
    )
    parser.add_argument(
        "--peer-port",
        action="append",
        type=int,
        default=[],
        help="Peer TCP port to track as peer traffic (repeatable).",
    )
    parser.add_argument(
        "--orderer-port",
        action="append",
        type=int,
        default=[],
        help="Orderer TCP port to track as orderer traffic (repeatable).",
    )
    parser.add_argument(
        "--no-default-fabric-ports",
        action="store_true",
        help="Do not auto-add default peer/orderer ports (7051, 7050).",
    )
    parser.add_argument(
        "--peer-metrics-url",
        action="append",
        default=[],
        help="Peer Prometheus metrics URL for gossip counter rates (repeatable).",
    )
    parser.add_argument(
        "--peer-metrics-prefix",
        action="append",
        default=[],
        help="Metric name prefix to sum for gossip-style counters (repeatable, default: gossip_).",
    )
    parser.add_argument(
        "--export-tikz",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Export PGFPlots/TikZ .tex next to each PNG (default: enabled).",
    )
    return parser.parse_args()

# main orchestrates idle communication baseline sampling, summaries, and plots.
# Lifecycle: Idle baseline benchmark entrypoint.
# Called by: module entrypoint (`if __name__ == "__main__"`).
# Triggered: when invoked directly or from suite scripts.
def main():
    """main helper for benchmark tooling."""
    apply_kit_plot_theme()
    apply_tikz_compat_patch()

    args = parse_args()
    if args.interval <= 0:
        raise SystemExit("--interval must be > 0")
    if args.duration < 0:
        raise SystemExit("--duration must be >= 0")

    try:
        import tikzplotlib  # type: ignore  # noqa: F401

        tikz_available = True
        tikz_error = ""
    except Exception as exc:
        tikz_available = False
        tikz_error = str(exc)

    control_ports = set()
    if not args.no_default_control_ports:
        control_ports.update({22, 8083, 9446})
    for p in args.control_exclude_port or []:
        if isinstance(p, int) and 0 < p <= 65535:
            control_ports.add(p)
    control_ports = sorted(control_ports)

    peer_ports = set()
    orderer_ports = set()
    if not args.no_default_fabric_ports:
        peer_ports.add(7051)
        orderer_ports.add(7050)
    for p in args.peer_port or []:
        if isinstance(p, int) and 0 < p <= 65535:
            peer_ports.add(p)
    for p in args.orderer_port or []:
        if isinstance(p, int) and 0 < p <= 65535:
            orderer_ports.add(p)
    peer_ports = sorted(peer_ports)
    orderer_ports = sorted(orderer_ports)
    peer_metrics_urls = [str(u).strip() for u in (args.peer_metrics_url or []) if str(u).strip()]
    peer_metrics_prefixes = [str(p).strip() for p in (args.peer_metrics_prefix or []) if str(p).strip()]
    if not peer_metrics_prefixes:
        peer_metrics_prefixes = ["gossip_"]

    if args.outdir:
        outdir = Path(args.outdir).resolve()
    elif args.input_csv:
        outdir = Path(args.input_csv).resolve().parent
    else:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        outdir = (Path("benchmarks") / "out" / f"idle_{stamp}").resolve()
    ensure_outdir(outdir)

    samples_path = outdir / "idle_network_samples.csv"
    if args.input_csv:
        samples_path = Path(args.input_csv).resolve()
        if not samples_path.exists():
            raise SystemExit(f"--input-csv not found: {samples_path}")
        print(f"Using existing samples: {samples_path}")
    else:
        print(
            "Collecting idle samples: "
            f"duration={args.duration:.1f}s interval={args.interval:.2f}s iface={args.iface} "
            f"control_ports={control_ports if control_ports else 'none'} "
            f"peer_ports={peer_ports if peer_ports else 'none'} "
            f"orderer_ports={orderer_ports if orderer_ports else 'none'} "
            f"peer_metrics_urls={len(peer_metrics_urls)}"
        )
        collect_idle_samples(
            csv_path=samples_path,
            iface=args.iface,
            interval_s=args.interval,
            duration_s=args.duration,
            control_ports=control_ports,
            peer_ports=peer_ports,
            orderer_ports=orderer_ports,
            peer_metrics_urls=peer_metrics_urls,
            peer_metrics_prefixes=peer_metrics_prefixes,
        )
        print(f"Wrote: {samples_path}")

    samples = pd.read_csv(samples_path)
    rates = build_rate_table(samples)
    if rates.empty:
        raise SystemExit("No valid intervals found in samples (need at least two samples).")

    rates_path = outdir / "idle_network_rates_per_min.csv"
    rates.to_csv(rates_path, index=False)
    print(f"Wrote: {rates_path}")

    summary_path = outdir / "idle_network_summary.csv"
    write_summary_csv(rates, summary_path)
    print(f"Wrote: {summary_path}")

    plot_bytes(rates, outdir, args.export_tikz, tikz_available, tikz_error)
    plot_packets(rates, outdir, args.export_tikz, tikz_available, tikz_error)
    plot_control_bytes(rates, outdir, args.export_tikz, tikz_available, tikz_error)
    plot_peer_orderer_gossip(rates, outdir, args.export_tikz, tikz_available, tikz_error)

    print(f"Done. Idle analysis outputs: {outdir}")


if __name__ == "__main__":
    main()
