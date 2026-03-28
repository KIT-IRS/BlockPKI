#!/usr/bin/env python3
"""Shared analysis helpers/constants for benchmark suite analysis stages.

Runtime flow: imported by benchmark analyzer stage modules and initialized once
from analyze_suite.main before stage execution.
"""

import json
import os
import re
from pathlib import Path

import matplotlib
import numpy as np
import pandas as pd

if not os.environ.get("DISPLAY"):
    matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.legend as mlegend  # noqa: F401
from cycler import cycler
from matplotlib.legend import Legend
from matplotlib.lines import Line2D
from matplotlib.text import Text
from matplotlib.ticker import FuncFormatter

_TIKZ_ENABLED = False
_TIKZ_ERROR = ""
_TIKZ_MISSING_WARNED = False
_TIKZ_LIB = None
_EMIT_PLOTS = True
MIXED_EPSILON_SECONDS = 0.05
WORKFLOW_CANONICAL_ORDER = ["csr", "revocation", "removal", "join"]
WORKFLOW_ACTION_SEQUENCE = {
    "csr": [
        "csr_submitted",
        "csr_voted",
        "csr_approved",
        "threshold_reached",
        "signing_initiated",
        "certificate_registered",
    ],
    "revocation": [
        "revocation_proposed",
        "revocation_voted",
        "certificate_revoked",
    ],
    "removal": [
        "member_removal_proposed",
        "member_removal_voted",
        "member_removed",
        "reshare_initiated",
        "reshare_completed",
    ],
    "join": [
        "member_join_requested",
        "member_join_voted",
        "member_join_approved",
        "reshare_initiated",
        "reshare_completed",
    ],
}
WORKFLOW_STAGE_SEQUENCE = {
    "csr": [
        "csr_submit_done",
        "csr_voted",
        "csr_approved",
        "cert_registered",
        "operation_end",
    ],
    "revocation": [
        "revocation_submit_done",
        "revocation_voted",
        "revocation_executed",
        "operation_end",
    ],
    "removal": [
        "removal_submit_done",
        "removal_voted",
        "removal_approved",
        "reshare_started",
        "reshare_completed",
        "operation_end",
    ],
    "join": [
        "join_submit_done",
        "join_voted",
        "join_approved",
        "reshare_started",
        "reshare_completed",
        "operation_end",
    ],
}

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


def set_emit_plots(enabled: bool):
    """set_emit_plots updates global plot emission behavior for analyzer stages.

    Lifecycle: Analyzer runtime configuration.
    Called by: analyze_suite.main.
    Triggered: once CLI args are parsed.
    """
    global _EMIT_PLOTS
    _EMIT_PLOTS = bool(enabled)


def initialize_plot_environment():
    """initialize_plot_environment configures plot theme and optional tikz support.

    Lifecycle: Analyzer process initialization.
    Called by: analyze_suite.main.
    Triggered: once at startup before stage analysis begins.
    """
    global _TIKZ_ENABLED
    global _TIKZ_ERROR
    global _TIKZ_LIB
    apply_tikz_compat_patch()
    apply_kit_plot_theme()
    _TIKZ_ENABLED = False
    _TIKZ_ERROR = ""
    _TIKZ_LIB = None
    try:
        import tikzplotlib

        _TIKZ_ENABLED = True
        _TIKZ_LIB = tikzplotlib
    except Exception as tikz_exc:
        _TIKZ_ERROR = str(tikz_exc)


def _rgb01(name: str):
    """_rgb01 helper for benchmark tooling."""
    r, g, b = KIT_COLORS_RGB[name]
    return (r / 255.0, g / 255.0, b / 255.0)

def apply_kit_plot_theme():
    """apply_kit_plot_theme helper for benchmark tooling."""
    # Keep white/yellow out of the default cycle for readability in reports and TikZ exports.
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

def apply_tikz_compat_patch():
    """apply_tikz_compat_patch helper for benchmark tooling."""
    # tikzplotlib on newer Matplotlib expects legacy private attributes.
    try:
        if not hasattr(Line2D, "_us_dashSeq"):
            Line2D._us_dashSeq = property(  # type: ignore[attr-defined]
                lambda self: (
                    self._dash_pattern[1] if hasattr(self, "_dash_pattern") and len(self._dash_pattern) > 1 else []
                )
            )
        if not hasattr(Line2D, "_us_dashOffset"):
            Line2D._us_dashOffset = property(  # type: ignore[attr-defined]
                lambda self: (
                    self._dash_pattern[0] if hasattr(self, "_dash_pattern") and len(self._dash_pattern) > 0 else 0
                )
            )
        if not hasattr(Legend, "_ncol"):
            Legend._ncol = property(  # type: ignore[attr-defined]
                lambda self: getattr(self, "_ncols", 1)
            )
    except Exception:
        pass

def safe_read_csv(path: Path) -> pd.DataFrame:
    """safe_read_csv helper for benchmark tooling."""
    if not path.exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except Exception as exc:
        print(f"Warning: failed to read {path}: {exc}")
        return pd.DataFrame()

def run_num_from_id(run_id: str) -> int:
    """run_num_from_id helper for benchmark tooling."""
    m = re.search(r"(\d+)$", str(run_id))
    if not m:
        return -1
    try:
        return int(m.group(1))
    except Exception:
        return -1

def trailing_int_token(value: str):
    """trailing_int_token helper for benchmark tooling."""
    m = re.search(r"(\d+)$", str(value or "").strip())
    if not m:
        return np.nan
    try:
        return int(m.group(1))
    except Exception:
        return np.nan

def workflow_base_from_tag(workflow_tag: str) -> str:
    """workflow_base_from_tag helper for benchmark tooling."""
    s = str(workflow_tag or "").strip()
    if not s:
        return ""
    return s.split("_", 1)[0]

def ordered_workflows(values):
    """ordered_workflows helper for benchmark tooling."""
    tokens = [str(v).strip() for v in values if str(v).strip()]
    seen = set(tokens)
    ordered = [wf for wf in WORKFLOW_CANONICAL_ORDER if wf in seen]
    extras = sorted([wf for wf in seen if wf not in WORKFLOW_CANONICAL_ORDER])
    return ordered + extras

def canonical_action_order_key(workflow_base: str, action: str):
    """canonical_action_order_key helper for benchmark tooling."""
    wf = str(workflow_base or "").strip()
    token = str(action or "").strip()
    seq = WORKFLOW_ACTION_SEQUENCE.get(wf, [])
    if token in seq:
        return (0, seq.index(token), token)
    return (1, 9999, token)

def canonical_stage_order_key(workflow_base: str, stage_end: str):
    """canonical_stage_order_key helper for benchmark tooling."""
    wf = str(workflow_base or "").strip()
    token = str(stage_end or "").strip()
    seq = WORKFLOW_STAGE_SEQUENCE.get(wf, [])
    if token in seq:
        return (0, seq.index(token), token)
    return (1, 9999, token)

def ordered_actions_for_workflow(workflow_base: str, actions):
    """ordered_actions_for_workflow helper for benchmark tooling."""
    wf = str(workflow_base or "").strip()
    seq = WORKFLOW_ACTION_SEQUENCE.get(wf, [])
    action_tokens = [str(a).strip() for a in actions if str(a).strip()]
    action_set = set(action_tokens)
    ordered = [a for a in seq if a in action_set]
    extras = sorted([a for a in action_set if a not in seq])
    return ordered + extras

def sort_by_canonical_action(df: pd.DataFrame, workflow_col: str = "workflow_base", action_col: str = "action") -> pd.DataFrame:
    """sort_by_canonical_action helper for benchmark tooling."""
    if df.empty:
        return df
    out = df.copy()
    out["_action_order_key"] = out.apply(
        lambda r: canonical_action_order_key(r.get(workflow_col, ""), r.get(action_col, "")),
        axis=1,
    )
    out = out.sort_values([workflow_col, "_action_order_key", action_col]).drop(columns=["_action_order_key"])
    return out

def stage_residual_bucket(stage_end: str) -> str:
    """stage_residual_bucket helper for benchmark tooling."""
    token = str(stage_end or "").strip().lower()
    if "voted" in token:
        return "voting_residual"
    if token in {"reshare_started", "reshare_completed"}:
        return "reshare_residual"
    if token == "operation_end":
        return "operation_end_residual"
    return "governance_residual"

def apply_nonnegative_baseline(ax, values, axis: str = "y", boxplot: bool = False):
    """apply_nonnegative_baseline helper for benchmark tooling."""
    try:
        arr = np.asarray(values, dtype=float).reshape(-1)
    except Exception:
        arr = np.array([], dtype=float)
    arr = arr[np.isfinite(arr)]
    if arr.size == 0:
        return
    if np.nanmin(arr) >= 0:
        if axis in {"y", "both"}:
            ax.set_ylim(bottom=0)
        if axis in {"x", "both"}:
            ax.set_xlim(left=0)
    elif boxplot and axis in {"y", "both"}:
        ax.axhline(0, color="black", linewidth=0.8, alpha=0.5)

def to_datetime_utc(df: pd.DataFrame, cols) -> pd.DataFrame:
    """to_datetime_utc helper for benchmark tooling."""
    for col in cols:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce", utc=True)
    return df

def duration_seconds(df: pd.DataFrame, start_col: str, end_col: str, out_col: str):
    """duration_seconds helper for benchmark tooling."""
    if start_col in df.columns and end_col in df.columns:
        df[out_col] = (df[end_col] - df[start_col]).dt.total_seconds()
    else:
        df[out_col] = pd.NA

def ensure_outdir(path: Path):
    """ensure_outdir helper for benchmark tooling."""
    try:
        path.mkdir(parents=True, exist_ok=True)
    except PermissionError as exc:
        raise SystemExit(
            f"Cannot create output directory '{path}': {exc}. "
            f"Choose a writable path via --outdir."
        ) from exc

def sanitize_figure_labels(fig):
    """sanitize_figure_labels helper for benchmark tooling."""
    # TikZ/LaTeX treats "_" as a subscript marker. Use plain spaces for all plot labels.
    try:
        text_nodes = fig.findobj(match=Text)
    except Exception:
        text_nodes = []
    for node in text_nodes:
        try:
            text = node.get_text()
        except Exception:
            continue
        if not isinstance(text, str) or "_" not in text:
            continue
        try:
            node.set_text(text.replace("_", " "))
        except Exception:
            continue

def save_plot(fig, out_path: Path, export_tikz: bool = False):
    """save_plot helper for benchmark tooling."""
    global _TIKZ_MISSING_WARNED
    if not _EMIT_PLOTS:
        plt.close(fig)
        return
    sanitize_figure_labels(fig)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    if export_tikz:
        tikz_path = out_path.with_suffix(".tex")
        if _TIKZ_ENABLED and _TIKZ_LIB is not None:
            tmp_tikz_path = tikz_path.with_name(f"{tikz_path.name}.tmp")
            try:
                _TIKZ_LIB.save(str(tmp_tikz_path))
                if tmp_tikz_path.exists() and tmp_tikz_path.stat().st_size > 0:
                    tmp_tikz_path.replace(tikz_path)
                else:
                    if tmp_tikz_path.exists():
                        try:
                            tmp_tikz_path.unlink()
                        except Exception:
                            pass
                    print(f"Warning: TikZ export produced empty file for {out_path.name}; keeping previous .tex (if any).")
            except Exception as exc:
                if tmp_tikz_path.exists():
                    try:
                        tmp_tikz_path.unlink()
                    except Exception:
                        pass
                print(f"Warning: failed to export TikZ for {out_path.name}: {exc}")
        else:
            if _TIKZ_MISSING_WARNED:
                plt.close(fig)
                return
            print(
                "Warning: --export-tikz requested but tikzplotlib is unavailable "
                f"({_TIKZ_ERROR}). Skipping TikZ export for {out_path.name}."
            )
            _TIKZ_MISSING_WARNED = True
    plt.close(fig)

def boxplot_with_labels(ax, data, labels, showfliers=False):
    """boxplot_with_labels helper for benchmark tooling."""
    # Matplotlib >=3.9 uses tick_labels; older versions use labels.
    try:
        return ax.boxplot(data, tick_labels=labels, showfliers=showfliers)
    except TypeError:
        return ax.boxplot(data, labels=labels, showfliers=showfliers)

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

def apply_bytes_axis(ax, axis: str = "y"):
    """apply_bytes_axis helper for benchmark tooling."""
    fmt = FuncFormatter(lambda x, _pos: human_bytes(x))
    if axis in {"y", "both"}:
        ax.yaxis.set_major_formatter(fmt)
    if axis in {"x", "both"}:
        ax.xaxis.set_major_formatter(fmt)

def parse_counter_map(raw):
    """parse_counter_map helper for benchmark tooling."""
    token = str(raw if raw is not None else "").strip()
    if not token or token.upper() in {"NA", "N/A", "NONE", "NULL"}:
        return {}
    try:
        obj = json.loads(token)
    except Exception:
        return {}
    if not isinstance(obj, dict):
        return {}
    out = {}
    for key, value in obj.items():
        k = str(key).strip()
        if not k:
            continue
        try:
            out[k] = float(value)
        except Exception:
            continue
    return out

def action_from_stage(stage_name: str) -> str:
    """action_from_stage helper for benchmark tooling."""
    token = str(stage_name or "").strip()
    if not token:
        return ""
    mapping = {
        "csr_submit_done": "csr_submitted",
        "csr_voted": "csr_voted",
        "csr_approved": "csr_approved",
        "cert_registered": "certificate_registered",
        "revocation_submit_done": "revocation_proposed",
        "revocation_voted": "revocation_voted",
        "revocation_executed": "certificate_revoked",
        "join_submit_done": "member_join_requested",
        "join_voted": "member_join_voted",
        "join_approved": "member_join_approved",
        "removal_submit_done": "member_removal_proposed",
        "removal_voted": "member_removal_voted",
        "removal_approved": "member_removed",
        "reshare_started": "reshare_initiated",
        "reshare_completed": "reshare_completed",
    }
    return mapping.get(token, token)

def flatten_multiindex_columns(df: pd.DataFrame) -> pd.DataFrame:
    """flatten_multiindex_columns helper for benchmark tooling."""
    if not isinstance(df.columns, pd.MultiIndex):
        return df
    cols = []
    for parts in df.columns.to_flat_index():
        labels = [str(p) for p in parts if str(p)]
        cols.append("_".join(labels))
    df.columns = cols
    return df
