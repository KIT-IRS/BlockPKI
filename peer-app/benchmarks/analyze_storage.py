#!/usr/bin/env python3
"""Storage-focused analysis stages for benchmark suites.

Runtime flow: imported by analyze_suite and executed for storage/byte-accounting
stages after workflow timing analysis completes.
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

if __package__:
    from .analyze_common import (
        action_from_stage,
        apply_bytes_axis,
        apply_nonnegative_baseline,
        boxplot_with_labels,
        canonical_stage_order_key,
        flatten_multiindex_columns,
        ordered_actions_for_workflow,
        ordered_workflows,
        parse_counter_map,
        run_num_from_id,
        safe_read_csv,
        save_plot,
        sort_by_canonical_action,
        stage_residual_bucket,
        workflow_base_from_tag,
    )
else:
    from analyze_common import (
        action_from_stage,
        apply_bytes_axis,
        apply_nonnegative_baseline,
        boxplot_with_labels,
        canonical_stage_order_key,
        flatten_multiindex_columns,
        ordered_actions_for_workflow,
        ordered_workflows,
        parse_counter_map,
        run_num_from_id,
        safe_read_csv,
        save_plot,
        sort_by_canonical_action,
        stage_residual_bucket,
        workflow_base_from_tag,
    )


def analyze_storage(suite_root: Path, outdir: Path, include_all_paths: bool = False, export_tikz: bool = False):
    """analyze_storage helper for benchmark tooling."""
    path = suite_root / "suite_storage_deltas_all_runs.csv"
    df = safe_read_csv(path)
    if df.empty:
        print(f"Info: missing/empty {path.name}")
        return

    component_delta_cols = [c for c in df.columns if c.endswith("_delta_bytes") and c != "delta_bytes"]

    for c in ["delta_bytes", "bytes_before", "bytes_after"] + component_delta_cols:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")
    if "run_id" in df.columns:
        df["run_num"] = df["run_id"].map(run_num_from_id)
    else:
        df["run_num"] = -1
    if "workflow_base" not in df.columns:
        df["workflow_base"] = df.get("workflow", "").map(workflow_base_from_tag)

    coverage_rows = []
    if "path" in df.columns:
        for p, g in df.groupby("path", dropna=False):
            has_component = False
            if component_delta_cols:
                mask = pd.Series(False, index=g.index)
                for c in component_delta_cols:
                    token = g[c].astype(str).str.strip().str.upper()
                    mask = mask | ((token != "") & (token != "NA") & (token != "N/A") & (token != "NONE") & (token != "NULL"))
                has_component = bool(mask.any())
            coverage_rows.append(
                {
                    "path": p,
                    "rows": int(len(g)),
                    "component_split_populated": has_component,
                }
            )
    coverage_df = pd.DataFrame(coverage_rows).sort_values(["rows", "path"], ascending=[False, True])
    coverage_path = outdir / "storage_path_coverage.csv"
    coverage_df.to_csv(coverage_path, index=False)

    if not include_all_paths and "path" in df.columns:
        path_norm = df["path"].astype(str).str.strip().str.rstrip("/")
        df = df[path_norm.str.endswith("/volumes")].copy()
        if df.empty:
            available = ", ".join(sorted({str(x) for x in coverage_df.get("path", [])}))
            print("Info: no Docker volumes rows found in suite_storage_deltas_all_runs.csv")
            if available:
                print(f"Info: available storage paths: {available}")
            print(f"Wrote: {coverage_path}")
            return

    summary = (
        df.groupby(["workflow_base", "path"], dropna=False)["delta_bytes"]
        .agg(["count", "mean", "min", "max", "sum"])
        .reset_index()
        .sort_values(["workflow_base", "path"])
    )
    summary_path = outdir / "storage_summary_by_workflow_path.csv"
    summary.to_csv(summary_path, index=False)

    workflow_summary = (
        df.groupby("workflow_base", dropna=False)["delta_bytes"]
        .agg(["count", "mean", "min", "max", "sum"])
        .reset_index()
        .sort_values("workflow_base")
    )
    workflow_summary_path = outdir / "storage_summary_by_workflow.csv"
    workflow_summary.to_csv(workflow_summary_path, index=False)

    # Keep run/workflow CSV for diagnostics, but skip non-component storage charts.
    storage_plot_df = df.dropna(subset=["delta_bytes"]).copy()
    by_run = pd.DataFrame()
    by_run_src = storage_plot_df[storage_plot_df["run_num"] >= 0].copy()
    if not by_run_src.empty:
        by_run = (
            by_run_src.groupby(["run_num", "workflow_base"], dropna=False)["delta_bytes"]
            .mean()
            .reset_index()
            .sort_values(["workflow_base", "run_num"])
        )
        by_run_path = outdir / "storage_delta_by_run_workflow.csv"
        by_run.to_csv(by_run_path, index=False)

    component_summary_path = None
    component_by_run_path = None
    if component_delta_cols:
        comp_parts = []
        for col in component_delta_cols:
            comp = col[: -len("_delta_bytes")]
            part = df[["workflow_base", "run_num", col]].copy()
            part["component"] = comp
            part = part.rename(columns={col: "delta_bytes"})
            part["delta_bytes"] = pd.to_numeric(part["delta_bytes"], errors="coerce")
            comp_parts.append(part)

        if comp_parts:
            comp_df = pd.concat(comp_parts, ignore_index=True)
            comp_df = comp_df.dropna(subset=["delta_bytes"])
            if not comp_df.empty:
                comp_summary = (
                    comp_df.groupby(["workflow_base", "component"], dropna=False)["delta_bytes"]
                    .agg(["count", "mean", "min", "max", "sum"])
                    .reset_index()
                    .sort_values(["workflow_base", "component"])
                )
                component_summary_path = outdir / "storage_component_summary_by_workflow.csv"
                comp_summary.to_csv(component_summary_path, index=False)

                comp_plot = (
                    comp_summary.pivot(index="workflow_base", columns="component", values="mean")
                    .fillna(0)
                    .sort_index()
                )
                if not comp_plot.empty:
                    fig = plt.figure(figsize=(10, 5))
                    bottom = np.zeros(len(comp_plot))
                    x = np.arange(len(comp_plot))
                    for comp in comp_plot.columns:
                        vals = comp_plot[comp].to_numpy()
                        plt.bar(x, vals, bottom=bottom, label=comp)
                        bottom = bottom + vals
                    plt.xticks(list(x), comp_plot.index.tolist())
                    plt.ylabel("Avg Delta Bytes")
                    scope = "All Paths" if include_all_paths else "/var/lib/docker/volumes Only"
                    plt.title(f"Average Storage Delta by Workflow and Component ({scope})")
                    plt.legend()
                    plt.grid(axis="y", alpha=0.3)
                    apply_bytes_axis(plt.gca(), axis="y")
                    apply_nonnegative_baseline(plt.gca(), comp_plot.to_numpy().reshape(-1))
                    save_plot(fig, outdir / "storage_component_delta_by_workflow.png", export_tikz=export_tikz)

                # Faceted boxplot: one panel per component with workflow on x-axis.
                workflows = sorted(comp_df["workflow_base"].dropna().astype(str).str.strip().unique())
                components = sorted(comp_df["component"].dropna().astype(str).str.strip().unique())
                if workflows and components:
                    fig, axes = plt.subplots(1, len(components), figsize=(5.2 * len(components), 5), sharey=False)
                    if len(components) == 1:
                        axes = [axes]
                    for ax, comp in zip(axes, components):
                        sub = comp_df[comp_df["component"] == comp]
                        box_data = [sub.loc[sub["workflow_base"] == wf, "delta_bytes"].dropna() for wf in workflows]
                        if all(len(vals) == 0 for vals in box_data):
                            ax.text(0.5, 0.5, "no data", ha="center", va="center", transform=ax.transAxes)
                            ax.set_xticks([])
                        else:
                            safe_data = [vals if len(vals) > 0 else [np.nan] for vals in box_data]
                            boxplot_with_labels(ax, safe_data, workflows, showfliers=False)
                        ax.set_title(comp)
                        ax.set_xlabel("workflow")
                        ax.grid(axis="y", alpha=0.3)
                        apply_bytes_axis(ax, axis="y")
                        apply_nonnegative_baseline(
                            ax,
                            np.concatenate([vals.to_numpy(dtype=float) for vals in box_data if len(vals) > 0])
                            if any(len(vals) > 0 for vals in box_data)
                            else np.array([]),
                            boxplot=True,
                        )
                    axes[0].set_ylabel("Delta Bytes")
                    scope = "All Paths" if include_all_paths else "/var/lib/docker/volumes Only"
                    fig.suptitle(f"Storage Delta Distribution by Workflow and Component ({scope})")
                    save_plot(fig, outdir / "storage_component_delta_boxplot.png", export_tikz=export_tikz)

                comp_run = comp_df[comp_df["run_num"] >= 0].copy()
                if not comp_run.empty:
                    comp_run_summary = (
                        comp_run.groupby(["run_num", "workflow_base", "component"], dropna=False)["delta_bytes"]
                        .mean()
                        .reset_index()
                        .sort_values(["component", "workflow_base", "run_num"])
                    )
                    component_by_run_path = outdir / "storage_component_delta_by_run.csv"
                    comp_run_summary.to_csv(component_by_run_path, index=False)

                    comp_names = sorted(comp_run_summary["component"].dropna().astype(str).str.strip().unique())
                    fig, axes = plt.subplots(1, len(comp_names), figsize=(5.2 * len(comp_names), 5), sharey=False)
                    if len(comp_names) == 1:
                        axes = [axes]
                    for ax, comp in zip(axes, comp_names):
                        comp_part = comp_run_summary[comp_run_summary["component"] == comp]
                        if comp_part.empty:
                            ax.text(0.5, 0.5, "no data", ha="center", va="center", transform=ax.transAxes)
                            ax.set_xticks([])
                            ax.set_title(comp)
                            continue
                        for wf, g in comp_part.groupby("workflow_base", dropna=False):
                            g = g.sort_values("run_num")
                            ax.plot(g["run_num"], g["delta_bytes"], marker="o", label=str(wf))
                        ax.set_title(comp)
                        ax.set_xlabel("Run #")
                        ax.grid(alpha=0.3)
                        apply_bytes_axis(ax, axis="y")
                        apply_nonnegative_baseline(ax, comp_part["delta_bytes"].to_numpy(dtype=float))
                    axes[0].set_ylabel("Mean Delta Bytes")
                    handles, labels = axes[0].get_legend_handles_labels()
                    if handles:
                        fig.legend(handles, labels, loc="upper center", ncol=max(1, min(4, len(labels))))
                    scope = "All Paths" if include_all_paths else "/var/lib/docker/volumes Only"
                    fig.suptitle(f"Storage Component Delta by Run and Workflow ({scope})")
                    save_plot(fig, outdir / "storage_component_delta_by_run.png", export_tikz=export_tikz)

    print(f"Wrote: {summary_path}")
    print(f"Wrote: {workflow_summary_path}")
    print(f"Wrote: {coverage_path}")
    if not by_run.empty:
        print(f"Wrote: {outdir / 'storage_delta_by_run_workflow.csv'}")
    if component_summary_path:
        print(f"Wrote: {component_summary_path}")
    if component_by_run_path:
        print(f"Wrote: {component_by_run_path}")

def analyze_storage_stages(suite_root: Path, outdir: Path, export_tikz: bool = False):
    """analyze_storage_stages helper for benchmark tooling."""
    path = suite_root / "suite_storage_stage_deltas_all_runs.csv"
    df = safe_read_csv(path)
    if df.empty:
        print(f"Info: missing/empty {path.name}")
        return

    if "run_id" in df.columns:
        df["run_num"] = df["run_id"].map(run_num_from_id)
    else:
        df["run_id"] = ""
        df["run_num"] = -1
    if "workflow_base" not in df.columns:
        df["workflow_base"] = df.get("workflow", "").map(workflow_base_from_tag)

    component_cols = [c for c in df.columns if c.endswith("_volume_delta_bytes")]
    if not component_cols:
        print("Info: no component delta columns found in suite_storage_stage_deltas_all_runs.csv")
        return

    for col in component_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    long_parts = []
    for col in component_cols:
        component = col[: -len("_volume_delta_bytes")]
        part = df[
            [
                "run_id",
                "run_num",
                "workflow_base",
                "stage_start",
                "stage_end",
                "path",
                "operation_id",
                col,
            ]
        ].copy()
        part = part.rename(columns={col: "delta_bytes"})
        part["component"] = component
        long_parts.append(part)
    long_df = pd.concat(long_parts, ignore_index=True)
    long_df = long_df.dropna(subset=["delta_bytes"])
    if long_df.empty:
        print("Info: no numeric rows in suite_storage_stage_deltas_all_runs.csv component columns")
        return

    summary = (
        long_df.groupby(
            ["workflow_base", "stage_start", "stage_end", "component"], dropna=False
        )["delta_bytes"]
        .agg(["count", "mean", "min", "max", "sum"])
        .reset_index()
        .sort_values(["workflow_base", "stage_start", "stage_end", "component"])
    )
    summary_path = outdir / "storage_stage_component_summary_by_workflow.csv"
    summary.to_csv(summary_path, index=False)

    by_run = (
        long_df[long_df["run_num"] >= 0]
        .groupby(
            ["run_id", "run_num", "workflow_base", "stage_start", "stage_end", "component"],
            dropna=False,
        )["delta_bytes"]
        .mean()
        .reset_index()
        .sort_values(["run_num", "workflow_base", "stage_start", "stage_end", "component"])
    )
    by_run_path = outdir / "storage_stage_component_by_run.csv"
    by_run.to_csv(by_run_path, index=False)

    topk_path = suite_root / "suite_storage_stage_topk_volumes_all_runs.csv"
    topk_df = safe_read_csv(topk_path)
    topk_summary_path = outdir / "storage_stage_topk_volumes_summary.csv"
    if not topk_df.empty:
        topk_df["delta_bytes"] = pd.to_numeric(topk_df.get("delta_bytes"), errors="coerce")
        topk_df = topk_df.dropna(subset=["delta_bytes"])
        topk_df["abs_delta_bytes"] = topk_df["delta_bytes"].abs()
        topk_summary = (
            topk_df.groupby(["volume_name", "component"], dropna=False)["abs_delta_bytes"]
            .agg(["count", "mean", "max", "sum"])
            .reset_index()
            .sort_values(["sum", "mean"], ascending=[False, False])
        )
        topk_summary.to_csv(topk_summary_path, index=False)
    else:
        pd.DataFrame(
            columns=["volume_name", "component", "count", "mean", "max", "sum"]
        ).to_csv(topk_summary_path, index=False)

    print(f"Wrote: {summary_path}")
    print(f"Wrote: {by_run_path}")
    print(f"Wrote: {topk_summary_path}")

def analyze_peer_ledger_store_breakdown(suite_root: Path, outdir: Path, export_tikz: bool = False):
    """analyze_peer_ledger_store_breakdown helper for benchmark tooling."""
    path = suite_root / "suite_storage_stage_peer_ledger_deltas_all_runs.csv"
    df = safe_read_csv(path)
    if df.empty:
        print(f"Info: missing/empty {path.name}")
        return

    if "workflow_base" not in df.columns:
        df["workflow_base"] = df.get("workflow", "").map(workflow_base_from_tag)
    if "run_id" not in df.columns:
        df["run_id"] = ""
    if "workflow_tag" not in df.columns:
        df["workflow_tag"] = ""
    if "operation_id" not in df.columns:
        df["operation_id"] = ""
    if "proposal_id" not in df.columns:
        df["proposal_id"] = ""
    if "stage_start" not in df.columns:
        df["stage_start"] = ""
    if "stage_end" not in df.columns:
        df["stage_end"] = ""
    if "component" in df.columns:
        df = df[df["component"].astype(str).str.strip() == "peer"].copy()
    if df.empty:
        print("Info: no peer rows in suite_storage_stage_peer_ledger_deltas_all_runs.csv")
        return

    component_cols = [
        "block_files_delta_bytes",
        "block_index_delta_bytes",
        "leveldb_data_delta_bytes",
        "leveldb_wal_meta_delta_bytes",
        "peer_store_other_delta_bytes",
    ]
    for col in component_cols:
        if col not in df.columns:
            df[col] = np.nan
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df = df.dropna(subset=component_cols, how="all")
    if df.empty:
        print("Info: no numeric peer-ledger-store rows found")
        return

    id_cols = [
        "run_id",
        "workflow_base",
        "workflow_tag",
        "operation_id",
        "proposal_id",
        "stage_start",
        "stage_end",
    ]
    op_stage = (
        df.groupby(id_cols, dropna=False)[component_cols]
        .sum(min_count=1)
        .reset_index()
    )
    op_stage = op_stage.dropna(subset=component_cols, how="all")
    if op_stage.empty:
        print("Info: no aggregated peer-ledger-store rows found")
        return

    op_stage_out = outdir / "peer_ledger_store_deltas_by_operation_stage.csv"
    op_stage.to_csv(op_stage_out, index=False)

    stage_summary = (
        op_stage.groupby(["workflow_base", "stage_start", "stage_end"], dropna=False)[component_cols]
        .agg(["count", "mean", "median", "sum", "max"])
        .reset_index()
    )
    stage_summary = flatten_multiindex_columns(stage_summary)
    if "workflow_base_" in stage_summary.columns:
        stage_summary = stage_summary.rename(columns={"workflow_base_": "workflow_base"})
    if "stage_start_" in stage_summary.columns:
        stage_summary = stage_summary.rename(columns={"stage_start_": "stage_start"})
    if "stage_end_" in stage_summary.columns:
        stage_summary = stage_summary.rename(columns={"stage_end_": "stage_end"})
    stage_summary["stage_order"] = stage_summary.apply(
        lambda r: canonical_stage_order_key(r.get("workflow_base", ""), r.get("stage_end", "")),
        axis=1,
    )
    stage_summary = stage_summary.sort_values(["workflow_base", "stage_order", "stage_end"]).drop(columns=["stage_order"])
    stage_summary_out = outdir / "peer_ledger_store_stage_summary_by_workflow.csv"
    stage_summary.to_csv(stage_summary_out, index=False)

    wf_summary = (
        op_stage.groupby("workflow_base", dropna=False)[component_cols]
        .agg(["count", "mean", "median", "sum", "max"])
        .reset_index()
    )
    wf_summary = flatten_multiindex_columns(wf_summary)
    if "workflow_base_" in wf_summary.columns:
        wf_summary = wf_summary.rename(columns={"workflow_base_": "workflow_base"})
    wf_order = ordered_workflows(wf_summary["workflow_base"].astype(str).str.strip().unique())
    wf_summary["workflow_order"] = wf_summary["workflow_base"].map(
        lambda wf: wf_order.index(str(wf).strip()) if str(wf).strip() in wf_order else 9999
    )
    wf_summary = wf_summary.sort_values(["workflow_order", "workflow_base"]).drop(columns=["workflow_order"])
    wf_summary_out = outdir / "peer_ledger_store_summary_by_workflow.csv"
    wf_summary.to_csv(wf_summary_out, index=False)

    # Per request: keep CSV summaries, but do not emit peer-ledger-store composition/stage diagrams.

    print(f"Wrote: {op_stage_out}")
    print(f"Wrote: {stage_summary_out}")
    print(f"Wrote: {wf_summary_out}")

def analyze_storage_logical_vs_physical(suite_root: Path, outdir: Path, export_tikz: bool = False):
    """analyze_storage_logical_vs_physical helper for benchmark tooling."""
    tx_path = suite_root / "suite_tx_events_all_runs.csv"
    tx_size_path = suite_root / "suite_tx_block_sizes_all_runs.csv"
    stage_path = suite_root / "suite_storage_stage_deltas_all_runs.csv"

    tx_df = safe_read_csv(tx_path)
    tx_size_df = safe_read_csv(tx_size_path)
    stage_df = safe_read_csv(stage_path)

    logical_breakdown_out = outdir / "storage_logical_action_breakdown_all_runs.csv"
    logical_summary_out = outdir / "storage_logical_action_summary_by_workflow.csv"
    logical_category_summary_out = outdir / "storage_logical_category_summary_by_action.csv"
    logical_vs_physical_out = outdir / "storage_logical_vs_physical_by_action.csv"
    amplification_out = outdir / "storage_amplification_by_action.csv"
    csr_comp_out = outdir / "storage_cost_composition_csr_cert_registered.csv"
    tx_block_breakdown_out = outdir / "tx_block_size_breakdown_all_runs.csv"
    tx_block_summary_out = outdir / "tx_block_size_summary_by_action.csv"
    peer_comp_action_out = outdir / "peer_volume_composition_by_action_all_runs.csv"
    peer_comp_operation_out = outdir / "peer_volume_composition_by_operation.csv"
    peer_comp_workflow_out = outdir / "peer_volume_composition_by_workflow.csv"
    peer_stage_detailed_out = outdir / "peer_volume_stage_contribution_detailed_by_workflow.csv"
    peer_residual_action_out = outdir / "peer_volume_residual_breakdown_by_action.csv"
    peer_residual_workflow_out = outdir / "peer_volume_residual_breakdown_by_workflow.csv"

    logical_breakdown_base = pd.DataFrame()
    logical_breakdown = pd.DataFrame()
    logical_summary = pd.DataFrame()
    logical_category_summary = pd.DataFrame()
    merged = pd.DataFrame()
    amplification = pd.DataFrame()
    csr_comp = pd.DataFrame(columns=["component_type", "category", "bytes_mean", "bytes_sum", "rows"])
    tx_block_breakdown = pd.DataFrame()
    tx_block_summary = pd.DataFrame()
    peer_comp_action = pd.DataFrame()
    peer_comp_operation = pd.DataFrame()
    peer_comp_workflow = pd.DataFrame()
    peer_stage_detailed = pd.DataFrame(columns=["workflow_base", "stage_end", "count", "mean", "median", "sum", "max"])
    peer_residual_action = pd.DataFrame(
        columns=[
            "workflow_base",
            "action",
            "governance_residual_bytes",
            "voting_residual_bytes",
            "reshare_residual_bytes",
            "operation_end_residual_bytes",
        ]
    )
    peer_residual_workflow = pd.DataFrame(
        columns=[
            "workflow_base",
            "governance_residual_bytes",
            "voting_residual_bytes",
            "reshare_residual_bytes",
            "operation_end_residual_bytes",
        ]
    )

    if not tx_df.empty:
        if "workflow_base" not in tx_df.columns:
            tx_df["workflow_base"] = tx_df.get("workflow", "").map(workflow_base_from_tag)
        tx_df["run_id"] = tx_df.get("run_id", "").astype(str).str.strip()
        tx_df["workflow_base"] = tx_df.get("workflow_base", "").astype(str).str.strip()
        tx_df["operation_id"] = tx_df.get("operation_id", "").astype(str).str.strip()
        tx_df["proposal_id"] = tx_df.get("proposal_id", "").astype(str).str.strip()
        tx_df["action"] = tx_df.get("action", "").astype(str).str.strip()
        tx_df["event_name"] = tx_df.get("event_name", "").astype(str).str.strip()
        tx_df["logical_write_bytes_total"] = pd.to_numeric(tx_df.get("logical_write_bytes_total"), errors="coerce")
        tx_df["logical_delete_bytes_total"] = pd.to_numeric(tx_df.get("logical_delete_bytes_total"), errors="coerce")
        tx_df["logical_write_by_category"] = tx_df.get("logical_write_by_category", "")

        has_logical = (
            tx_df["logical_write_bytes_total"].notna()
            | tx_df["logical_delete_bytes_total"].notna()
            | tx_df["event_name"].eq("StorageAttribution")
        )
        logical_events = tx_df[has_logical].copy()
        if not logical_events.empty:
            logical_events["action"] = np.where(
                logical_events["action"].astype(str).str.strip() != "",
                logical_events["action"],
                logical_events["event_name"],
            )
            logical_events["op_ref"] = np.where(
                logical_events["operation_id"] != "",
                logical_events["operation_id"],
                logical_events["proposal_id"],
            )
            logical_events["join_key"] = (
                logical_events["run_id"]
                + "|"
                + logical_events["workflow_base"]
                + "|"
                + logical_events["action"]
                + "|"
                + logical_events["op_ref"]
            )

            logical_breakdown_base = (
                logical_events.groupby(
                    ["run_id", "workflow_base", "operation_id", "proposal_id", "action", "join_key"],
                    dropna=False,
                )[["logical_write_bytes_total", "logical_delete_bytes_total"]]
                .sum(min_count=1)
                .reset_index()
            )
            logical_breakdown_base["logical_write_bytes_total"] = logical_breakdown_base["logical_write_bytes_total"].fillna(0)
            logical_breakdown_base["logical_delete_bytes_total"] = logical_breakdown_base["logical_delete_bytes_total"].fillna(0)
            logical_breakdown = logical_breakdown_base.copy()

            category_rows = []
            for _, row in logical_events.iterrows():
                cat_map = parse_counter_map(row.get("logical_write_by_category", ""))
                for category, value in cat_map.items():
                    category_rows.append(
                        {
                            "run_id": row.get("run_id", ""),
                            "workflow_base": row.get("workflow_base", ""),
                            "operation_id": row.get("operation_id", ""),
                            "proposal_id": row.get("proposal_id", ""),
                            "action": row.get("action", ""),
                            "join_key": row.get("join_key", ""),
                            "category": category,
                            "logical_category_bytes": float(value),
                        }
                    )
            if category_rows:
                cat_df = pd.DataFrame(category_rows)
                cat_agg = (
                    cat_df.groupby(
                        ["run_id", "workflow_base", "operation_id", "proposal_id", "action", "join_key", "category"],
                        dropna=False,
                    )["logical_category_bytes"]
                    .sum()
                    .reset_index()
                )
                logical_breakdown = logical_breakdown.merge(
                    cat_agg,
                    on=["run_id", "workflow_base", "operation_id", "proposal_id", "action", "join_key"],
                    how="left",
                )
            else:
                logical_breakdown["category"] = ""
                logical_breakdown["logical_category_bytes"] = np.nan

            logical_summary = (
                logical_breakdown_base.groupby(["workflow_base", "action"], dropna=False)[
                    ["logical_write_bytes_total", "logical_delete_bytes_total"]
                ]
                .agg(["count", "mean", "median", "sum", "max"])
                .reset_index()
            )
            logical_summary = flatten_multiindex_columns(logical_summary)
            if "workflow_base_" in logical_summary.columns:
                logical_summary = logical_summary.rename(columns={"workflow_base_": "workflow_base"})
            if "action_" in logical_summary.columns:
                logical_summary = logical_summary.rename(columns={"action_": "action"})
            logical_category_summary_for_join = pd.DataFrame()

            cat_rows = logical_breakdown.copy()
            if not cat_rows.empty:
                cat_rows["category"] = cat_rows.get("category", "").astype(str).str.strip()
                cat_rows["logical_category_bytes"] = pd.to_numeric(cat_rows.get("logical_category_bytes"), errors="coerce")
                cat_rows = cat_rows[(cat_rows["category"] != "") & (cat_rows["logical_category_bytes"].notna())]
                if not cat_rows.empty:
                    logical_category_summary = (
                        cat_rows.groupby(["action", "category"], dropna=False)["logical_category_bytes"]
                        .agg(["count", "mean", "median", "sum", "max"])
                        .reset_index()
                        .sort_values(["sum", "mean"], ascending=[False, False])
                    )
                    logical_category_summary_for_join = (
                        cat_rows.groupby(["workflow_base", "action"], dropna=False)["logical_category_bytes"]
                        .agg(["count", "mean", "median", "sum", "max"])
                        .reset_index()
                    )
                    logical_category_summary_for_join = flatten_multiindex_columns(logical_category_summary_for_join)
                    if "workflow_base_" in logical_category_summary_for_join.columns:
                        logical_category_summary_for_join = logical_category_summary_for_join.rename(
                            columns={"workflow_base_": "workflow_base"}
                        )
                    if "action_" in logical_category_summary_for_join.columns:
                        logical_category_summary_for_join = logical_category_summary_for_join.rename(
                            columns={"action_": "action"}
                        )
            if not logical_category_summary_for_join.empty:
                logical_summary = logical_summary.merge(
                    logical_category_summary_for_join,
                    on=["workflow_base", "action"],
                    how="left",
                    suffixes=("", "_logical_category_bytes"),
                )
            for col in [
                "logical_category_bytes_count",
                "logical_category_bytes_mean",
                "logical_category_bytes_median",
                "logical_category_bytes_sum",
                "logical_category_bytes_max",
            ]:
                if col not in logical_summary.columns:
                    logical_summary[col] = np.nan

            logical_action_dist = (
                logical_breakdown_base.copy()
            )
            logical_action_dist = logical_action_dist[logical_action_dist["action"].astype(str).str.strip() != ""].copy()
            # Per request: no per-workflow `storage_logical_action_means_<workflow>` diagrams.

            if not logical_action_dist.empty:
                combined_rows = []
                for wf in ordered_workflows(logical_action_dist["workflow_base"].dropna().astype(str).str.strip().unique()):
                    wf_rows = logical_action_dist[logical_action_dist["workflow_base"].astype(str).str.strip() == wf]
                    ordered_actions = ordered_actions_for_workflow(wf, wf_rows["action"].astype(str).str.strip().unique())
                    for action in ordered_actions:
                        vals = pd.to_numeric(
                            wf_rows[wf_rows["action"].astype(str).str.strip() == action]["logical_write_bytes_total"],
                            errors="coerce",
                        ).dropna()
                        if len(vals) == 0:
                            continue
                        combined_rows.append((f"{wf}|{action}", vals))
                if combined_rows:
                    fig, ax = plt.subplots(figsize=(max(10, len(combined_rows) * 0.75), 5.4))
                    labels = [item[0] for item in combined_rows]
                    groups = [item[1] for item in combined_rows]
                    boxplot_with_labels(ax, groups, labels, showfliers=False)
                    ax.tick_params(axis="x", rotation=35)
                    ax.set_title("Logical State Write Distribution by Workflow|Action")
                    ax.set_ylabel("Logical write bytes")
                    ax.grid(axis="y", alpha=0.3)
                    apply_bytes_axis(ax, axis="y")
                    apply_nonnegative_baseline(
                        ax,
                        np.concatenate([vals.to_numpy(dtype=float) for vals in groups]),
                        boxplot=True,
                    )
                    save_plot(
                        fig,
                        outdir / "storage_logical_action_distribution_combined.png",
                        export_tikz=export_tikz,
                    )

    physical = pd.DataFrame()
    if not stage_df.empty:
        stage_df["run_id"] = stage_df.get("run_id", "").astype(str).str.strip()
        if "workflow_base" not in stage_df.columns:
            stage_df["workflow_base"] = stage_df.get("workflow", "").map(workflow_base_from_tag)
        stage_df["workflow_base"] = stage_df.get("workflow_base", "").astype(str).str.strip()
        stage_df["operation_id"] = stage_df.get("operation_id", "").astype(str).str.strip()
        stage_df["proposal_id"] = stage_df.get("proposal_id", "").astype(str).str.strip()
        stage_df["stage_end"] = stage_df.get("stage_end", "").astype(str).str.strip()
        stage_df["delta_bytes"] = pd.to_numeric(stage_df.get("delta_bytes"), errors="coerce")

        if "path" in stage_df.columns:
            path_norm = stage_df["path"].astype(str).str.strip().str.rstrip("/")
            vol_rows = stage_df[path_norm.str.endswith("/volumes")].copy()
            if not vol_rows.empty:
                stage_df = vol_rows

        stage_df["action"] = stage_df["stage_end"].map(action_from_stage)
        stage_df["op_ref"] = np.where(
            stage_df["operation_id"] != "",
            stage_df["operation_id"],
            stage_df["proposal_id"],
        )
        stage_df["join_key"] = (
            stage_df["run_id"]
            + "|"
            + stage_df["workflow_base"]
            + "|"
            + stage_df["action"]
            + "|"
            + stage_df["op_ref"]
        )
        physical = (
            stage_df.groupby(
                ["run_id", "workflow_base", "operation_id", "proposal_id", "action", "join_key"],
                dropna=False,
            )["delta_bytes"]
            .sum(min_count=1)
            .reset_index()
            .rename(columns={"delta_bytes": "physical_delta_bytes"})
        )

    if not physical.empty or not logical_breakdown_base.empty:
        physical_df = (
            physical
            if not physical.empty
            else pd.DataFrame(
                columns=[
                    "run_id",
                    "workflow_base",
                    "operation_id",
                    "proposal_id",
                    "action",
                    "join_key",
                    "physical_delta_bytes",
                ]
            )
        )
        logical_expanded_df = (
            logical_breakdown[
                [
                    "run_id",
                    "workflow_base",
                    "operation_id",
                    "proposal_id",
                    "action",
                    "join_key",
                    "logical_write_bytes_total",
                    "logical_delete_bytes_total",
                    "category",
                    "logical_category_bytes",
                ]
            ]
            if not logical_breakdown.empty
            else pd.DataFrame(
                columns=[
                    "run_id",
                    "workflow_base",
                    "operation_id",
                    "proposal_id",
                    "action",
                    "join_key",
                    "logical_write_bytes_total",
                    "logical_delete_bytes_total",
                    "category",
                    "logical_category_bytes",
                ]
            )
        )
        logical_base_df = (
            logical_breakdown_base[
                [
                    "run_id",
                    "workflow_base",
                    "operation_id",
                    "proposal_id",
                    "action",
                    "join_key",
                    "logical_write_bytes_total",
                    "logical_delete_bytes_total",
                ]
            ]
            if not logical_breakdown_base.empty
            else pd.DataFrame(
                columns=[
                    "run_id",
                    "workflow_base",
                    "operation_id",
                    "proposal_id",
                    "action",
                    "join_key",
                    "logical_write_bytes_total",
                    "logical_delete_bytes_total",
                ]
            )
        )
        merged = physical_df.merge(
            logical_expanded_df,
            on=["run_id", "workflow_base", "operation_id", "proposal_id", "action", "join_key"],
            how="outer",
        )
        merged_base = physical_df.merge(
            logical_base_df,
            on=["run_id", "workflow_base", "operation_id", "proposal_id", "action", "join_key"],
            how="outer",
        )
        merged["physical_delta_bytes"] = pd.to_numeric(merged.get("physical_delta_bytes"), errors="coerce")
        merged["logical_write_bytes_total"] = pd.to_numeric(merged.get("logical_write_bytes_total"), errors="coerce")
        merged["logical_delete_bytes_total"] = pd.to_numeric(merged.get("logical_delete_bytes_total"), errors="coerce")
        merged["logical_category_bytes"] = pd.to_numeric(merged.get("logical_category_bytes"), errors="coerce")
        merged_base["physical_delta_bytes"] = pd.to_numeric(merged_base.get("physical_delta_bytes"), errors="coerce")
        merged_base["logical_write_bytes_total"] = pd.to_numeric(merged_base.get("logical_write_bytes_total"), errors="coerce")
        merged_base["logical_delete_bytes_total"] = pd.to_numeric(merged_base.get("logical_delete_bytes_total"), errors="coerce")
        merged["amplification_factor"] = np.where(
            merged["logical_write_bytes_total"] > 0,
            merged["physical_delta_bytes"] / merged["logical_write_bytes_total"],
            np.nan,
        )
        merged_base["amplification_factor"] = np.where(
            merged_base["logical_write_bytes_total"] > 0,
            merged_base["physical_delta_bytes"] / merged_base["logical_write_bytes_total"],
            np.nan,
        )

        amplification = (
            merged_base.groupby(["workflow_base", "action"], dropna=False)[
                ["physical_delta_bytes", "logical_write_bytes_total", "amplification_factor"]
            ]
            .agg(["count", "mean", "median", "sum", "max"])
            .reset_index()
        )
        amplification = flatten_multiindex_columns(amplification)
        if "workflow_base_" in amplification.columns:
            amplification = amplification.rename(columns={"workflow_base_": "workflow_base"})
        if "action_" in amplification.columns:
            amplification = amplification.rename(columns={"action_": "action"})

        csr_rows_base = merged_base[
            (merged_base["workflow_base"].astype(str).str.strip() == "csr")
            & (merged_base["action"].astype(str).str.strip() == "certificate_registered")
        ].copy()
        csr_rows_category = merged[
            (merged["workflow_base"].astype(str).str.strip() == "csr")
            & (merged["action"].astype(str).str.strip() == "certificate_registered")
        ].copy()
        if not csr_rows_base.empty or not csr_rows_category.empty:
            comp_rows = []
            physical_vals = pd.to_numeric(csr_rows_base["physical_delta_bytes"], errors="coerce").dropna()
            if len(physical_vals) > 0:
                comp_rows.append(
                    {
                        "component_type": "physical",
                        "category": "total",
                        "bytes_mean": float(physical_vals.mean()),
                        "bytes_sum": float(physical_vals.sum()),
                        "rows": int(len(physical_vals)),
                    }
                )
            cat_vals = (
                csr_rows_category.groupby("category", dropna=False)["logical_category_bytes"]
                .sum(min_count=1)
                .reset_index()
            )
            for _, row in cat_vals.iterrows():
                category = str(row.get("category", "")).strip()
                if not category:
                    continue
                vals = pd.to_numeric(
                    csr_rows_category.loc[csr_rows_category["category"] == category, "logical_category_bytes"], errors="coerce"
                ).dropna()
                if len(vals) == 0:
                    continue
                comp_rows.append(
                    {
                        "component_type": "logical",
                        "category": category,
                        "bytes_mean": float(vals.mean()),
                        "bytes_sum": float(vals.sum()),
                        "rows": int(len(vals)),
                    }
                )
            if comp_rows:
                csr_comp = pd.DataFrame(comp_rows)

    tx_size_source = tx_size_df.copy()
    if tx_size_source.empty and not tx_df.empty:
        size_cols = [
            "tx_envelope_bytes",
            "tx_payload_bytes",
            "block_bytes",
            "block_data_bytes",
            "block_overhead_bytes",
            "block_tx_count",
            "block_shared_overhead_per_tx_bytes",
            "tx_index_in_block",
        ]
        if any(col in tx_df.columns for col in size_cols):
            tx_size_source = tx_df.copy()

    if not tx_size_source.empty:
        if "workflow_base" not in tx_size_source.columns:
            tx_size_source["workflow_base"] = tx_size_source.get("workflow", "").map(workflow_base_from_tag)
        tx_size_source["run_id"] = tx_size_source.get("run_id", "").astype(str).str.strip()
        tx_size_source["workflow_base"] = tx_size_source.get("workflow_base", "").astype(str).str.strip()
        tx_size_source["operation_id"] = tx_size_source.get("operation_id", "").astype(str).str.strip()
        tx_size_source["proposal_id"] = tx_size_source.get("proposal_id", "").astype(str).str.strip()
        tx_size_source["action"] = tx_size_source.get("action", "").astype(str).str.strip()
        tx_size_source["event_name"] = tx_size_source.get("event_name", "").astype(str).str.strip()
        tx_size_source["tx_id"] = tx_size_source.get("tx_id", "").astype(str).str.strip()
        tx_size_source["block_number"] = tx_size_source.get("block_number", "").astype(str).str.strip()

        for col in [
            "tx_envelope_bytes",
            "tx_payload_bytes",
            "block_bytes",
            "block_data_bytes",
            "block_overhead_bytes",
            "block_tx_count",
            "block_shared_overhead_per_tx_bytes",
            "tx_index_in_block",
        ]:
            if col in tx_size_source.columns:
                tx_size_source[col] = pd.to_numeric(tx_size_source[col], errors="coerce")
            else:
                tx_size_source[col] = np.nan

        if "block_overhead_bytes" not in tx_size_source.columns:
            tx_size_source["block_overhead_bytes"] = np.nan
        missing_overhead = tx_size_source["block_overhead_bytes"].isna()
        tx_size_source.loc[missing_overhead, "block_overhead_bytes"] = (
            tx_size_source.loc[missing_overhead, "block_bytes"] - tx_size_source.loc[missing_overhead, "block_data_bytes"]
        )
        tx_size_source["block_overhead_bytes"] = tx_size_source["block_overhead_bytes"].clip(lower=0)

        if "block_shared_overhead_per_tx_bytes" not in tx_size_source.columns:
            tx_size_source["block_shared_overhead_per_tx_bytes"] = np.nan
        missing_shared = tx_size_source["block_shared_overhead_per_tx_bytes"].isna()
        denom = tx_size_source.loc[missing_shared, "block_tx_count"]
        numer = tx_size_source.loc[missing_shared, "block_overhead_bytes"]
        tx_size_source.loc[missing_shared & (denom > 0), "block_shared_overhead_per_tx_bytes"] = numer / denom

        tx_size_source = tx_size_source[
            tx_size_source[["tx_envelope_bytes", "block_bytes", "block_tx_count", "block_shared_overhead_per_tx_bytes"]]
            .notna()
            .any(axis=1)
        ].copy()

        tx_size_source["op_ref"] = np.where(
            tx_size_source["operation_id"] != "",
            tx_size_source["operation_id"],
            tx_size_source["proposal_id"],
        )
        tx_size_source["join_key"] = (
            tx_size_source["run_id"]
            + "|"
            + tx_size_source["workflow_base"]
            + "|"
            + tx_size_source["action"]
            + "|"
            + tx_size_source["op_ref"]
        )

        tx_block_breakdown = (
            tx_size_source.groupby(
                ["run_id", "workflow_base", "operation_id", "proposal_id", "action", "join_key"],
                dropna=False,
            )[
                [
                    "tx_envelope_bytes",
                    "tx_payload_bytes",
                    "block_bytes",
                    "block_data_bytes",
                    "block_overhead_bytes",
                    "block_tx_count",
                    "block_shared_overhead_per_tx_bytes",
                ]
            ]
            .max(numeric_only=True)
            .reset_index()
        )

        logical_totals = pd.DataFrame(
            columns=[
                "run_id",
                "workflow_base",
                "operation_id",
                "proposal_id",
                "action",
                "join_key",
                "logical_write_bytes_total",
            ]
        )
        if not logical_breakdown.empty:
            logical_totals = (
                logical_breakdown.groupby(
                    ["run_id", "workflow_base", "operation_id", "proposal_id", "action", "join_key"],
                    dropna=False,
                )["logical_write_bytes_total"]
                .max()
                .reset_index()
            )

        tx_block_breakdown = tx_block_breakdown.merge(
            logical_totals,
            on=["run_id", "workflow_base", "operation_id", "proposal_id", "action", "join_key"],
            how="left",
        )
        tx_block_breakdown["logical_write_bytes_total"] = pd.to_numeric(
            tx_block_breakdown.get("logical_write_bytes_total"),
            errors="coerce",
        )
        tx_block_breakdown["block_allocated_bytes"] = (
            tx_block_breakdown["tx_envelope_bytes"] + tx_block_breakdown["block_shared_overhead_per_tx_bytes"]
        )
        tx_block_breakdown["tx_overhead_vs_logical_bytes"] = (
            tx_block_breakdown["tx_envelope_bytes"] - tx_block_breakdown["logical_write_bytes_total"]
        )
        tx_block_breakdown["block_allocated_overhead_vs_logical_bytes"] = (
            tx_block_breakdown["block_allocated_bytes"] - tx_block_breakdown["logical_write_bytes_total"]
        )
        tx_block_breakdown["tx_to_logical_ratio"] = np.where(
            tx_block_breakdown["logical_write_bytes_total"] > 0,
            tx_block_breakdown["tx_envelope_bytes"] / tx_block_breakdown["logical_write_bytes_total"],
            np.nan,
        )
        tx_block_breakdown["block_allocated_to_logical_ratio"] = np.where(
            tx_block_breakdown["logical_write_bytes_total"] > 0,
            tx_block_breakdown["block_allocated_bytes"] / tx_block_breakdown["logical_write_bytes_total"],
            np.nan,
        )

        tx_block_summary = (
            tx_block_breakdown.groupby(["workflow_base", "action"], dropna=False)[
                [
                    "logical_write_bytes_total",
                    "tx_envelope_bytes",
                    "tx_payload_bytes",
                    "block_shared_overhead_per_tx_bytes",
                    "block_allocated_bytes",
                    "tx_to_logical_ratio",
                    "block_allocated_to_logical_ratio",
                ]
            ]
            .agg(["count", "mean", "median", "sum", "max"])
            .reset_index()
        )
        tx_block_summary = flatten_multiindex_columns(tx_block_summary)
        if "workflow_base_" in tx_block_summary.columns:
            tx_block_summary = tx_block_summary.rename(columns={"workflow_base_": "workflow_base"})
        if "action_" in tx_block_summary.columns:
            tx_block_summary = tx_block_summary.rename(columns={"action_": "action"})

        if not tx_block_breakdown.empty:
            action_means = (
                tx_block_breakdown.groupby(["workflow_base", "action"], dropna=False)[
                    [
                        "logical_write_bytes_total",
                        "tx_envelope_bytes",
                        "block_shared_overhead_per_tx_bytes",
                    ]
                ]
                .mean(numeric_only=True)
                .reset_index()
            )
            if not action_means.empty:
                action_means = sort_by_canonical_action(action_means, workflow_col="workflow_base", action_col="action")
                action_means["logical_write_bytes_total"] = pd.to_numeric(
                    action_means["logical_write_bytes_total"], errors="coerce"
                ).fillna(0)
                action_means["tx_envelope_bytes"] = pd.to_numeric(
                    action_means["tx_envelope_bytes"], errors="coerce"
                ).fillna(0)
                action_means["block_shared_overhead_per_tx_bytes"] = pd.to_numeric(
                    action_means["block_shared_overhead_per_tx_bytes"], errors="coerce"
                ).fillna(0)
                action_means["tx_overhead_bytes"] = (
                    action_means["tx_envelope_bytes"] - action_means["logical_write_bytes_total"]
                ).clip(lower=0)
                for scope in ["combined"]:
                    scope_df = action_means.copy()
                    title_scope = "Combined"
                    out_name = "tx_block_size_components_by_action_combined.png"
                    scope_df["label"] = (
                        scope_df["workflow_base"].astype(str).str.strip()
                        + "|"
                        + scope_df["action"].astype(str).str.strip()
                    )
                    if scope_df.empty:
                        continue
                    fig = plt.figure(figsize=(max(10, len(scope_df) * 0.75), 5.6))
                    x = np.arange(len(scope_df))
                    logical_vals = scope_df["logical_write_bytes_total"].to_numpy()
                    tx_overhead_vals = scope_df["tx_overhead_bytes"].to_numpy()
                    block_vals = scope_df["block_shared_overhead_per_tx_bytes"].to_numpy()
                    plt.bar(x, logical_vals, label="logical_state_write")
                    plt.bar(x, tx_overhead_vals, bottom=logical_vals, label="serialized_tx_overhead")
                    plt.bar(x, block_vals, bottom=logical_vals + tx_overhead_vals, label="allocated_block_overhead")
                    plt.xticks(x, scope_df["label"].astype(str).tolist(), rotation=35, ha="right")
                    plt.ylabel("Bytes (mean per operation)")
                    plt.title(f"Logical + Serialized TX + Block Overhead ({title_scope})")
                    plt.grid(axis="y", alpha=0.3)
                    ax = plt.gca()
                    handles, labels = ax.get_legend_handles_labels()
                    if handles:
                        fig.legend(handles, labels, loc="upper center", ncol=max(1, min(3, len(labels))), bbox_to_anchor=(0.5, 1.04))
                    apply_bytes_axis(ax, axis="y")
                    apply_nonnegative_baseline(ax, np.concatenate([logical_vals, tx_overhead_vals, block_vals]))
                    save_plot(fig, outdir / out_name, export_tikz=export_tikz)
                    # Backward-compatible alias filename: copy from canonical combined artifact.
                    src_png = outdir / out_name
                    alias_png = outdir / "tx_block_size_components_by_action.png"
                    try:
                        shutil.copyfile(src_png, alias_png)
                    except Exception:
                        pass
                    if export_tikz:
                        src_tex = src_png.with_suffix(".tex")
                        alias_tex = alias_png.with_suffix(".tex")
                        if src_tex.exists():
                            try:
                                shutil.copyfile(src_tex, alias_tex)
                            except Exception:
                                pass

            ratio_plot = tx_block_breakdown.copy()
            ratio_long = []
            for metric, label in [
                ("tx_to_logical_ratio", "tx/logical"),
                ("block_allocated_to_logical_ratio", "tx+block/logical"),
            ]:
                vals = pd.to_numeric(ratio_plot.get(metric), errors="coerce")
                if vals is None:
                    continue
                part = ratio_plot[["workflow_base", "action"]].copy()
                part["ratio"] = vals
                part["metric"] = label
                ratio_long.append(part)
            if ratio_long:
                ratio_df = pd.concat(ratio_long, ignore_index=True)
                ratio_df = ratio_df.dropna(subset=["ratio"])
                ratio_df = ratio_df[np.isfinite(ratio_df["ratio"])]
                ratio_df = ratio_df[ratio_df["ratio"] >= 0]
                if not ratio_df.empty:
                    workflow_tokens = ordered_workflows(ratio_df["workflow_base"].dropna().astype(str).str.strip().unique())
                    metric_order = ["tx/logical", "tx+block/logical"]
                    for scope in workflow_tokens + ["combined"]:
                        if scope == "combined":
                            scope_df = ratio_df.copy()
                            title_scope = "Combined"
                            out_dist_name = "tx_block_overhead_ratio_distribution.png"
                            out_bar_name = "tx_block_overhead_ratio_by_action_combined.png"
                        else:
                            scope_df = ratio_df[ratio_df["workflow_base"].astype(str).str.strip() == scope].copy()
                            # Per request: no per-workflow overhead-ratio distribution/means diagrams.
                            continue
                        if scope_df.empty:
                            continue

                        labels = []
                        groups = []
                        if scope == "combined":
                            for wf in workflow_tokens:
                                wf_df = scope_df[scope_df["workflow_base"].astype(str).str.strip() == wf]
                                ordered_actions = ordered_actions_for_workflow(
                                    wf, wf_df["action"].astype(str).str.strip().unique()
                                )
                                for action in ordered_actions:
                                    for metric in metric_order:
                                        vals = wf_df[
                                            (wf_df["action"].astype(str).str.strip() == action)
                                            & (wf_df["metric"].astype(str).str.strip() == metric)
                                        ]["ratio"].dropna()
                                        if len(vals) == 0:
                                            continue
                                        labels.append(f"{wf}|{action}|{metric}")
                                        groups.append(vals)
                        else:
                            ordered_actions = ordered_actions_for_workflow(
                                scope,
                                scope_df["action"].astype(str).str.strip().unique(),
                            )
                            for action in ordered_actions:
                                for metric in metric_order:
                                    vals = scope_df[
                                        (scope_df["action"].astype(str).str.strip() == action)
                                        & (scope_df["metric"].astype(str).str.strip() == metric)
                                    ]["ratio"].dropna()
                                    if len(vals) == 0:
                                        continue
                                    labels.append(f"{action}|{metric}")
                                    groups.append(vals)
                        if groups:
                            fig, ax = plt.subplots(figsize=(max(10, len(labels) * 0.75), 5.2))
                            boxplot_with_labels(ax, groups, labels, showfliers=False)
                            ax.set_ylabel("Ratio")
                            ax.set_title(f"Serialized TX/Block Overhead Ratio Distribution ({title_scope})")
                            ax.tick_params(axis="x", rotation=35)
                            ax.grid(axis="y", alpha=0.3)
                            apply_nonnegative_baseline(
                                ax,
                                np.concatenate([vals.to_numpy(dtype=float) for vals in groups]),
                                boxplot=True,
                            )
                            save_plot(fig, outdir / out_dist_name, export_tikz=export_tikz)

                        # Per request: do not emit per-workflow "tx_block_overhead_ratio_by_action_<workflow>" charts.
                        if scope != "combined":
                            continue

                        if scope == "combined":
                            ratio_means = (
                                scope_df.groupby(["workflow_base", "action", "metric"], dropna=False)["ratio"]
                                .mean(numeric_only=True)
                                .reset_index()
                            )
                        else:
                            ratio_means = (
                                scope_df.groupby(["action", "metric"], dropna=False)["ratio"]
                                .mean(numeric_only=True)
                                .reset_index()
                            )
                        if ratio_means.empty:
                            continue
                        if scope == "combined":
                            ratio_means = sort_by_canonical_action(
                                ratio_means,
                                workflow_col="workflow_base",
                                action_col="action",
                            )
                            ratio_means["label"] = (
                                ratio_means["workflow_base"].astype(str).str.strip()
                                + "|"
                                + ratio_means["action"].astype(str).str.strip()
                            )
                        else:
                            ordered_actions = ordered_actions_for_workflow(
                                scope,
                                ratio_means["action"].astype(str).str.strip().unique(),
                            )
                            ratio_means["action_order"] = ratio_means["action"].map(
                                lambda a: ordered_actions.index(str(a).strip()) if str(a).strip() in ordered_actions else 9999
                            )
                            ratio_means = ratio_means.sort_values(["action_order", "action", "metric"])
                            ratio_means["label"] = ratio_means["action"].astype(str).str.strip()

                        pivot = ratio_means.pivot_table(index="label", columns="metric", values="ratio", aggfunc="mean").fillna(0)
                        if pivot.empty:
                            continue
                        fig = plt.figure(figsize=(max(9, len(pivot) * 0.8), 5.0))
                        x = np.arange(len(pivot))
                        width = 0.38
                        left_vals = pd.to_numeric(pivot.get("tx/logical", 0), errors="coerce").fillna(0).to_numpy()
                        right_vals = pd.to_numeric(pivot.get("tx+block/logical", 0), errors="coerce").fillna(0).to_numpy()
                        plt.bar(x - width / 2, left_vals, width=width, label="tx/logical")
                        plt.bar(x + width / 2, right_vals, width=width, label="tx+block/logical")
                        plt.xticks(x, pivot.index.astype(str).tolist(), rotation=35, ha="right")
                        plt.ylabel("Mean ratio")
                        plt.title(f"Serialized TX/Block Overhead Ratio Means ({title_scope})")
                        plt.grid(axis="y", alpha=0.3)
                        ax = plt.gca()
                        handles, labels = ax.get_legend_handles_labels()
                        if handles:
                            fig.legend(handles, labels, loc="upper center", ncol=2, bbox_to_anchor=(0.5, 1.03))
                        apply_nonnegative_baseline(ax, np.concatenate([left_vals, right_vals]))
                        save_plot(fig, outdir / out_bar_name, export_tikz=export_tikz)

    # Peer-volume composition: stage contribution + tx/block overhead decomposition.
    if not stage_df.empty and "peer_volume_delta_bytes" in stage_df.columns and "stage_end" in stage_df.columns:
        stage_peer = stage_df.copy()
        if "workflow_base" not in stage_peer.columns:
            stage_peer["workflow_base"] = stage_peer.get("workflow", "").map(workflow_base_from_tag)
        stage_peer["run_id"] = stage_peer.get("run_id", "").astype(str).str.strip()
        stage_peer["workflow_base"] = stage_peer.get("workflow_base", "").astype(str).str.strip()
        stage_peer["operation_id"] = stage_peer.get("operation_id", "").astype(str).str.strip()
        stage_peer["proposal_id"] = stage_peer.get("proposal_id", "").astype(str).str.strip()
        stage_peer["stage_end"] = stage_peer.get("stage_end", "").astype(str).str.strip()
        stage_peer["peer_volume_delta_bytes"] = pd.to_numeric(stage_peer.get("peer_volume_delta_bytes"), errors="coerce")
        if "path" in stage_peer.columns:
            path_norm = stage_peer["path"].astype(str).str.strip().str.rstrip("/")
            vol_rows = stage_peer[path_norm.str.endswith("/volumes")].copy()
            if not vol_rows.empty:
                stage_peer = vol_rows
        stage_peer["action"] = stage_peer["stage_end"].map(action_from_stage)
        stage_peer["op_ref"] = np.where(
            stage_peer["operation_id"] != "",
            stage_peer["operation_id"],
            stage_peer["proposal_id"],
        )
        stage_peer["join_key"] = (
            stage_peer["run_id"]
            + "|"
            + stage_peer["workflow_base"]
            + "|"
            + stage_peer["action"]
            + "|"
            + stage_peer["op_ref"]
        )
        stage_peer = stage_peer[stage_peer["action"].astype(str).str.strip() != ""].copy()

        base_key_cols = ["run_id", "workflow_base", "operation_id", "proposal_id", "action", "join_key", "op_ref"]

        peer_store_path = suite_root / "suite_storage_stage_peer_ledger_deltas_all_runs.csv"
        peer_store_df = safe_read_csv(peer_store_path)
        peer_store_action = pd.DataFrame(
            columns=base_key_cols + ["block_files_bytes", "block_index_bytes", "leveldb_bytes", "peer_store_other_bytes"]
        )
        peer_store_operation = pd.DataFrame(
            columns=[
                "run_id",
                "workflow_base",
                "op_ref",
                "block_files_bytes",
                "block_index_bytes",
                "leveldb_bytes",
                "peer_store_other_bytes",
            ]
        )
        if not peer_store_df.empty:
            if "workflow_base" not in peer_store_df.columns:
                peer_store_df["workflow_base"] = peer_store_df.get("workflow", "").map(workflow_base_from_tag)
            if "run_id" not in peer_store_df.columns:
                peer_store_df["run_id"] = ""
            if "operation_id" not in peer_store_df.columns:
                peer_store_df["operation_id"] = ""
            if "proposal_id" not in peer_store_df.columns:
                peer_store_df["proposal_id"] = ""
            if "component" in peer_store_df.columns:
                peer_store_df = peer_store_df[peer_store_df["component"].astype(str).str.strip() == "peer"].copy()
            if "path" in peer_store_df.columns:
                pnorm = peer_store_df["path"].astype(str).str.strip().str.rstrip("/")
                peer_store_df = peer_store_df[pnorm.str.endswith("/volumes")].copy()
            peer_store_df["run_id"] = peer_store_df["run_id"].astype(str).str.strip()
            peer_store_df["workflow_base"] = peer_store_df["workflow_base"].astype(str).str.strip()
            peer_store_df["operation_id"] = peer_store_df["operation_id"].astype(str).str.strip()
            peer_store_df["proposal_id"] = peer_store_df["proposal_id"].astype(str).str.strip()
            peer_store_df["op_ref"] = np.where(
                peer_store_df["operation_id"] != "",
                peer_store_df["operation_id"],
                peer_store_df["proposal_id"],
            )
            if "stage_end" not in peer_store_df.columns:
                peer_store_df["stage_end"] = ""
            peer_store_df["stage_end"] = peer_store_df["stage_end"].astype(str).str.strip()
            peer_store_df["action"] = peer_store_df["stage_end"].map(action_from_stage)
            peer_store_df["join_key"] = (
                peer_store_df["run_id"]
                + "|"
                + peer_store_df["workflow_base"]
                + "|"
                + peer_store_df["action"]
                + "|"
                + peer_store_df["op_ref"]
            )
            peer_store_df = peer_store_df[peer_store_df["action"].astype(str).str.strip() != ""].copy()
            peer_store_cols = [
                "block_files_delta_bytes",
                "block_index_delta_bytes",
                "leveldb_data_delta_bytes",
                "leveldb_wal_meta_delta_bytes",
                "peer_store_other_delta_bytes",
            ]
            for col in peer_store_cols:
                if col not in peer_store_df.columns:
                    peer_store_df[col] = 0
                peer_store_df[col] = pd.to_numeric(peer_store_df[col], errors="coerce").fillna(0)
            peer_store_action = (
                peer_store_df.groupby(base_key_cols, dropna=False)[peer_store_cols]
                .sum(min_count=1)
                .reset_index()
                .rename(
                    columns={
                        "block_files_delta_bytes": "block_files_bytes",
                        "block_index_delta_bytes": "block_index_bytes",
                        "peer_store_other_delta_bytes": "peer_store_other_bytes",
                    }
                )
            )
            peer_store_action["leveldb_bytes"] = (
                pd.to_numeric(peer_store_action.get("leveldb_data_delta_bytes"), errors="coerce").fillna(0)
                + pd.to_numeric(peer_store_action.get("leveldb_wal_meta_delta_bytes"), errors="coerce").fillna(0)
            )
            peer_store_action = peer_store_action[
                base_key_cols + ["block_files_bytes", "block_index_bytes", "leveldb_bytes", "peer_store_other_bytes"]
            ].copy()

            peer_store_operation = (
                peer_store_action.groupby(["run_id", "workflow_base", "op_ref"], dropna=False)[
                    ["block_files_bytes", "block_index_bytes", "leveldb_bytes", "peer_store_other_bytes"]
                ]
                .sum(min_count=1)
                .reset_index()
            )
            peer_store_operation = peer_store_operation[
                [
                    "run_id",
                    "workflow_base",
                    "op_ref",
                    "block_files_bytes",
                    "block_index_bytes",
                    "leveldb_bytes",
                    "peer_store_other_bytes",
                ]
            ].copy()
        stage_breakdown_action = (
            stage_peer.groupby(base_key_cols + ["stage_end"], dropna=False)["peer_volume_delta_bytes"]
            .sum(min_count=1)
            .reset_index()
            .rename(columns={"peer_volume_delta_bytes": "stage_peer_bytes"})
        )
        peer_stage = (
            stage_breakdown_action.groupby(base_key_cols, dropna=False)["stage_peer_bytes"]
            .sum(min_count=1)
            .reset_index()
            .rename(columns={"stage_peer_bytes": "peer_stage_bytes"})
        )

        logical_action_totals = pd.DataFrame(columns=base_key_cols + ["logical_write_bytes_total"])
        if not logical_breakdown.empty:
            logical_action_totals = (
                logical_breakdown.groupby(
                    ["run_id", "workflow_base", "operation_id", "proposal_id", "action", "join_key"],
                    dropna=False,
                )["logical_write_bytes_total"]
                .max()
                .reset_index()
            )
            logical_action_totals["operation_id"] = logical_action_totals["operation_id"].astype(str).str.strip()
            logical_action_totals["proposal_id"] = logical_action_totals["proposal_id"].astype(str).str.strip()
            logical_action_totals["op_ref"] = np.where(
                logical_action_totals["operation_id"] != "",
                logical_action_totals["operation_id"],
                logical_action_totals["proposal_id"],
            )

        tx_action_totals = pd.DataFrame(columns=base_key_cols + ["tx_envelope_bytes", "block_shared_overhead_per_tx_bytes"])
        if not tx_size_source.empty:
            tx_comp = tx_size_source.copy()
            if "workflow_base" not in tx_comp.columns:
                tx_comp["workflow_base"] = tx_comp.get("workflow", "").map(workflow_base_from_tag)
            tx_comp["run_id"] = tx_comp.get("run_id", "").astype(str).str.strip()
            tx_comp["workflow_base"] = tx_comp.get("workflow_base", "").astype(str).str.strip()
            tx_comp["operation_id"] = tx_comp.get("operation_id", "").astype(str).str.strip()
            tx_comp["proposal_id"] = tx_comp.get("proposal_id", "").astype(str).str.strip()
            tx_comp["action"] = tx_comp.get("action", "").astype(str).str.strip()
            tx_comp["tx_id"] = tx_comp.get("tx_id", "").astype(str).str.strip()
            tx_comp["block_number"] = tx_comp.get("block_number", "").astype(str).str.strip()
            tx_comp["tx_index_in_block"] = pd.to_numeric(tx_comp.get("tx_index_in_block"), errors="coerce")
            tx_comp["tx_envelope_bytes"] = pd.to_numeric(tx_comp.get("tx_envelope_bytes"), errors="coerce")
            tx_comp["block_shared_overhead_per_tx_bytes"] = pd.to_numeric(
                tx_comp.get("block_shared_overhead_per_tx_bytes"), errors="coerce"
            )
            tx_comp["op_ref"] = np.where(
                tx_comp["operation_id"] != "",
                tx_comp["operation_id"],
                tx_comp["proposal_id"],
            )
            tx_comp["join_key"] = (
                tx_comp["run_id"]
                + "|"
                + tx_comp["workflow_base"]
                + "|"
                + tx_comp["action"]
                + "|"
                + tx_comp["op_ref"]
            )
            tx_comp = tx_comp[tx_comp["action"] != ""].copy()
            dedup_cols = [
                "run_id",
                "workflow_base",
                "action",
                "join_key",
                "tx_id",
                "block_number",
                "tx_index_in_block",
                "tx_envelope_bytes",
                "block_shared_overhead_per_tx_bytes",
            ]
            dedup_cols = [c for c in dedup_cols if c in tx_comp.columns]
            tx_unique = tx_comp.drop_duplicates(subset=dedup_cols, keep="first")
            tx_action_totals = (
                tx_unique.groupby(
                    ["run_id", "workflow_base", "operation_id", "proposal_id", "action", "join_key", "op_ref"],
                    dropna=False,
                )[["tx_envelope_bytes", "block_shared_overhead_per_tx_bytes"]]
                .sum(min_count=1)
                .reset_index()
            )

        peer_comp_action = peer_stage.merge(
            logical_action_totals[
                ["run_id", "workflow_base", "operation_id", "proposal_id", "action", "join_key", "op_ref", "logical_write_bytes_total"]
            ],
            on=base_key_cols,
            how="left",
        )
        peer_comp_action = peer_comp_action.merge(
            tx_action_totals[
                [
                    "run_id",
                    "workflow_base",
                    "operation_id",
                    "proposal_id",
                    "action",
                    "join_key",
                    "op_ref",
                    "tx_envelope_bytes",
                    "block_shared_overhead_per_tx_bytes",
                ]
            ],
            on=base_key_cols,
            how="left",
        )
        peer_comp_action = peer_comp_action.merge(
            peer_store_action[
                base_key_cols + ["block_files_bytes", "block_index_bytes", "leveldb_bytes", "peer_store_other_bytes"]
            ],
            on=base_key_cols,
            how="left",
        )
        for col in [
            "peer_stage_bytes",
            "logical_write_bytes_total",
            "tx_envelope_bytes",
            "block_shared_overhead_per_tx_bytes",
            "block_files_bytes",
            "block_index_bytes",
            "leveldb_bytes",
            "peer_store_other_bytes",
        ]:
            peer_comp_action[col] = pd.to_numeric(peer_comp_action.get(col), errors="coerce").fillna(0)
        peer_comp_action["tx_overhead_bytes"] = (
            peer_comp_action["tx_envelope_bytes"] - peer_comp_action["logical_write_bytes_total"]
        ).clip(lower=0)
        peer_comp_action["block_overhead_bytes"] = peer_comp_action["block_shared_overhead_per_tx_bytes"].clip(lower=0)
        peer_comp_action["block_accounted_bytes"] = (
            peer_comp_action["logical_write_bytes_total"]
            + peer_comp_action["tx_overhead_bytes"]
            + peer_comp_action["block_overhead_bytes"]
        )
        peer_comp_action["block_files_additional_bytes"] = (
            peer_comp_action["block_files_bytes"] - peer_comp_action["block_accounted_bytes"]
        ).clip(lower=0)
        peer_comp_action["other_peer_blockchain_bytes"] = (
            peer_comp_action["peer_stage_bytes"]
            - peer_comp_action["logical_write_bytes_total"]
            - peer_comp_action["tx_overhead_bytes"]
            - peer_comp_action["block_overhead_bytes"]
        )
        peer_comp_action["other_peer_blockchain_bytes_clipped"] = peer_comp_action["other_peer_blockchain_bytes"].clip(lower=0)

        stage_residual = stage_breakdown_action.merge(
            peer_comp_action[base_key_cols + ["peer_stage_bytes", "other_peer_blockchain_bytes_clipped"]],
            on=base_key_cols,
            how="left",
        )
        for col in ["peer_stage_bytes", "other_peer_blockchain_bytes_clipped", "stage_peer_bytes"]:
            stage_residual[col] = pd.to_numeric(stage_residual.get(col), errors="coerce").fillna(0)
        stage_residual["stage_share"] = np.where(
            stage_residual["peer_stage_bytes"] > 0,
            stage_residual["stage_peer_bytes"] / stage_residual["peer_stage_bytes"],
            0.0,
        )
        stage_residual["allocated_residual_bytes"] = (
            stage_residual["other_peer_blockchain_bytes_clipped"] * stage_residual["stage_share"]
        )
        stage_residual["residual_bucket"] = stage_residual["stage_end"].map(stage_residual_bucket)

        residual_cols = [
            "governance_residual_bytes",
            "voting_residual_bytes",
            "reshare_residual_bytes",
            "operation_end_residual_bytes",
        ]
        residual_wide = pd.DataFrame(columns=base_key_cols + residual_cols)
        if not stage_residual.empty:
            residual_wide = (
                stage_residual.groupby(base_key_cols + ["residual_bucket"], dropna=False)["allocated_residual_bytes"]
                .sum(min_count=1)
                .reset_index()
                .pivot_table(
                    index=base_key_cols,
                    columns="residual_bucket",
                    values="allocated_residual_bytes",
                    aggfunc="sum",
                    fill_value=0,
                )
                .reset_index()
            )
            residual_wide.columns = [str(c) if not isinstance(c, tuple) else str(c[-1]) for c in residual_wide.columns]
        rename_map = {
            "governance_residual": "governance_residual_bytes",
            "voting_residual": "voting_residual_bytes",
            "reshare_residual": "reshare_residual_bytes",
            "operation_end_residual": "operation_end_residual_bytes",
        }
        residual_wide = residual_wide.rename(columns=rename_map)
        for col in residual_cols:
            if col not in residual_wide.columns:
                residual_wide[col] = 0.0
        if not residual_wide.empty:
            peer_comp_action = peer_comp_action.merge(
                residual_wide[base_key_cols + residual_cols],
                on=base_key_cols,
                how="left",
            )
        for col in residual_cols:
            peer_comp_action[col] = pd.to_numeric(peer_comp_action.get(col), errors="coerce").fillna(0)
        peer_comp_action["residual_known_total_bytes"] = peer_comp_action[residual_cols].sum(axis=1, min_count=1)
        peer_comp_action["residual_unattributed_bytes"] = (
            peer_comp_action["other_peer_blockchain_bytes_clipped"] - peer_comp_action["residual_known_total_bytes"]
        ).clip(lower=0)

        op_keys = ["run_id", "workflow_base", "op_ref"]
        peer_comp_operation = (
            peer_comp_action.groupby(op_keys, dropna=False)[
                [
                    "peer_stage_bytes",
                    "logical_write_bytes_total",
                    "tx_overhead_bytes",
                    "block_overhead_bytes",
                    "block_accounted_bytes",
                    "block_files_additional_bytes",
                    "block_files_bytes",
                    "block_index_bytes",
                    "leveldb_bytes",
                    "peer_store_other_bytes",
                    "other_peer_blockchain_bytes",
                    "other_peer_blockchain_bytes_clipped",
                    "residual_known_total_bytes",
                    "residual_unattributed_bytes",
                    *residual_cols,
                ]
            ]
            .sum(min_count=1)
            .reset_index()
        )
        for col in [
            "block_accounted_bytes",
            "block_files_additional_bytes",
            "block_files_bytes",
            "block_index_bytes",
            "leveldb_bytes",
            "peer_store_other_bytes",
        ]:
            peer_comp_operation[col] = pd.to_numeric(peer_comp_operation.get(col), errors="coerce").fillna(0)
        # Backward-compatible alias.
        peer_comp_operation["block_files_overhead_bytes"] = peer_comp_operation["block_files_additional_bytes"]

        peer_comp_workflow = (
            peer_comp_operation.groupby("workflow_base", dropna=False)[
                [
                    "peer_stage_bytes",
                    "logical_write_bytes_total",
                    "tx_overhead_bytes",
                    "block_overhead_bytes",
                    "block_accounted_bytes",
                    "block_files_additional_bytes",
                    "other_peer_blockchain_bytes",
                    "other_peer_blockchain_bytes_clipped",
                    "residual_known_total_bytes",
                    "residual_unattributed_bytes",
                    "block_files_bytes",
                    "block_index_bytes",
                    "leveldb_bytes",
                    "peer_store_other_bytes",
                    "block_files_overhead_bytes",
                    *residual_cols,
                ]
            ]
            .agg(["count", "mean", "median", "sum", "max"])
            .reset_index()
        )
        peer_comp_workflow = flatten_multiindex_columns(peer_comp_workflow)
        if "workflow_base_" in peer_comp_workflow.columns:
            peer_comp_workflow = peer_comp_workflow.rename(columns={"workflow_base_": "workflow_base"})

        peer_stage_detailed = (
            stage_peer.groupby(["workflow_base", "stage_end"], dropna=False)["peer_volume_delta_bytes"]
            .agg(["count", "mean", "median", "sum", "max"])
            .reset_index()
        )
        if not peer_stage_detailed.empty:
            for c in ["count", "mean", "median", "sum", "max"]:
                peer_stage_detailed[c] = pd.to_numeric(peer_stage_detailed[c], errors="coerce")
            # Drop empty/no-op stage rows to avoid misleading zero bars such as csr|operation_end.
            peer_stage_detailed = peer_stage_detailed[
                (peer_stage_detailed["mean"].abs() > 0)
                | (peer_stage_detailed["sum"].abs() > 0)
                | (peer_stage_detailed["max"].abs() > 0)
            ].copy()
        if not peer_stage_detailed.empty:
            peer_stage_detailed["stage_order_key"] = peer_stage_detailed.apply(
                lambda r: canonical_stage_order_key(r.get("workflow_base", ""), r.get("stage_end", "")),
                axis=1,
            )
            peer_stage_detailed = peer_stage_detailed.sort_values(
                ["workflow_base", "stage_order_key", "stage_end"]
            ).drop(columns=["stage_order_key"])

        peer_residual_action = (
            peer_comp_action.groupby(["workflow_base", "action"], dropna=False)[residual_cols]
            .mean(numeric_only=True)
            .reset_index()
        )
        peer_residual_action = sort_by_canonical_action(
            peer_residual_action, workflow_col="workflow_base", action_col="action"
        )
        peer_residual_workflow = (
            peer_comp_action.groupby("workflow_base", dropna=False)[residual_cols]
            .mean(numeric_only=True)
            .reset_index()
        )
        if not peer_residual_workflow.empty:
            wf_order = ordered_workflows(peer_residual_workflow["workflow_base"].astype(str).str.strip().unique())
            peer_residual_workflow["workflow_order"] = peer_residual_workflow["workflow_base"].map(
                lambda wf: wf_order.index(str(wf).strip()) if str(wf).strip() in wf_order else 9999
            )
            peer_residual_workflow = (
                peer_residual_workflow.sort_values(["workflow_order", "workflow_base"]).drop(columns=["workflow_order"])
            )

        wf_plot = (
            peer_comp_operation.groupby("workflow_base", dropna=False)[
                [
                    "block_accounted_bytes",
                    "block_files_additional_bytes",
                    "block_index_bytes",
                    "leveldb_bytes",
                    "peer_store_other_bytes",
                ]
            ]
            .mean(numeric_only=True)
            .reset_index()
        )
        if not wf_plot.empty:
            wf_value_cols = [
                "block_accounted_bytes",
                "block_files_additional_bytes",
                "block_index_bytes",
                "leveldb_bytes",
                "peer_store_other_bytes",
            ]
            wf_plot["component_total_bytes"] = wf_plot[wf_value_cols].sum(axis=1, min_count=1)
            wf_plot = wf_plot[pd.to_numeric(wf_plot["component_total_bytes"], errors="coerce").fillna(0) > 0].copy()
            wf_plot = wf_plot.drop(columns=["component_total_bytes"])
        if not wf_plot.empty:
            wf_order = ordered_workflows(wf_plot["workflow_base"].astype(str).str.strip().unique())
            wf_plot["workflow_order"] = wf_plot["workflow_base"].map(
                lambda wf: wf_order.index(str(wf).strip()) if str(wf).strip() in wf_order else 9999
            )
            wf_plot = wf_plot.sort_values(["workflow_order", "workflow_base"]).drop(columns=["workflow_order"])
            fig = plt.figure(figsize=(11.8, 5.6))
            x = np.arange(len(wf_plot))
            stack_cols = [
                ("block_accounted_bytes", "block_accounted(state+tx+block_overhead)"),
                ("block_files_additional_bytes", "block_files_additional"),
                ("block_index_bytes", "block_index"),
                ("leveldb_bytes", "leveldb"),
                ("peer_store_other_bytes", "other"),
            ]
            active_cols = []
            for col, _label in stack_cols:
                total_col = float(pd.to_numeric(wf_plot[col], errors="coerce").fillna(0).sum())
                if total_col > 0:
                    active_cols.append((col, _label))
            if not active_cols:
                active_cols = stack_cols[:3]
            bottom = np.zeros(len(wf_plot), dtype=float)
            plotted = []
            for col, label in active_cols:
                vals = pd.to_numeric(wf_plot[col], errors="coerce").fillna(0).to_numpy()
                plt.bar(x, vals, bottom=bottom, label=label)
                bottom = bottom + vals
                plotted.append(vals)
            plt.xticks(x, wf_plot["workflow_base"].astype(str).tolist())
            plt.ylabel("Bytes (mean per operation)")
            plt.title("Peer Volume Composition by Workflow")
            plt.grid(axis="y", alpha=0.3)
            ax = plt.gca()
            handles, labels = ax.get_legend_handles_labels()
            if handles:
                fig.legend(handles, labels, loc="upper center", ncol=max(1, min(3, len(labels))), bbox_to_anchor=(0.5, 1.06))
            fig.subplots_adjust(top=0.80)
            apply_bytes_axis(ax, axis="y")
            apply_nonnegative_baseline(ax, np.concatenate(plotted))
            save_plot(fig, outdir / "peer_volume_composition_by_workflow.png", export_tikz=export_tikz)

            # Per request: keep stage contribution CSV only; do not emit per-workflow detailed charts.

        action_plot = (
            peer_comp_action.groupby(["workflow_base", "action"], dropna=False)[
                [
                    "block_accounted_bytes",
                    "block_files_additional_bytes",
                    "block_index_bytes",
                    "leveldb_bytes",
                    "peer_store_other_bytes",
                ]
            ]
            .mean(numeric_only=True)
            .reset_index()
        )
        if not action_plot.empty:
            action_value_cols = [
                "block_accounted_bytes",
                "block_files_additional_bytes",
                "block_index_bytes",
                "leveldb_bytes",
                "peer_store_other_bytes",
            ]
            action_plot["component_total_bytes"] = action_plot[action_value_cols].sum(axis=1, min_count=1)
            action_plot = action_plot[pd.to_numeric(action_plot["component_total_bytes"], errors="coerce").fillna(0) > 0].copy()
            action_plot = action_plot.drop(columns=["component_total_bytes"])
        if not action_plot.empty:
            action_plot = sort_by_canonical_action(
                action_plot,
                workflow_col="workflow_base",
                action_col="action",
            )
            workflow_tokens = ordered_workflows(action_plot["workflow_base"].astype(str).str.strip().unique())
            for scope in workflow_tokens:
                scope_df = action_plot[action_plot["workflow_base"].astype(str).str.strip() == scope].copy()
                ordered_actions = ordered_actions_for_workflow(
                    scope,
                    scope_df["action"].astype(str).str.strip().unique(),
                )
                scope_df["action_order"] = scope_df["action"].map(
                    lambda a: ordered_actions.index(str(a).strip()) if str(a).strip() in ordered_actions else 9999
                )
                scope_df = scope_df.sort_values(["action_order", "action"])
                scope_df["label"] = scope_df["action"].astype(str).str.strip()
                out_name = f"peer_volume_composition_by_workflow_action_{scope}.png"
                title = f"{scope}: Peer Volume Composition by Action"
                if scope_df.empty:
                    continue
                fig = plt.figure(figsize=(max(9.6, len(scope_df) * 0.72), 5.4))
                x = np.arange(len(scope_df))
                stack_cols = [
                    ("block_accounted_bytes", "block_accounted(state+tx+block_overhead)"),
                    ("block_files_additional_bytes", "block_files_additional"),
                    ("block_index_bytes", "block_index"),
                    ("leveldb_bytes", "leveldb"),
                    ("peer_store_other_bytes", "other"),
                ]
                active_cols = []
                for col, _label in stack_cols:
                    total_col = float(pd.to_numeric(scope_df[col], errors="coerce").fillna(0).sum())
                    if total_col > 0:
                        active_cols.append((col, _label))
                if not active_cols:
                    active_cols = stack_cols[:3]
                bottom = np.zeros(len(scope_df), dtype=float)
                plotted = []
                for col, label in active_cols:
                    vals = pd.to_numeric(scope_df[col], errors="coerce").fillna(0).to_numpy()
                    plt.bar(x, vals, bottom=bottom, label=label)
                    bottom = bottom + vals
                    plotted.append(vals)
                plt.xticks(x, scope_df["label"].astype(str).tolist(), rotation=28, ha="right")
                plt.ylabel("Bytes (mean per operation)")
                plt.title(title)
                plt.grid(axis="y", alpha=0.3)
                ax = plt.gca()
                handles, labels = ax.get_legend_handles_labels()
                if handles:
                    fig.legend(handles, labels, loc="upper center", ncol=max(1, min(4, len(labels))), bbox_to_anchor=(0.5, 1.05))
                fig.subplots_adjust(top=0.80)
                apply_bytes_axis(ax, axis="y")
                apply_nonnegative_baseline(ax, np.concatenate(plotted))
                save_plot(fig, outdir / out_name, export_tikz=export_tikz)

        # Remove obsolete combined files so re-analysis doesn't leave stale oversized plots behind.
        for stale_name in [
            "peer_volume_stage_contribution_detailed_combined.png",
            "peer_volume_stage_contribution_detailed_combined.tex",
            "peer_volume_composition_by_workflow_action_combined.png",
            "peer_volume_composition_by_workflow_action_combined.tex",
            "peer_volume_composition_by_workflow_action.png",
            "peer_volume_composition_by_workflow_action.tex",
            "peer_ledger_store_composition_by_workflow.png",
            "peer_ledger_store_composition_by_workflow.tex",
        ]:
            stale_path = outdir / stale_name
            if stale_path.exists():
                try:
                    stale_path.unlink()
                except Exception:
                    pass

        # Remove stale per-workflow diagrams that are intentionally no longer emitted.
        deprecated_workflow_plots = [
            "peer_volume_stage_contribution_detailed_*.png",
            "peer_volume_stage_contribution_detailed_*.tex",
            "peer_ledger_store_stage_breakdown_*.png",
            "peer_ledger_store_stage_breakdown_*.tex",
        ]
        for pattern in deprecated_workflow_plots:
            for stale_path in outdir.glob(pattern):
                try:
                    stale_path.unlink()
                except Exception:
                    pass

        for wf in ["csr", "revocation", "removal", "join"]:
            for suffix in [".png", ".tex"]:
                stale_path = outdir / f"storage_logical_action_distribution_{wf}{suffix}"
                if stale_path.exists():
                    try:
                        stale_path.unlink()
                    except Exception:
                        pass
                stale_path = outdir / f"storage_logical_action_means_{wf}{suffix}"
                if stale_path.exists():
                    try:
                        stale_path.unlink()
                    except Exception:
                        pass
                stale_path = outdir / f"tx_block_overhead_ratio_distribution_{wf}{suffix}"
                if stale_path.exists():
                    try:
                        stale_path.unlink()
                    except Exception:
                        pass
                for base in ["tx_block_size_components_by_action_", "tx_block_overhead_ratio_by_action_"]:
                    stale_path = outdir / f"{base}{wf}{suffix}"
                    if stale_path.exists():
                        try:
                            stale_path.unlink()
                        except Exception:
                            pass

    logical_breakdown.to_csv(logical_breakdown_out, index=False)
    logical_summary.to_csv(logical_summary_out, index=False)
    logical_category_summary.to_csv(logical_category_summary_out, index=False)
    merged.to_csv(logical_vs_physical_out, index=False)
    amplification.to_csv(amplification_out, index=False)
    csr_comp.to_csv(csr_comp_out, index=False)
    tx_block_breakdown.to_csv(tx_block_breakdown_out, index=False)
    tx_block_summary.to_csv(tx_block_summary_out, index=False)
    peer_comp_action.to_csv(peer_comp_action_out, index=False)
    peer_comp_operation.to_csv(peer_comp_operation_out, index=False)
    peer_comp_workflow.to_csv(peer_comp_workflow_out, index=False)
    peer_stage_detailed.to_csv(peer_stage_detailed_out, index=False)
    peer_residual_action.to_csv(peer_residual_action_out, index=False)
    peer_residual_workflow.to_csv(peer_residual_workflow_out, index=False)

    print(f"Wrote: {logical_breakdown_out}")
    print(f"Wrote: {logical_summary_out}")
    print(f"Wrote: {logical_category_summary_out}")
    print(f"Wrote: {logical_vs_physical_out}")
    print(f"Wrote: {amplification_out}")
    print(f"Wrote: {csr_comp_out}")
    print(f"Wrote: {tx_block_breakdown_out}")
    print(f"Wrote: {tx_block_summary_out}")
    print(f"Wrote: {peer_comp_action_out}")
    print(f"Wrote: {peer_comp_operation_out}")
    print(f"Wrote: {peer_comp_workflow_out}")
    print(f"Wrote: {peer_stage_detailed_out}")
    print(f"Wrote: {peer_residual_action_out}")
    print(f"Wrote: {peer_residual_workflow_out}")
