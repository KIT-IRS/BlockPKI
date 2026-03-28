#!/usr/bin/env python3
"""Workflow/resource/query/communication analysis stages for benchmark suites.

Runtime flow: imported by analyze_suite and executed in the same stage order
as the legacy monolithic analyzer.
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

if __package__:
    from .analyze_common import (
        MIXED_EPSILON_SECONDS,
        _rgb01,
        apply_bytes_axis,
        apply_nonnegative_baseline,
        boxplot_with_labels,
        duration_seconds,
        flatten_multiindex_columns,
        ordered_workflows,
        parse_counter_map,
        run_num_from_id,
        safe_read_csv,
        save_plot,
        to_datetime_utc,
        trailing_int_token,
        workflow_base_from_tag,
    )
    from .latency_model import MIXED_EPSILON_SECONDS as LATENCY_MIXED_EPSILON_SECONDS, derive_latency_components
else:
    from analyze_common import (
        MIXED_EPSILON_SECONDS,
        _rgb01,
        apply_bytes_axis,
        apply_nonnegative_baseline,
        boxplot_with_labels,
        duration_seconds,
        flatten_multiindex_columns,
        ordered_workflows,
        parse_counter_map,
        run_num_from_id,
        safe_read_csv,
        save_plot,
        to_datetime_utc,
        trailing_int_token,
        workflow_base_from_tag,
    )
    from latency_model import MIXED_EPSILON_SECONDS as LATENCY_MIXED_EPSILON_SECONDS, derive_latency_components


def resolve_suite_workflow_runs_path(suite_root: Path) -> Path:
    """resolve_suite_workflow_runs_path helper for benchmark tooling."""
    canonical = suite_root / "suite_workflow_runs_all.csv"
    legacy = suite_root / "suite_workflow_runs_v2_all.csv"
    if canonical.exists():
        return canonical
    return legacy


def analyze_workflow(suite_root: Path, outdir: Path, export_tikz: bool = False):
    """analyze_workflow helper for benchmark tooling."""
    path = resolve_suite_workflow_runs_path(suite_root)
    if path.name == "suite_workflow_runs_v2_all.csv":
        print("Warning: using legacy suite_workflow_runs_v2_all.csv input; prefer suite_workflow_runs_all.csv.")
    df = safe_read_csv(path)
    if df.empty:
        print(f"Info: missing/empty {path.name}")
        return

    df["run_num"] = df.get("run_id", "").map(run_num_from_id)
    if "workflow_base" not in df.columns:
        df["workflow_base"] = df.get("workflow_tag", "").map(workflow_base_from_tag)
    else:
        missing = df["workflow_base"].isna() | (df["workflow_base"].astype(str).str.strip() == "")
        df.loc[missing, "workflow_base"] = df.loc[missing, "workflow_tag"].map(workflow_base_from_tag)
    latency = df.apply(
        lambda r: pd.Series(derive_latency_components(r.to_dict(), mixed_epsilon_seconds=LATENCY_MIXED_EPSILON_SECONDS)),
        axis=1,
    )
    for col in latency.columns:
        df[col] = latency[col]

    enriched_path = outdir / "workflow_runs_enriched.csv"
    enriched_legacy_path = outdir / "workflow_runs_v2_enriched.csv"
    df.to_csv(enriched_path, index=False)
    df.to_csv(enriched_legacy_path, index=False)

    duration_cols = [
        "client_duration_s",
        "client_to_submitted_s",
        "submit_to_vote_s",
        "vote_to_approved_s",
        "approved_to_cert_registered_s",
        "approved_to_reshare_start_s",
        "approved_to_reshare_completed_s",
        "reshare_duration_s",
        "post_reshare_tail_s",
        "reshare_complete_to_local_idle_s",
        "local_idle_to_operation_end_s",
        "execution_to_operation_end_s",
        "cert_registered_to_operation_end_s",
        "cert_registered_to_signing_idle_s",
        "signing_idle_to_operation_end_s",
    ]
    numeric_cols = duration_cols + [
        "blockchain_total_s",
        "blockchain_effective_s",
        "tss_reshare_total_s",
        "local_key_idle_wait_s",
        "tss_coordination_total_s",
        "local_finalize_total_s",
        "tss_total_s",
        "decomposed_total_s",
        "decomposition_gap_s",
        "mixed_transition_s_raw",
        "mixed_transition_s",
        "overlap_correction_s_raw",
        "overlap_correction_s",
        "explained_total_s",
    ]
    numeric_cols = [c for c in numeric_cols if c in df.columns]
    summary = (
        df.groupby("workflow_base", dropna=False)[numeric_cols]
        .agg(["count", "mean", "min", "max", "median"])
        .reset_index()
    )
    summary.columns = ["_".join([c for c in col if c]) for col in summary.columns.to_flat_index()]
    summary = summary.rename(columns={"workflow_base_": "workflow_base"})
    summary_path = outdir / "workflow_summary.csv"
    summary_legacy_path = outdir / "workflow_v2_summary.csv"
    summary.to_csv(summary_path, index=False)
    summary.to_csv(summary_legacy_path, index=False)

    missing_cols = [
        "submit_tx_id",
        "execute_tx_id",
        "submitted_observed_ts",
        "voted_ts",
        "approved_or_executed_ts",
        "reshare_started_ts",
        "reshare_completed_ts",
        "cert_registered_ts",
    ]
    missing_cols = [c for c in missing_cols if c in df.columns]
    missing_stats_rows = []
    for wf, g in df.groupby("workflow_base", dropna=False):
        row = {"workflow_base": wf, "rows": len(g)}
        for col in missing_cols:
            missing = g[col].isna() | (g[col].astype(str).str.strip() == "")
            row[f"{col}_missing"] = int(missing.sum())
            row[f"{col}_missing_pct"] = float(missing.mean() * 100.0)
        missing_stats_rows.append(row)
    missing_stats = pd.DataFrame(missing_stats_rows)
    missing_stats_path = outdir / "workflow_missing_fields.csv"
    missing_stats_legacy_path = outdir / "workflow_v2_missing_fields.csv"
    missing_stats.to_csv(missing_stats_path, index=False)
    missing_stats.to_csv(missing_stats_legacy_path, index=False)

    # Targeted diagnostics for join/removal/revocation decomposition mismatches.
    mismatch_diag_path = None
    mismatch_summary_path = None
    mismatch_scope = df[df["workflow_base"].isin(["join", "removal", "revocation"])].copy()
    if not mismatch_scope.empty:
        diag_rows = []
        for _, row in mismatch_scope.iterrows():
            reasons = []
            approved_ts = row.get("approved_or_executed_ts")
            reshare_started_ts = row.get("reshare_started_ts")
            reshare_completed_ts = row.get("reshare_completed_ts")
            mixed_transition_s_raw = row.get("mixed_transition_s_raw")
            mixed_transition_s = row.get("mixed_transition_s")
            client_duration_s = row.get("client_duration_s")
            tss_reshare_total_s = row.get("tss_reshare_total_s")
            workflow_base = str(row.get("workflow_base", "")).strip()
            workflow_tag = str(row.get("workflow_tag", "")).strip()
            operation_id = str(row.get("operation_id", "")).strip()
            workflow_tag_suffix = trailing_int_token(workflow_tag)
            operation_id_suffix = trailing_int_token(operation_id)
            tag_operation_id_suffix_delta_s = np.nan
            if pd.notna(workflow_tag_suffix) and pd.notna(operation_id_suffix):
                tag_operation_id_suffix_delta_s = float(operation_id_suffix) - float(workflow_tag_suffix)

            if pd.isna(approved_ts):
                reasons.append("missing_approved_or_executed_ts")
            if workflow_base in {"join", "removal"} and pd.isna(reshare_started_ts):
                reasons.append("missing_reshare_started_ts")
            if workflow_base in {"join", "removal"} and pd.isna(reshare_completed_ts):
                reasons.append("missing_reshare_completed_ts")
            if pd.notna(approved_ts) and pd.notna(reshare_started_ts) and reshare_started_ts < approved_ts:
                reasons.append("reshare_started_before_approval")
            if pd.notna(approved_ts) and pd.notna(reshare_completed_ts) and reshare_completed_ts < approved_ts:
                reasons.append("reshare_completed_before_approval")
            if pd.notna(reshare_started_ts) and pd.notna(reshare_completed_ts) and reshare_completed_ts < reshare_started_ts:
                reasons.append("reshare_completed_before_start")
            if pd.notna(mixed_transition_s_raw) and float(mixed_transition_s_raw) > 0:
                reasons.append("mixed_transition_present")
                if pd.notna(client_duration_s) and float(client_duration_s) > 0:
                    if float(mixed_transition_s_raw) / float(client_duration_s) >= 0.20:
                        reasons.append("mixed_transition_ge_20pct")
            if (
                workflow_base in {"join", "removal"}
                and pd.isna(tss_reshare_total_s)
                and pd.notna(mixed_transition_s_raw)
                and float(mixed_transition_s_raw) > 0
            ):
                reasons.append("no_tss_reshare_attribution")
            if workflow_base == "revocation":
                if pd.isna(row.get("execution_to_operation_end_s")):
                    reasons.append("missing_execution_to_operation_end")
                if pd.notna(row.get("execution_to_operation_end_s")) and float(row.get("execution_to_operation_end_s")) < 0:
                    reasons.append("negative_execution_to_operation_end")
            if pd.notna(tag_operation_id_suffix_delta_s) and abs(float(tag_operation_id_suffix_delta_s)) > 0:
                reasons.append("tag_operation_id_suffix_mismatch")

            diag_rows.append(
                {
                    "run_id": row.get("run_id", ""),
                    "workflow_base": row.get("workflow_base", ""),
                    "workflow_tag": workflow_tag,
                    "operation_id": operation_id,
                    "proposal_id": row.get("proposal_id", ""),
                    "epoch": row.get("epoch", ""),
                    "client_duration_s": row.get("client_duration_s", np.nan),
                    "blockchain_total_s": row.get("blockchain_total_s", np.nan),
                    "blockchain_effective_s": row.get("blockchain_effective_s", np.nan),
                    "tss_coordination_total_s": row.get("tss_coordination_total_s", np.nan),
                    "local_key_idle_wait_s": row.get("local_key_idle_wait_s", np.nan),
                    "local_finalize_total_s": row.get("local_finalize_total_s", np.nan),
                    "local_idle_to_operation_end_s": row.get("local_idle_to_operation_end_s", np.nan),
                    "tss_total_s": row.get("tss_total_s", np.nan),
                    "mixed_transition_s_raw": row.get("mixed_transition_s_raw", np.nan),
                    "mixed_transition_s": row.get("mixed_transition_s", np.nan),
                    "overlap_correction_s": row.get("overlap_correction_s", np.nan),
                    "approved_or_executed_ts": approved_ts,
                    "reshare_started_ts": reshare_started_ts,
                    "reshare_completed_ts": reshare_completed_ts,
                    "execution_to_operation_end_s": row.get("execution_to_operation_end_s", np.nan),
                    "workflow_tag_suffix": workflow_tag_suffix,
                    "operation_id_suffix": operation_id_suffix,
                    "tag_operation_id_suffix_delta_s": tag_operation_id_suffix_delta_s,
                    "reason_codes": ";".join(reasons),
                }
            )
        mismatch_diag = pd.DataFrame(diag_rows)
        mismatch_diag_path = outdir / "workflow_join_removal_mismatch_diagnostics.csv"
        mismatch_diag.to_csv(mismatch_diag_path, index=False)

        expanded = mismatch_diag.copy()
        expanded["reason_codes"] = expanded["reason_codes"].fillna("").astype(str)
        expanded = expanded[expanded["reason_codes"].str.strip() != ""]
        if not expanded.empty:
            expanded["reason"] = expanded["reason_codes"].str.split(";")
            expanded = expanded.explode("reason")
            expanded["reason"] = expanded["reason"].astype(str).str.strip()
            expanded = expanded[expanded["reason"] != ""]
            mismatch_summary = (
                expanded.groupby(["workflow_base", "reason"], dropna=False)
                .size()
                .reset_index(name="rows")
                .sort_values(["workflow_base", "rows", "reason"], ascending=[True, False, True])
            )
        else:
            mismatch_summary = pd.DataFrame(columns=["workflow_base", "reason", "rows"])
        mismatch_summary_path = outdir / "workflow_join_removal_mismatch_summary.csv"
        mismatch_summary.to_csv(mismatch_summary_path, index=False)

    # Per-operation stage rows for direct downstream analysis.
    stage_rows = []
    for _, row in df.iterrows():
        wf = str(row.get("workflow_base", "")).strip()

        def append_stage(stage_group, stage_name, latency):
            """append_stage helper for benchmark tooling."""
            if pd.isna(latency):
                return
            try:
                latency_val = float(latency)
            except Exception:
                return
            if not np.isfinite(latency_val) or latency_val <= 0:
                return
            stage_rows.append(
                {
                    "run_id": row.get("run_id"),
                    "workflow_base": wf,
                    "workflow_tag": row.get("workflow_tag"),
                    "operation_id": row.get("operation_id"),
                    "proposal_id": row.get("proposal_id"),
                    "stage_group": stage_group,
                    "stage_name": stage_name,
                    "latency_s": latency_val,
                }
            )

        append_stage("blockchain", "client_to_submit", row.get("client_to_submitted_s"))
        append_stage("blockchain", "submit_to_vote", row.get("submit_to_vote_s"))

        vote_stage_name = "vote_to_approved"
        if wf == "csr":
            vote_stage_name = "vote_to_signature"
        elif wf in {"revocation", "removal"}:
            vote_stage_name = "vote_to_execution"
        elif wf == "join":
            vote_stage_name = "vote_to_approval"
        append_stage("blockchain", vote_stage_name, row.get("vote_to_approved_s"))

        if wf == "csr":
            append_stage("tss_coordination", "signature_to_registration", row.get("approved_to_cert_registered_s"))
            append_stage("blockchain", "registration_to_operation_end", row.get("cert_registered_to_operation_end_s"))
            continue

        if wf in {"join", "removal"}:
            pre = row.get("approved_to_reshare_start_s")
            window = row.get("reshare_duration_s")
            completed = row.get("approved_to_reshare_completed_s")

            if wf == "join":
                pre_name = "approval_to_reshare_start"
                fallback_name = "approval_to_reshare_completed"
            else:
                pre_name = "execution_to_reshare_start"
                fallback_name = "execution_to_reshare_completed"

            if pd.notna(pre) and pd.notna(window):
                append_stage("tss_coordination", pre_name, pre)
                append_stage("tss_coordination", "reshare_window", window)
            elif pd.notna(completed):
                append_stage("tss_coordination", fallback_name, completed)
            elif pd.notna(window):
                append_stage("tss_coordination", "reshare_window", window)
            local_idle_wait = row.get("local_key_idle_wait_s")
            local_idle_tail = row.get("local_idle_to_operation_end_s")
            if pd.notna(local_idle_wait) or pd.notna(local_idle_tail):
                append_stage("tss_coordination", "reshare_complete_to_local_idle", local_idle_wait)
                append_stage("blockchain", "local_idle_to_operation_end", local_idle_tail)
            else:
                append_stage("blockchain", "reshare_complete_to_local_idle_or_end", row.get("local_finalize_total_s"))
            continue

        if wf == "revocation":
            append_stage("blockchain", "execution_to_operation_end", row.get("execution_to_operation_end_s"))
        else:
            append_stage("blockchain", "operation_finalize", row.get("local_finalize_total_s"))

    mixed_diag = df[
        [
            "run_id",
            "workflow_base",
            "workflow_tag",
            "operation_id",
            "proposal_id",
            "client_duration_s",
            "blockchain_total_s",
            "blockchain_effective_s",
            "tss_coordination_total_s",
            "local_key_idle_wait_s",
            "local_finalize_total_s",
            "local_idle_to_operation_end_s",
            "decomposed_total_s",
            "decomposition_gap_s",
            "mixed_transition_s_raw",
            "mixed_transition_s",
            "overlap_correction_s",
        ]
    ].copy()
    mixed_diag["mixed_ge_eps"] = (
        pd.to_numeric(mixed_diag["mixed_transition_s"], errors="coerce").fillna(0) >= MIXED_EPSILON_SECONDS
    )
    mixed_diag_path = outdir / "workflow_stage_latency_mixed_diagnostics.csv"
    mixed_diag.to_csv(mixed_diag_path, index=False)

    mixed_summary = (
        mixed_diag.groupby("workflow_base", dropna=False)
        .agg(
            rows=("workflow_base", "size"),
            rows_with_mixed_ge_eps=("mixed_ge_eps", "sum"),
            mixed_transition_s_raw_mean=("mixed_transition_s_raw", "mean"),
            mixed_transition_s_raw_max=("mixed_transition_s_raw", "max"),
            mixed_transition_s_mean=("mixed_transition_s", "mean"),
            overlap_correction_s_mean=("overlap_correction_s", "mean"),
            decomposition_gap_s_mean=("decomposition_gap_s", "mean"),
        )
        .reset_index()
        .sort_values("workflow_base")
    )
    mixed_summary_path = outdir / "workflow_stage_latency_mixed_summary.csv"
    mixed_summary.to_csv(mixed_summary_path, index=False)

    stage_ops = pd.DataFrame(stage_rows)
    stage_ops_path = outdir / "workflow_stage_latency_by_operation.csv"
    stage_ops.to_csv(stage_ops_path, index=False)

    stage_breakdown = pd.DataFrame()
    if not stage_ops.empty:
        stage_breakdown = (
            stage_ops.groupby(["workflow_base", "stage_group", "stage_name"], dropna=False)["latency_s"]
            .agg(["count", "mean", "min", "max", "median"])
            .reset_index()
            .sort_values(["workflow_base", "stage_group", "stage_name"])
        )
    stage_breakdown_path = outdir / "workflow_stage_latency_breakdown.csv"
    stage_breakdown.to_csv(stage_breakdown_path, index=False)

    component_totals = (
        df.groupby("workflow_base", dropna=False)[
            [
                "blockchain_total_s",
                "blockchain_effective_s",
                "tss_coordination_total_s",
                "local_key_idle_wait_s",
                "local_finalize_total_s",
                "tss_total_s",
                "mixed_transition_s_raw",
                "mixed_transition_s",
                "overlap_correction_s",
                "explained_total_s",
            ]
        ]
        .agg(["count", "mean", "min", "max", "median"])
        .reset_index()
    )
    component_totals.columns = ["_".join([c for c in col if c]) for col in component_totals.columns.to_flat_index()]
    component_totals = component_totals.rename(columns={"workflow_base_": "workflow_base"})
    component_totals_path = outdir / "workflow_component_totals.csv"
    component_totals.to_csv(component_totals_path, index=False)

    join_removal_diag_path = None
    join_removal_diag = df[df["workflow_base"].isin(["join", "removal"])].copy()
    if not join_removal_diag.empty:
        join_removal_diag["coordination_share_pct"] = np.where(
            join_removal_diag["client_duration_s"] > 0,
            (join_removal_diag["tss_coordination_total_s"] / join_removal_diag["client_duration_s"]) * 100.0,
            np.nan,
        )
        join_removal_diag["local_finalize_share_pct"] = np.where(
            join_removal_diag["client_duration_s"] > 0,
            (join_removal_diag["local_finalize_total_s"] / join_removal_diag["client_duration_s"]) * 100.0,
            np.nan,
        )
        join_removal_diag["finalize_class"] = np.where(
            pd.to_numeric(join_removal_diag["local_finalize_total_s"], errors="coerce").fillna(0) <= MIXED_EPSILON_SECONDS,
            "none_or_short",
            "local_finalize_wait",
        )
        join_removal_diag["local_finalize_source"] = (
            "reshare_completed_ts->client_end_ts (includes wait_for_local_key_session_idle)"
        )
        join_removal_diag = join_removal_diag[
            [
                "run_id",
                "workflow_base",
                "workflow_tag",
                "operation_id",
                "proposal_id",
                "client_duration_s",
                "blockchain_total_s",
                "blockchain_effective_s",
                "tss_coordination_total_s",
                "local_finalize_total_s",
                "approved_to_reshare_start_s",
                "reshare_duration_s",
                "post_reshare_tail_s",
                "local_key_idle_wait_s",
                "local_idle_to_operation_end_s",
                "coordination_share_pct",
                "local_finalize_share_pct",
                "finalize_class",
                "local_finalize_source",
            ]
        ]
        join_removal_diag_path = outdir / "measurement_join_vs_removal_latency_diagnostics.csv"
        join_removal_diag.to_csv(join_removal_diag_path, index=False)

    mvcc_summary_path = None
    mvcc_by_run_path = None
    retry_cols = ["submit_retries_total", "submit_retries_mvcc", "submit_retries_non_mvcc"]
    if all(col in df.columns for col in retry_cols):
        retry_df = df.copy()
        for col in retry_cols:
            retry_df[col] = pd.to_numeric(retry_df[col], errors="coerce").fillna(0)
        if "status" in retry_df.columns:
            retry_df["status"] = retry_df["status"].astype(str).str.strip().str.lower()
        else:
            retry_df["status"] = ""
        retry_df["has_mvcc_retry"] = retry_df["submit_retries_mvcc"] > 0

        mvcc_summary = (
            retry_df.groupby("workflow_base", dropna=False)
            .agg(
                rows=("workflow_base", "size"),
                success_rows=("status", lambda s: int((s == "success").sum())),
                failed_rows=("status", lambda s: int((s == "failed").sum())),
                retries_total_sum=("submit_retries_total", "sum"),
                retries_mvcc_sum=("submit_retries_mvcc", "sum"),
                retries_non_mvcc_sum=("submit_retries_non_mvcc", "sum"),
                retries_total_mean=("submit_retries_total", "mean"),
                retries_mvcc_mean=("submit_retries_mvcc", "mean"),
                retries_non_mvcc_mean=("submit_retries_non_mvcc", "mean"),
                operations_with_mvcc_retry=("has_mvcc_retry", "sum"),
            )
            .reset_index()
            .sort_values("workflow_base")
        )
        mvcc_summary["operations_with_mvcc_retry_pct"] = np.where(
            mvcc_summary["rows"] > 0,
            (pd.to_numeric(mvcc_summary["operations_with_mvcc_retry"], errors="coerce") / mvcc_summary["rows"]) * 100.0,
            np.nan,
        )
        mvcc_summary["retries_mvcc_per_success"] = np.where(
            mvcc_summary["success_rows"] > 0,
            pd.to_numeric(mvcc_summary["retries_mvcc_sum"], errors="coerce") / mvcc_summary["success_rows"],
            np.nan,
        )
        mvcc_summary["retries_total_per_success"] = np.where(
            mvcc_summary["success_rows"] > 0,
            pd.to_numeric(mvcc_summary["retries_total_sum"], errors="coerce") / mvcc_summary["success_rows"],
            np.nan,
        )
        mvcc_summary_path = outdir / "workflow_mvcc_retry_summary.csv"
        mvcc_summary.to_csv(mvcc_summary_path, index=False)

        mvcc_by_run = (
            retry_df[retry_df["run_num"] >= 0]
            .groupby(["run_id", "run_num", "workflow_base"], dropna=False)[retry_cols]
            .sum(min_count=1)
            .reset_index()
            .sort_values(["workflow_base", "run_num"])
        )
        mvcc_by_run_path = outdir / "workflow_mvcc_retry_by_run.csv"
        mvcc_by_run.to_csv(mvcc_by_run_path, index=False)

        # MVCC retry diagrams intentionally disabled: users requested CSV-only output.
        legacy_mvcc_plot_names = [
            "workflow_mvcc_retry_pressure_by_workflow.png",
            "workflow_mvcc_retry_pressure_by_workflow.tex",
            "workflow_mvcc_retry_pressure_by_run.png",
            "workflow_mvcc_retry_pressure_by_run.tex",
        ]
        for name in legacy_mvcc_plot_names:
            stale = outdir / name
            if stale.exists():
                try:
                    stale.unlink()
                except Exception:
                    pass

    tss_compute_wait_summary_path = None
    tss_proxy_cols = [
        "tss_signing_compute_s",
        "tss_signing_wait_s",
        "tss_reshare_compute_s",
        "tss_reshare_wait_s",
        "tss_key_session_compute_s",
        "tss_key_session_wait_s",
        "tss_compute_proxy_s",
        "tss_wait_proxy_s",
    ]
    if any(col in df.columns for col in tss_proxy_cols):
        tss_df = df.copy()
        for col in tss_proxy_cols:
            if col in tss_df.columns:
                tss_df[col] = pd.to_numeric(tss_df[col], errors="coerce")
            else:
                tss_df[col] = np.nan
        tss_summary = (
            tss_df.groupby("workflow_base", dropna=False)[tss_proxy_cols]
            .agg(["count", "mean", "min", "max", "median"])
            .reset_index()
        )
        tss_summary.columns = ["_".join([c for c in col if c]) for col in tss_summary.columns.to_flat_index()]
        tss_summary = tss_summary.rename(columns={"workflow_base_": "workflow_base"})
        tss_compute_wait_summary_path = outdir / "workflow_tss_compute_wait_summary.csv"
        tss_summary.to_csv(tss_compute_wait_summary_path, index=False)

    gossip_summary_path = None
    if {"gossip_convergence_s", "gossip_convergence_status"}.issubset(df.columns):
        gossip_df = df.copy()
        gossip_df["gossip_convergence_s"] = pd.to_numeric(gossip_df["gossip_convergence_s"], errors="coerce")
        for col in [
            "gossip_height_before_max",
            "gossip_height_after_max",
            "gossip_target_height",
            "gossip_height_delta",
            "gossip_peers_observed",
            "gossip_peers_converged",
        ]:
            if col in gossip_df.columns:
                gossip_df[col] = pd.to_numeric(gossip_df[col], errors="coerce")
        gossip_df["gossip_convergence_status"] = gossip_df["gossip_convergence_status"].astype(str).str.strip().str.lower()
        gossip_df["gossip_converged"] = gossip_df["gossip_convergence_status"] == "converged"
        gossip_summary = (
            gossip_df.groupby("workflow_base", dropna=False)
            .agg(
                rows=("workflow_base", "size"),
                converged_rows=("gossip_converged", "sum"),
                convergence_s_mean=("gossip_convergence_s", "mean"),
                convergence_s_p95=("gossip_convergence_s", lambda s: np.nan if s.dropna().empty else float(np.percentile(s.dropna(), 95))),
                height_delta_mean=("gossip_height_delta", "mean"),
                peers_observed_mean=("gossip_peers_observed", "mean"),
                peers_converged_mean=("gossip_peers_converged", "mean"),
            )
            .reset_index()
            .sort_values("workflow_base")
        )
        gossip_summary_path = outdir / "workflow_gossip_convergence_summary.csv"
        gossip_summary.to_csv(gossip_summary_path, index=False)

        conv_plot = gossip_summary.copy()
        conv_plot = conv_plot[conv_plot["converged_rows"] > 0]
        if not conv_plot.empty:
            ordered = ordered_workflows(conv_plot["workflow_base"].astype(str).tolist())
            conv_plot["wf_order"] = conv_plot["workflow_base"].astype(str).map(lambda wf: ordered.index(wf) if wf in ordered else 9999)
            conv_plot = conv_plot.sort_values(["wf_order", "workflow_base"])
            x = np.arange(len(conv_plot))
            vals = pd.to_numeric(conv_plot["convergence_s_mean"], errors="coerce").fillna(0).to_numpy()
            fig = plt.figure(figsize=(9, 5))
            plt.bar(x, vals, width=0.6)
            plt.xticks(x, conv_plot["workflow_base"])
            plt.ylabel("Seconds")
            plt.title("Gossip Convergence Time by Workflow")
            plt.grid(axis="y", alpha=0.3)
            apply_nonnegative_baseline(plt.gca(), vals)
            save_plot(fig, outdir / "workflow_gossip_convergence_by_workflow.png", export_tikz=export_tikz)

    # Plot: boxplot of client duration per workflow
    plot_df = df.dropna(subset=["client_duration_s"]).copy()
    if not plot_df.empty:
        workflows = ordered_workflows(plot_df["workflow_base"].dropna().unique())
        box_data = [plot_df.loc[plot_df["workflow_base"] == wf, "client_duration_s"] for wf in workflows]
        fig, ax = plt.subplots(figsize=(10, 5))
        boxplot_with_labels(ax, box_data, workflows, showfliers=False)
        for idx, vals in enumerate(box_data, start=1):
            if len(vals) == 0:
                continue
            jitter_x = np.random.normal(loc=idx, scale=0.04, size=len(vals))
            ax.scatter(jitter_x, vals, s=24, alpha=0.7, color=_rgb01("kit_blue"), zorder=3)
            ax.text(idx, np.nanmax(vals) + 0.2, f"n={len(vals)}", ha="center", va="bottom", fontsize=9)
        ax.set_ylabel("Client Duration (s)")
        ax.set_title("Workflow Duration Distribution (V2)")
        ax.grid(axis="y", alpha=0.3)
        apply_nonnegative_baseline(ax, np.concatenate([v.to_numpy(dtype=float) for v in box_data if len(v) > 0]), boxplot=True)
        save_plot(fig, outdir / "workflow_client_duration_boxplot.png", export_tikz=export_tikz)

    # Plot: line by run
    plot_df = df.dropna(subset=["client_duration_s"]).copy()
    plot_df = plot_df[plot_df["run_num"] >= 0]
    if not plot_df.empty:
        fig = plt.figure(figsize=(10, 5))
        for wf in ordered_workflows(plot_df["workflow_base"].dropna().unique()):
            g = plot_df[plot_df["workflow_base"] == wf]
            g = g.sort_values("run_num")
            plt.plot(g["run_num"], g["client_duration_s"], marker="o", label=wf)
        plt.xlabel("Run #")
        plt.ylabel("Client Duration (s)")
        plt.title("Workflow Duration by Run (V2)")
        plt.legend()
        plt.grid(alpha=0.3)
        apply_nonnegative_baseline(plt.gca(), plot_df["client_duration_s"].to_numpy(dtype=float))
        save_plot(fig, outdir / "workflow_client_duration_by_run.png", export_tikz=export_tikz)

    # Plot: workflow component split (blockchain effective vs TSS coordination).
    comp_plot = (
        df.groupby("workflow_base", dropna=False)[
            ["blockchain_effective_s", "tss_coordination_total_s"]
        ]
        .mean(numeric_only=True)
        .reset_index()
    )
    if not comp_plot.empty:
        comp_plot["workflow_order"] = comp_plot["workflow_base"].map(
            lambda wf: ordered_workflows(comp_plot["workflow_base"].tolist()).index(str(wf).strip())
            if str(wf).strip() in ordered_workflows(comp_plot["workflow_base"].tolist())
            else 9999
        )
        comp_plot = comp_plot.sort_values(["workflow_order", "workflow_base"]).drop(columns=["workflow_order"])
        comp_plot[["blockchain_effective_s", "tss_coordination_total_s"]] = comp_plot[
            ["blockchain_effective_s", "tss_coordination_total_s"]
        ].fillna(0.0)
        fig = plt.figure(figsize=(9, 5))
        x = range(len(comp_plot))
        plt.bar(x, comp_plot["blockchain_effective_s"], label="blockchain")
        plt.bar(
            x,
            comp_plot["tss_coordination_total_s"],
            bottom=comp_plot["blockchain_effective_s"],
            label="tss_coordination",
        )
        plt.xticks(list(x), comp_plot["workflow_base"])
        plt.ylabel("Mean Seconds")
        plt.title("Workflow Latency Split (Blockchain vs TSS Coordination)")
        plt.legend()
        plt.grid(axis="y", alpha=0.3)
        for i, row in comp_plot.reset_index(drop=True).iterrows():
            total = float(row["blockchain_effective_s"] + row["tss_coordination_total_s"])
            if total <= 0:
                continue
            plt.text(i, total + 0.1, f"{total:.2f}s", ha="center", va="bottom", fontsize=9)
        apply_nonnegative_baseline(
            plt.gca(),
            comp_plot[["blockchain_effective_s", "tss_coordination_total_s"]].to_numpy().reshape(-1),
        )
        save_plot(fig, outdir / "workflow_stage_latency_averages.png", export_tikz=export_tikz)

    # Plot: latency split distributions by workflow.
    split_components = [
        ("blockchain_effective_s", "blockchain"),
        ("tss_coordination_total_s", "tss_coordination"),
    ]
    split_plot_df = df.copy()
    split_plot_df = split_plot_df[split_plot_df["workflow_base"].astype(str).str.strip() != ""]
    workflows = ordered_workflows(split_plot_df["workflow_base"].dropna().unique())
    if workflows and split_components:
        fig, axes = plt.subplots(1, len(split_components), figsize=(5.4 * len(split_components), 4.8), sharey=False)
        if len(split_components) == 1:
            axes = [axes]
        for ax, (col, label) in zip(axes, split_components):
            box_data = [split_plot_df.loc[split_plot_df["workflow_base"] == wf, col].dropna() for wf in workflows]
            # Keep stable axis even when some workflow/component combinations are empty.
            if all(len(vals) == 0 for vals in box_data):
                ax.text(0.5, 0.5, "no data", ha="center", va="center", transform=ax.transAxes)
                ax.set_xticks([])
            else:
                safe_data = [vals if len(vals) > 0 else [np.nan] for vals in box_data]
                boxplot_with_labels(ax, safe_data, workflows, showfliers=False)
            ax.set_title(label)
            ax.set_xlabel("workflow")
            ax.grid(axis="y", alpha=0.3)
            concat_vals = np.concatenate([vals.to_numpy(dtype=float) for vals in box_data if len(vals) > 0]) if any(
                len(vals) > 0 for vals in box_data
            ) else np.array([])
            apply_nonnegative_baseline(ax, concat_vals, boxplot=True)
        axes[0].set_ylabel("Seconds")
        fig.suptitle("Latency Split Distribution by Workflow (Mixed Isolated)")
        save_plot(fig, outdir / "workflow_latency_split_boxplot.png", export_tikz=export_tikz)

    mixed_plot_source = mixed_diag.copy()
    mixed_plot_source["run_num"] = mixed_plot_source["run_id"].map(run_num_from_id)
    mixed_nonzero = mixed_plot_source[pd.to_numeric(mixed_plot_source["mixed_transition_s"], errors="coerce").fillna(0) > 0]
    if not mixed_nonzero.empty:
        fig = plt.figure(figsize=(10, 5))
        for wf in ordered_workflows(mixed_nonzero["workflow_base"].dropna().unique()):
            g = mixed_nonzero[mixed_nonzero["workflow_base"] == wf].copy()
            g = g[g["run_num"] >= 0].sort_values("run_num")
            if g.empty:
                continue
            plt.plot(g["run_num"], g["mixed_transition_s_raw"], marker="o", label=str(wf))
        plt.xlabel("Run #")
        plt.ylabel("Mixed transition (s, raw)")
        plt.title("Mixed Transition Diagnostics by Run")
        plt.grid(alpha=0.3)
        plt.legend()
        apply_nonnegative_baseline(plt.gca(), mixed_nonzero["mixed_transition_s_raw"].to_numpy(dtype=float))
        save_plot(fig, outdir / "workflow_mixed_transition_diagnostics.png", export_tikz=export_tikz)

    print(f"Wrote: {enriched_path}")
    print(f"Wrote: {summary_path}")
    print(f"Wrote: {missing_stats_path}")
    if mismatch_diag_path:
        print(f"Wrote: {mismatch_diag_path}")
    if mismatch_summary_path:
        print(f"Wrote: {mismatch_summary_path}")
    print(f"Wrote: {mixed_diag_path}")
    print(f"Wrote: {mixed_summary_path}")
    print(f"Wrote: {stage_ops_path}")
    print(f"Wrote: {stage_breakdown_path}")
    print(f"Wrote: {component_totals_path}")
    if join_removal_diag_path:
        print(f"Wrote: {join_removal_diag_path}")
    if mvcc_summary_path:
        print(f"Wrote: {mvcc_summary_path}")
    if mvcc_by_run_path:
        print(f"Wrote: {mvcc_by_run_path}")
    if tss_compute_wait_summary_path:
        print(f"Wrote: {tss_compute_wait_summary_path}")
    if gossip_summary_path:
        print(f"Wrote: {gossip_summary_path}")

    # Remove stale plots that are intentionally no longer emitted.
    for stale_name in [
        "workflow_tss_compute_wait_proxy_by_workflow.png",
        "workflow_tss_compute_wait_proxy_by_workflow.tex",
    ]:
        stale_path = outdir / stale_name
        if stale_path.exists():
            try:
                stale_path.unlink()
            except Exception:
                pass

def analyze_workflow_v2(suite_root: Path, outdir: Path, export_tikz: bool = False):
    """analyze_workflow_v2 helper for benchmark tooling."""
    print("Warning: analyze_workflow_v2 is deprecated; use analyze_workflow.")
    return analyze_workflow(suite_root, outdir, export_tikz=export_tikz)


def analyze_resources(suite_root: Path, outdir: Path, export_tikz: bool = False):
    """analyze_resources helper for benchmark tooling."""
    path = suite_root / "suite_resources_summary_all_runs.csv"
    df = safe_read_csv(path)
    if df.empty:
        print(f"Info: missing/empty {path.name}")
        return

    if "workflow_base" not in df.columns:
        df["workflow_base"] = df.get("workflow", "").map(workflow_base_from_tag)
    if "run_id" in df.columns:
        df["run_num"] = df["run_id"].map(run_num_from_id)
    else:
        df["run_num"] = -1

    num_cols = [c for c in ["cpu_avg", "cpu_max", "mem_avg", "mem_max"] if c in df.columns]
    component_cols = [
        c
        for c in [
            "tss_cpu_avg",
            "tss_mem_avg",
            "peer_cpu_avg",
            "peer_mem_avg",
            "orderer_cpu_avg",
            "orderer_mem_avg",
        ]
        if c in df.columns
    ]
    for c in num_cols:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    for c in component_cols:
        df[c] = pd.to_numeric(df[c], errors="coerce")

    summary = df.groupby("workflow_base", dropna=False)[num_cols].mean(numeric_only=True).reset_index()
    summary_path = outdir / "resource_summary_by_workflow.csv"
    summary.to_csv(summary_path, index=False)

    if not summary.empty and "cpu_avg" in summary.columns and "mem_avg" in summary.columns:
        fig = plt.figure(figsize=(9, 5))
        x = range(len(summary))
        w = 0.35
        plt.bar([i - w / 2 for i in x], summary["cpu_avg"], width=w, label="cpu_avg")
        plt.bar([i + w / 2 for i in x], summary["mem_avg"], width=w, label="mem_avg")
        plt.xticks(list(x), summary["workflow_base"])
        plt.ylabel("Percent")
        plt.title("Average CPU/MEM by Workflow")
        plt.legend()
        plt.grid(axis="y", alpha=0.3)
        save_plot(fig, outdir / "resource_cpu_mem_by_workflow.png", export_tikz=export_tikz)

    component_summary_path = None
    cpu_long_path = None
    mem_long_path = None
    by_run_path = None
    component_map = {
        "tss": {"cpu": "tss_cpu_avg", "mem": "tss_mem_avg"},
        "peer": {"cpu": "peer_cpu_avg", "mem": "peer_mem_avg"},
        "orderer": {"cpu": "orderer_cpu_avg", "mem": "orderer_mem_avg"},
    }
    component_names = [name for name, cols in component_map.items() if cols["cpu"] in df.columns and cols["mem"] in df.columns]

    if component_names:
        comp_summary_parts = []
        for name in component_names:
            cols = component_map[name]
            part = (
                df.groupby("workflow_base", dropna=False)[[cols["cpu"], cols["mem"]]]
                .agg(["count", "mean", "min", "max", "median"])
                .reset_index()
            )
            part.columns = ["_".join([c for c in col if c]) for col in part.columns.to_flat_index()]
            part = part.rename(columns={"workflow_base_": "workflow_base"})
            part["component"] = name
            comp_summary_parts.append(part)
        comp_summary_df = pd.concat(comp_summary_parts, ignore_index=True)
        component_summary_path = outdir / "resource_component_summary_by_workflow.csv"
        comp_summary_df.to_csv(component_summary_path, index=False)

        cpu_rows = []
        mem_rows = []
        for _, row in df.iterrows():
            wf = row.get("workflow_base")
            run_id = row.get("run_id", "")
            run_num = row.get("run_num", -1)
            for name in component_names:
                cols = component_map[name]
                cpu_val = row.get(cols["cpu"])
                mem_val = row.get(cols["mem"])
                if pd.notna(cpu_val):
                    cpu_rows.append(
                        {
                            "run_id": run_id,
                            "run_num": run_num,
                            "workflow_base": wf,
                            "component": name,
                            "cpu_pct": float(cpu_val),
                        }
                    )
                if pd.notna(mem_val):
                    mem_rows.append(
                        {
                            "run_id": run_id,
                            "run_num": run_num,
                            "workflow_base": wf,
                            "component": name,
                            "mem_pct": float(mem_val),
                        }
                    )
        cpu_long = pd.DataFrame(cpu_rows)
        mem_long = pd.DataFrame(mem_rows)
        if not cpu_long.empty:
            cpu_long_path = outdir / "resource_component_cpu_by_workflow_long.csv"
            cpu_long.to_csv(cpu_long_path, index=False)
        if not mem_long.empty:
            mem_long_path = outdir / "resource_component_mem_by_workflow_long.csv"
            mem_long.to_csv(mem_long_path, index=False)

        workflows = sorted(df["workflow_base"].dropna().astype(str).str.strip().unique())

        if not cpu_long.empty and workflows:
            fig, axes = plt.subplots(1, len(component_names), figsize=(5.2 * len(component_names), 5), sharey=False)
            if len(component_names) == 1:
                axes = [axes]
            for ax, component in zip(axes, component_names):
                sub = cpu_long[cpu_long["component"] == component]
                box_data = [sub.loc[sub["workflow_base"] == wf, "cpu_pct"].dropna() for wf in workflows]
                if all(len(vals) == 0 for vals in box_data):
                    ax.text(0.5, 0.5, "no data", ha="center", va="center", transform=ax.transAxes)
                    ax.set_xticks([])
                else:
                    safe_data = [vals if len(vals) > 0 else [np.nan] for vals in box_data]
                    boxplot_with_labels(ax, safe_data, workflows, showfliers=False)
                ax.set_title(f"{component} CPU")
                ax.set_xlabel("workflow")
                ax.grid(axis="y", alpha=0.3)
            axes[0].set_ylabel("Percent of host total CPU")
            fig.suptitle("Component CPU Distribution by Workflow")
            save_plot(fig, outdir / "resource_component_cpu_boxplot.png", export_tikz=export_tikz)

        if not mem_long.empty and workflows:
            fig, axes = plt.subplots(1, len(component_names), figsize=(5.2 * len(component_names), 5), sharey=False)
            if len(component_names) == 1:
                axes = [axes]
            for ax, component in zip(axes, component_names):
                sub = mem_long[mem_long["component"] == component]
                box_data = [sub.loc[sub["workflow_base"] == wf, "mem_pct"].dropna() for wf in workflows]
                if all(len(vals) == 0 for vals in box_data):
                    ax.text(0.5, 0.5, "no data", ha="center", va="center", transform=ax.transAxes)
                    ax.set_xticks([])
                else:
                    safe_data = [vals if len(vals) > 0 else [np.nan] for vals in box_data]
                    boxplot_with_labels(ax, safe_data, workflows, showfliers=False)
                ax.set_title(f"{component} MEM")
                ax.set_xlabel("workflow")
                ax.grid(axis="y", alpha=0.3)
            axes[0].set_ylabel("Percent of host total RAM")
            fig.suptitle("Component Memory Distribution by Workflow")
            save_plot(fig, outdir / "resource_component_mem_boxplot.png", export_tikz=export_tikz)

        run_frames = []
        if not cpu_long.empty:
            c = cpu_long.copy()
            c["metric"] = "cpu_pct"
            c = c.rename(columns={"cpu_pct": "value"})
            run_frames.append(c)
        if not mem_long.empty:
            m = mem_long.copy()
            m["metric"] = "mem_pct"
            m = m.rename(columns={"mem_pct": "value"})
            run_frames.append(m)
        if run_frames:
            run_df = pd.concat(run_frames, ignore_index=True)
            run_df = run_df[run_df["run_num"] >= 0]
            if not run_df.empty:
                by_run = (
                    run_df.groupby(["run_num", "workflow_base", "component", "metric"], dropna=False)["value"]
                    .mean()
                    .reset_index()
                    .sort_values(["metric", "component", "workflow_base", "run_num"])
                )
                by_run_path = outdir / "resource_component_by_run.csv"
                by_run.to_csv(by_run_path, index=False)

                for metric, title, ylab, out_name in [
                    ("cpu_pct", "Component CPU by Run", "Percent of host total CPU", "resource_component_cpu_by_run.png"),
                    ("mem_pct", "Component Memory by Run", "Percent of host total RAM", "resource_component_mem_by_run.png"),
                ]:
                    sub_metric = by_run[by_run["metric"] == metric]
                    if sub_metric.empty:
                        continue
                    fig, axes = plt.subplots(1, len(component_names), figsize=(5.2 * len(component_names), 5), sharey=False)
                    if len(component_names) == 1:
                        axes = [axes]
                    for ax, component in zip(axes, component_names):
                        comp_df = sub_metric[sub_metric["component"] == component]
                        if comp_df.empty:
                            ax.text(0.5, 0.5, "no data", ha="center", va="center", transform=ax.transAxes)
                            ax.set_xticks([])
                            ax.set_title(component)
                            continue
                        for wf, g in comp_df.groupby("workflow_base", dropna=False):
                            g = g.sort_values("run_num")
                            ax.plot(g["run_num"], g["value"], marker="o", label=str(wf))
                        ax.set_title(component)
                        ax.set_xlabel("Run #")
                        ax.grid(alpha=0.3)
                    axes[0].set_ylabel(ylab)
                    handles, labels = axes[0].get_legend_handles_labels()
                    if handles:
                        fig.legend(handles, labels, loc="upper center", ncol=max(1, min(4, len(labels))))
                    fig.suptitle(title)
                    save_plot(fig, outdir / out_name, export_tikz=export_tikz)

    print(f"Wrote: {summary_path}")
    if component_summary_path:
        print(f"Wrote: {component_summary_path}")
    if cpu_long_path:
        print(f"Wrote: {cpu_long_path}")
    if mem_long_path:
        print(f"Wrote: {mem_long_path}")
    if by_run_path:
        print(f"Wrote: {by_run_path}")

def analyze_query_latency(suite_root: Path, outdir: Path, export_tikz: bool = False):
    """analyze_query_latency helper for benchmark tooling."""
    iter_path = suite_root / "suite_query_bench_all_runs.csv"
    summary_path = suite_root / "suite_query_bench_averages.csv"
    iter_df = safe_read_csv(iter_path)
    summary_df = safe_read_csv(summary_path)

    if iter_df.empty and summary_df.empty:
        print(f"Info: missing/empty {iter_path.name} and {summary_path.name}")
        return

    metrics = ["status_ms", "merkle_root_ms", "merkle_proof_ms", "proof_verify_ms", "end_to_end_ms"]
    size_metrics = [
        "merkle_tree_size",
        "merkle_root_payload_bytes",
        "merkle_proof_payload_bytes",
        "merkle_proof_only_bytes",
        "proof_nodes",
    ]
    wrote = []

    if not iter_df.empty:
        if "run_id" not in iter_df.columns:
            iter_df["run_id"] = ""
        iter_df["run_num"] = iter_df["run_id"].map(run_num_from_id)
        for m in metrics:
            if m in iter_df.columns:
                iter_df[m] = pd.to_numeric(iter_df[m], errors="coerce")
        for m in size_metrics:
            if m in iter_df.columns:
                iter_df[m] = pd.to_numeric(iter_df[m], errors="coerce")

        summary_rows = []
        for metric in metrics:
            if metric not in iter_df.columns:
                continue
            vals = iter_df[metric].dropna().tolist()
            if not vals:
                summary_rows.append(
                    {
                        "metric": metric,
                        "count": 0,
                        "mean_ms": "",
                        "std_ms": "",
                        "p50_ms": "",
                        "p95_ms": "",
                        "p99_ms": "",
                        "min_ms": "",
                        "max_ms": "",
                    }
                )
                continue
            arr = np.array(vals, dtype=float)
            summary_rows.append(
                {
                    "metric": metric,
                    "count": int(len(arr)),
                    "mean_ms": float(np.mean(arr)),
                    "std_ms": float(np.std(arr)),
                    "p50_ms": float(np.percentile(arr, 50)),
                    "p95_ms": float(np.percentile(arr, 95)),
                    "p99_ms": float(np.percentile(arr, 99)),
                    "min_ms": float(np.min(arr)),
                    "max_ms": float(np.max(arr)),
                }
            )
        metric_summary_df = pd.DataFrame(summary_rows)
        metric_summary_out = outdir / "query_latency_summary_by_metric.csv"
        metric_summary_df.to_csv(metric_summary_out, index=False)
        wrote.append(metric_summary_out)

        long_parts = []
        for metric in metrics:
            if metric not in iter_df.columns:
                continue
            part = iter_df[["run_id", "run_num", metric]].copy()
            part = part.rename(columns={metric: "latency_ms"})
            part["metric"] = metric
            long_parts.append(part)
        long_df = pd.concat(long_parts, ignore_index=True) if long_parts else pd.DataFrame()
        long_df = long_df.dropna(subset=["latency_ms"]) if not long_df.empty else long_df
        if not long_df.empty:
            by_run = (
                long_df[long_df["run_num"] >= 0]
                .groupby(["run_id", "run_num", "metric"], dropna=False)["latency_ms"]
                .mean()
                .reset_index()
                .sort_values(["metric", "run_num"])
            )
        else:
            by_run = pd.DataFrame(columns=["run_id", "run_num", "metric", "latency_ms"])
        by_run_out = outdir / "query_latency_by_run.csv"
        by_run.to_csv(by_run_out, index=False)
        wrote.append(by_run_out)

        if not long_df.empty:
            box_groups = []
            box_labels = []
            for metric in metrics:
                vals = long_df[long_df["metric"] == metric]["latency_ms"].dropna()
                if len(vals) == 0:
                    continue
                box_groups.append(vals)
                box_labels.append(metric)
            if box_groups:
                fig, ax = plt.subplots(figsize=(10, 5))
                boxplot_with_labels(ax, box_groups, box_labels, showfliers=False)
                ax.set_ylabel("Latency (ms)")
                ax.set_title("Query Latency Distribution")
                ax.grid(axis="y", alpha=0.3)
                save_plot(fig, outdir / "query_latency_boxplots.png", export_tikz=export_tikz)

            if not by_run.empty:
                fig = plt.figure(figsize=(10, 5))
                for metric, g in by_run.groupby("metric", dropna=False):
                    plt.plot(g["run_num"], g["latency_ms"], marker="o", label=metric)
                plt.xlabel("Run #")
                plt.ylabel("Mean Latency (ms)")
                plt.title("Query Latency by Run")
                plt.grid(alpha=0.3)
                plt.legend()
                save_plot(fig, outdir / "query_latency_by_run.png", export_tikz=export_tikz)

        size_present = [m for m in size_metrics if m in iter_df.columns]
        if size_present:
            size_summary_rows = []
            for metric in size_present:
                vals = iter_df[metric].dropna().tolist()
                if not vals:
                    size_summary_rows.append(
                        {
                            "metric": metric,
                            "count": 0,
                            "mean": "",
                            "std": "",
                            "p50": "",
                            "p95": "",
                            "p99": "",
                            "min": "",
                            "max": "",
                        }
                    )
                    continue
                arr = np.array(vals, dtype=float)
                size_summary_rows.append(
                    {
                        "metric": metric,
                        "count": int(len(arr)),
                        "mean": float(np.mean(arr)),
                        "std": float(np.std(arr)),
                        "p50": float(np.percentile(arr, 50)),
                        "p95": float(np.percentile(arr, 95)),
                        "p99": float(np.percentile(arr, 99)),
                        "min": float(np.min(arr)),
                        "max": float(np.max(arr)),
                    }
                )
            size_summary_df = pd.DataFrame(size_summary_rows)
            size_summary_path = outdir / "query_merkle_size_summary.csv"
            size_summary_df.to_csv(size_summary_path, index=False)
            wrote.append(size_summary_path)

            proof_size_cols = [
                c for c in ["merkle_proof_payload_bytes", "merkle_proof_only_bytes", "merkle_root_payload_bytes"] if c in iter_df.columns
            ]
            if proof_size_cols:
                box_groups = []
                box_labels = []
                for col in proof_size_cols:
                    vals = iter_df[col].dropna()
                    if len(vals) == 0:
                        continue
                    box_groups.append(vals)
                    box_labels.append(col)
                if box_groups:
                    fig, ax = plt.subplots(figsize=(10, 5))
                    boxplot_with_labels(ax, box_groups, box_labels, showfliers=False)
                    ax.set_ylabel("Bytes")
                    ax.set_title("Merkle Payload/Proof Size Distribution")
                    ax.grid(axis="y", alpha=0.3)
                    apply_bytes_axis(ax, axis="y")
                    concat_vals = np.concatenate([vals.to_numpy(dtype=float) for vals in box_groups if len(vals) > 0])
                    apply_nonnegative_baseline(ax, concat_vals, boxplot=True)
                    save_plot(fig, outdir / "query_merkle_proof_size_boxplots.png", export_tikz=export_tikz)

            if {"merkle_tree_size", "merkle_proof_payload_bytes"}.issubset(iter_df.columns):
                scatter_df = iter_df[["merkle_tree_size", "merkle_proof_payload_bytes"]].dropna()
                if not scatter_df.empty:
                    fig, ax = plt.subplots(figsize=(8.5, 5))
                    ax.scatter(
                        scatter_df["merkle_tree_size"].to_numpy(dtype=float),
                        scatter_df["merkle_proof_payload_bytes"].to_numpy(dtype=float),
                        alpha=0.75,
                        s=24,
                    )
                    ax.set_xlabel("Merkle Tree Size")
                    ax.set_ylabel("Proof Payload Size (bytes)")
                    ax.set_title("Merkle Tree Size vs Proof Payload Size")
                    ax.grid(alpha=0.3)
                    apply_bytes_axis(ax, axis="y")
                    apply_nonnegative_baseline(
                        ax,
                        scatter_df["merkle_proof_payload_bytes"].to_numpy(dtype=float),
                        axis="y",
                    )
                    save_plot(fig, outdir / "query_merkle_tree_vs_proof_size.png", export_tikz=export_tikz)

    else:
        # Fallback: if only per-run summary exists, emit it as by-run CSV.
        fallback_out = outdir / "query_latency_summary_by_metric.csv"
        summary_df.to_csv(fallback_out, index=False)
        wrote.append(fallback_out)

    for p in wrote:
        print(f"Wrote: {p}")

def analyze_communication(suite_root: Path, outdir: Path, export_tikz: bool = False):
    """analyze_communication helper for benchmark tooling."""
    msg_path = suite_root / "suite_message_counts_all_runs.csv"
    phase_path = suite_root / "suite_phase_summary_all_runs.csv"
    manifest_path = suite_root / "suite_manifest.json"
    msg_df = safe_read_csv(msg_path)
    phase_df = safe_read_csv(phase_path)

    if msg_df.empty:
        fallback_parts = []
        for run_dir in sorted(suite_root.glob("run_*")):
            fallback_path = run_dir / "raw" / "message_counts.csv"
            part = safe_read_csv(fallback_path)
            if part.empty:
                continue
            part["run_id"] = run_dir.name
            fallback_parts.append(part)
        if fallback_parts:
            msg_df = pd.concat(fallback_parts, ignore_index=True)
            print(
                "Info: suite_message_counts_all_runs.csv missing; "
                "using per-run raw/message_counts.csv fallback."
            )

    if msg_df.empty and phase_df.empty:
        print(f"Info: missing/empty {msg_path.name} and {phase_path.name}")
        return

    wrote_paths = []

    if not msg_df.empty:
        if "workflow_base" not in msg_df.columns:
            msg_df["workflow_base"] = msg_df.get("workflow", "").map(workflow_base_from_tag)
        if "run_id" in msg_df.columns:
            msg_df["run_num"] = msg_df["run_id"].map(run_num_from_id)
        else:
            msg_df["run_id"] = ""
            msg_df["run_num"] = -1

        msg_numeric_cols = [
            "tss_p2p_sent",
            "tss_p2p_recv",
            "tss_p2p_sent_broadcast",
            "tss_p2p_sent_direct",
            "tss_p2p_recv_broadcast",
            "tss_p2p_recv_direct",
            "gossip_metric_total",
        ]
        for col in msg_numeric_cols:
            if col in msg_df.columns:
                msg_df[col] = pd.to_numeric(msg_df[col], errors="coerce")

        msg_df["tss_total_msgs"] = msg_df[["tss_p2p_sent", "tss_p2p_recv"]].sum(axis=1, min_count=1)
        msg_df["broadcast_total_msgs"] = msg_df[
            ["tss_p2p_sent_broadcast", "tss_p2p_recv_broadcast"]
        ].sum(axis=1, min_count=1)
        msg_df["direct_total_msgs"] = msg_df[
            ["tss_p2p_sent_direct", "tss_p2p_recv_direct"]
        ].sum(axis=1, min_count=1)
        msg_df["sent_recv_imbalance_msgs"] = msg_df["tss_p2p_sent"] - msg_df["tss_p2p_recv"]

        msg_enriched_path = outdir / "communication_message_counts_enriched.csv"
        msg_df.to_csv(msg_enriched_path, index=False)
        wrote_paths.append(msg_enriched_path)

        summary_cols = [
            c
            for c in [
                "tss_p2p_sent",
                "tss_p2p_recv",
                "tss_total_msgs",
                "broadcast_total_msgs",
                "direct_total_msgs",
                "sent_recv_imbalance_msgs",
                "gossip_metric_total",
            ]
            if c in msg_df.columns
        ]
        if summary_cols:
            msg_summary = (
                msg_df.groupby("workflow_base", dropna=False)[summary_cols]
                .agg(["count", "mean", "min", "max", "sum"])
                .reset_index()
            )
            msg_summary = flatten_multiindex_columns(msg_summary)
            msg_summary = msg_summary.rename(columns={"workflow_base_": "workflow_base"})
            msg_summary_path = outdir / "communication_message_summary_by_workflow.csv"
            msg_summary.to_csv(msg_summary_path, index=False)
            wrote_paths.append(msg_summary_path)

            mean_df = (
                msg_df.groupby("workflow_base", dropna=False)[summary_cols]
                .mean(numeric_only=True)
                .reset_index()
                .sort_values("workflow_base")
            )
            if {"tss_p2p_sent", "tss_p2p_recv"}.issubset(mean_df.columns):
                fig = plt.figure(figsize=(9, 5))
                x = np.arange(len(mean_df))
                width = 0.35
                plt.bar(x - width / 2, mean_df["tss_p2p_sent"], width=width, label="sent")
                plt.bar(x + width / 2, mean_df["tss_p2p_recv"], width=width, label="recv")
                plt.xticks(x, mean_df["workflow_base"])
                plt.ylabel("Message count per operation (avg)")
                plt.title("TSS Messages Sent/Received by Workflow")
                plt.grid(axis="y", alpha=0.3)
                plt.legend()
                save_plot(fig, outdir / "communication_sent_recv_by_workflow.png", export_tikz=export_tikz)

            mode_cols = [
                "tss_p2p_sent_broadcast",
                "tss_p2p_sent_direct",
                "tss_p2p_recv_broadcast",
                "tss_p2p_recv_direct",
            ]
            if all(c in mean_df.columns for c in mode_cols):
                fig, axes = plt.subplots(1, 2, figsize=(12, 5), sharey=True)
                x = np.arange(len(mean_df))

                sent_bc = mean_df["tss_p2p_sent_broadcast"].to_numpy()
                sent_dir = mean_df["tss_p2p_sent_direct"].to_numpy()
                axes[0].bar(x, sent_bc, label="broadcast")
                axes[0].bar(x, sent_dir, bottom=sent_bc, label="direct")
                axes[0].set_xticks(x, mean_df["workflow_base"])
                axes[0].set_title("Sent Network Type Split")
                axes[0].set_xlabel("workflow")
                axes[0].set_ylabel("Message count per operation (avg)")
                axes[0].grid(axis="y", alpha=0.3)

                recv_bc = mean_df["tss_p2p_recv_broadcast"].to_numpy()
                recv_dir = mean_df["tss_p2p_recv_direct"].to_numpy()
                axes[1].bar(x, recv_bc, label="broadcast")
                axes[1].bar(x, recv_dir, bottom=recv_bc, label="direct")
                axes[1].set_xticks(x, mean_df["workflow_base"])
                axes[1].set_title("Received Network Type Split")
                axes[1].set_xlabel("workflow")
                axes[1].grid(axis="y", alpha=0.3)

                handles, labels = axes[0].get_legend_handles_labels()
                if handles:
                    fig.legend(handles, labels, loc="upper center", ncol=2)
                fig.suptitle("Network Type (Broadcast vs Direct) by Workflow")
                save_plot(fig, outdir / "communication_network_type_split_by_workflow.png", export_tikz=export_tikz)

        run_cols = [c for c in ["tss_p2p_sent", "tss_p2p_recv", "tss_total_msgs"] if c in msg_df.columns]
        if run_cols:
            msg_run = (
                msg_df[msg_df["run_num"] >= 0]
                .groupby(["run_id", "run_num", "workflow_base"], dropna=False)[run_cols]
                .mean(numeric_only=True)
                .reset_index()
                .sort_values(["workflow_base", "run_num"])
            )
            msg_run_path = outdir / "communication_message_counts_by_run_workflow.csv"
            msg_run.to_csv(msg_run_path, index=False)
            wrote_paths.append(msg_run_path)
            if not msg_run.empty and "tss_total_msgs" in msg_run.columns:
                fig = plt.figure(figsize=(10, 5))
                for wf, g in msg_run.groupby("workflow_base", dropna=False):
                    g = g.sort_values("run_num")
                    plt.plot(g["run_num"], g["tss_total_msgs"], marker="o", label=str(wf))
                plt.xlabel("Run #")
                plt.ylabel("Total messages per operation (avg)")
                plt.title("TSS Total Message Count by Run")
                plt.grid(alpha=0.3)
                plt.legend()
                save_plot(fig, outdir / "communication_messages_by_run.png", export_tikz=export_tikz)

        type_rows = []
        for _, row in msg_df.iterrows():
            run_id = str(row.get("run_id", "")).strip()
            run_num = row.get("run_num", -1)
            workflow = str(row.get("workflow_base", "")).strip()
            for direction, key in [("sent", "tss_p2p_sent_by_type"), ("recv", "tss_p2p_recv_by_type")]:
                if key not in msg_df.columns:
                    continue
                counters = parse_counter_map(row.get(key, ""))
                for msg_type, count in counters.items():
                    type_rows.append(
                        {
                            "run_id": run_id,
                            "run_num": run_num,
                            "workflow_base": workflow,
                            "direction": direction,
                            "message_type": msg_type,
                            "count": float(count),
                        }
                    )
        type_df = pd.DataFrame(type_rows)
        if not type_df.empty:
            type_long_path = outdir / "communication_type_counts_long.csv"
            type_df.to_csv(type_long_path, index=False)
            wrote_paths.append(type_long_path)

            type_wf = (
                type_df.groupby(["workflow_base", "direction", "message_type"], dropna=False)["count"]
                .sum()
                .reset_index()
                .sort_values(["workflow_base", "direction", "count"], ascending=[True, True, False])
            )
            type_wf_path = outdir / "communication_type_counts_by_workflow.csv"
            type_wf.to_csv(type_wf_path, index=False)
            wrote_paths.append(type_wf_path)

    tx_path = suite_root / "suite_tx_events_all_runs.csv"
    tx_df = safe_read_csv(tx_path)
    if not tx_df.empty:
        if "workflow_base" not in tx_df.columns:
            tx_df["workflow_base"] = tx_df.get("workflow", "").map(workflow_base_from_tag)
        tx_df["workflow_base"] = tx_df["workflow_base"].astype(str).str.strip()
        tx_df = tx_df[tx_df["workflow_base"] != ""].copy()
        if "run_id" not in tx_df.columns:
            tx_df["run_id"] = ""
        tx_df["run_num"] = tx_df["run_id"].map(run_num_from_id)
        if "event" not in tx_df.columns:
            tx_df["event"] = ""
        tx_df["event"] = tx_df["event"].astype(str).str.strip()
        if "event_name" not in tx_df.columns:
            tx_df["event_name"] = ""
        tx_df["event_name"] = tx_df["event_name"].astype(str).str.strip()
        if "operation_id" not in tx_df.columns:
            tx_df["operation_id"] = ""
        tx_df["operation_id"] = tx_df["operation_id"].astype(str).str.strip()
        if "function" not in tx_df.columns:
            tx_df["function"] = ""
        tx_df["function"] = tx_df["function"].astype(str).str.strip()

        # StorageAttribution is a benchmark-only synthetic mirror event for logical-write accounting.
        # Exclude it from blockchain signal counts to avoid inflating cc_event_observed.
        is_storage_attr = (
            tx_df["event"].astype(str).str.strip().str.lower().eq("cc_event_observed")
            & tx_df["event_name"].astype(str).str.strip().str.lower().eq("storageattribution")
        )
        storage_attr_by_wf = (
            tx_df[is_storage_attr]
            .groupby("workflow_base", dropna=False)
            .size()
            .reset_index(name="excluded_storage_attribution_rows")
        )
        tx_df_comm = tx_df[~is_storage_attr].copy()

        tracked_events = ["tx_submit_started", "tx_submitted", "tx_committed", "tx_failed", "cc_event_observed"]
        event_counts = (
            tx_df_comm.groupby(["workflow_base", "event"], dropna=False)
            .size()
            .unstack(fill_value=0)
            .reset_index()
        )
        for ev in tracked_events:
            if ev not in event_counts.columns:
                event_counts[ev] = 0
        keep_cols = ["workflow_base"] + tracked_events
        event_counts = event_counts[keep_cols]

        unique_runs = (
            tx_df_comm.groupby("workflow_base", dropna=False)["run_id"]
            .nunique()
            .reset_index(name="unique_runs")
        )
        unique_ops = (
            tx_df_comm[tx_df_comm["operation_id"] != ""]
            .groupby("workflow_base", dropna=False)["operation_id"]
            .nunique()
            .reset_index(name="unique_operations")
        )
        committed = tx_df_comm[tx_df_comm["event"] == "tx_committed"].copy()
        vote_functions = {"VoteOnCSR", "VoteOnRevocation", "VoteOnJoinRequest", "VoteOnRemoveMember"}
        committed["is_vote_tx"] = committed["function"].isin(vote_functions)
        committed_totals = (
            committed.groupby("workflow_base", dropna=False)["is_vote_tx"]
            .agg(committed_tx_count="size", committed_vote_tx_count="sum")
            .reset_index()
        )
        committed_totals["committed_vote_tx_ratio"] = np.where(
            committed_totals["committed_tx_count"] > 0,
            committed_totals["committed_vote_tx_count"] / committed_totals["committed_tx_count"],
            np.nan,
        )

        bc_summary = event_counts.merge(unique_runs, on="workflow_base", how="left")
        bc_summary = bc_summary.merge(unique_ops, on="workflow_base", how="left")
        bc_summary = bc_summary.merge(committed_totals, on="workflow_base", how="left")
        bc_summary = bc_summary.merge(storage_attr_by_wf, on="workflow_base", how="left")
        bc_summary["excluded_storage_attribution_rows"] = (
            pd.to_numeric(bc_summary["excluded_storage_attribution_rows"], errors="coerce")
            .fillna(0)
            .astype(int)
        )
        bc_summary["blockchain_signal_rows_total"] = bc_summary[tracked_events].sum(axis=1, min_count=1)
        for ev in tracked_events:
            bc_summary[f"{ev}_avg_per_run"] = np.where(
                bc_summary["unique_runs"] > 0,
                pd.to_numeric(bc_summary[ev], errors="coerce") / bc_summary["unique_runs"],
                np.nan,
            )
            bc_summary[f"{ev}_avg_per_operation"] = np.where(
                bc_summary["unique_operations"] > 0,
                pd.to_numeric(bc_summary[ev], errors="coerce") / bc_summary["unique_operations"],
                np.nan,
            )
        bc_summary["blockchain_signal_rows_total_avg_per_run"] = np.where(
            bc_summary["unique_runs"] > 0,
            pd.to_numeric(bc_summary["blockchain_signal_rows_total"], errors="coerce") / bc_summary["unique_runs"],
            np.nan,
        )
        bc_summary["blockchain_signal_rows_total_avg_per_operation"] = np.where(
            bc_summary["unique_operations"] > 0,
            pd.to_numeric(bc_summary["blockchain_signal_rows_total"], errors="coerce") / bc_summary["unique_operations"],
            np.nan,
        )
        bc_summary = bc_summary.sort_values("workflow_base")
        bc_summary_path = outdir / "communication_blockchain_message_counts_by_workflow.csv"
        bc_summary.to_csv(bc_summary_path, index=False)
        wrote_paths.append(bc_summary_path)

        by_run = (
            tx_df_comm.groupby(["run_id", "run_num", "workflow_base", "event"], dropna=False)
            .size()
            .unstack(fill_value=0)
            .reset_index()
        )
        for ev in tracked_events:
            if ev not in by_run.columns:
                by_run[ev] = 0
        by_run["blockchain_signal_rows_total"] = by_run[tracked_events].sum(axis=1, min_count=1)
        by_run = by_run[["run_id", "run_num", "workflow_base"] + tracked_events + ["blockchain_signal_rows_total"]]
        by_run = by_run.sort_values(["workflow_base", "run_num"])
        by_run_path = outdir / "communication_blockchain_message_counts_by_run_workflow.csv"
        by_run.to_csv(by_run_path, index=False)
        wrote_paths.append(by_run_path)

        if not bc_summary.empty:
            fig = plt.figure(figsize=(10, 5))
            x = np.arange(len(bc_summary))
            bottom = np.zeros(len(bc_summary))
            stacked_cols = ["tx_submitted", "tx_committed", "cc_event_observed", "tx_failed"]
            for col in stacked_cols:
                avg_col = f"{col}_avg_per_run"
                vals = pd.to_numeric(bc_summary.get(avg_col, np.nan), errors="coerce").fillna(0).to_numpy()
                plt.bar(x, vals, bottom=bottom, label=col)
                bottom = bottom + vals
            plt.xticks(x, bc_summary["workflow_base"])
            plt.ylabel("Rows per run (avg)")
            plt.title("Blockchain Message Signals by Workflow (Average per Run)")
            plt.grid(axis="y", alpha=0.3)
            plt.legend()
            save_plot(fig, outdir / "communication_blockchain_messages_by_workflow.png", export_tikz=export_tikz)

    if not phase_df.empty and {"rx_delta_sum", "tx_delta_sum"}.issubset(phase_df.columns):
        if "workflow_base" not in phase_df.columns:
            phase_df["workflow_base"] = phase_df.get("workflow", "").map(workflow_base_from_tag)
        if "run_id" in phase_df.columns:
            phase_df["run_num"] = phase_df["run_id"].map(run_num_from_id)
        else:
            phase_df["run_id"] = ""
            phase_df["run_num"] = -1
        phase_df["rx_delta_sum"] = pd.to_numeric(phase_df["rx_delta_sum"], errors="coerce")
        phase_df["tx_delta_sum"] = pd.to_numeric(phase_df["tx_delta_sum"], errors="coerce")
        has_adjusted = {"rx_delta_adjusted_sum", "tx_delta_adjusted_sum"}.issubset(phase_df.columns)
        if has_adjusted:
            phase_df["rx_delta_adjusted_sum"] = pd.to_numeric(phase_df["rx_delta_adjusted_sum"], errors="coerce")
            phase_df["tx_delta_adjusted_sum"] = pd.to_numeric(phase_df["tx_delta_adjusted_sum"], errors="coerce")
        has_control = {"control_rx_delta_sum", "control_tx_delta_sum"}.issubset(phase_df.columns)
        if has_control:
            phase_df["control_rx_delta_sum"] = pd.to_numeric(phase_df["control_rx_delta_sum"], errors="coerce")
            phase_df["control_tx_delta_sum"] = pd.to_numeric(phase_df["control_tx_delta_sum"], errors="coerce")

        agg_cols = ["rx_delta_sum", "tx_delta_sum"]
        if has_adjusted:
            agg_cols.extend(["rx_delta_adjusted_sum", "tx_delta_adjusted_sum"])
        if has_control:
            agg_cols.extend(["control_rx_delta_sum", "control_tx_delta_sum"])

        bytes_by_run = (
            phase_df.groupby(["run_id", "run_num", "workflow_base"], dropna=False)[agg_cols]
            .sum(min_count=1)
            .reset_index()
        )
        bytes_by_run["total_bytes_raw"] = bytes_by_run[["rx_delta_sum", "tx_delta_sum"]].sum(axis=1, min_count=1)
        if has_adjusted:
            bytes_by_run["rx_delta_sum_raw"] = bytes_by_run["rx_delta_sum"]
            bytes_by_run["tx_delta_sum_raw"] = bytes_by_run["tx_delta_sum"]
            bytes_by_run["rx_delta_sum"] = bytes_by_run["rx_delta_adjusted_sum"]
            bytes_by_run["tx_delta_sum"] = bytes_by_run["tx_delta_adjusted_sum"]
            bytes_by_run["total_bytes_adjusted"] = bytes_by_run[["rx_delta_sum", "tx_delta_sum"]].sum(axis=1, min_count=1)
            bytes_by_run["total_bytes"] = bytes_by_run["total_bytes_adjusted"]
            bytes_by_run["network_bytes_mode"] = "adjusted_control_ports"
        else:
            bytes_by_run["total_bytes"] = bytes_by_run["total_bytes_raw"]
            bytes_by_run["network_bytes_mode"] = "raw"
        bytes_by_run = bytes_by_run.sort_values(["workflow_base", "run_num"])
        bytes_by_run_path = outdir / "communication_bytes_by_run_workflow.csv"
        bytes_by_run.to_csv(bytes_by_run_path, index=False)
        wrote_paths.append(bytes_by_run_path)

        summary_cols = ["rx_delta_sum", "tx_delta_sum", "total_bytes"]
        for extra in ["rx_delta_sum_raw", "tx_delta_sum_raw", "total_bytes_raw", "total_bytes_adjusted", "control_rx_delta_sum", "control_tx_delta_sum"]:
            if extra in bytes_by_run.columns:
                summary_cols.append(extra)
        bytes_summary = (
            bytes_by_run.groupby("workflow_base", dropna=False)[summary_cols]
            .agg(["count", "mean", "min", "max", "sum"])
            .reset_index()
        )
        bytes_summary = flatten_multiindex_columns(bytes_summary)
        bytes_summary = bytes_summary.rename(columns={"workflow_base_": "workflow_base"})
        bytes_summary_path = outdir / "communication_bytes_summary_by_workflow.csv"
        bytes_summary.to_csv(bytes_summary_path, index=False)
        wrote_paths.append(bytes_summary_path)

        mean_bytes = (
            bytes_by_run.groupby("workflow_base", dropna=False)[["rx_delta_sum", "tx_delta_sum"]]
            .mean(numeric_only=True)
            .reset_index()
            .sort_values("workflow_base")
        )
        if not mean_bytes.empty:
            mode_label = "control-adjusted" if has_adjusted else "raw"
            fig = plt.figure(figsize=(9, 5))
            x = np.arange(len(mean_bytes))
            width = 0.35
            plt.bar(x - width / 2, mean_bytes["rx_delta_sum"], width=width, label="rx")
            plt.bar(x + width / 2, mean_bytes["tx_delta_sum"], width=width, label="tx")
            plt.xticks(x, mean_bytes["workflow_base"])
            plt.ylabel("Bytes per operation (avg)")
            plt.title(f"Network Bytes (RX/TX) by Workflow ({mode_label})")
            plt.grid(axis="y", alpha=0.3)
            plt.legend()
            ax = plt.gca()
            apply_bytes_axis(ax, axis="y")
            apply_nonnegative_baseline(
                ax,
                np.concatenate(
                    [
                        pd.to_numeric(mean_bytes["rx_delta_sum"], errors="coerce").fillna(0).to_numpy(),
                        pd.to_numeric(mean_bytes["tx_delta_sum"], errors="coerce").fillna(0).to_numpy(),
                    ]
                ),
            )
            save_plot(fig, outdir / "communication_bytes_by_workflow.png", export_tikz=export_tikz)

        bytes_run_plot = bytes_by_run[bytes_by_run["run_num"] >= 0].copy()
        if not bytes_run_plot.empty:
            mode_label = "control-adjusted" if has_adjusted else "raw"
            fig = plt.figure(figsize=(10, 5))
            for wf, g in bytes_run_plot.groupby("workflow_base", dropna=False):
                g = g.sort_values("run_num")
                plt.plot(g["run_num"], g["total_bytes"], marker="o", label=str(wf))
            plt.xlabel("Run #")
            plt.ylabel("Total RX+TX bytes per operation")
            plt.title(f"Network Bytes by Run ({mode_label})")
            plt.grid(alpha=0.3)
            plt.legend()
            ax = plt.gca()
            apply_bytes_axis(ax, axis="y")
            apply_nonnegative_baseline(
                ax,
                pd.to_numeric(bytes_run_plot["total_bytes"], errors="coerce").fillna(0).to_numpy(),
            )
            save_plot(fig, outdir / "communication_bytes_by_run.png", export_tikz=export_tikz)

    if manifest_path.exists():
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
            cfg = manifest.get("config", {})
            passthrough = cfg.get("run_workflows_pass_through", {})
            context_df = pd.DataFrame(
                [
                    {
                        "resources_iface": passthrough.get("resources_iface", ""),
                        "no_resources_control_subtract": bool(
                            passthrough.get("no_resources_control_subtract", False)
                        ),
                        "resources_control_exclude_port": ";".join(
                            str(x) for x in (passthrough.get("resources_control_exclude_port", []) or [])
                        ),
                        "peer_metrics_url_count": len(passthrough.get("peer_metrics_url", []) or []),
                        "peer_metrics_prefix": ";".join(passthrough.get("peer_metrics_prefix", []) or []),
                        "collect_messages": bool(passthrough.get("collect_messages", False)),
                    }
                ]
            )
            ctx_path = outdir / "communication_network_context.csv"
            context_df.to_csv(ctx_path, index=False)
            wrote_paths.append(ctx_path)
        except Exception:
            pass

    for p in wrote_paths:
        print(f"Wrote: {p}")

def tx_event_key(row: pd.Series) -> str:
    """tx_event_key helper for benchmark tooling."""
    event = str(row.get("event", "") or "").strip()
    event_name = str(row.get("event_name", "") or "").strip()
    action = str(row.get("action", "") or "").strip()
    function = str(row.get("function", "") or "").strip()
    if event == "cc_event_observed":
        label = event_name or action or "unknown_cc_event"
        return f"cc:{label}"
    if event.startswith("tx_"):
        return f"{event}:{function}" if function else event
    if event_name:
        return event_name
    if action:
        return f"{event}:{action}" if event else action
    return event or "unknown"

def analyze_tx_events(suite_root: Path, outdir: Path, export_tikz: bool = False):
    """analyze_tx_events helper for benchmark tooling."""
    path = suite_root / "suite_tx_events_all_runs.csv"
    df = safe_read_csv(path)
    if df.empty:
        print(f"Info: missing/empty {path.name}")
        return

    if "workflow_base" not in df.columns:
        df["workflow_base"] = df.get("workflow", "").map(workflow_base_from_tag)
    else:
        missing = df["workflow_base"].isna() | (df["workflow_base"].astype(str).str.strip() == "")
        df.loc[missing, "workflow_base"] = df.loc[missing, "workflow"].map(workflow_base_from_tag)
    df["workflow_base"] = df["workflow_base"].astype(str).str.strip()
    df.loc[df["workflow_base"].str.lower().isin(["nan", "none", "<na>"]), "workflow_base"] = ""
    if "run_id" in df.columns:
        df["run_id_norm"] = df["run_id"].astype(str).str.strip()
        df.loc[df["run_id_norm"] == "", "run_id_norm"] = "unmapped"
    else:
        df["run_id_norm"] = "unmapped"
    if "operation_id" in df.columns:
        df["operation_id_norm"] = df["operation_id"].astype(str).str.strip()
    else:
        df["operation_id_norm"] = ""
    df["event_key"] = df.apply(tx_event_key, axis=1)

    counts = (
        df.groupby(["run_id_norm", "workflow_base", "event_key"], dropna=False)
        .size()
        .reset_index(name="count")
        .sort_values(["run_id_norm", "workflow_base", "count", "event_key"], ascending=[True, True, False, True])
    )
    counts_path = outdir / "tx_event_counts_by_run_workflow.csv"
    counts.to_csv(counts_path, index=False)

    workflow_runs_path = resolve_suite_workflow_runs_path(suite_root)
    workflow_runs = safe_read_csv(workflow_runs_path)
    coverage_rows = []
    if not workflow_runs.empty:
        if "workflow_base" not in workflow_runs.columns:
            workflow_runs["workflow_base"] = workflow_runs.get("workflow_tag", "").map(workflow_base_from_tag)
        else:
            missing = workflow_runs["workflow_base"].isna() | (workflow_runs["workflow_base"].astype(str).str.strip() == "")
            workflow_runs.loc[missing, "workflow_base"] = workflow_runs.loc[missing, "workflow_tag"].map(workflow_base_from_tag)
        workflow_runs["workflow_base"] = workflow_runs["workflow_base"].astype(str).str.strip()
        workflow_runs.loc[workflow_runs["workflow_base"].str.lower().isin(["nan", "none", "<na>"]), "workflow_base"] = ""
        if "run_id" not in workflow_runs.columns:
            workflow_runs["run_id"] = ""
        if "operation_id" not in workflow_runs.columns:
            workflow_runs["operation_id"] = ""

        ops = workflow_runs.copy()
        ops["run_id_norm"] = ops["run_id"].astype(str).str.strip()
        ops["operation_id_norm"] = ops["operation_id"].astype(str).str.strip()
        ops = ops[(ops["workflow_base"].astype(str).str.strip() != "") & (ops["operation_id_norm"] != "")]
        total_ops_raw = (
            ops[["run_id_norm", "workflow_base", "operation_id_norm"]]
            .drop_duplicates()
            .groupby("workflow_base", dropna=False)
            .size()
            .to_dict()
        )

        ev_pairs = df.copy()
        ev_pairs = ev_pairs[
            (ev_pairs["workflow_base"].astype(str).str.strip() != "")
            & (ev_pairs["operation_id_norm"] != "")
            & (ev_pairs["run_id_norm"] != "unmapped")
        ]
        rows_with_event_raw = (
            ev_pairs[["run_id_norm", "workflow_base", "operation_id_norm"]]
            .drop_duplicates()
            .groupby("workflow_base", dropna=False)
            .size()
            .to_dict()
        )

        # Normalize workflow keys to strings to avoid mixed-type key mismatches
        # (e.g., float/NaN keys from CSV inference) during lookup and ordering.
        total_ops = {}
        for key, value in total_ops_raw.items():
            token = str(key).strip()
            if token == "" or token.lower() in {"nan", "none", "<na>"}:
                continue
            total_ops[token] = total_ops.get(token, 0) + int(value)

        rows_with_event = {}
        for key, value in rows_with_event_raw.items():
            token = str(key).strip()
            if token == "" or token.lower() in {"nan", "none", "<na>"}:
                continue
            rows_with_event[token] = rows_with_event.get(token, 0) + int(value)

        workflow_keys = []
        for wf in list(total_ops.keys()) + list(rows_with_event.keys()):
            token = str(wf).strip()
            if token == "" or token.lower() in {"nan", "none", "<na>"}:
                continue
            workflow_keys.append(token)
        workflows = ordered_workflows(workflow_keys)
        for wf in workflows:
            ops_total = int(total_ops.get(wf, 0))
            ops_with = int(rows_with_event.get(wf, 0))
            coverage = float(ops_with / ops_total) if ops_total > 0 else 0.0
            coverage_rows.append(
                {
                    "workflow_base": wf,
                    "total_ops": ops_total,
                    "ops_with_events": ops_with,
                    "event_coverage_ratio": coverage,
                }
            )
    coverage_df = pd.DataFrame(coverage_rows)
    coverage_path = outdir / "tx_event_coverage_by_workflow.csv"
    coverage_df.to_csv(coverage_path, index=False)

    mapping_summary = (
        df.groupby("run_id_norm", dropna=False)
        .size()
        .reset_index(name="rows")
        .sort_values("rows", ascending=False)
    )
    mapping_summary_path = outdir / "tx_event_run_mapping_summary.csv"
    mapping_summary.to_csv(mapping_summary_path, index=False)

    print(f"Wrote: {counts_path}")
    print(f"Wrote: {coverage_path}")
    print(f"Wrote: {mapping_summary_path}")

    if not coverage_df.empty and float(coverage_df["event_coverage_ratio"].mean()) < 0.6:
        print(
            "Warning: tx event coverage is sparse (<60% ops with events). "
            "Check --metrics paths and peer event listener health."
        )

def analyze_optimization_potential(suite_root: Path, outdir: Path, export_tikz: bool = False):
    """analyze_optimization_potential helper for benchmark tooling."""
    enriched_path = outdir / "workflow_runs_enriched.csv"
    enriched_legacy_path = outdir / "workflow_runs_v2_enriched.csv"
    wf_path = resolve_suite_workflow_runs_path(suite_root)

    wf = safe_read_csv(enriched_path)
    if wf.empty:
        wf = safe_read_csv(enriched_legacy_path)
    if wf.empty:
        wf = safe_read_csv(wf_path)
        if wf.empty:
            print(f"Info: missing/empty {wf_path.name}")
            return
        if "workflow_base" not in wf.columns:
            wf["workflow_base"] = wf.get("workflow_tag", "").map(workflow_base_from_tag)
        time_cols = [
            "client_start_ts",
            "client_end_ts",
            "submitted_observed_ts",
            "voted_ts",
            "approved_or_executed_ts",
        ]
        wf = to_datetime_utc(wf, time_cols)
        duration_seconds(wf, "client_start_ts", "client_end_ts", "client_duration_s")
        duration_seconds(wf, "submitted_observed_ts", "voted_ts", "submit_to_vote_s")
        duration_seconds(wf, "voted_ts", "approved_or_executed_ts", "vote_to_approved_s")

    for c in ["client_duration_s", "submit_to_vote_s", "vote_to_approved_s"]:
        if c in wf.columns:
            wf[c] = pd.to_numeric(wf[c], errors="coerce")
        else:
            wf[c] = np.nan

    wf_ops = wf.copy()
    wf_ops["run_id"] = wf_ops.get("run_id", "").astype(str).str.strip()
    wf_ops["operation_id"] = wf_ops.get("operation_id", "").astype(str).str.strip()
    wf_ops["workflow_base"] = wf_ops.get("workflow_base", "").astype(str).str.strip()
    wf_ops["voting_phase_s"] = wf_ops[["submit_to_vote_s", "vote_to_approved_s"]].sum(axis=1, min_count=1)
    wf_ops["voting_phase_s"] = pd.to_numeric(wf_ops["voting_phase_s"], errors="coerce").fillna(0).clip(lower=0)
    wf_ops["client_duration_s"] = pd.to_numeric(wf_ops["client_duration_s"], errors="coerce")

    ops = wf_ops.copy()
    ops["no_voting_savings_est_s"] = pd.to_numeric(ops["voting_phase_s"], errors="coerce").fillna(0).clip(lower=0)
    ops["projected_client_no_voting_s"] = np.where(
        ops["client_duration_s"].notna(),
        np.maximum(ops["client_duration_s"] - ops["no_voting_savings_est_s"], 0),
        np.nan,
    )
    ops["no_voting_savings_pct"] = np.where(
        ops["client_duration_s"] > 0,
        (ops["no_voting_savings_est_s"] / ops["client_duration_s"]) * 100.0,
        np.nan,
    )

    op_out = outdir / "optimization_potential_by_operation.csv"
    ops.to_csv(op_out, index=False)

    wf_summary = (
        ops.groupby("workflow_base", dropna=False)[
            [
                "client_duration_s",
                "no_voting_savings_est_s",
                "projected_client_no_voting_s",
                "no_voting_savings_pct",
            ]
        ]
        .agg(["count", "mean", "min", "max", "median", "sum"])
        .reset_index()
    )
    wf_summary.columns = ["_".join([c for c in col if c]) for col in wf_summary.columns.to_flat_index()]
    wf_summary = wf_summary.rename(columns={"workflow_base_": "workflow_base"})
    wf_out = outdir / "optimization_potential_by_workflow.csv"
    wf_summary.to_csv(wf_out, index=False)

    # Estimate ledger-size shrink for "no voting" with priority:
    # 1) direct vote-stage deltas from suite_storage_stage_deltas_all_runs.csv
    # 2) fallback tx-ratio estimator when direct stage coverage is missing.
    storage_path = suite_root / "suite_storage_deltas_all_runs.csv"
    tx_path = suite_root / "suite_tx_events_all_runs.csv"
    stage_path = suite_root / "suite_storage_stage_deltas_all_runs.csv"
    storage_df = safe_read_csv(storage_path)
    tx_df = safe_read_csv(tx_path)
    stage_df = safe_read_csv(stage_path)
    op_impact_out = None
    wf_impact_out = None

    if not storage_df.empty:
        if "workflow_base" not in storage_df.columns:
            storage_df["workflow_base"] = storage_df.get("workflow", "").map(workflow_base_from_tag)
        storage_df["workflow_base"] = storage_df["workflow_base"].astype(str).str.strip()
        if "run_id" not in storage_df.columns:
            storage_df["run_id"] = ""
        storage_df["run_id"] = storage_df["run_id"].astype(str).str.strip()
        if "delta_bytes" in storage_df.columns:
            storage_df["delta_bytes"] = pd.to_numeric(storage_df["delta_bytes"], errors="coerce")
        else:
            storage_df["delta_bytes"] = np.nan
        for c in ["peer_volume_delta_bytes", "orderer_volume_delta_bytes", "other_volume_delta_bytes"]:
            if c in storage_df.columns:
                storage_df[c] = pd.to_numeric(storage_df[c], errors="coerce")
            else:
                storage_df[c] = np.nan

        if "path" in storage_df.columns:
            path_norm = storage_df["path"].astype(str).str.strip().str.rstrip("/")
            vol_rows = storage_df[path_norm.str.endswith("/volumes")].copy()
            if not vol_rows.empty:
                storage_df = vol_rows

        storage_key = (
            storage_df.groupby(["run_id", "workflow_base"], dropna=False)[
                ["delta_bytes", "peer_volume_delta_bytes", "orderer_volume_delta_bytes", "other_volume_delta_bytes"]
            ]
            .mean(numeric_only=True)
            .reset_index()
        )

        stage_vote_key = pd.DataFrame(
            columns=[
                "run_id",
                "workflow_base",
                "stage_vote_delta_bytes",
                "stage_vote_peer_delta_bytes",
                "stage_vote_orderer_delta_bytes",
                "stage_vote_other_delta_bytes",
            ]
        )
        if not stage_df.empty:
            if "workflow_base" not in stage_df.columns:
                stage_df["workflow_base"] = stage_df.get("workflow", "").map(workflow_base_from_tag)
            stage_df["workflow_base"] = stage_df["workflow_base"].astype(str).str.strip()
            stage_df["run_id"] = stage_df.get("run_id", "").astype(str).str.strip()
            stage_df["stage_end"] = stage_df.get("stage_end", "").astype(str).str.strip()
            stage_df["delta_bytes"] = pd.to_numeric(stage_df.get("delta_bytes"), errors="coerce")
            for c in ["peer_volume_delta_bytes", "orderer_volume_delta_bytes", "other_volume_delta_bytes"]:
                stage_df[c] = pd.to_numeric(stage_df.get(c), errors="coerce")
            if "path" in stage_df.columns:
                stage_path_norm = stage_df["path"].astype(str).str.strip().str.rstrip("/")
                stage_vol_rows = stage_df[stage_path_norm.str.endswith("/volumes")].copy()
                if not stage_vol_rows.empty:
                    stage_df = stage_vol_rows
            vote_stage_rows = stage_df[stage_df["stage_end"].str.contains("voted", case=False, na=False)].copy()
            if not vote_stage_rows.empty:
                stage_vote_key = (
                    vote_stage_rows.groupby(["run_id", "workflow_base"], dropna=False)[
                        [
                            "delta_bytes",
                            "peer_volume_delta_bytes",
                            "orderer_volume_delta_bytes",
                            "other_volume_delta_bytes",
                        ]
                    ]
                    .sum(min_count=1)
                    .reset_index()
                    .rename(
                        columns={
                            "delta_bytes": "stage_vote_delta_bytes",
                            "peer_volume_delta_bytes": "stage_vote_peer_delta_bytes",
                            "orderer_volume_delta_bytes": "stage_vote_orderer_delta_bytes",
                            "other_volume_delta_bytes": "stage_vote_other_delta_bytes",
                        }
                    )
                )

        tx_key = pd.DataFrame(columns=["run_id", "workflow_base", "committed_tx_count", "committed_vote_tx_count", "vote_tx_ratio"])
        if not tx_df.empty:
            if "workflow_base" not in tx_df.columns:
                tx_df["workflow_base"] = tx_df.get("workflow", "").map(workflow_base_from_tag)
            tx_df["workflow_base"] = tx_df["workflow_base"].astype(str).str.strip()
            tx_df["run_id"] = tx_df.get("run_id", "").astype(str).str.strip()
            tx_df["event"] = tx_df.get("event", "").astype(str).str.strip()
            tx_df["function"] = tx_df.get("function", "").astype(str).str.strip()

            tx_committed = tx_df[tx_df["event"] == "tx_committed"].copy()
            vote_functions = {"VoteOnCSR", "VoteOnRevocation", "VoteOnJoinRequest", "VoteOnRemoveMember"}
            tx_committed["is_vote_tx"] = tx_committed["function"].isin(vote_functions)
            if not tx_committed.empty:
                tx_key = (
                    tx_committed.groupby(["run_id", "workflow_base"], dropna=False)["is_vote_tx"]
                    .agg(committed_tx_count="size", committed_vote_tx_count="sum")
                    .reset_index()
                )
                tx_key["vote_tx_ratio"] = np.where(
                    tx_key["committed_tx_count"] > 0,
                    tx_key["committed_vote_tx_count"] / tx_key["committed_tx_count"],
                    np.nan,
                )

        ops_key = ops.copy()
        ops_key["run_id"] = ops_key.get("run_id", "").astype(str).str.strip()
        ops_key["workflow_base"] = ops_key.get("workflow_base", "").astype(str).str.strip()
        ops_key = ops_key[
            [
                "run_id",
                "workflow_base",
                "operation_id",
                "client_duration_s",
                "no_voting_savings_est_s",
                "no_voting_savings_pct",
            ]
        ].copy()

        op_impact = ops_key.merge(storage_key, on=["run_id", "workflow_base"], how="left")
        op_impact = op_impact.merge(stage_vote_key, on=["run_id", "workflow_base"], how="left")
        op_impact = op_impact.merge(tx_key, on=["run_id", "workflow_base"], how="left")
        op_impact["vote_tx_ratio"] = pd.to_numeric(op_impact["vote_tx_ratio"], errors="coerce")

        direct_available = op_impact["stage_vote_delta_bytes"].notna()
        op_impact["estimator_mode"] = np.where(direct_available, "stage_vote_direct", "tx_ratio_fallback")
        op_impact["estimated_storage_saved_bytes_no_voting"] = np.where(
            direct_available,
            np.maximum(pd.to_numeric(op_impact["stage_vote_delta_bytes"], errors="coerce"), 0),
            pd.to_numeric(op_impact["delta_bytes"], errors="coerce") * op_impact["vote_tx_ratio"],
        )
        op_impact["estimated_peer_saved_bytes_no_voting"] = np.where(
            op_impact["stage_vote_peer_delta_bytes"].notna(),
            np.maximum(pd.to_numeric(op_impact["stage_vote_peer_delta_bytes"], errors="coerce"), 0),
            pd.to_numeric(op_impact["peer_volume_delta_bytes"], errors="coerce") * op_impact["vote_tx_ratio"],
        )
        op_impact["estimated_orderer_saved_bytes_no_voting"] = np.where(
            op_impact["stage_vote_orderer_delta_bytes"].notna(),
            np.maximum(pd.to_numeric(op_impact["stage_vote_orderer_delta_bytes"], errors="coerce"), 0),
            pd.to_numeric(op_impact["orderer_volume_delta_bytes"], errors="coerce") * op_impact["vote_tx_ratio"],
        )
        op_impact["estimated_other_saved_bytes_no_voting"] = np.where(
            op_impact["stage_vote_other_delta_bytes"].notna(),
            np.maximum(pd.to_numeric(op_impact["stage_vote_other_delta_bytes"], errors="coerce"), 0),
            pd.to_numeric(op_impact["other_volume_delta_bytes"], errors="coerce") * op_impact["vote_tx_ratio"],
        )
        op_impact["estimated_storage_shrink_pct_no_voting"] = np.where(
            pd.to_numeric(op_impact["delta_bytes"], errors="coerce").abs() > 0,
            (op_impact["estimated_storage_saved_bytes_no_voting"] / op_impact["delta_bytes"]) * 100.0,
            np.nan,
        )
        op_impact["data_coverage"] = np.where(
            op_impact["estimator_mode"] == "stage_vote_direct",
            1.0,
            np.where(op_impact["vote_tx_ratio"].notna(), 0.5, 0.0),
        )
        op_impact["confidence"] = np.where(
            op_impact["data_coverage"] >= 0.8,
            "high",
            np.where(op_impact["data_coverage"] >= 0.5, "medium", "low"),
        )
        op_impact_out = outdir / "optimization_no_voting_ledger_impact_by_operation.csv"
        op_impact.to_csv(op_impact_out, index=False)

        wf_impact = (
            op_impact.groupby("workflow_base", dropna=False)[
                [
                    "client_duration_s",
                    "no_voting_savings_est_s",
                    "no_voting_savings_pct",
                    "committed_tx_count",
                    "committed_vote_tx_count",
                    "vote_tx_ratio",
                    "delta_bytes",
                    "peer_volume_delta_bytes",
                    "orderer_volume_delta_bytes",
                    "other_volume_delta_bytes",
                    "estimated_storage_saved_bytes_no_voting",
                    "estimated_peer_saved_bytes_no_voting",
                    "estimated_orderer_saved_bytes_no_voting",
                    "estimated_other_saved_bytes_no_voting",
                    "estimated_storage_shrink_pct_no_voting",
                    "data_coverage",
                ]
            ]
            .agg(["count", "mean", "min", "max", "median", "sum"])
            .reset_index()
        )
        wf_impact = flatten_multiindex_columns(wf_impact)
        if "workflow_base_" in wf_impact.columns:
            wf_impact = wf_impact.rename(columns={"workflow_base_": "workflow_base"})

        mode_df = (
            op_impact.groupby("workflow_base", dropna=False)
            .agg(
                has_stage_vote_direct=("estimator_mode", lambda s: s.astype(str).eq("stage_vote_direct").any()),
                data_coverage=("data_coverage", lambda s: float(pd.to_numeric(s, errors="coerce").fillna(0).mean())),
            )
            .reset_index()
        )
        mode_df["estimator_mode"] = np.where(
            mode_df["has_stage_vote_direct"],
            "stage_vote_direct",
            "tx_ratio_fallback",
        )
        mode_df = mode_df.drop(columns=["has_stage_vote_direct"])
        mode_df["confidence"] = np.where(
            mode_df["data_coverage"] >= 0.8,
            "high",
            np.where(mode_df["data_coverage"] >= 0.5, "medium", "low"),
        )
        wf_impact = wf_impact.merge(mode_df, on="workflow_base", how="left")
        wf_impact["estimation_confidence"] = wf_impact["confidence"]

        wf_impact_out = outdir / "optimization_no_voting_ledger_impact_by_workflow.csv"
        wf_impact.to_csv(wf_impact_out, index=False)

    print(f"Wrote: {op_out}")
    print(f"Wrote: {wf_out}")
    if op_impact_out is not None:
        print(f"Wrote: {op_impact_out}")
    if wf_impact_out is not None:
        print(f"Wrote: {wf_impact_out}")

def analyze_measurement_sanity(suite_root: Path, outdir: Path):
    """analyze_measurement_sanity helper for benchmark tooling."""
    sanity_rows = []

    # 1) Stage-sum vs client-duration residual.
    enriched = safe_read_csv(outdir / "workflow_runs_enriched.csv")
    if enriched.empty:
        enriched = safe_read_csv(outdir / "workflow_runs_v2_enriched.csv")
    stage_ops = safe_read_csv(outdir / "workflow_stage_latency_by_operation.csv")
    if not enriched.empty and not stage_ops.empty:
        for col in ["run_id", "workflow_base", "operation_id", "proposal_id"]:
            if col in enriched.columns:
                enriched[col] = enriched[col].astype(str).str.strip()
            if col in stage_ops.columns:
                stage_ops[col] = stage_ops[col].astype(str).str.strip()
        stage_sum = (
            stage_ops.groupby(["run_id", "workflow_base", "operation_id", "proposal_id"], dropna=False)["latency_s"]
            .sum(min_count=1)
            .reset_index()
            .rename(columns={"latency_s": "stage_sum_s"})
        )
        merged = enriched.merge(
            stage_sum,
            on=["run_id", "workflow_base", "operation_id", "proposal_id"],
            how="left",
        )
        merged["client_duration_s"] = pd.to_numeric(merged.get("client_duration_s"), errors="coerce")
        merged["stage_sum_s"] = pd.to_numeric(merged.get("stage_sum_s"), errors="coerce")
        merged = merged[merged["client_duration_s"].notna() & merged["stage_sum_s"].notna()].copy()
        if not merged.empty:
            merged["residual_s"] = merged["client_duration_s"] - merged["stage_sum_s"]
            for wf, g in merged.groupby("workflow_base", dropna=False):
                vals = pd.to_numeric(g["residual_s"], errors="coerce").dropna().to_numpy(dtype=float)
                if vals.size == 0:
                    continue
                abs_vals = np.abs(vals)
                sanity_rows.extend(
                    [
                        {
                            "check_name": "stage_sum_vs_client_residual",
                            "workflow_base": wf,
                            "metric": "mean_signed_residual_s",
                            "value": float(np.mean(vals)),
                            "numerator": "",
                            "denominator": "",
                            "details": "client_duration_s - sum(stage_latency_s)",
                        },
                        {
                            "check_name": "stage_sum_vs_client_residual",
                            "workflow_base": wf,
                            "metric": "mean_abs_residual_s",
                            "value": float(np.mean(abs_vals)),
                            "numerator": "",
                            "denominator": "",
                            "details": "abs(client_duration_s - sum(stage_latency_s))",
                        },
                        {
                            "check_name": "stage_sum_vs_client_residual",
                            "workflow_base": wf,
                            "metric": "p95_abs_residual_s",
                            "value": float(np.percentile(abs_vals, 95)),
                            "numerator": "",
                            "denominator": "",
                            "details": "95th percentile absolute residual",
                        },
                    ]
                )

    # 2) Retry inflation from tx_submit_started vs tx_committed.
    tx_df = safe_read_csv(suite_root / "suite_tx_events_all_runs.csv")
    if not tx_df.empty:
        if "workflow_base" not in tx_df.columns:
            tx_df["workflow_base"] = tx_df.get("workflow", "").map(workflow_base_from_tag)
        tx_df["workflow_base"] = tx_df["workflow_base"].astype(str).str.strip()
        tx_df["event"] = tx_df.get("event", "").astype(str).str.strip()
        counts = (
            tx_df.groupby(["workflow_base", "event"], dropna=False)
            .size()
            .unstack(fill_value=0)
            .reset_index()
        )
        for col in ["tx_submit_started", "tx_committed"]:
            if col not in counts.columns:
                counts[col] = 0
        counts["retry_inflation_rows"] = pd.to_numeric(counts["tx_submit_started"], errors="coerce") - pd.to_numeric(
            counts["tx_committed"], errors="coerce"
        )
        counts["retry_inflation_rows"] = counts["retry_inflation_rows"].clip(lower=0)
        counts["retry_inflation_ratio"] = np.where(
            pd.to_numeric(counts["tx_committed"], errors="coerce") > 0,
            counts["retry_inflation_rows"] / counts["tx_committed"],
            np.nan,
        )
        for _, row in counts.iterrows():
            wf = row.get("workflow_base", "")
            sanity_rows.extend(
                [
                    {
                        "check_name": "retry_inflation",
                        "workflow_base": wf,
                        "metric": "retry_inflation_rows",
                        "value": float(pd.to_numeric(row.get("retry_inflation_rows"), errors="coerce") or 0),
                        "numerator": float(pd.to_numeric(row.get("tx_submit_started"), errors="coerce") or 0),
                        "denominator": float(pd.to_numeric(row.get("tx_committed"), errors="coerce") or 0),
                        "details": "max(tx_submit_started - tx_committed, 0)",
                    },
                    {
                        "check_name": "retry_inflation",
                        "workflow_base": wf,
                        "metric": "retry_inflation_ratio",
                        "value": float(pd.to_numeric(row.get("retry_inflation_ratio"), errors="coerce"))
                        if pd.notna(pd.to_numeric(row.get("retry_inflation_ratio"), errors="coerce"))
                        else np.nan,
                        "numerator": float(pd.to_numeric(row.get("retry_inflation_rows"), errors="coerce") or 0),
                        "denominator": float(pd.to_numeric(row.get("tx_committed"), errors="coerce") or 0),
                        "details": "retry_inflation_rows / tx_committed",
                    },
                ]
            )

    # 3) Logical-row expansion marker (category-expanded rows).
    logical_breakdown = safe_read_csv(outdir / "storage_logical_action_breakdown_all_runs.csv")
    if not logical_breakdown.empty and "join_key" in logical_breakdown.columns:
        logical_breakdown["workflow_base"] = logical_breakdown.get("workflow_base", "").astype(str).str.strip()
        by_wf = (
            logical_breakdown.groupby("workflow_base", dropna=False)
            .agg(rows=("join_key", "size"), unique_join_keys=("join_key", "nunique"))
            .reset_index()
        )
        by_wf["row_expansion_ratio"] = np.where(
            by_wf["unique_join_keys"] > 0,
            by_wf["rows"] / by_wf["unique_join_keys"],
            np.nan,
        )
        for _, row in by_wf.iterrows():
            sanity_rows.append(
                {
                    "check_name": "logical_row_expansion",
                    "workflow_base": row.get("workflow_base", ""),
                    "metric": "row_expansion_ratio",
                    "value": float(pd.to_numeric(row.get("row_expansion_ratio"), errors="coerce"))
                    if pd.notna(pd.to_numeric(row.get("row_expansion_ratio"), errors="coerce"))
                    else np.nan,
                    "numerator": float(pd.to_numeric(row.get("rows"), errors="coerce") or 0),
                    "denominator": float(pd.to_numeric(row.get("unique_join_keys"), errors="coerce") or 0),
                    "details": "rows / unique join_key (values >1 imply category expansion)",
                }
            )

    # 4) TX/block mapping coverage.
    tx_size_df = safe_read_csv(suite_root / "suite_tx_block_sizes_all_runs.csv")
    if not tx_df.empty and not tx_size_df.empty:
        if "workflow_base" not in tx_size_df.columns:
            tx_size_df["workflow_base"] = tx_size_df.get("workflow", "").map(workflow_base_from_tag)
        tx_size_df["workflow_base"] = tx_size_df["workflow_base"].astype(str).str.strip()
        tx_size_df["tx_id"] = tx_size_df.get("tx_id", "").astype(str).str.strip()
        committed = tx_df.copy()
        if "workflow_base" not in committed.columns:
            committed["workflow_base"] = committed.get("workflow", "").map(workflow_base_from_tag)
        committed["workflow_base"] = committed["workflow_base"].astype(str).str.strip()
        committed["event"] = committed.get("event", "").astype(str).str.strip()
        committed["tx_id"] = committed.get("tx_id", "").astype(str).str.strip()
        committed = committed[(committed["event"] == "tx_committed") & (committed["tx_id"] != "")]
        mapped = tx_size_df[tx_size_df["tx_id"] != ""].copy()
        workflows = sorted(
            set(committed["workflow_base"].dropna().astype(str).str.strip().unique())
            | set(mapped["workflow_base"].dropna().astype(str).str.strip().unique())
        )
        for wf in workflows:
            committed_ids = set(committed[committed["workflow_base"] == wf]["tx_id"].tolist())
            mapped_ids = set(mapped[mapped["workflow_base"] == wf]["tx_id"].tolist())
            intersection = committed_ids & mapped_ids
            coverage = (len(intersection) / len(committed_ids)) if committed_ids else np.nan
            sanity_rows.append(
                {
                    "check_name": "tx_block_mapping_coverage",
                    "workflow_base": wf,
                    "metric": "coverage_ratio",
                    "value": float(coverage) if pd.notna(coverage) else np.nan,
                    "numerator": float(len(intersection)),
                    "denominator": float(len(committed_ids)),
                    "details": "unique committed tx_id present in suite_tx_block_sizes_all_runs.csv",
                }
            )

    sanity_df = pd.DataFrame(
        sanity_rows,
        columns=["check_name", "workflow_base", "metric", "value", "numerator", "denominator", "details"],
    )
    out_path = outdir / "measurement_sanity_report.csv"
    sanity_df.to_csv(out_path, index=False)
    print(f"Wrote: {out_path}")

# prune_analysis_outputs prunes analysis outputs according to selected artifact profile.
# Lifecycle: Post-analysis artifact lifecycle management.
# Called by: analyze_suite.main.
# Triggered: at analysis end when compact profile is requested.
def prune_analysis_outputs(outdir: Path, profile: str):
    """prune_analysis_outputs helper for benchmark tooling."""
    if profile == "full" or not outdir.exists():
        return {"files_removed": 0, "bytes_freed": 0}

    keep_csv = {
        "workflow_summary.csv",
        "workflow_v2_summary.csv",
        "workflow_missing_fields.csv",
        "workflow_v2_missing_fields.csv",
        "workflow_runs_enriched.csv",
        "workflow_runs_v2_enriched.csv",
        "workflow_stage_latency_breakdown.csv",
        "workflow_stage_latency_mixed_diagnostics.csv",
        "workflow_stage_latency_mixed_summary.csv",
        "workflow_component_totals.csv",
        "measurement_join_vs_removal_latency_diagnostics.csv",
        "workflow_mvcc_retry_summary.csv",
        "workflow_mvcc_retry_by_run.csv",
        "workflow_tss_compute_wait_summary.csv",
        "workflow_gossip_convergence_summary.csv",
        "measurement_sanity_report.csv",
        "storage_summary_by_workflow.csv",
        "storage_component_summary_by_workflow.csv",
        "storage_stage_component_summary_by_workflow.csv",
        "query_latency_summary_by_metric.csv",
        "query_merkle_size_summary.csv",
        "communication_message_summary_by_workflow.csv",
        "communication_blockchain_message_counts_by_workflow.csv",
        "tx_event_coverage_by_workflow.csv",
        "tx_event_run_mapping_summary.csv",
        "storage_logical_action_breakdown_all_runs.csv",
        "storage_logical_action_summary_by_workflow.csv",
        "storage_logical_category_summary_by_action.csv",
        "storage_logical_vs_physical_by_action.csv",
        "storage_amplification_by_action.csv",
        "storage_cost_composition_csr_cert_registered.csv",
        "tx_block_size_breakdown_all_runs.csv",
        "tx_block_size_summary_by_action.csv",
        "peer_volume_composition_by_action_all_runs.csv",
        "peer_volume_composition_by_operation.csv",
        "peer_volume_composition_by_workflow.csv",
        "peer_ledger_store_deltas_by_operation_stage.csv",
        "peer_ledger_store_stage_summary_by_workflow.csv",
        "peer_ledger_store_summary_by_workflow.csv",
        "peer_volume_stage_contribution_detailed_by_workflow.csv",
        "peer_volume_residual_breakdown_by_action.csv",
        "peer_volume_residual_breakdown_by_workflow.csv",
        "optimization_potential_by_operation.csv",
        "optimization_potential_by_workflow.csv",
        "optimization_no_voting_ledger_impact_by_operation.csv",
        "optimization_no_voting_ledger_impact_by_workflow.csv",
    }

    removed = 0
    bytes_freed = 0
    for path in outdir.iterdir():
        if not path.is_file():
            continue
        if path.suffix in {".png", ".tex"}:
            pass
        elif path.suffix == ".csv":
            if path.name in keep_csv:
                continue
        else:
            continue

        try:
            bytes_freed += path.stat().st_size
        except Exception:
            pass
        try:
            path.unlink()
            removed += 1
        except Exception:
            continue

    return {"files_removed": removed, "bytes_freed": bytes_freed}
