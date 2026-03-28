# Measurement Method (Benchmark Suite + Analyzer)

This document defines how benchmark values are collected, transformed, and interpreted.

## 1) Scope

The method covers:
- Workflow latency decomposition (`csr`, `revocation`, `removal`, `join`)
- Storage deltas (total + peer/orderer split + stage slices)
- Logical state-write bytes from tx events
- Serialized transaction and allocated block-overhead bytes
- Peer-volume composition and residual attribution
- Sanity checks for measurement quality

No runtime protocol behavior is changed by this method. It is analysis-only.

## 1.1) Iterative Validation Loop

Recommended loop for repeatable experiments:
1. Run suite collection (`run_benchmark_suite.py`) with strict quality gates enabled.
2. Run analyzer (`analyze_suite.py`) and inspect `measurement_sanity_report.csv` first.
3. Review coverage/diagnostics:
   - `tx_event_coverage_by_workflow.csv`
   - `workflow_stage_latency_mixed_diagnostics.csv`
   - `workflow_join_removal_mismatch_diagnostics.csv`
4. Fix instrumentation or config issues (metrics paths, event listener, storage path/split config).
5. Re-run the full suite and compare key aggregate CSVs, not only plots.

Pass criteria for a submission-quality run:
- no strict-quality failures in suite manifest,
- non-zero committed tx-event mapping coverage,
- stable workflow/storage aggregates across repeated runs.

## 2) Data Lineage

### 2.1 Raw runtime sources
- TSS peer API + metrics JSONL (`state/<org>/metrics.jsonl`)
- Workflow runner telemetry (`run_workflows.py`)
- Fabric tx/event stream (`tx_*`, `cc_event_observed`)
- Optional tx/block size capture (`suite_tx_block_sizes_all_runs.csv`)
- Storage snapshots from Docker volumes (`/var/lib/docker/volumes` by default)
- Stage-level storage slices (`suite_storage_stage_deltas_all_runs.csv`)

### 2.2 Suite aggregation
`run_benchmark_suite.py` writes suite-level files, including:
- `suite_workflow_runs_all.csv` (canonical)
- `suite_workflow_runs_v2_all.csv` (legacy alias, same content)
- `suite_tx_events_all_runs.csv`
- `suite_tx_block_sizes_all_runs.csv`
- `suite_storage_deltas_all_runs.csv`
- `suite_storage_stage_deltas_all_runs.csv`
- `suite_message_counts_all_runs.csv`
- `suite_phase_summary_all_runs.csv`

### 2.3 Analyzer outputs
`analyze_suite.py` reads suite files and writes derived CSVs/plots in `<suite>/analysis`.

## 3) Latency Decomposition

## 3.1 Base durations
For each operation row in `suite_workflow_runs_all.csv`:
- `client_duration_s = client_end_ts - client_start_ts`
- `client_to_submitted_s = submitted_observed_ts - client_start_ts`
- `submit_to_vote_s = voted_ts - submitted_observed_ts`
- `vote_to_approved_s = approved_or_executed_ts - voted_ts`
- `approved_to_cert_registered_s = cert_registered_ts - approved_or_executed_ts`
- `approved_to_reshare_start_s = reshare_started_ts - approved_or_executed_ts`
- `reshare_duration_s = reshare_completed_ts - reshare_started_ts`
- `approved_to_reshare_completed_s = reshare_completed_ts - approved_or_executed_ts`
- `post_reshare_tail_s = client_end_ts - reshare_completed_ts`
- `execution_to_operation_end_s = client_end_ts - approved_or_executed_ts`
- `cert_registered_to_operation_end_s = client_end_ts - cert_registered_ts`

Negative durations are invalidated (`NaN`). -> Can appear when some metadata is compacted

## 3.2 Component formulas
- `blockchain_total_s = client_to_submitted_s + submit_to_vote_s + vote_to_approved_s`
- `tss_reshare_total_s`:
  - preferred: `approved_to_reshare_start_s + reshare_duration_s`
  - fallback: `approved_to_reshare_completed_s`
  - fallback: `reshare_duration_s`
- `tss_coordination_total_s = approved_to_cert_registered_s + tss_reshare_total_s + local_key_idle_wait_s`
- `local_finalize_total_s`:
  - `csr`: `cert_registered_to_operation_end_s`
  - `revocation`: `execution_to_operation_end_s`
  - `join/removal` (preferred split):
    - `local_key_idle_wait_s = reshare_complete_to_local_idle_s` (counted in `tss_coordination_total_s`)
    - `local_finalize_total_s = local_idle_to_operation_end_s`
  - `join/removal` fallback: `post_reshare_tail_s`
  - fallback: `execution_to_operation_end_s`

Primary decomposition:
- `blockchain_effective_s = blockchain_total_s + local_finalize_total_s`
- `decomposed_total_s = blockchain_effective_s + tss_coordination_total_s`
- `decomposition_gap_s = client_duration_s - decomposed_total_s`

Mixed/overlap diagnostics:
- `mixed_transition_s_raw = max(decomposition_gap_s, 0)`
- `overlap_correction_s_raw = max(-decomposition_gap_s, 0)`
- epsilon threshold: `50ms`
  - `mixed_transition_s = mixed_transition_s_raw if >= 0.05 else 0`
  - `overlap_correction_s = overlap_correction_s_raw if >= 0.05 else 0`

Primary charts exclude mixed from stacked latency; mixed is isolated in:
- `workflow_stage_latency_mixed_diagnostics.csv`
- `workflow_stage_latency_mixed_summary.csv`

## 3.3 Stage-level latency rows
`workflow_stage_latency_by_operation.csv` contains only:
- `stage_group=blockchain`
- `stage_group=tss_coordination`
- `stage_group=local_finalize`

`mixed` rows are intentionally excluded from this file.

## 3.4 Join/removal diagnostic
`measurement_join_vs_removal_latency_diagnostics.csv` explains why join/removal can differ by:
- coordination share (`tss_coordination_total_s / client_duration_s`)
- local finalize share (`local_finalize_total_s / client_duration_s`)

## 3.5 Formula-to-Output Mapping

Latency decomposition outputs:
- `workflow_runs_enriched.csv`: per-operation derived timing fields.
- `workflow_summary.csv`: grouped aggregates (`count/mean/min/max/median`) by workflow.
- `workflow_stage_latency_breakdown.csv`: stage-grouped totals for stacked latency views.

Storage/byte-accounting outputs:
- `storage_logical_action_breakdown_all_runs.csv`: logical state-write rows (action-level).
- `storage_logical_vs_physical_by_action.csv`: logical vs measured physical deltas.
- `storage_amplification_by_action.csv`: amplification factors by workflow/action.
- `tx_block_size_breakdown_all_runs.csv`: serialized tx and block-overhead derived terms.

Communication outputs:
- `communication_message_counts_enriched.csv`: per-run message counts with normalized workflow tags.
- `communication_message_summary_by_workflow.csv`: workflow-level aggregation of message totals.
- `communication_bytes_summary_by_workflow.csv`: RX/TX byte summaries (adjusted preferred when available).

## 4) Storage and Byte Accounting

## 4.1 Physical storage deltas
From `suite_storage_deltas_all_runs.csv` and `suite_storage_stage_deltas_all_runs.csv`:
- Total delta: `delta_bytes`
- Component splits when available:
  - `peer_volume_delta_bytes`
  - `orderer_volume_delta_bytes`
  - `other_volume_delta_bytes`

Default path filter is Docker volumes (`.../volumes`), unless explicitly overridden.

## 4.2 Logical state-write bytes
From `suite_tx_events_all_runs.csv`:
- `logical_write_bytes_total`
- `logical_delete_bytes_total`
- `logical_write_by_category` (JSON map)

Logical grouping key:
- `join_key = run_id | workflow_base | action | op_ref`
- `op_ref = operation_id if present else proposal_id`

Category expansion can produce multiple rows per `join_key` (one per category). This is why:
- totals must be interpreted by grouping key,
- row counts alone can overstate apparent volume.

## 4.3 Serialized tx + block overhead
From `suite_tx_block_sizes_all_runs.csv`:
- `tx_envelope_bytes`
- `block_shared_overhead_per_tx_bytes`

Derived:
- `block_allocated_bytes = tx_envelope_bytes + block_shared_overhead_per_tx_bytes`
- `tx_overhead_vs_logical_bytes = tx_envelope_bytes - logical_write_bytes_total`
- `block_allocated_overhead_vs_logical_bytes = block_allocated_bytes - logical_write_bytes_total`
- `tx_to_logical_ratio = tx_envelope_bytes / logical_write_bytes_total` (if logical > 0)
- `block_allocated_to_logical_ratio = block_allocated_bytes / logical_write_bytes_total` (if logical > 0)

Ratios can be `< 1` for specific actions if logical payload exceeds serialized envelope for that aggregated grouping.

## 4.4 Peer volume composition
Per action group:
- `peer_stage_bytes` (from peer volume stage deltas)
- `logical_write_bytes_total` (direct)
- `tx_overhead_bytes = max(tx_envelope_bytes - logical_write_bytes_total, 0)` (direct-derived)
- `block_overhead_bytes = max(block_shared_overhead_per_tx_bytes, 0)` (direct-derived)
- `other_peer_blockchain_bytes = peer_stage_bytes - logical - tx_overhead - block_overhead`
- `other_peer_blockchain_bytes_clipped = max(other_peer_blockchain_bytes, 0)`

Important:
- `other_peer_blockchain_bytes*` is a residual, not a directly measured internal Fabric field.

## 4.5 Residual decomposition (inferred)
Residual is stage-attributed into:
- `governance_residual_bytes`
- `voting_residual_bytes`
- `reshare_residual_bytes`
- `operation_end_residual_bytes`

This split is inference-based from stage labels, not byte-precise protocol internals.

Outputs:
- `peer_volume_residual_breakdown_by_action.csv`
- `peer_volume_residual_breakdown_by_workflow.csv`
- `peer_volume_stage_contribution_detailed_by_workflow.csv`

## 5) Communication Metrics

From message counts and tx-event signals:
- TSS sent/recv counts by workflow
- Blockchain signal rows (`tx_submit_started`, `tx_submitted`, `tx_committed`, `tx_failed`, `cc_event_observed`)
- StorageAttribution `cc_event_observed` rows are excluded from blockchain signal counts

Network bytes:
- Raw RX/TX is sampled from `/proc/net/dev` on the configured interface.
- Optional control-plane subtraction is approximated from TCP socket counters (`ss -tinHn`) for configured ports
  (default workflow/suite runner ports: `22`, `8083`, `9446`).
- Phase summaries include:
  - `rx_delta_sum`, `tx_delta_sum` (raw)
  - `control_rx_delta_sum`, `control_tx_delta_sum` (estimated control-plane bytes)
  - `rx_delta_adjusted_sum`, `tx_delta_adjusted_sum` (raw minus control estimate, floored at 0)
- Analyzer prefers adjusted byte columns when present and falls back to raw otherwise.

## 6) Sanity Report

`measurement_sanity_report.csv` includes:
- Stage-sum residual vs client duration
- Retry inflation (`tx_submit_started - tx_committed`)
- Logical row-expansion ratio (`rows / unique join_key`)
- tx/block mapping coverage (`committed tx_id` found in tx/block table)

## 7) Persistence and Pruning Semantics

Interpretation of measured bytes:
- Ledger block files and indexes are mostly append-only and effectively persistent.
- State DB entries represent latest world-state values; old values are superseded.
- Compaction/pruning can reduce some storage classes over time, but not ledger append history.
- Residual peer bytes can include index structures, metadata, validation artifacts, and stage-local effects not explicitly separated by current telemetry.

## 8) Common Interpretation Pitfalls

- Mean vs sum confusion: workflow mean plots are per-operation averages, not global totals.
- Category-expanded logical rows: action/category tables can multiply rows per operation.
- Retry amplification: high submit retries increase tx signals and can skew per-workflow counts.
- Mixed latency misread: mixed is now diagnostic, not part of primary component bars.
- Residual over-precision: residual sub-buckets are inferred attribution, not exact internal Fabric decomposition.

## 9) Known Limitations / Downsides

- Event mapping is heuristic when direct operation/proposal references are missing (timestamp-window fallback).
- Control-plane byte subtraction is an approximation (socket-counter based), not packet-accurate attribution.
- Storage residual buckets (`*_residual_bytes`) are inferred attribution and can aggregate multiple internal causes.
- Missing/compacted timestamps can shift some rows to `NaN` durations, reducing usable sample counts.
- Cross-run comparability depends on stable environment load, peer/orderer background activity, and consistent storage roots.

## 10) Canonical Naming and Legacy Aliases

Canonical measurement naming now avoids `v2` in primary interfaces:
- `workflow_runs.csv`
- `suite_workflow_runs_all.csv`
- `suite_workflow_latency_averages.csv`
- `workflow_runs_enriched.csv`
- `workflow_summary.csv`

Legacy `v2` names are still written/read as compatibility aliases during migration.
