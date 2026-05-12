# Measurement Method (Benchmark Suite + Analyzer)

This document defines how benchmark values are collected, transformed, and interpreted.

## 1) Scope

The method covers:
- Workflow latency decomposition (`csr`, `revocation`, `query`, `removal`, `join`)
- Storage deltas (total + peer/orderer split + stage slices)
- Logical state-write bytes from tx events
- Serialized transaction and allocated block-overhead bytes
- Peer-volume composition and residual attribution
- Sanity checks for measurement quality

## 1.1) Iterative Validation Loop

Used loop:
1. Run suite collection (`run_benchmark_suite.py`)
2. Run analyzer (`analyze_suite.py`) and inspect `measurement_sanity_report.csv` first.
3. Review coverage/diagnostics:
   - `tx_event_coverage_by_workflow.csv`
   - `workflow_stage_latency_mixed_diagnostics.csv`
   - `workflow_join_removal_mismatch_diagnostics.csv`
4. Fix instrumentation and config issues (metrics paths, event listener, storage path/split config).
5. Re-run the full suite

Pass criteria for a strict submission-quality run:
- no strict-quality failures in suite manifest,
- Reasonable committed tx-event mapping coverage,
- stable workflow/storage aggregates across repeated runs.

## 2) Data Lineage

### 2.1 Raw runtime sources
- TSS runtime  + metrics JSONL (`state/<org>/metrics.jsonl`)
- Workflow execution (`run_workflows.py`)
- Fabric tx/event stream (`tx_*`, `cc_event_observed`)
- tx/block size capture (`suite_tx_block_sizes_all_runs.csv`)
- Storage snapshots from Docker volumes (`/var/lib/docker/volumes`)
- Stage-level storage slices (`suite_storage_stage_deltas_all_runs.csv`)

### 2.2 Suite aggregation
`run_benchmark_suite.py` writes suite-level files

### 2.3 Analyzer outputs
`analyze_suite.py` reads suite files and writes derived CSVs/plots in `<suite>/analysis`.

## 3) Latency Decomposition

## 3.1 Base durations
Each workflow operation has milestone timestamps in `suite_workflow_runs_all.csv`.
Every latency value is computed as:

`duration = later_timestamp - earlier_timestamp`

Main latency columns:

| Column | Start -> End | Meaning |
|---|---|---|
| `client_duration_s` | `client_start_ts` -> `client_end_ts` | End-to-end user-visible duration |
| `client_to_submitted_s` | `client_start_ts` -> `submitted_observed_ts` | Client-side submit/setup time |
| `submit_to_vote_s` | `submitted_observed_ts` -> `voted_ts` | Time until voting/acks begin to complete |
| `vote_to_approved_s` | `voted_ts` -> `approved_or_executed_ts` | Governance decision/commit phase |
| `approved_to_cert_registered_s` | `approved_or_executed_ts` -> `cert_registered_ts` | Post-approval signing + registration path |
| `approved_to_reshare_start_s` | `approved_or_executed_ts` -> `reshare_started_ts` | Wait until reshare starts |
| `reshare_duration_s` | `reshare_started_ts` -> `reshare_completed_ts` | Actual reshare runtime |
| `approved_to_reshare_completed_s` | `approved_or_executed_ts` -> `reshare_completed_ts` | Full approval-to-reshare-complete span |
| `post_reshare_tail_s` | `reshare_completed_ts` -> `client_end_ts` | Tail time after reshare completion |
| `execution_to_operation_end_s` | `approved_or_executed_ts` -> `client_end_ts` | Generic post-execution tail (until the change is noticed at the peer) |
| `cert_registered_to_operation_end_s` | `cert_registered_ts` -> `client_end_ts` | CSR-specific local tail (until cert is synced.|

- If either timestamp is missing, the derived duration is empty (`NaN`).
- Negative values indicate timestamp/order issues and are treated as invalid in analysis.
- `client_duration_s` is the full latency

## 3.2 Component formulas
- `blockchain_total_s = client_to_submitted_s + submit_to_vote_s + vote_to_approved_s`
- `tss_reshare_total_s = approved_to_reshare_start_s + reshare_duration_s`
- `tss_coordination_total_s = approved_to_cert_registered_s + tss_reshare_total_s + local_key_idle_wait_s`
- `local_finalize_total_s`:
  - `csr`: `cert_registered_to_operation_end_s`
  - `revocation`: `execution_to_operation_end_s`
  - `join/removal`:
    - `local_key_idle_wait_s = reshare_complete_to_local_idle_s` (counted in `tss_coordination_total_s`)
    - `local_finalize_total_s = local_idle_to_operation_end_s`
  - `join/removal` fallback: `post_reshare_tail_s`
  - fallback: `execution_to_operation_end_s`

Primary decomposition:
- `blockchain_effective_s = blockchain_total_s + local_finalize_total_s`
- `decomposed_total_s = blockchain_effective_s + tss_coordination_total_s`
- `decomposition_gap_s = client_duration_s - decomposed_total_s`

## 3.3 Stage-level latency rows
`workflow_stage_latency_by_operation.csv` contains:
- `stage_group=blockchain`
- `stage_group=tss_coordination`
- `stage_group=local_finalize`

## 3.4 Metric Calculation

Latency metrics:
- Source: `suite_workflow_runs_all.csv` 
- Core formulas:
  - `client_duration_s = client_end_ts - client_start_ts`
  - `blockchain_total_s = client_to_submitted_s + submit_to_vote_s + vote_to_approved_s`
  - `tss_coordination_total_s = approved_to_cert_registered_s + tss_reshare_total_s + local_key_idle_wait_s`
  - `decomposed_total_s = blockchain_effective_s + tss_coordination_total_s`
  - reliable when all timestamp fields exist

Tx-event mapping and coverage:
- Source: `suite_tx_events_all_runs.csv`
- Core metrics:
  - `tx_event_coverage_by_workflow.csv`:
    - `total_ops = unique (run_id, workflow_base, operation_id)` from workflow rows
    - `ops_with_events = unique (run_id, workflow_base, operation_id)` from mapped tx-event rows
    - `event_coverage_ratio = ops_with_events / total_ops` when `total_ops > 0`
- Reliability:
  - depends on the event coverage

Serialized tx/block overhead metrics:
- Source: `suite_tx_block_sizes_all_runs.csv`
- Core fields:
  - `tx_envelope_bytes`
  - `block_shared_overhead_per_tx_bytes`
  - `(block_bytes - block_data_bytes) / block_tx_count`
- Derived fields:
  - `block_allocated_bytes = tx_envelope_bytes + block_shared_overhead_per_tx_bytes`
  - `tx_overhead_vs_logical_bytes = tx_envelope_bytes - logical_write_bytes_total`
  - `block_allocated_overhead_vs_logical_bytes = block_allocated_bytes - logical_write_bytes_total`
  - `tx_to_logical_ratio` and `block_allocated_to_logical_ratio` only when `logical_write_bytes_total > 0`
- Reliability:
  - high for direct tx/block size fields on captured tx IDs
  - medium for RWSet-relative ratios (depends on logical attribution coverage)

Storage metrics:
- Source:
  - physical: `suite_storage_deltas_all_runs.csv`, `suite_storage_stage_deltas_all_runs.csv`
  - logical: `suite_tx_events_all_runs.csv` logical counters
- Core formulas:
  - physical delta: `delta_bytes = bytes_after - bytes_before`
  - logical grouping key: `join_key = run_id|workflow_base|action|op_ref`
- Reliability:
  - high for deterministic snapshot arithmetic
  - medium where background compaction/pruning causes large run-to-run variance (only happens during long runs conf 5 and 6)

Communication metrics:
- Source:
  - message counts: workflow message counters
  - network bytes: `/proc/net/dev`, optional control-plane subtraction via `ss -tinHn`
- Reliability:
  - high for TSS message counters
  - medium for network-byte attribution after control-plane subtraction (the subtraction is an approximation)


## 4) Storage and Byte Accounting


## 4.1 Physical storage deltas (direct measurement)

Source files:
- `suite_storage_deltas_all_runs.csv`
- `suite_storage_stage_deltas_all_runs.csv`

Core formula:
- `delta_bytes = bytes_after - bytes_before`

Important columns:
- `delta_bytes`: total path delta
- `peer_volume_delta_bytes`: peer-matched volume delta
- `orderer_volume_delta_bytes`: orderer-matched volume delta
- `other_volume_delta_bytes`: unmatched remainder

Interpretation:
- This is direct filesystem snapshot.
- It includes everything happening in those paths during the window, including background compaction/pruning.

## 4.2 Logical state-write bytes (chaincode-level logical payload)

Source file:
- `suite_tx_events_all_runs.csv`

Core fields:
- `logical_write_bytes_total`
- `logical_delete_bytes_total`
- `logical_write_by_category`

Grouping key used to align logical bytes with other metrics:
- `join_key = run_id|workflow_base|action|op_ref`
- `op_ref = operation_id` when present, otherwise `proposal_id`

Interpretation:
- Represents logical state mutation payload seen in attribution events.

## 4.3 Serialized tx size + allocated block overhead

Source file:
- `suite_tx_block_sizes_all_runs.csv`

Direct size fields:
- `tx_envelope_bytes`
- `block_shared_overhead_per_tx_bytes`

Derived fields:
- `block_allocated_bytes = tx_envelope_bytes + block_shared_overhead_per_tx_bytes`
- `tx_overhead_vs_logical_bytes = tx_envelope_bytes - logical_write_bytes_total`
- `block_allocated_overhead_vs_logical_bytes = block_allocated_bytes - logical_write_bytes_total`
- `tx_to_logical_ratio = tx_envelope_bytes / logical_write_bytes_total` when logical > 0
- `block_allocated_to_logical_ratio = block_allocated_bytes / logical_write_bytes_total` when logical > 0

Interpretation:
- `tx_overhead_vs_logical_bytes` is transaction overhead relative to logical writes.
- `block_shared_overhead_per_tx_bytes` is block-level overhead allocated per tx.
- Ratios are blank when logical bytes are missing or zero.

## 4.4 Peer volume composition (accounted vs residual)

For each action/workflow grouping, the analyzer builds:
- `peer_stage_bytes` (measured)
- `logical_write_bytes_total` (logical payload)
- `tx_overhead_bytes = max(tx_envelope_bytes - logical_write_bytes_total, 0)`
- `block_overhead_bytes = max(block_shared_overhead_per_tx_bytes, 0)`
- `other_peer_blockchain_bytes = peer_stage_bytes - logical - tx_overhead - block_overhead`
- `other_peer_blockchain_bytes_clipped = max(other_peer_blockchain_bytes, 0)`

Interpretation:
- First four terms are accounted components.
- `other_peer_blockchain_bytes*` is residual remainder,

## 4.5 Residual decomposition (inferred attribution)

Residual is further split by stage labels into:
- `governance_residual_bytes`
- `voting_residual_bytes`
- `reshare_residual_bytes`
- `operation_end_residual_bytes`

Interpretation:
- Useful for directional diagnosis
- Not byte-exact provenance.

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
  - `rx_delta_adjusted_sum`, `tx_delta_adjusted_sum` (raw minus control estimate)

## 6) Known Limitations / Downsides

- Event mapping is heuristic when direct operation/proposal references are missing (timestamp-window fallback).
- Control-plane byte subtraction for communication is an approximation (socket-counter based), not packet-accurate attribution.
- Storage residual buckets (`*_residual_bytes`) are inferred attribution and can aggregate multiple internal causes.
- Missing timestamps can shift some rows to `NaN` durations, reducing usable sample counts.

## 7) Reliability of `measurements/Conf_1..Conf_6`

Observed quality status:
- All six configs report `measurement_quality.failures = ["tx_event_unmapped_policy_fail"]` in strict mode.
- This is driven by unmapped background tx-events in shared metrics files, not by workflow-step failures.
- Workflow execution itself succeeded in these datasets.

CSR tx/block coverage (from `measurement_sanity_report.csv`, `tx_block_mapping_coverage`):
- `Conf_1 = 1.00`
- `Conf_2 = 0.833`
- `Conf_3 = 1.00`
- `Conf_4 = 0.885`
- `Conf_5 = 0.962`
- `Conf_6 = 0.75`

Interpretation:
- Latency metrics remain mostly usable.
- CSR tx/block byte accounting is weaker for `Conf_2`, `Conf_4`, `Conf_6` because not all committed CSR tx IDs have block-size rows.
- Join/removal/revocation tx/block coverage is stronger in this dataset.

Additional dataset-specific caveats:
- `Conf_5` and `Conf_6` contain `reshare` coverage rows with `total_ops=0` and `ops_with_events>0` (background-event noise rows).
- `Conf_5` and `Conf_6` show elevated storage variance for some workflows (likely compaction/pruning/background churn effects).

Practical conclusion:
- The dataset is usable for system-level behavior trends.
- Strong byte-precise claims should be restricted to metric families with high coverage for the target workflow/config.
