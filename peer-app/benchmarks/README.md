# Benchmarking Guide (TSS PKI)

This folder contains scripts to capture benchmarks from the system

The scripts can be run individually but for the thesis benchmarks, the aggregated suite with the invocation as described in the deployment readme was used.
This automatically generates csv files and plots.


## 1) Enable Metrics (JSONL)

Metrics are written to:
```
state/<org>/metrics.jsonl
```

You can disable metrics from the runtime by setting envvar:
```
TSS_METRICS_ENABLED=false
```

Events are emitted for:
- `csr_api_received`, `csr_submitted`, `signing_session_active`, `tss_signing_start`, `tss_signing_complete`, `cert_registered`
- `join_request_submitted`, `join_request_voted`
- `member_removal_proposed`, `member_removal_voted`
- `revocation_proposed`, `revocation_voted`
- `reshare_acknowledged`, `reshare_keygen_start`, `tss_keygen_complete`, `reshare_complete_submitted`, `reshare_complete_recorded`
<<<<<<< Updated upstream
=======
- `tx_submit_started`, `tx_submitted`, `tx_committed`, `tx_failed`
- `cc_event_observed` 
>>>>>>> Stashed changes

## 2) Convert Metrics -> CSV Durations

```
python3 benchmarks/compute_durations.py --metrics state/org1/metrics.jsonl --outdir benchmarks/out
```

Outputs:
- `events.csv`: raw events with timestamps
- `durations.csv`: derived latencies per proposal/epoch

## 2b) Label Resource Samples With Phases

<<<<<<< Updated upstream
Use this to label per-second resource samples with CSR/reshare phase buckets.

CSR example:
```
=======
`label_resources.py`all workflows:
- `csr`
- `revocation`
- `join`
- `removal`
- `reshare`
- `auto` (operation-based detection; default)

CSR example:

```shell
>>>>>>> Stashed changes
python3 benchmarks/label_resources.py \
  --resources benchmarks/out/resources_csr_1771488811.csv \
  --metrics state/org1/metrics.jsonl \
  --proposal-id csr-org1-1771488811 \
  --mode csr \
  --out benchmarks/out/resources_csr_1771488811_labeled.csv
```
Notes:
- If `csr_api_received` is missing (e.g., you only have non-API peer metrics), the labeler uses the first resource sample as `csr_consensus_est`.

<<<<<<< Updated upstream
Reshare example:
```
python3 benchmarks/label_resources.py \
  --resources benchmarks/out/resources_csr_1771488811.csv \
  --metrics state/org1/metrics.jsonl \
=======
Revocation / join / removal examples:
```shell
python3 benchmarks/label_resources.py \
  --resources benchmarks/out/resources_revocation_1772000000.csv \
  --metrics state/irs1/metrics.jsonl state/irs2/metrics.jsonl state/irs3/metrics.jsonl \
  --mode revocation \
  --out benchmarks/out/resources_revocation_1772000000_labeled.csv

python3 benchmarks/label_resources.py \
  --resources benchmarks/out/resources_join_1772000001.csv \
  --metrics state/irs1/metrics.jsonl state/irs2/metrics.jsonl state/irs3/metrics.jsonl \
  --mode join \
  --out benchmarks/out/resources_join_1772000001_labeled.csv

python3 benchmarks/label_resources.py \
  --resources benchmarks/out/resources_removal_1772000002.csv \
  --metrics state/irs1/metrics.jsonl state/irs2/metrics.jsonl state/irs3/metrics.jsonl \
  --mode removal \
  --out benchmarks/out/resources_removal_1772000002_labeled.csv
```

Reshare example:
```shell
python3 benchmarks/label_resources.py \
  --resources benchmarks/out/resources_reshare_1772000003.csv \
  --metrics state/irs1/metrics.jsonl state/irs2/metrics.jsonl state/irs3/metrics.jsonl \
  --mode reshare \
>>>>>>> Stashed changes
  --epoch 3 \
  --mode reshare \
  --out benchmarks/out/resources_reshare_epoch3_labeled.csv
```

<<<<<<< Updated upstream
=======
Batch + merged output example:
``` shell
python3 benchmarks/label_resources.py \
  --resources \
    benchmarks/out/resources_csr_1772000100.csv \
    benchmarks/out/resources_revocation_1772000200.csv \
    benchmarks/out/resources_join_1772000300.csv \
    benchmarks/out/resources_removal_1772000400.csv \
  --metrics state/irs1/metrics.jsonl state/irs2/metrics.jsonl state/irs3/metrics.jsonl \
  --mode auto \
  --outdir benchmarks/out/labeled \
  --merged-out benchmarks/out/resources_all_labeled.csv \
  --merged-phase-summary-out benchmarks/out/resources_all_phase_summary.csv
```

>>>>>>> Stashed changes
## 3) Optional Workflow Orchestration

Run a workflow against the Web UI API:
```
python3 benchmarks/run_workflows.py --api http://localhost:8080 --workflow csr
python3 benchmarks/run_workflows.py --api http://localhost:8080 --workflow join
python3 benchmarks/run_workflows.py --api http://localhost:8080 --workflow revocation --member-id x509::...
python3 benchmarks/run_workflows.py --api http://localhost:8080 --workflow removal --member-id x509::...
```

Flags:
- `--no-wait` to just submit proposals without waiting
- `--timeout` and `--poll` to control completion polling
- `--cn/--o/--l/--st/--c` to customize CSR subjects
- Removal requires `--member-id` to avoid accidental deletion
- `--measure` to capture storage deltas + CPU/RAM samples per workflow
- `--collect-resources` to capture CPU/RAM without storage
- `--collect-messages` to capture TSS P2P counts (requires `/api/metrics/p2p`)
- `--phase-tags` to label resource samples with the current workflow phase
- `--peer-metrics-url` to capture Fabric peer gossip counters from Prometheus metrics
- `--storage-path` (repeatable) to define what to measure for storage deltas
<<<<<<< Updated upstream
=======
- default storage source for `--measure` is Docker volumes (`<DockerRootDir>/volumes`) resolved via `docker info`
- `--storage-component <label>=<regex>` (repeatable) to split Docker volume growth by component (default: peer/orderer)
- `--storage-slices` to record milestone-level storage deltas per operation (opt-in)
- `--storage-topk <N>` top volume contributors per milestone stage when `--storage-slices` is enabled
- `--proc-match <label>=<regex>` (repeatable) to override process matchers used for CPU/RAM (`tss|peer|orderer`)
- `--resources-control-exclude-port <port>` (repeatable) to subtract approximate control-plane TCP traffic from RX/TX
  (default excluded ports: `22`, `8083`, `9446`)
- `--no-resources-control-subtract` to disable subtraction and keep raw RX/TX
- `--measurement` to emit deterministic additive workflow measurement output (`workflow_runs.csv`)
- `--measurement-v2` remains accepted as a deprecated alias
- `--metrics <path>` (repeatable) to infer milestones from metrics JSONL
- `--operation-id` optional operation identifier override for workflow rows
>>>>>>> Stashed changes

Example (single command, all measurements):
``` shell
python3 benchmarks/run_workflows.py --api http://localhost:8080 --workflow csr \
  --measure --storage-path /var/lib/docker/volumes --storage-path /opt/fabric \
  --resources-interval 1 --resources-iface eth0
```

Example (add message counts + gossip metrics):
``` shell
python3 benchmarks/run_workflows.py --api http://localhost:8080 --workflow csr \
  --collect-messages \
  --peer-metrics-url http://localhost:9446/metrics \
  --peer-metrics-prefix gossip_
```
Outputs:
- `benchmarks/out/resources_<workflow>.csv` (raw samples)
- `benchmarks/out/resources_summary.csv` (avg/max per workflow)
- `benchmarks/out/storage_deltas.csv` (before/after deltas)
- `benchmarks/out/message_counts.csv` (TSS P2P + optional gossip counts)
<<<<<<< Updated upstream
=======
- `benchmarks/out/workflow_runs.csv` (when `--measurement` is enabled)
- `benchmarks/out/workflow_runs_v2.csv` (legacy alias written for compatibility)

### 3b) Multi-Run Benchmark Suite (raw-preserving + auto-labeling)

Use the suite runner when you want repeated runs with per-run isolation and global aggregates:
``` shell
python3 benchmarks/run_benchmark_suite.py \
  --api http://localhost:8083 \
  --runs 3 \
  --member-id x509::... \
  --artifact-profile compact \
  --metrics state/irs1/metrics.jsonl state/irs2/metrics.jsonl state/irs3/metrics.jsonl \
  --measurement \
  --query-cert-source auto_csr \
  --strict-measurement-quality \
  --tx-event-unmapped-policy fail \
  --tx-event-window-skew-sec 120 \
  --workflows csr,revocation,removal,join \
  --measure --collect-messages --phase-tags \
  --storage-slices --storage-topk 5 \
  --query-bench --query-iters 30 --query-warmup 5 \
  --peer-metrics-url http://localhost:9446/metrics \
  --peer-metrics-prefix gossip_ \
  --outroot benchmarks/out/suite_$(date +%Y%m%d_%H%M%S)
```

Artifact profiles (`--artifact-profile`):
- `compact` (default): keeps measurement-critical outputs and prunes heavy per-run artifacts after suite aggregation.
- `full`: preserves current full artifact set.
- `ultra`: keeps suite-level outputs and removes per-run directories after aggregation.

Per-run outputs:
- `<outroot>/run_00N/raw/resources_<workflow>_<ts>.csv`
- `<outroot>/run_00N/raw/resources_summary.csv`
- `<outroot>/run_00N/raw/storage_deltas.csv`
- `<outroot>/run_00N/raw/storage_stage_deltas.csv` (when `--storage-slices`)
- `<outroot>/run_00N/raw/storage_stage_volume_deltas.csv` (when `--storage-slices`)
- `<outroot>/run_00N/raw/storage_stage_topk_volumes.csv` (when `--storage-slices`)
- `<outroot>/run_00N/labeled/resources_all_labeled.csv`
- `<outroot>/run_00N/labeled/resources_all_phase_summary.csv`
- `<outroot>/run_00N/query/query_bench_iterations.csv` (when `--query-bench`)
- `<outroot>/run_00N/query/query_bench_summary.csv` (when `--query-bench`)
- `<outroot>/run_00N/logs/<workflow>.log`
- `<outroot>/run_00N/manifest.json`

Suite-level outputs:
- `<outroot>/suite_manifest.json`
- `<outroot>/suite_resources_summary_all_runs.csv`
- `<outroot>/suite_resources_summary_averages.csv`
- `<outroot>/suite_storage_deltas_all_runs.csv`
- `<outroot>/suite_storage_deltas_averages.csv`
- `<outroot>/suite_storage_stage_deltas_all_runs.csv` (when `--storage-slices`)
- `<outroot>/suite_storage_stage_deltas_averages.csv` (when `--storage-slices`)
- `<outroot>/suite_storage_stage_volume_deltas_all_runs.csv` (when `--storage-slices`)
- `<outroot>/suite_storage_stage_topk_volumes_all_runs.csv` (when `--storage-slices`)
- `<outroot>/suite_message_counts_all_runs.csv` (when `--collect-messages` or peer metrics are enabled)
- `<outroot>/suite_message_counts_averages.csv` (workflow averages over message-count fields)
- `<outroot>/suite_resources_labeled_all_runs.csv` (only in `--artifact-profile full`)
- `<outroot>/suite_phase_summary_all_runs.csv`
- `<outroot>/suite_phase_summary_averages.csv`
- `<outroot>/suite_workflow_runs_all.csv` (when `--measurement` is enabled)
- `<outroot>/suite_workflow_runs_v2_all.csv` (legacy alias written for compatibility)
- `<outroot>/suite_workflow_latency_averages.csv` (grouped by canonical workflow; includes `mixed_transition_s_*`, `overlap_correction_s_*`, `explained_total_s_*`)
- `<outroot>/suite_workflow_latency_v2_averages.csv` (legacy alias written for compatibility)
- `<outroot>/suite_tx_events_all_runs.csv` (normalized tx/event telemetry rows)
- `<outroot>/suite_query_bench_all_runs.csv` (when `--query-bench`)
- `<outroot>/suite_query_bench_averages.csv` (when `--query-bench`)

Analyzer (`analyze_suite.py`) adds:
- In `--analysis-profile compact` (default), only core CSV outputs are retained.
- The full list below corresponds to `--analysis-profile full`.
- Measurement method deep-dive: `benchmarks/MEASUREMENT_METHOD.md`
- `<outroot>/analysis/storage_path_coverage.csv`
- `<outroot>/analysis/tx_event_coverage_by_workflow.csv`
- `<outroot>/analysis/workflow_join_removal_mismatch_diagnostics.csv`
- `<outroot>/analysis/workflow_join_removal_mismatch_summary.csv`
- `<outroot>/analysis/workflow_stage_latency_mixed_diagnostics.csv`
- `<outroot>/analysis/workflow_stage_latency_mixed_summary.csv`
- `<outroot>/analysis/measurement_join_vs_removal_latency_diagnostics.csv`
- `<outroot>/analysis/measurement_sanity_report.csv`
- `<outroot>/analysis/communication_message_counts_enriched.csv`
- `<outroot>/analysis/communication_message_summary_by_workflow.csv`
- `<outroot>/analysis/communication_message_counts_by_run_workflow.csv`
- `<outroot>/analysis/communication_blockchain_message_counts_by_workflow.csv`
- `<outroot>/analysis/communication_blockchain_message_counts_by_run_workflow.csv`
- `<outroot>/analysis/communication_blockchain_messages_by_workflow.(png|tex)`
- `<outroot>/analysis/communication_sent_recv_by_workflow.(png|tex)`
- `<outroot>/analysis/communication_network_type_split_by_workflow.(png|tex)` (broadcast/direct split)
- `<outroot>/analysis/communication_type_counts_long.csv` (message-type decomposition from `*_by_type`)
- `<outroot>/analysis/communication_type_top20.(csv|png|tex)`
- `<outroot>/analysis/communication_bytes_by_run_workflow.csv` (RX/TX byte sums from labeled phase summaries)
- `<outroot>/analysis/communication_bytes_by_workflow.(png|tex)`
- `<outroot>/analysis/workflow_mixed_transition_diagnostics.png` (only when mixed remains after thresholding)
- `<outroot>/analysis/resource_component_summary_by_workflow.csv`
- `<outroot>/analysis/resource_component_cpu_boxplot.png`
- `<outroot>/analysis/resource_component_cpu_boxplot_combined.png`
- `<outroot>/analysis/resource_component_mem_boxplot.png`
- `<outroot>/analysis/resource_component_mem_boxplot_combined.png`
- `<outroot>/analysis/resource_component_cpu_by_run.png`
- `<outroot>/analysis/resource_component_mem_by_run.png`
- `<outroot>/analysis/optimization_potential_by_operation.csv`
- `<outroot>/analysis/optimization_potential_by_workflow.csv`
- `<outroot>/analysis/optimization_no_voting_savings_by_workflow.png`
- `<outroot>/analysis/optimization_no_voting_ledger_impact_by_operation.csv`
- `<outroot>/analysis/optimization_no_voting_ledger_impact_by_workflow.csv`
- `<outroot>/analysis/optimization_no_voting_ledger_shrink_by_workflow.(png|tex)`
- `<outroot>/analysis/storage_component_delta_boxplot.png`
- `<outroot>/analysis/storage_stage_component_summary_by_workflow.csv`
- `<outroot>/analysis/storage_stage_component_by_run.csv`
- `<outroot>/analysis/storage_stage_topk_volumes_summary.csv`
- `<outroot>/analysis/storage_stage_component_stacked_by_workflow.(png|tex)`
- `<outroot>/analysis/storage_stage_component_boxplot.(png|tex)`
- `<outroot>/analysis/storage_stage_topk_volumes.(png|tex)`
- `<outroot>/analysis/storage_logical_action_breakdown_all_runs.csv`
- `<outroot>/analysis/storage_logical_action_summary_by_workflow.csv`
- `<outroot>/analysis/storage_logical_vs_physical_by_action.csv`
- `<outroot>/analysis/storage_amplification_by_action.csv`
- `<outroot>/analysis/storage_cost_composition_csr_cert_registered.csv`
- `<outroot>/analysis/peer_volume_stage_contribution_detailed_by_workflow.csv`
- `<outroot>/analysis/peer_volume_residual_breakdown_by_action.csv`
- `<outroot>/analysis/peer_volume_residual_breakdown_by_workflow.csv`
- `<outroot>/analysis/query_latency_summary_by_metric.csv`
- `<outroot>/analysis/query_latency_by_run.csv`
- `<outroot>/analysis/query_latency_boxplots.(png|tex)`
- `<outroot>/analysis/query_latency_by_run.(png|tex)`
- plot `.png` files and matching PGFPlots/TikZ `.tex` files by default
- use `--no-export-tikz` to disable TikZ output

Analysis profiles (`--analysis-profile`):
- `compact` (default): writes core analysis CSVs only; plots and auxiliary CSVs are pruned.
- `full`: keeps the full CSV + plot/TikZ output set.

Measurement method:
- `benchmarks/MEASUREMENT_METHOD.md` documents data lineage, metric formulas, decomposition logic, and interpretation caveats.

TikZ export example:
``` shell
python3 -m pip install --upgrade \
  "matplotlib==3.7.5" \
  "tikzplotlib==0.10.1" \
  "webcolors==1.13"
MPLBACKEND=Agg python3 benchmarks/analyze_suite.py \
  --suite-root <outroot> \
  --outdir <outroot>/analysis \
  --analysis-profile full
```

### 3c) Standalone Query Latency Benchmark

Use this to benchmark certificate status + Merkle queries independently of the suite:
``` shell
python3 benchmarks/benchmark_queries.py \
  --api http://localhost:8083 \
  --cert-id 'x509::CN=Member1@irs3.kit.edu,...' \
  --iters 30 \
  --warmup 5 \
  --timeout 10 \
  --outdir benchmarks/out/query_bench_$(date +%Y%m%d_%H%M%S)
```

Outputs:
- `query_bench_iterations.csv` (per-iteration timings + HTTP status/ok flags)
- `query_bench_summary.csv` (`mean/std/p50/p95/p99/min/max` per metric)
- strict quality is enabled by default (`--require-status-success`, `--require-proof-success`)
- In suite mode, query benchmark is triggered immediately after the first successful `csr` workflow in each run (before `revocation`), with a post-run fallback only when no CSR target is available.
>>>>>>> Stashed changes

## 4) Resource + Network Sampling

Run on the node you want to measure:
``` shell
python3 benchmarks/collect_resources.py --interval 1 --output benchmarks/out/resources.csv --iface eth0
```

<<<<<<< Updated upstream
=======
Optional process matcher overrides:
``` shell
python3 benchmarks/collect_resources.py --interval 1 --output benchmarks/out/resources.csv --iface eth0 \
  --proc-match tss=tss_peer \
  --proc-match peer='peer node start' \
  --proc-match orderer=orderer
```

>>>>>>> Stashed changes
This writes:
- total CPU%
- total memory%
- per-process CPU/MEM for `tss_peer`, `peer`, `orderer`
- RX/TX bytes (interface counters)

Collect **idle baseline** by running it while no transactions are occurring.

<<<<<<< Updated upstream
=======
### 4b) Idle Communication Baseline (with Plots)

Use this script when you want a standalone idle-load run with suite-style diagrams:

``` shell
python3 benchmarks/idle_comm_baseline.py \
  --duration 600 \
  --interval 3 \
  --iface eth0 \
  --outdir benchmarks/out/idle_$(date +%Y%m%d_%H%M%S)
```

Default control-plane subtraction ports are `22`, `8083`, and `9446`.  
Default Fabric split ports are `7051` (peer) and `7050` (orderer).  
Override/add ports and enable gossip counter rates from peer metrics:

``` shell
python3 benchmarks/idle_comm_baseline.py \
  --duration 900 \
  --interval 2 \
  --iface eth0 \
  --peer-port 9051 \
  --orderer-port 8050 \
  --peer-metrics-url http://localhost:9446/metrics \
  --peer-metrics-prefix gossip_
```

Analyze an existing sample file without re-collecting:

```
python3 benchmarks/idle_comm_baseline.py \
  --input-csv /opt/fabric/benchmarks/out/idle_20260307_120000/idle_network_samples.csv
```

Outputs:
- `idle_network_samples.csv` (raw per-sample counters and deltas)
- `idle_network_rates_per_min.csv` (per-minute rates)
- `idle_network_summary.csv` (`mean/p50/p95/max`)
- `idle_bytes_per_minute.(png|tex)` (raw + adjusted TX/RX bytes/min)
- `idle_packets_per_minute.(png|tex)` (TX/RX packets/min)
- `idle_control_bytes_per_minute.(png|tex)` (only when subtracted control bytes are non-zero)
- `idle_peer_orderer_gossip_per_minute.(png|tex)` (peer bytes/min, orderer bytes/min, gossip counter rate/min)

>>>>>>> Stashed changes
## 5) Storage Measurement

``` shell
./benchmarks/measure_storage.sh --output benchmarks/out/storage.csv \
  --path /var/lib/docker/volumes \
  --path /opt/fabric
```

Use this after each workflow to estimate ledger growth per transaction set.

---

## Results Cheat Sheet

**Files and how to read them:**

- `benchmarks/out/events.csv`  
  Raw metrics events (one row per event). Useful for debugging event ordering or missing markers.

- `benchmarks/out/durations.csv`  
  Derived latencies per proposal/epoch:
  - `type`: `csr`, `revocation`, `member_removal`, `join_request`, `reshare`
  - `id`: proposal ID or epoch
  - `reason`: reshare reason (if present)
  - `proposal_s`: proposal submitted -> vote/ack
  - `tss_s`: TSS signing/keygen duration (where applicable)
  - `registration_s`: signing done -> recorded on-chain
  - `total_s`: end-to-end latency

- `benchmarks/out/resources_<workflow>.csv`  
  Raw samples from `collect_resources.py`:
  - `operation` tag (e.g., `csr_1771488645`)
  - `phase` (e.g., `csr_submit`, `csr_wait_cert`)
  - `cpu_total_pct`, `mem_used_pct`
  - `rx_bytes`, `tx_bytes` for the chosen interface
  - per-process CPU/MEM for `tss_peer`, `peer`, `orderer`

<<<<<<< Updated upstream
=======
- `benchmarks/out/resources_<workflow>_labeled.csv`  
  Same samples with detailed timeline:
  - `phase_derived`, `phase_start_ts`, `phase_end_ts`, `phase_elapsed_s`
  - nearest timeline marker fields (`marker_prev*`, `marker_next*`)
  - `proposal_id_derived`, `workflow_derived`, `entity_id_derived`, `epoch_derived`, `timeline_markers`

- `benchmarks/out/resources_<workflow>_phase_summary.csv`  
  Per-phase aggregates (samples, time span, avg/max CPU/MEM, RX/TX deltas).

- `benchmarks/out/resources_all_labeled.csv` (optional merged output)  
  Combined labeled rows across multiple resource files. Includes `source_file`.

- `benchmarks/out/resources_all_phase_summary.csv` (optional merged summary)  
  Per-workflow + per-phase aggregates for merged runs.

>>>>>>> Stashed changes
- `benchmarks/out/resources_summary.csv`  
  Per-workflow averages and maxima for CPU/MEM (total + per process).

- `benchmarks/out/storage_deltas.csv`  
  Per-workflow before/after storage deltas per `--storage-path`.

- `benchmarks/out/storage.csv`  
  Snapshot sizes per path from `measure_storage.sh` (run this after each workflow to compare).

- `benchmarks/out/message_counts.csv`  
  Per-workflow message totals:
  - `tss_p2p_*`: counts from the TSS P2P layer
  - `tss_p2p_*_by_type`: JSON map of `keygen` / `reshare` / `signing`
  - `gossip_metric_total`: sum of Fabric peer metrics that match `--peer-metrics-prefix`

<<<<<<< Updated upstream
**Sanity checks:**
- If `durations.csv` is empty, ensure `TSS_METRICS_ENABLED=true` and that `state/<org>/metrics.jsonl` has events.
- `collect_resources.py` uses `/proc`, so run it on Linux hosts only.
 - Gossip counts require Fabric peer Prometheus metrics to be enabled (operations endpoint + `CORE_METRICS_PROVIDER=prometheus`).

## 6) Recommended Test Configs

Run the same benchmarks across multiple configs:
- **N=2, quorum=50%** -> `t=1` (2-of-2)
- **N=3, quorum=50%** -> `t=1` (2-of-3)
- **N=3, quorum=67%** -> `t=2` (3-of-3)
- **N=4, quorum=75%** -> `t=2` (3-of-4)
- **N=5, quorum=60-67%** -> `t=3` (4-of-5)

Also vary:
- Observer count (0, 1, 2) to quantify ledger replication impact
- Network latency (e.g., WAN vs LAN)

## 7) Suggested Workflow Runs

For each config, run:
- CSR submission -> certificate registered
- Membership add (join request) -> reshare completed
- Membership removal -> reshare completed
- Certificate revocation

Record metrics + resources + storage before and after each run.
=======
>>>>>>> Stashed changes
