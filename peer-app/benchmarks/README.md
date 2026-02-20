# Benchmarking Guide (TSS PKI)

This folder contains lightweight tooling to capture **latency**, **resource usage**, **network**, and **storage** for the TSS PKI system.

## 1) Enable Metrics (JSONL)

Metrics are written to:
```
state/<org>/metrics.jsonl
```

You can disable metrics by setting:
```
TSS_METRICS_ENABLED=false
```

Events are emitted for:
- `csr_api_received`, `csr_submitted`, `signing_session_active`, `tss_signing_start`, `tss_signing_complete`, `cert_registered`
- `join_request_submitted`, `join_request_voted`
- `member_removal_proposed`, `member_removal_voted`
- `revocation_proposed`, `revocation_voted`
- `reshare_acknowledged`, `reshare_keygen_start`, `tss_keygen_complete`, `reshare_complete_submitted`, `reshare_complete_recorded`

## 2) Convert Metrics -> CSV Durations

```
python3 benchmarks/compute_durations.py --metrics state/org1/metrics.jsonl --outdir benchmarks/out
```

Outputs:
- `events.csv`: raw events with timestamps
- `durations.csv`: derived latencies per proposal/epoch

## 2b) Label Resource Samples With Phases

Use this to label per-second resource samples with CSR/reshare phase buckets.

CSR example:
```
python3 benchmarks/label_resources.py \
  --resources benchmarks/out/resources_csr_1771488811.csv \
  --metrics state/org1/metrics.jsonl \
  --proposal-id csr-org1-1771488811 \
  --mode csr \
  --out benchmarks/out/resources_csr_1771488811_labeled.csv
```
Notes:
- If `csr_api_received` is missing (e.g., you only have non-API peer metrics), the labeler uses the first resource sample as `csr_consensus_est`.

Reshare example:
```
python3 benchmarks/label_resources.py \
  --resources benchmarks/out/resources_csr_1771488811.csv \
  --metrics state/org1/metrics.jsonl \
  --epoch 3 \
  --mode reshare \
  --out benchmarks/out/resources_reshare_epoch3_labeled.csv
```

## 3) Optional Workflow Orchestration

Run a workflow against the Web UI API (useful for repeatable tests):
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

Example (single command, all measurements):
```
python3 benchmarks/run_workflows.py --api http://localhost:8080 --workflow csr \
  --measure --storage-path /var/lib/docker/volumes --storage-path /opt/fabric \
  --resources-interval 1 --resources-iface eth0
```

Example (add message counts + gossip metrics):
```
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

## 4) Resource + Network Sampling

Run on the node you want to measure:
```
python3 benchmarks/collect_resources.py --interval 1 --output benchmarks/out/resources.csv --iface eth0
```

This writes:
- total CPU%
- total memory%
- per-process CPU/MEM for `tss_peer`, `peer`, `orderer`
- RX/TX bytes (interface counters)

Collect **idle baseline** by running it while no transactions are occurring.

## 5) Storage Measurement

```
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
