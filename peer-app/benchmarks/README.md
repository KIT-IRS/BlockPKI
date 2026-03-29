# Benchmarking Guide (TSS PKI)

This folder contains scripts to capture benchmarks from the system

The most likely scenario is to use the commands provided in the  **[Deployment readme](./deployment/README.md)**


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

## 4) Resource + Network Sampling

Run on the node you want to measure:
``` shell
python3 benchmarks/collect_resources.py --interval 1 --output benchmarks/out/resources.csv --iface eth0
```

This writes:
- total CPU%
- total memory%
- per-process CPU/MEM for `tss_peer`, `peer`, `orderer`
- RX/TX bytes (interface counters)

Collect **idle baseline** by running it while no transactions are occurring.

## 5) Storage Measurement

``` shell
./benchmarks/measure_storage.sh --output benchmarks/out/storage.csv \
  --path /var/lib/docker/volumes \
  --path /opt/fabric
```

Use this after each workflow to estimate ledger growth per transaction set.

---


