#!/usr/bin/env bash
# measure_storage.sh captures timestamped path-size snapshots for benchmark storage deltas.
# Runtime flow: reads one or more --path arguments, measures bytes with du -sb,
# and writes a simple ts/path/bytes CSV used by workflow and suite aggregation.

set -euo pipefail

output="storage.csv"
paths=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      output="$2"
      shift 2
      ;;
    --path)
      paths+=("$2")
      shift 2
      ;;
    *)
      echo "Unknown arg: $1" >&2
      exit 1
      ;;
  esac
done

if [[ ${#paths[@]} -eq 0 ]]; then
  echo "Usage: $0 --output storage.csv --path /var/lib/docker/volumes --path /opt/fabric" >&2
  exit 1
fi

ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "ts,path,bytes" > "$output"

for p in "${paths[@]}"; do
  if [[ -e "$p" ]]; then
    bytes=$(du -sb "$p" | awk '{print $1}')
    echo "${ts},${p},${bytes}" >> "$output"
  else
    echo "${ts},${p},NA" >> "$output"
  fi
done
