#!/usr/bin/env python3
"""Analyze benchmark suite outputs and generate summary tables + plots.

Example:
  python3 benchmarks/analyze_suite.py \
    --suite-root /opt/fabric/benchmarks/out/suite_20260228_151209
"""

import argparse
from pathlib import Path


def main():
    """main helper for benchmark tooling."""
    parser = argparse.ArgumentParser(description="Analyze benchmark suite CSVs with pandas and generate plots.")
    parser.add_argument("--suite-root", required=True, help="Path to suite output root (contains suite_*.csv files)")
    parser.add_argument("--outdir", default="", help="Output directory for analysis artifacts (default: <suite-root>/analysis)")
    parser.add_argument(
        "--analysis-profile",
        choices=["compact", "full"],
        default="compact",
        help="Analysis artifact profile (default: compact)",
    )
    parser.add_argument(
        "--include-all-storage-paths",
        action="store_true",
        help="Include all storage paths. Default only analyzes /var/lib/docker/volumes.",
    )
    parser.set_defaults(export_tikz=True)
    parser.add_argument(
        "--export-tikz",
        dest="export_tikz",
        action="store_true",
        help="Export each generated plot as PGFPlots/TikZ .tex via tikzplotlib (default: enabled).",
    )
    parser.add_argument(
        "--no-export-tikz",
        dest="export_tikz",
        action="store_false",
        help="Disable TikZ export and write PNG only.",
    )
    args = parser.parse_args()

    try:
        if __package__:
            from .analyze_common import ensure_outdir, initialize_plot_environment, set_emit_plots
            from .analyze_storage import (
                analyze_peer_ledger_store_breakdown,
                analyze_storage,
                analyze_storage_logical_vs_physical,
                analyze_storage_stages,
            )
            from .analyze_workflow import (
                analyze_communication,
                analyze_measurement_sanity,
                analyze_optimization_potential,
                analyze_query_latency,
                analyze_resources,
                analyze_tx_events,
                analyze_workflow,
                prune_analysis_outputs,
            )
        else:
            from analyze_common import ensure_outdir, initialize_plot_environment, set_emit_plots
            from analyze_storage import (
                analyze_peer_ledger_store_breakdown,
                analyze_storage,
                analyze_storage_logical_vs_physical,
                analyze_storage_stages,
            )
            from analyze_workflow import (
                analyze_communication,
                analyze_measurement_sanity,
                analyze_optimization_potential,
                analyze_query_latency,
                analyze_resources,
                analyze_tx_events,
                analyze_workflow,
                prune_analysis_outputs,
            )
    except ModuleNotFoundError as exc:
        missing = str(getattr(exc, "name", "") or "")
        if missing in {"numpy", "pandas", "matplotlib", "cycler"}:
            raise SystemExit(
                "Missing Python dependency "
                f"'{missing}'. Install required packages, e.g.:\n"
                "  python -m pip install pandas numpy matplotlib cycler"
            ) from exc
        raise

    suite_root = Path(args.suite_root).expanduser().resolve()
    if not suite_root.exists():
        raise SystemExit(f"Suite root not found: {suite_root}")

    outdir = Path(args.outdir).expanduser().resolve() if args.outdir else suite_root / "analysis"
    ensure_outdir(outdir)

    initialize_plot_environment()
    set_emit_plots(args.analysis_profile == "full")
    export_tikz = bool(args.export_tikz and args.analysis_profile == "full")

    analyze_workflow(suite_root, outdir, export_tikz=export_tikz)
    analyze_resources(suite_root, outdir, export_tikz=export_tikz)
    analyze_storage(suite_root, outdir, include_all_paths=args.include_all_storage_paths, export_tikz=export_tikz)
    analyze_storage_stages(suite_root, outdir, export_tikz=export_tikz)
    analyze_peer_ledger_store_breakdown(suite_root, outdir, export_tikz=export_tikz)
    analyze_query_latency(suite_root, outdir, export_tikz=export_tikz)
    analyze_communication(suite_root, outdir, export_tikz=export_tikz)
    analyze_tx_events(suite_root, outdir, export_tikz=export_tikz)
    analyze_storage_logical_vs_physical(suite_root, outdir, export_tikz=export_tikz)
    analyze_optimization_potential(suite_root, outdir, export_tikz=export_tikz)
    analyze_measurement_sanity(suite_root, outdir)

    pruned = prune_analysis_outputs(outdir, args.analysis_profile)
    if args.analysis_profile == "compact":
        print(
            "Analysis retention (compact): "
            f"files_removed={pruned.get('files_removed', 0)}, "
            f"bytes_freed={pruned.get('bytes_freed', 0)}"
        )

    print(f"Done. Analysis outputs: {outdir}")


if __name__ == "__main__":
    main()
