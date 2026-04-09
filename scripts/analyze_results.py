#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.14"
# dependencies = []
# ///
"""Summarize benchmark JSONL results with percentile statistics."""

import csv
import json
import math
import sys
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser, Namespace
from dataclasses import dataclass
from enum import StrEnum, auto
from pathlib import Path
from statistics import fmean
from typing import Any, Iterator, NamedTuple

DEFAULT_GROUP_BY = ["proto", "mode", "payload_bytes", "concurrency"]
DEFAULT_METRICS = ["tcp", "handshake", "ttlb"]
UNIT_SCALE = {"ns": 1.0, "us": 1_000.0, "ms": 1_000_000.0}
STAT_COLUMNS = ["metric", "n", "unit", "mean"]


class Unit(StrEnum):
    NS = auto()
    US = auto()
    MS = auto()

    def __str__(self) -> str:
        return self.value

    @property
    def scale(self) -> float:
        return UNIT_SCALE[self.value]


class OutputFormat(StrEnum):
    MARKDOWN = auto()
    JSON = auto()
    CSV = auto()

    def __str__(self) -> str:
        return self.value


class PercentileSpec(NamedTuple):
    label: str
    q: float


PERCENTILES = [
    PercentileSpec("p50", 0.50),
    PercentileSpec("p95", 0.95),
    PercentileSpec("p99", 0.99),
]


@dataclass(frozen=True, slots=True)
class SummaryRow:
    group_fields: dict[str, Any]
    metric: str
    n: int
    unit: Unit
    mean: float
    p50: float
    p95: float
    p99: float

    def to_flat_dict(self) -> dict[str, Any]:
        """Return a flat dict suitable for JSON serialization or table rendering."""
        return {
            **self.group_fields,
            "metric": self.metric,
            "n": self.n,
            "unit": self.unit.value,
            "mean": self.mean,
            **{spec.label: getattr(self, spec.label) for spec in PERCENTILES},
        }


def parse_args() -> Namespace:
    parser = ArgumentParser(
        description="Summarize benchmark JSONL results with percentile statistics.",
        formatter_class=ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("input", nargs="+", help="Input JSONL file(s)")
    parser.add_argument(
        "-g",
        "--group-by",
        nargs="+",
        default=DEFAULT_GROUP_BY,
        metavar="FIELD",
        help="Record fields used to group benchmark rows",
    )
    parser.add_argument(
        "-m",
        "--metrics",
        nargs="+",
        default=DEFAULT_METRICS,
        metavar="FIELD",
        help="Numeric record fields to summarize",
    )
    parser.add_argument(
        "-u",
        "--unit",
        type=Unit,
        choices=list(Unit),
        default=Unit.MS,
        metavar=f"{{{','.join(str(u) for u in Unit)}}}",
        help="Display unit for metric columns",
    )
    parser.add_argument(
        "-f",
        "--format",
        type=OutputFormat,
        choices=list(OutputFormat),
        default=OutputFormat.MARKDOWN,
        metavar=f"{{{','.join(str(f) for f in OutputFormat)}}}",
        help="Output format",
    )
    return parser.parse_args()


def _iter_lines(path_str: str) -> Iterator[tuple[str, int, str]]:
    if path_str == "-":
        yield from ((path_str, i, line) for i, line in enumerate(sys.stdin, 1))
    else:
        path = Path(path_str)
        with path.open() as f:
            yield from ((path_str, i, line) for i, line in enumerate(f, 1))


def load_records(paths: list[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path_str in paths:
        for source, line_number, line in _iter_lines(path_str):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError as e:
                raise SystemExit(
                    f"{source}:{line_number}: invalid JSONL record: {e.msg}"
                ) from e
            if not isinstance(record, dict):
                raise SystemExit(
                    f"{source}:{line_number}: expected object record, got {type(record).__name__}"
                )
            records.append(record)

    if not records:
        raise SystemExit("no input records found")
    return records


def group_records(
    records: list[dict[str, Any]],
    group_by: list[str],
) -> dict[tuple[Any, ...], list[dict[str, Any]]]:
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for record in records:
        missing = [field for field in group_by if field not in record]
        if missing:
            raise SystemExit(
                f"record is missing grouping field(s): {', '.join(missing)}"
            )
        key = tuple(record[field] for field in group_by)
        grouped.setdefault(key, []).append(record)
    return grouped


def percentile(sorted_values: list[float], q: float) -> float:
    """Return the q-th percentile using the nearest-rank method.

    Args:
        sorted_values: Non-empty list of values sorted ascending.
        q: Quantile in [0, 1].
    """
    if not sorted_values:
        raise ValueError("percentile requires at least one value")
    n = len(sorted_values)
    rank = max(1, min(n, math.ceil(q * n)))
    return sorted_values[rank - 1]


def _extract_metric_values(
    records: list[dict[str, Any]],
    metric: str,
) -> list[float]:
    values: list[float] = []
    for record in records:
        value = record.get(metric)
        if value is None:
            raise SystemExit(f"record is missing metric field: {metric!r}")
        if not isinstance(value, int | float):
            raise SystemExit(
                f"metric field {metric!r} must be numeric, got {type(value).__name__}"
            )
        values.append(float(value))
    return values


def summarize(
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]],
    group_by: list[str],
    metrics: list[str],
    unit: Unit,
) -> list[SummaryRow]:
    rows: list[SummaryRow] = []

    for group_key in sorted(grouped):
        records = grouped[group_key]
        group_fields = dict(zip(group_by, group_key, strict=True))

        for metric in metrics:
            raw = _extract_metric_values(records, metric + "_ns")
            raw.sort()
            scaled = [v / unit.scale for v in raw]
            percentile_values = {
                spec.label: percentile(scaled, spec.q) for spec in PERCENTILES
            }
            rows.append(
                SummaryRow(
                    group_fields=group_fields,
                    metric=metric,
                    n=len(scaled),
                    unit=unit,
                    mean=fmean(scaled),
                    p50=percentile_values["p50"],
                    p95=percentile_values["p95"],
                    p99=percentile_values["p99"],
                )
            )

    return rows


def format_cell(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.4g}"
    return str(value).replace("|", "\\|")


def output_columns(group_by: list[str]) -> list[str]:
    return [*group_by, *STAT_COLUMNS, *(spec.label for spec in PERCENTILES)]


def render_markdown(rows: list[SummaryRow], group_by: list[str]) -> str:
    columns = output_columns(group_by)
    lines = [
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join("---" for _ in columns) + " |",
    ]

    for row in rows:
        flat = row.to_flat_dict()
        cells = [format_cell(flat[col]) for col in columns]
        lines.append("| " + " | ".join(cells) + " |")

    return "\n".join(lines)


def write_csv(rows: list[SummaryRow], group_by: list[str]) -> None:
    columns = output_columns(group_by)
    writer = csv.DictWriter(sys.stdout, fieldnames=columns)
    writer.writeheader()
    for row in rows:
        writer.writerow(row.to_flat_dict())


def main() -> None:
    args = parse_args()
    records = load_records(args.input)
    grouped = group_records(records, args.group_by)
    rows = summarize(grouped, args.group_by, args.metrics, args.unit)

    if args.format == OutputFormat.JSON:
        json.dump([row.to_flat_dict() for row in rows], sys.stdout, indent=2)
        print()
        return

    if args.format == OutputFormat.CSV:
        write_csv(rows, args.group_by)
        return

    print(render_markdown(rows, args.group_by))


if __name__ == "__main__":
    main()
