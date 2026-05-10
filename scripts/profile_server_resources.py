#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.14"
# dependencies = []
# ///
"""Profile server-side resources for configured benchmark entries."""

import json
import os
import signal
import sys
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser, Namespace
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from shutil import which
from socket import create_connection
from subprocess import PIPE, Popen, run
from tempfile import NamedTemporaryFile
from time import sleep, time
from typing import Any

import tomllib

PERF_EVENTS = (
    "task-clock,cycles,instructions,context-switches,cpu-migrations,page-faults"
)
PERF_EVENT_NAMES = PERF_EVENTS.split(",")
SCHEMA_VERSION = 1

type Json = None | bool | int | float | str | list["Json"] | dict[str, "Json"] | Any
type JsonObject = dict[str, Json]


@dataclass(frozen=True, slots=True)
class Endpoint:
    host: str
    port: int


@dataclass(frozen=True, slots=True)
class Benchmark:
    server: str
    server_name: str
    proto: str
    mode: str
    payload: int
    iters: int
    warmup: int
    concurrency: int
    timeout_secs: int
    verification: JsonObject


@dataclass(frozen=True, slots=True)
class Commands:
    server: list[str]
    runner: list[str]


def unix_ms() -> int:
    return round(time() * 1000)


def parse_args() -> Namespace:
    parser = ArgumentParser(
        description="Profile server process resource usage for benchmark entries.",
        formatter_class=ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--config", type=Path, default=Path("benchmarks/full.toml"))
    parser.add_argument(
        "--out",
        type=Path,
        help="Output JSONL path. Existing files are overwritten; use distinct paths for chunked runs.",
    )
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument(
        "--server-bin", type=Path, default=Path("target/release/server")
    )
    parser.add_argument(
        "--runner-bin", type=Path, default=Path("target/release/runner")
    )
    parser.add_argument("--cert", type=Path)
    parser.add_argument("--key", type=Path)
    parser.add_argument("--tool", choices=("perf", "proc", "both"), default="both")
    parser.add_argument("--start-index", type=int)
    parser.add_argument("--limit", type=int)
    return parser.parse_args()


def default_out_path() -> Path:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return Path("results") / "profiling" / f"server-resources-{timestamp}.jsonl"


def executable(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def parse_endpoint(server: str) -> Endpoint:
    host, sep, port_text = server.rpartition(":")
    if sep == "" or host == "" or port_text == "":
        raise ValueError(f"server address must be host:port: {server}")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ValueError(f"server address has invalid port: {server}") from exc
    if not 0 < port <= 65_535:
        raise ValueError(f"server address port is out of range: {server}")
    return Endpoint(host=host.removeprefix("[").removesuffix("]"), port=port)


def is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def require_int(entry: JsonObject, field: str, index: int) -> int:
    value = entry.get(field)
    if not isinstance(value, int):
        raise ValueError(f"benchmark {index} field {field!r} must be an integer")
    return value


def require_str(entry: JsonObject, field: str, index: int) -> str:
    value = entry.get(field)
    if not isinstance(value, str):
        raise ValueError(f"benchmark {index} field {field!r} must be a string")
    return value


def verification(entry: JsonObject, index: int) -> JsonObject:
    raw = entry.get("verification")
    if not isinstance(raw, dict):
        raise ValueError(f"benchmark {index} field 'verification' must be a table")
    kind = raw.get("kind")
    if not isinstance(kind, str):
        raise ValueError(f"benchmark {index} verification.kind must be a string")
    result: JsonObject = {"kind": kind}
    path = raw.get("path")
    if path is not None:
        if not isinstance(path, str):
            raise ValueError(f"benchmark {index} verification.path must be a string")
        result["path"] = path
    return result


def optional_str(entry: JsonObject, field: str, default: str, index: int) -> str:
    value = entry.get(field, default)
    if not isinstance(value, str):
        raise ValueError(f"benchmark {index} field {field!r} must be a string")
    return value


def load_benchmarks(config: Path) -> list[Benchmark]:
    with config.open("rb") as handle:
        parsed = tomllib.load(handle)
    raw_benchmarks = parsed.get("benchmarks")
    if not isinstance(raw_benchmarks, list):
        raise ValueError("config must contain a [[benchmarks]] array")

    benchmarks: list[Benchmark] = []
    for index, raw in enumerate(raw_benchmarks):
        if not isinstance(raw, dict):
            raise ValueError(f"benchmark {index} must be a table")
        entry: JsonObject = raw
        benchmarks.append(
            Benchmark(
                server=require_str(entry, "server", index),
                server_name=optional_str(entry, "server_name", "localhost", index),
                proto=require_str(entry, "proto", index),
                mode=require_str(entry, "mode", index),
                payload=require_int(entry, "payload", index),
                iters=require_int(entry, "iters", index),
                warmup=require_int(entry, "warmup", index),
                concurrency=require_int(entry, "concurrency", index),
                timeout_secs=require_int(entry, "timeout_secs", index)
                if "timeout_secs" in entry
                else 30,
                verification=verification(entry, index),
            )
        )
    return benchmarks


def selected_indices(total: int, start: int | None, limit: int | None) -> range:
    start_index = start or 0
    if start_index < 0 or start_index > total:
        raise ValueError(f"--start-index must be between 0 and {total}")
    if limit is not None and limit < 0:
        raise ValueError("--limit must be non-negative")
    end = total if limit is None else min(total, start_index + limit)
    return range(start_index, end)


def find_cert_pair(
    args: Namespace, benchmarks: list[Benchmark]
) -> tuple[Path | None, Path | None]:
    cert = args.cert
    key = args.key
    if cert is None and Path("certs/server.der").is_file():
        cert = Path("certs/server.der")
    if key is None and Path("certs/server.key").is_file():
        key = Path("certs/server.key")

    uses_cacert = any(
        bench.verification.get("kind") == "cacert" for bench in benchmarks
    )
    if uses_cacert and (
        cert is None or key is None or not cert.is_file() or not key.is_file()
    ):
        raise ValueError(
            "cacert verification requires --cert and --key, or existing "
            "certs/server.der and certs/server.key"
        )
    if (args.cert is None) != (args.key is None):
        raise ValueError("--cert and --key must be provided together")
    return cert, key


def validate_args(
    args: Namespace, benchmarks: list[Benchmark]
) -> tuple[Path | None, Path | None]:
    if args.repeats < 1:
        raise ValueError("--repeats must be at least 1")
    if not args.config.is_file():
        raise ValueError(f"config file not found: {args.config}")
    if not executable(args.server_bin):
        raise ValueError(f"server binary missing or not executable: {args.server_bin}")
    if not executable(args.runner_bin):
        raise ValueError(f"runner binary missing or not executable: {args.runner_bin}")
    if args.tool in ("perf", "both") and which("perf") is None:
        raise ValueError("perf is unavailable on PATH")
    for index, bench in enumerate(benchmarks):
        endpoint = parse_endpoint(bench.server)
        if not is_loopback_host(endpoint.host):
            raise ValueError(
                f"benchmark {index} server address must be loopback for local profiling: "
                f"{bench.server}"
            )
        if not isinstance(bench.server_name, str):
            raise ValueError(f"benchmark {index} server_name must be a string")
    return find_cert_pair(args, benchmarks)


def count_completed_requests(output: str) -> int:
    completed = 0
    for line in output.splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and "iteration" in record:
            completed += 1
    return completed


def benchmark_json(bench: Benchmark) -> JsonObject:
    return {
        "server": bench.server,
        "server_name": bench.server_name,
        "proto": bench.proto,
        "mode": bench.mode,
        "payload": bench.payload,
        "iters": bench.iters,
        "warmup": bench.warmup,
        "concurrency": bench.concurrency,
        "timeout_secs": bench.timeout_secs,
        "verification": bench.verification,
    }


def commands(
    args: Namespace, bench: Benchmark, cert: Path | None, key: Path | None
) -> Commands:
    server = [
        str(args.server_bin),
        "--mode",
        bench.mode,
        "--proto",
        bench.proto,
        "--listen",
        bench.server,
    ]
    if cert is not None and key is not None:
        server.extend(["--cert", str(cert), "--key", str(key)])

    runner = [
        str(args.runner_bin),
        "--server",
        bench.server,
        "--server-name",
        bench.server_name,
        "--proto",
        bench.proto,
        "--mode",
        bench.mode,
        "--payload-bytes",
        str(bench.payload),
        "--iters",
        str(bench.iters),
        "--warmup",
        str(bench.warmup),
        "--concurrency",
        str(bench.concurrency),
        "--timeout-secs",
        str(bench.timeout_secs),
    ]
    ca_cert = bench.verification.get("path")
    if bench.verification.get("kind") == "cacert" and isinstance(ca_cert, str):
        runner.extend(["--ca-cert", ca_cert])
    return Commands(server=server, runner=runner)


def stop_process_group(process: Popen[str]) -> str:
    stderr = ""
    if process.poll() is None:
        for sig, grace in (
            (signal.SIGINT, 5.0),
            (signal.SIGTERM, 2.0),
            (signal.SIGKILL, 0.0),
        ):
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                break
            try:
                _, stderr = process.communicate(timeout=grace)
                break
            except TimeoutError:
                continue
    if process.poll() is None:
        _, stderr = process.communicate()
    else:
        try:
            _, tail = process.communicate(timeout=0.1)
            stderr = tail or stderr
        except TimeoutError:
            pass
    return stderr


def base_record(
    args: Namespace,
    index: int,
    repeat: int,
    bench: Benchmark,
    command: Commands,
    started_at: int,
) -> JsonObject:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": args.tool,
        "config_path": str(args.config),
        "benchmark_index": index,
        "repeat": repeat,
        "kex_group": bench.mode,
        "proto": bench.proto,
        "payload_bytes": bench.payload,
        "concurrency": bench.concurrency,
        "completed_requests": None,
        "started_at_unix_ms": started_at,
        "finished_at_unix_ms": started_at,
        "benchmark": benchmark_json(bench),
        "server": {
            "command": command.server,
            "pid": None,
            "exit_code": None,
            "stderr": "",
        },
        "runner": {
            "command": command.runner,
            "exit_code": None,
            "completed_requests": None,
            "stderr": "",
        },
        "measurement": {},
    }


def ss_reports_listening(endpoint: Endpoint) -> bool:
    output = run(["ss", "-H", "-ltn"], capture_output=True, text=True, check=False)
    if output.returncode != 0:
        return False
    port_suffix = f":{endpoint.port}"
    bracketed_port_suffix = f"]:{endpoint.port}"
    for line in output.stdout.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        local_address = fields[3]
        if local_address.endswith(port_suffix) or local_address.endswith(
            bracketed_port_suffix
        ):
            return True
    return False


def tcp_probe_reports_ready(endpoint: Endpoint) -> bool:
    try:
        with create_connection((endpoint.host, endpoint.port), timeout=0.2):
            return True
    except OSError:
        return False


def wait_for_ready(
    endpoint: Endpoint, timeout_secs: int, process: Popen[str]
) -> tuple[str, str | None]:
    deadline = time() + timeout_secs
    has_ss = which("ss") is not None
    while time() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"server exited before readiness: {process.returncode}")
        if has_ss and ss_reports_listening(endpoint):
            return "ss", None
        if not has_ss and tcp_probe_reports_ready(endpoint):
            return (
                "tcp_connect",
                "ss unavailable; TCP readiness probe can trigger an expected TLS EOF warning",
            )
        sleep(0.05)
    raise TimeoutError(
        f"server did not listen at {endpoint.host}:{endpoint.port}"
        if has_ss
        else f"server did not accept connections at {endpoint.host}:{endpoint.port}"
    )


def parse_perf(raw: str) -> JsonObject:
    events: JsonObject = {}
    for line in raw.splitlines():
        columns = line.split(",")
        if len(columns) < 3:
            continue
        value = columns[0].strip()
        event = columns[2].strip().split(":", maxsplit=1)[0]
        if event in PERF_EVENT_NAMES:
            events[event] = value
    return events


def read_proc_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        return f"<error: {exc}>"


def parse_status_value(status: str, name: str) -> int | None:
    prefix = f"{name}:"
    for line in status.splitlines():
        if not line.startswith(prefix):
            continue
        fields = line.removeprefix(prefix).strip().split()
        if not fields:
            return None
        try:
            return int(fields[0])
        except ValueError:
            return None
    return None


def delta(initial: int | None, final: int | None) -> int | None:
    if initial is None or final is None:
        return None
    return final - initial


def run_runner_with_perf(
    command: Commands,
    server_pid: int,
    perf_file_path: str,
) -> tuple[int, str, str]:
    perf_command = [
        "perf",
        "stat",
        "-x",
        ",",
        "--no-big-num",
        "-e",
        PERF_EVENTS,
        "-p",
        str(server_pid),
        "-o",
        perf_file_path,
        "--",
        *command.runner,
    ]
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    process = Popen(
        perf_command,
        stdout=PIPE,
        stderr=PIPE,
        text=True,
        env=env,
    )
    stdout, stderr = process.communicate()
    return process.returncode, stdout, stderr


def run_runner(command: Commands) -> tuple[int, str, str]:
    runner = run(command.runner, capture_output=True, text=True, check=False)
    return runner.returncode, runner.stdout, runner.stderr


def run_measurement(
    args: Namespace,
    index: int,
    repeat: int,
    bench: Benchmark,
    command: Commands,
) -> tuple[JsonObject, bool]:
    started_at = unix_ms()
    record = base_record(args, index, repeat, bench, command, started_at)
    perf_raw = ""
    initial_status = ""
    final_status = ""
    readiness_warning: str | None = None
    process = Popen(
        command.server,
        stdout=PIPE,
        stderr=PIPE,
        text=True,
        start_new_session=True,
    )
    server = record["server"]
    if isinstance(server, dict):
        server["pid"] = process.pid
    try:
        readiness_method, readiness_warning = wait_for_ready(
            parse_endpoint(bench.server), bench.timeout_secs, process
        )
        if isinstance(server, dict):
            server["readiness_method"] = readiness_method
            server["readiness_warning"] = readiness_warning
        if args.tool in ("proc", "both"):
            initial_status = read_proc_file(Path("/proc") / str(process.pid) / "status")
        if args.tool in ("perf", "both"):
            with NamedTemporaryFile("r", encoding="utf-8") as perf_file:
                runner_exit_code, runner_stdout, runner_stderr = run_runner_with_perf(
                    command, process.pid, perf_file.name
                )
                perf_file.seek(0)
                perf_raw = perf_file.read()
        else:
            runner_exit_code, runner_stdout, runner_stderr = run_runner(command)
        completed_requests = count_completed_requests(runner_stdout)
        runner_record = record["runner"]
        if isinstance(runner_record, dict):
            runner_record["exit_code"] = runner_exit_code
            runner_record["completed_requests"] = completed_requests
            runner_record["stderr"] = runner_stderr
        record["completed_requests"] = completed_requests
        if args.tool in ("proc", "both"):
            final_status = read_proc_file(Path("/proc") / str(process.pid) / "status")
        if runner_exit_code != 0:
            record["error"] = f"runner exited with {runner_exit_code}"
    except Exception as exc:
        if args.tool in ("proc", "both"):
            final_status = read_proc_file(Path("/proc") / str(process.pid) / "status")
        record["error"] = str(exc)
    finally:
        stderr = stop_process_group(process)
        expected_shutdown = process.returncode in (-signal.SIGINT, 128 + signal.SIGINT)
        if isinstance(server, dict):
            server["exit_code"] = process.returncode
            server["expected_shutdown"] = expected_shutdown
            if "readiness_method" not in server:
                server["readiness_method"] = None
                server["readiness_warning"] = readiness_warning
            server["stderr"] = stderr
        measurement: JsonObject = {}
        if args.tool in ("perf", "both"):
            measurement["perf_events"] = parse_perf(perf_raw)
            measurement["perf_raw"] = perf_raw
        if args.tool in ("proc", "both"):
            initial_voluntary = parse_status_value(
                initial_status, "voluntary_ctxt_switches"
            )
            final_voluntary = parse_status_value(
                final_status, "voluntary_ctxt_switches"
            )
            initial_nonvoluntary = parse_status_value(
                initial_status, "nonvoluntary_ctxt_switches"
            )
            final_nonvoluntary = parse_status_value(
                final_status, "nonvoluntary_ctxt_switches"
            )
            measurement["initial_status_after_ready"] = initial_status
            measurement["final_status"] = final_status
            measurement["peak_rss_kb"] = parse_status_value(final_status, "VmHWM")
            measurement["current_rss_kb"] = parse_status_value(final_status, "VmRSS")
            measurement["voluntary_ctxt_switches_initial"] = initial_voluntary
            measurement["voluntary_ctxt_switches_final"] = final_voluntary
            measurement["voluntary_ctxt_switches_delta"] = delta(
                initial_voluntary, final_voluntary
            )
            measurement["nonvoluntary_ctxt_switches_initial"] = initial_nonvoluntary
            measurement["nonvoluntary_ctxt_switches_final"] = final_nonvoluntary
            measurement["nonvoluntary_ctxt_switches_delta"] = delta(
                initial_nonvoluntary, final_nonvoluntary
            )
        record["measurement"] = measurement
        record["finished_at_unix_ms"] = unix_ms()
    return record, "error" not in record


def write_record(handle, record: JsonObject) -> None:
    json.dump(record, handle, separators=(",", ":"))
    handle.write("\n")
    handle.flush()


def main() -> int:
    args = parse_args()
    if args.out is None:
        args.out = default_out_path()
    try:
        if not args.config.is_file():
            raise ValueError(f"config file not found: {args.config}")
        benchmarks = load_benchmarks(args.config)
        cert, key = validate_args(args, benchmarks)
        indices = selected_indices(len(benchmarks), args.start_index, args.limit)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("w", encoding="utf-8") as handle:
            for index in indices:
                bench = benchmarks[index]
                command = commands(args, bench, cert, key)
                for repeat in range(1, args.repeats + 1):
                    record, ok = run_measurement(args, index, repeat, bench, command)
                    write_record(handle, record)
                    if not ok:
                        return 1
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
