#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.14"
# dependencies = []
# ///
"""Generate a benchmark matrix TOML file from parameterized dimensions."""

from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser, Namespace
from dataclasses import dataclass
from enum import StrEnum, auto


@dataclass(frozen=True, slots=True)
class BenchmarkEntry:
    verification: str
    server: str
    proto: str
    mode: str
    payload: int
    iters: int
    warmup: int
    concurrency: int

    def render(self) -> str:
        return "\n".join(
            [
                "[[benchmarks]]",
                f'verification.kind = "{self.verification}"',
                f'server = "{self.server}"',
                f'proto = "{self.proto}"',
                f'mode = "{self.mode}"',
                f"payload = {self.payload}",
                f"iters = {self.iters}",
                f"warmup = {self.warmup}",
                f"concurrency = {self.concurrency}",
            ]
        )

    def __str__(self) -> str:
        return self.render()


class Mode(StrEnum):
    X25519 = auto()
    SECP256R1 = auto()
    X25519MLKEM768 = auto()
    SECP256R1MLKEM768 = auto()


@dataclass(frozen=True, slots=True)
class Endpoint:
    host: str
    port: int

    def render(self) -> str:
        return f"{self.host}:{self.port}"

    def __str__(self) -> str:
        return self.render()


@dataclass(frozen=True, slots=True)
class Variant:
    proto: str
    mode: str


type PortMap = dict[Variant, Endpoint]


def parse_args() -> Namespace:
    p = ArgumentParser(
        description="Generate a benchmark matrix TOML file.",
        formatter_class=ArgumentDefaultsHelpFormatter,
    )

    p.add_argument("--host", default="127.0.0.1")
    p.add_argument(
        "--port",
        action="append",
        dest="ports",
        metavar="PROTO:MODE=PORT",
        help=(
            "Port for a proto:mode pair, e.g. raw:x25519=4433. Repeat for each "
            "combination. if ommited, ports are assigned sequentially from "
            "--base-port in (mode, proto) order."
        ),
    )
    p.add_argument(
        "--base-port",
        type=int,
        default=4433,
        help="Used only when --port is not provided",
    )
    p.add_argument("--protocols", nargs="+", default=["raw", "http1"], metavar="PROTO")
    p.add_argument(
        "--modes",
        nargs="+",
        default=[
            "x25519",
            "secp256r1",
            "x25519mlkem768",
            "secp256r1mlkem768",
        ],
        metavar="MODE",
    )
    p.add_argument(
        "--payloads",
        nargs="+",
        type=int,
        default=[1024, 10240, 102400, 1048576],
        metavar="BYTES",
    )
    p.add_argument(
        "--concurrencies",
        nargs="+",
        type=int,
        default=[1, 10, 100],
        metavar="N",
    )
    p.add_argument("--iters", type=int, default=200)
    p.add_argument("--warmup", type=int, default=20)
    p.add_argument("--verification", default="insecure")
    p.add_argument(
        "-o",
        "--output",
        default="-",
        metavar="FILE",
        help="Ouput file path, or - for stdout.",
    )

    return p.parse_args()


def build_port_map(
    host: str,
    base_port: int,
    modes: list[str],
    protocols: list[str],
    port_overrides: list[str] | None,
) -> PortMap:
    """Returns a (proto, mode) -> 'host:port' mapping.

    If --port flags are provided they must cover every (proto, mode) pair.
    Otherwise ports are assigned sequentially from base_port in
    (mode, proto) order (matching the original layout).
    """

    if port_overrides:
        mapping = {}
        for spec in port_overrides:
            try:
                key, port_str = spec.split("=", 1)
                proto, mode = key.split(":", 1)
                mapping[Variant(proto, mode)] = Endpoint(host, int(port_str))
            except ValueError as e:
                raise SystemError(
                    f"error: invalid --port spec {spec!r}, expected PROTO:MODE=PORT"
                ) from e
        missing = [
            f"{proto}:{mode}"
            for mode in modes
            for proto in protocols
            if (proto, mode) not in mapping
        ]
        if missing:
            raise SystemError(
                f"error: missing --port entries for: {', '.join(missing)}"
            )
        return mapping

    result = {}
    port = base_port
    for mode in modes:
        for proto in protocols:
            result[Variant(proto, mode)] = Endpoint(host=host, port=port)
            port += 1
    return result


def render_header(
    port_map: PortMap,
    modes: list[str],
    protocols: list[str],
    payloads: list[int],
    concurrencies: list[int],
    iters: int,
    warmup: int,
) -> str:
    lines = [
        "# Benchmark matrix for the main thesis baseline runs.",
        "#",
        "# Local port mapping:",
    ]
    for mode in modes:
        for proto in protocols:
            addr = port_map[Variant(proto, mode)]
            lines.append(f"# - {addr} => proto={proto}, mode={mode}")
    lines += [
        "#",
        "# Experiment dimensions:",
        f"# - protocol: {', '.join(protocols)}",
        f"# - mode: {', '.join(modes)}",
        f"# - payload: {', '.join(str(p) for p in payloads)} bytes",
        f"# - concurrency: {', '.join(str(c) for c in concurrencies)}",
        f"# - iterations: {iters} measured, {warmup} warmup",
    ]
    return "\n".join(lines)


def generate(args: Namespace) -> str:
    port_map = build_port_map(
        args.host,
        args.base_port,
        args.modes,
        args.protocols,
        args.ports,
    )
    blocks = [
        render_header(
            port_map,
            args.modes,
            args.protocols,
            args.payloads,
            args.concurrencies,
            args.iters,
            args.warmup,
        )
    ]

    for mode in args.modes:
        for proto in args.protocols:
            server = port_map[Variant(proto, mode)].render()
            for payload in args.payloads:
                for concurrency in args.concurrencies:
                    blocks.append(
                        BenchmarkEntry(
                            verification=args.verification,
                            server=server,
                            proto=proto,
                            mode=mode,
                            payload=payload,
                            iters=args.iters,
                            warmup=args.warmup,
                            concurrency=concurrency,
                        ).render()
                    )

    return "\n\n".join(blocks) + "\n"


def main() -> None:
    args = parse_args()
    output = generate(args)

    if args.output == "-":
        print(output)
    else:
        with open(args.output, "w") as f:
            f.write(output)


if __name__ == "__main__":
    main()
