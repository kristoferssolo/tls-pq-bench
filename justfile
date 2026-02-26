export RUSTC_WRAPPER := "sccache"
export RUST_LOG := env_var_or_default("RUST_LOG", "warn")

set shell := ["bash", "-cu"]

# Default recipe
default:
    @just --list

alias b := build
alias c := check
alias d := docs
alias f := fmt
alias t := test
alias bench := benchmark

# Run all checks (fmt, clippy, docs, test)
[group("dev")]
check: fmt clippy docs test

# Format code
[group("dev")]
fmt:
    cargo fmt --all

# Check formatting without modifying
[group("dev")]
fmt-check:
    cargo fmt --all -- --check

# Run clippy
[group("dev")]
clippy:
    cargo clippy --all-targets --all-features -- -D warnings

# Build documentation
[group("dev")]
docs:
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features

# Run tests with nextest
[group("dev")]
test:
    cargo nextest run --all-features
    cargo test --doc

# Build release binaries
[group("dev")]
build:
    cargo build --release

# Clean build artifacts
[group("dev")]
clean:
    cargo clean

# Install dev dependencies
[group("dev")]
setup:
    cargo install cargo-nextest

# Run server (default: x25519 on localhost:4433)
[group("run")]
server mode="x25519" proto="raw" listen="127.0.0.1:4433":
    cargo run --release --bin server -- --mode {{mode}} --proto {{proto}} --listen {{listen}}

# Run benchmark runner
[group("run")]
runner server mode="x25519" payload="1024" iters="100" warmup="10":
    cargo run --release --bin runner -- \
        --server {{server}} \
        --mode {{mode}} \
        --payload-bytes {{payload}} \
        --iters {{iters}} \
        --warmup {{warmup}}

# Run benchmark runner from a config file
[group("run")]
benchmark config="benchmarks.toml":
    cargo run --release --bin runner -- \
        --config {{config}}

