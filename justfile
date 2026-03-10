export RUSTC_WRAPPER := "sccache"
export RUST_LOG := env("RUST_LOG", "warn")

# -euo pipefail; -c must be last so just appends the script correctly

set shell := ["bash", "-euo", "pipefail", "-c"]

logs_dir := ".logs"
results_dir := "results"
benchmarks_dir := "benchmarks"
runner := "./target/release/runner"
server := "./target/release/server"

# List available recipes
default:
    @just --list

alias b := build
alias c := check
alias d := docs
alias f := fmt
alias t := test

[group("build")]
build:
    cargo build --release

# Start a single server instance
[group("run")]
server mode="x25519" proto="raw" listen="127.0.0.1:4433": build
    {{ server }} --mode {{ mode }} --proto {{ proto }} --listen {{ listen }}

# Start all four server instances (x25519+mlkem × raw+http1)
[group("run")]
multi-server: build
    #!/usr/bin/env bash
    just _setup
    pids=()

    cleanup() {
        for pid in "${pids[@]}"; do
            kill "$pid" 2>/dev/null || true
        done
        wait || true
    }

    trap cleanup EXIT INT TERM

    echo "Starting benchmark servers:"
    echo "    x25519 raw   -> 127.0.0.1:4433"
    echo "    x25519 http1 -> 127.0.0.1:4434"
    echo "    mlkem raw    -> 127.0.0.1:4435"
    echo "    mlkem http1  -> 127.0.0.1:4436"

    LOG_FORMAT=compact {{ server }} --mode x25519         --proto raw   --listen 127.0.0.1:4433 > {{ logs_dir }}/server-x25519-raw.log 2>&1           & pids+=($!)
    LOG_FORMAT=compact {{ server }} --mode x25519         --proto http1 --listen 127.0.0.1:4434 > {{ logs_dir }}/server-x25519-http1.log 2>&1         & pids+=($!)
    LOG_FORMAT=compact {{ server }} --mode x25519mlkem768 --proto raw   --listen 127.0.0.1:4435 > {{ logs_dir }}/server-x25519mlkem768-raw.log 2>&1   & pids+=($!)
    LOG_FORMAT=compact {{ server }} --mode x25519mlkem768 --proto http1 --listen 127.0.0.1:4436 > {{ logs_dir }}/server-x25519mlkem768-http1.log 2>&1 & pids+=($!)

    wait

# Run a parameterized benchmark against a live server
[group("run")]
runner server_addr="127.0.0.1:4433" proto="raw" mode="x25519" payload="1024" iters="200" warmup="20" concurrency="1": build
    {{ runner }} \
        --server {{ server_addr }} \
        --proto {{ proto }} \
        --mode {{ mode }} \
        --payload-bytes {{ payload }} \
        --iters {{ iters }} \
        --warmup {{ warmup }} \
        --concurrency {{ concurrency }}

# Run sanity matrix benchmark
[group("bench")]
sanity-matrix: build
    #!/usr/bin/env bash
    just _setup
    out="{{ results_dir }}/sanity-$(date +%F-%H%M%S).ndjson"
    echo "Writing sanity matrix results to $out"
    {{ runner }} --config {{ benchmarks_dir }}/sanity.toml > "$out"

[group("bench")]
baseline-matrix: build
    #!/usr/bin/env bash
    just _setup
    out="{{ results_dir }}/baseline-$(date +%F-%H%M%S).ndjson"
    echo "Writing baseline matrix results to $out"
    {{ runner }} --config {{ benchmarks_dir }}/baseline.toml > "$out"

# Smoke benchmarks - requires multi-server to be running
[group("bench")]
smoke-raw-x25519:
    just _bench 127.0.0.1:4433 raw x25519 smoke-raw-x25519.ndjson

[group("bench")]
smoke-http1-x25519:
    just _bench 127.0.0.1:4434 http1 x25519 smoke-http1-x25519.ndjson

[group("bench")]
smoke-raw-mlkem:
    just _bench 127.0.0.1:4435 raw x25519mlkem768 smoke-raw-mlkem.ndjson

[group("bench")]
smoke-http1-mlkem:
    just _bench 127.0.0.1:4436 http1 x25519mlkem768 smoke-http1-mlkem.ndjson

# Run all smoke benchmarks
[group("bench")]
smoke-all: smoke-raw-x25519 smoke-http1-x25519 smoke-raw-mlkem smoke-http1-mlkem

# Run all checks (fmt, clippy, docs, test)
[group("dev")]
check: fmt clippy docs test

[group("dev")]
fmt:
    cargo fmt --all

[group("dev")]
fmt-check:
    cargo fmt --all -- --check

[group("dev")]
clippy:
    cargo clippy --all-targets --all-features -- -D warnings

[group("dev")]
docs:
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features

[group("dev")]
test:
    cargo nextest run --all-features
    cargo test --doc

[group("dev")]
clean:
    cargo clean

[group("dev")]
setup:
    cargo install cargo-nextest sccache

_setup:
    mkdir -p {{ results_dir }} {{ logs_dir }} {{ benchmarks_dir }}

_bench server_addr proto mode out="" payload="1024" iters="200" warmup="20" concurrency="1": build
    just _setup
    {{ runner }} \
        --server        {{ server_addr }} \
        --proto         {{ proto }} \
        --mode          {{ mode }} \
        --payload-bytes {{ payload }} \
        --iters         {{ iters }} \
        --warmup        {{ warmup }} \
        --concurrency   {{ concurrency }} \
        {{ if out != "" { "> " + results_dir + "/" + out } else { "" } }}
