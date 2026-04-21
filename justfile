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
server mode="x25519" proto="raw" listen="127.0.0.1:4433" cert="" key="": build
    #!/usr/bin/env bash
    if [[ "{{ cert }}" != "" || "{{ key }}" != "" ]]; then
        if [[ "{{ cert }}" == "" || "{{ key }}" == "" ]]; then
            echo "server requires both cert and key, or neither" >&2
            exit 1
        fi
        exec {{ server }} --mode {{ mode }} --proto {{ proto }} --listen {{ listen }} --cert {{ cert }} --key {{ key }}
    fi
    exec {{ server }} --mode {{ mode }} --proto {{ proto }} --listen {{ listen }}

# Start all eight server instances (4 modes × raw+http1)
[group("run")]
multi-server cert="" key="":
    just _start-server-set multi-server 127.0.0.1 server "Starting benchmark servers:" "{{ cert }}" "{{ key }}"

# Start the full production listener set on one server host. This covers all four key exchange variants, each exposed over raw and http1: 4433/4434 x25519, 4435/4436 secp256r1, 4437/4438 x25519mlkem768, 4439/4440 secp256r1mlkem768.
[group("prod")]
prod-server bind_host="0.0.0.0" cert="" key="":
    just _start-server-set prod-server "{{ bind_host }}" prod-server "Starting production benchmark servers on {{ bind_host }}:" "{{ cert }}" "{{ key }}"

# Generate the scheduled remote benchmark configs and install/enable the systemd timers on the runner box. Expects an env file compatible with ops/scheduled-benchmarks.env.example.
[group("prod")]
prod-schedule env_file="/etc/tls-pq-bench/scheduled.env": build
    #!/usr/bin/env bash
    if [[ ! -f "{{ env_file }}" ]]; then
        echo "schedule env file not found: {{ env_file }}" >&2
        exit 1
    fi

    SCHEDULE_ENV_FILE="{{ env_file }}" ./scripts/generate_remote_schedule_configs.sh
    sudo install -m 0644 ops/systemd/tls-pq-bench-track.service /etc/systemd/system/tls-pq-bench-track.service
    sudo install -m 0644 ops/systemd/tls-pq-bench-track.timer /etc/systemd/system/tls-pq-bench-track.timer
    sudo install -m 0644 ops/systemd/tls-pq-bench-full.service /etc/systemd/system/tls-pq-bench-full.service
    sudo install -m 0644 ops/systemd/tls-pq-bench-full.timer /etc/systemd/system/tls-pq-bench-full.timer
    sudo systemctl daemon-reload
    sudo systemctl enable --now tls-pq-bench-track.timer
    sudo systemctl enable --now tls-pq-bench-full.timer


# Run a parameterized benchmark against a live server
[group("run")]
runner server_addr="127.0.0.1:4433" server_name="localhost" proto="raw" mode="x25519" payload="1024" iters="200" warmup="20" concurrency="1": build
    {{ runner }} \
        --server {{ server_addr }} \
        --server-name {{ server_name }} \
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
    out="{{ results_dir }}/sanity-$(date +%F-%H%M%S).jsonl"
    echo "Writing sanity matrix results to $out"
    {{ runner }} --config {{ benchmarks_dir }}/sanity.toml > "$out"

[group("bench")]
baseline-matrix: build
    #!/usr/bin/env bash
    just _setup
    out="{{ results_dir }}/baseline-$(date +%F-%H%M%S).jsonl"
    echo "Writing baseline matrix results to $out"
    {{ runner }} --config {{ benchmarks_dir }}/baseline.toml > "$out"

[group("bench")]
generate-matrix out="-":
    uv run --script scripts/generate_benchmark_matrix.py -o {{ out }}

[group("smoke")]
smoke-raw-x25519:
    just _bench 127.0.0.1:4433 raw x25519 smoke-raw-x25519.jsonl

[group("smoke")]
smoke-http1-x25519:
    just _bench 127.0.0.1:4434 http1 x25519 smoke-http1-x25519.jsonl

[group("smoke")]
smoke-raw-mlkem:
    just _bench 127.0.0.1:4437 raw x25519mlkem768 smoke-raw-mlkem.jsonl

[group("smoke")]
smoke-http1-mlkem:
    just _bench 127.0.0.1:4438 http1 x25519mlkem768 smoke-http1-mlkem.jsonl

[group("smoke")]
smoke-raw-secp256r1:
    just _bench 127.0.0.1:4435 raw secp256r1 smoke-raw-secp256r1.jsonl

[group("smoke")]
smoke-http1-secp256r1:
    just _bench 127.0.0.1:4436 http1 secp256r1 smoke-http1-secp256r1.jsonl

[group("smoke")]
smoke-raw-secp256r1-mlkem:
    just _bench 127.0.0.1:4439 raw secp256r1mlkem768 smoke-raw-secp256r1-mlkem.jsonl

[group("smoke")]
smoke-http1-secp256r1-mlkem:
    just _bench 127.0.0.1:4440 http1 secp256r1mlkem768 smoke-http1-secp256r1-mlkem.jsonl

# Smoke benchmarks - requires multi-server to be running
# Run all smoke benchmarks
[group("smoke")]
smoke-all: smoke-raw-x25519 smoke-http1-x25519 smoke-raw-secp256r1 smoke-http1-secp256r1 smoke-raw-mlkem smoke-http1-mlkem smoke-raw-secp256r1-mlkem smoke-http1-secp256r1-mlkem

# Run all checks (fmt, clippy, docs, test)
[group("dev")]
check: fmt clippy docs test

[group("dev")]
fmt:
    cargo fmt --all

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

[group("dev")]
generate-certs dir="certs" days="365":
    mkdir -p {{ dir }}
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout {{ dir }}/ca.key \
        -out {{ dir }}/ca.pem \
        -subj "/CN=tls-pq-bench CA" \
        -days {{ days }}
    openssl x509 -in {{ dir }}/ca.pem -outform DER -out {{ dir }}/ca.der
    openssl req -new -newkey rsa:2048 -nodes \
        -keyout {{ dir }}/server.key.pem \
        -out {{ dir }}/server.csr \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"
    openssl x509 -req \
        -in {{ dir }}/server.csr \
        -CA {{ dir }}/ca.pem \
        -CAkey {{ dir }}/ca.key \
        -CAcreateserial \
        -out {{ dir }}/server.pem \
        -days {{ days }} \
        -copy_extensions copy
    openssl x509 -in {{ dir }}/server.pem -outform DER -out {{ dir }}/server.der
    openssl pkcs8 -topk8 -inform PEM -outform DER -nocrypt \
        -in {{ dir }}/server.key.pem \
        -out {{ dir }}/server.key

_setup:
    mkdir -p {{ results_dir }} {{ logs_dir }} {{ benchmarks_dir }}

_bench server_addr proto mode server_name="localhost" out="" payload="1024" iters="200" warmup="20" concurrency="1": build
    just _setup
    {{ runner }} \
        --server        {{ server_addr }} \
        --server-name   {{ server_name }} \
        --proto         {{ proto }} \
        --mode          {{ mode }} \
        --payload-bytes {{ payload }} \
        --iters         {{ iters }} \
        --warmup        {{ warmup }} \
        --concurrency   {{ concurrency }} \
        {{ if out != "" { "> " + results_dir + "/" + out } else { "" } }}

_start-server-set recipe_name bind_host log_prefix banner cert="" key="": build
    #!/usr/bin/env bash
    just _setup
    pids=()
    names=()
    logs=()
    specs=(
        "x25519 raw 4433"
        "x25519 http1 4434"
        "secp256r1 raw 4435"
        "secp256r1 http1 4436"
        "x25519mlkem768 raw 4437"
        "x25519mlkem768 http1 4438"
        "secp256r1mlkem768 raw 4439"
        "secp256r1mlkem768 http1 4440"
    )

    cert_args=()
    if [[ "{{ cert }}" != "" || "{{ key }}" != "" ]]; then
        if [[ "{{ cert }}" == "" || "{{ key }}" == "" ]]; then
            echo "{{ recipe_name }} requires both cert and key, or neither" >&2
            exit 1
        fi
        if [[ ! -f "{{ cert }}" ]]; then
            echo "certificate file not found: {{ cert }}" >&2
            exit 1
        fi
        if [[ ! -f "{{ key }}" ]]; then
            echo "private key file not found: {{ key }}" >&2
            exit 1
        fi
        cert_args=(--cert "{{ cert }}" --key "{{ key }}")
    fi

    cleanup() {
        for pid in "${pids[@]}"; do
            kill "$pid" 2>/dev/null || true
        done
        wait || true
    }

    trap cleanup EXIT INT TERM

    echo "{{ banner }}"
    for spec in "${specs[@]}"; do
        read -r mode proto port <<< "$spec"
        name="$mode $proto"
        log="{{ logs_dir }}/{{ log_prefix }}-$mode-$proto.log"
        echo "    $name -> {{ bind_host }}:$port"
        LOG_FORMAT=compact {{ server }} --mode "$mode" --proto "$proto" --listen "{{ bind_host }}:$port" "${cert_args[@]}" > "$log" 2>&1 &
        pids+=($!)
        names+=("$name")
        logs+=("$log")
    done

    sleep 1

    for idx in "${!pids[@]}"; do
        if ! kill -0 "${pids[$idx]}" 2>/dev/null; then
            echo "server exited during startup: ${names[$idx]}" >&2
            wait "${pids[$idx]}" || true
            echo "--- ${logs[$idx]} ---" >&2
            cat "${logs[$idx]}" >&2 || true
            exit 1
        fi
    done

    wait
