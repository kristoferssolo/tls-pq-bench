export RUSTC_WRAPPER :=  env("RUSTC_WRAPPER", "sccache")
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
    just _start-server-set 127.0.0.1 server "Starting benchmark servers:" "{{ cert }}" "{{ key }}"

# Start the full production listener set on one server host. This covers all four key exchange variants, each exposed over raw and http1: 4433/4434 x25519, 4435/4436 secp256r1, 4437/4438 x25519mlkem768, 4439/4440 secp256r1mlkem768.
[group("prod")]
prod-server bind_host="0.0.0.0" cert="" key="":
    just _start-server-set "{{ bind_host }}" prod-server "Starting production benchmark servers on {{ bind_host }}:" "{{ cert }}" "{{ key }}"

# Install and enable the server-side systemd service on the benchmark server host.
[group("prod")]
prod-server-service env_file="/etc/tls-pq-bench/server.env": build
    #!/usr/bin/env bash
    if [[ ! -f "{{ env_file }}" ]]; then
        echo "server env file not found: {{ env_file }}" >&2
        exit 1
    fi

    sudo install -d -m 0755 /etc/tls-pq-bench
    sudo install -m 0644 "{{ env_file }}" /etc/tls-pq-bench/server.env
    sudo install -m 0644 ops/systemd/tls-pq-bench-server.service /etc/systemd/system/tls-pq-bench-server.service
    sudo systemctl daemon-reload
    sudo systemctl enable --now tls-pq-bench-server.service

# Generate the scheduled remote benchmark configs and install/enable the systemd timers on the runner box. Expects an env file compatible with ops/scheduled-benchmarks.env.example.
[group("prod")]
prod-schedule env_file="/etc/tls-pq-bench/scheduled.env": build
    #!/usr/bin/env bash
    if [[ ! -f "{{ env_file }}" ]]; then
        echo "schedule env file not found: {{ env_file }}" >&2
        exit 1
    fi

    # shellcheck disable=SC1090
    source "{{ env_file }}"
    : "${SERVER_HOST:?set SERVER_HOST to the remote benchmark server IP or hostname}"
    : "${SERVER_NAME:?set SERVER_NAME to the TLS DNS name or IP to verify}"

    CA_CERT="${CA_CERT:-certs/ca.der}"
    TRACK_CONFIG="${TRACK_CONFIG:-$PWD/benchmarks/remote-recurring.toml}"
    FULL_CONFIG="${FULL_CONFIG:-$PWD/benchmarks/remote-full.toml}"
    TRACK_ITERS="${TRACK_ITERS:-200}"
    TRACK_WARMUP="${TRACK_WARMUP:-20}"
    FULL_ITERS="${FULL_ITERS:-200}"
    FULL_WARMUP="${FULL_WARMUP:-20}"

    uv run --script scripts/generate_benchmark_matrix.py \
        --profile recurring \
        --host "${SERVER_HOST}" \
        --server-name "${SERVER_NAME}" \
        --ca-cert "${CA_CERT}" \
        --iters "${TRACK_ITERS}" \
        --warmup "${TRACK_WARMUP}" \
        --output "${TRACK_CONFIG}"

    uv run --script scripts/generate_benchmark_matrix.py \
        --profile full \
        --host "${SERVER_HOST}" \
        --server-name "${SERVER_NAME}" \
        --ca-cert "${CA_CERT}" \
        --iters "${FULL_ITERS}" \
        --warmup "${FULL_WARMUP}" \
        --output "${FULL_CONFIG}"

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
generate-certs dir="certs" days="365" server_name="localhost" server_ip="":
    #!/usr/bin/env bash
    mkdir -p {{ dir }}

    cn="{{ server_name }}"
    if [[ -z "$cn" && -n "{{ server_ip }}" ]]; then
        cn="{{ server_ip }}"
    fi
    if [[ -z "$cn" ]]; then
        echo "generate-certs requires server_name or server_ip" >&2
        exit 1
    fi

    san_entries=("DNS:localhost" "IP:127.0.0.1" "IP:::1")
    if [[ "{{ server_name }}" != "" && "{{ server_name }}" != "localhost" ]]; then
        san_entries+=("DNS:{{ server_name }}")
    fi
    if [[ "{{ server_ip }}" != "" && "{{ server_ip }}" != "127.0.0.1" && "{{ server_ip }}" != "::1" ]]; then
        san_entries+=("IP:{{ server_ip }}")
    fi
    san_csv="$(IFS=,; printf '%s' "${san_entries[*]}")"

    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout {{ dir }}/ca.key \
        -out {{ dir }}/ca.pem \
        -subj "/CN=tls-pq-bench CA" \
        -days {{ days }}
    openssl x509 -in {{ dir }}/ca.pem -outform DER -out {{ dir }}/ca.der
    openssl req -new -newkey rsa:2048 -nodes \
        -keyout {{ dir }}/server.key.pem \
        -out {{ dir }}/server.csr \
        -subj "/CN=${cn}" \
        -addext "subjectAltName=${san_csv}"
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

_start-server-set bind_host log_prefix banner cert="" key="": build
    REPO_DIR="$PWD" LOG_DIR="$PWD/{{ logs_dir }}" BIND_HOST="{{ bind_host }}" LOG_PREFIX="{{ log_prefix }}" BANNER="{{ banner }}" CERT="{{ cert }}" KEY="{{ key }}" ./scripts/run_server_set.sh
