#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="${REPO_DIR:-$(cd -- "${script_dir}/.." && pwd)}"
server_bin="${SERVER_BIN:-${repo_dir}/target/release/server}"
log_dir="${LOG_DIR:-${repo_dir}/.logs}"
bind_host="${BIND_HOST:-127.0.0.1}"
log_prefix="${LOG_PREFIX:-server}"
banner="${BANNER:-Starting benchmark servers:}"
cert="${CERT:-}"
key="${KEY:-}"

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

if [[ ! -x "${server_bin}" ]]; then
    echo "server binary not found or not executable: ${server_bin}" >&2
    exit 1
fi

cert_args=()
if [[ -n "${cert}" || -n "${key}" ]]; then
    if [[ -z "${cert}" || -z "${key}" ]]; then
        echo "server set requires both CERT and KEY, or neither" >&2
        exit 1
    fi
    if [[ ! -f "${cert}" ]]; then
        echo "certificate file not found: ${cert}" >&2
        exit 1
    fi
    if [[ ! -f "${key}" ]]; then
        echo "private key file not found: ${key}" >&2
        exit 1
    fi
    cert_args=(--cert "${cert}" --key "${key}")
fi

mkdir -p "${log_dir}"

pids=()
names=()
logs=()

cleanup() {
    for pid in "${pids[@]}"; do
        kill "${pid}" 2>/dev/null || true
    done
    wait || true
}

trap cleanup EXIT INT TERM

echo "${banner}"
for spec in "${specs[@]}"; do
    read -r mode proto port <<<"${spec}"
    name="${mode} ${proto}"
    log="${log_dir}/${log_prefix}-${mode}-${proto}.log"
    echo "    ${name} -> ${bind_host}:${port}"
    LOG_FORMAT=compact "${server_bin}" \
        --mode "${mode}" \
        --proto "${proto}" \
        --listen "${bind_host}:${port}" \
        "${cert_args[@]}" >"${log}" 2>&1 &
    pids+=($!)
    names+=("${name}")
    logs+=("${log}")
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
