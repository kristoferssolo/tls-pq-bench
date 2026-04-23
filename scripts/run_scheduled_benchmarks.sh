#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <lite|full>" >&2
    exit 2
fi

profile="$1"
case "${profile}" in
    lite|full) ;;
    *)
        echo "unknown profile: ${profile}" >&2
        exit 2
        ;;
esac

if [[ -n "${SCHEDULE_ENV_FILE:-}" && -f "${SCHEDULE_ENV_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${SCHEDULE_ENV_FILE}"
fi

: "${REPO_DIR:?set REPO_DIR to the repo root}"

RUNNER_BIN="${RUNNER_BIN:-${REPO_DIR}/target/release/runner}"
RESULTS_DIR="${RESULTS_DIR:-${REPO_DIR}/results/scheduled}"
LOG_DIR="${LOG_DIR:-${REPO_DIR}/.logs/scheduled}"
LOCK_DIR="${LOCK_DIR:-${REPO_DIR}/.locks}"
LITE_CONFIG="${LITE_CONFIG:-${REPO_DIR}/benchmarks/remote-recurring.toml}"
FULL_CONFIG="${FULL_CONFIG:-${REPO_DIR}/benchmarks/remote-full.toml}"

case "${profile}" in
    lite) config_path="${LITE_CONFIG}" ;;
    full) config_path="${FULL_CONFIG}" ;;
esac

if [[ ! -x "${RUNNER_BIN}" ]]; then
    echo "runner binary not found or not executable: ${RUNNER_BIN}" >&2
    exit 1
fi

if [[ ! -f "${config_path}" ]]; then
    echo "config file not found: ${config_path}" >&2
    exit 1
fi

mkdir -p "${RESULTS_DIR}" "${LOG_DIR}" "${LOCK_DIR}"

lock_file="${LOCK_DIR}/scheduled-${profile}.lock"
exec 9>"${lock_file}"
if ! flock -n 9; then
    echo "another ${profile} benchmark run is already active; skipping" >&2
    exit 0
fi

cd "${REPO_DIR}"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
result_path="${RESULTS_DIR}/${profile}-${timestamp}.jsonl"
log_path="${LOG_DIR}/${profile}-${timestamp}.log"
meta_path="${RESULTS_DIR}/${profile}-${timestamp}.meta"
runner_git_commit="$(git -C "${REPO_DIR}" rev-parse HEAD 2>/dev/null || echo unknown)"
runner_host="$(hostname)"

set +e
TLS_PQ_BENCH_SCHEDULE_PROFILE="${profile}" \
TLS_PQ_BENCH_CONFIG_PATH="${config_path}" \
TLS_PQ_BENCH_RESULT_PATH="${result_path}" \
TLS_PQ_BENCH_LOG_PATH="${log_path}" \
TLS_PQ_BENCH_RUNNER_GIT_COMMIT="${runner_git_commit}" \
TLS_PQ_BENCH_RUNNER_HOST="${runner_host}" \
TLS_PQ_BENCH_RUNNER_INSTANCE_TYPE="${RUNNER_INSTANCE_TYPE:-}" \
TLS_PQ_BENCH_RUNNER_REGION="${RUNNER_REGION:-}" \
TLS_PQ_BENCH_RUNNER_AZ="${RUNNER_AZ:-}" \
TLS_PQ_BENCH_SERVER_GIT_COMMIT="${SERVER_GIT_COMMIT:-}" \
TLS_PQ_BENCH_SERVER_HOST="${SERVER_HOST:-}" \
TLS_PQ_BENCH_SERVER_INSTANCE_TYPE="${SERVER_INSTANCE_TYPE:-}" \
TLS_PQ_BENCH_SERVER_REGION="${SERVER_REGION:-}" \
TLS_PQ_BENCH_SERVER_AZ="${SERVER_AZ:-}" \
"${RUNNER_BIN}" \
    --config "${config_path}" \
    --out "${result_path}" \
    --run-meta-out "${meta_path}" \
    2>"${log_path}"
status=$?
set -e

exit "${status}"
