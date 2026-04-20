#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <track|full>" >&2
    exit 2
fi

profile="$1"
case "${profile}" in
    track|full) ;;
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
TRACK_CONFIG="${TRACK_CONFIG:-${REPO_DIR}/benchmarks/remote-recurring.toml}"
FULL_CONFIG="${FULL_CONFIG:-${REPO_DIR}/benchmarks/remote-full.toml}"

case "${profile}" in
    track) config_path="${TRACK_CONFIG}" ;;
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

{
    printf 'profile=%s\n' "${profile}"
    printf 'started_at_utc=%s\n' "$(date -u +%FT%TZ)"
    printf 'config=%s\n' "${config_path}"
    printf 'runner=%s\n' "${RUNNER_BIN}"
    printf 'git_commit=%s\n' "$(git -C "${REPO_DIR}" rev-parse HEAD 2>/dev/null || echo unknown)"
    printf 'host=%s\n' "$(hostname)"
} >"${meta_path}"

set +e
"${RUNNER_BIN}" --config "${config_path}" >"${result_path}" 2>"${log_path}"
status=$?
set -e

{
    printf 'finished_at_utc=%s\n' "$(date -u +%FT%TZ)"
    printf 'status=%s\n' "${status}"
    printf 'result=%s\n' "${result_path}"
    printf 'log=%s\n' "${log_path}"
} >>"${meta_path}"

exit "${status}"
