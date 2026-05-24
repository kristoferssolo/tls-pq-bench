#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: scripts/sync_results_to_lfs.sh <archive-repo-path>" >&2
}

require_command() {
    local command_name="$1"

    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "missing required command: $command_name" >&2
        exit 1
    fi
}

repo_root() {
    local script_dir

    script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
    cd -- "$script_dir/.." && pwd
}

ensure_clean_archive_repo() {
    local archive_repo="$1"

    if [[ -n "$(git -C "$archive_repo" status --porcelain=v1 --untracked-files=normal)" ]]; then
        echo "archive repo has pending changes: $archive_repo" >&2
        exit 1
    fi
}

sync_tree() {
    local source_repo="$1"
    local archive_repo="$2"
    local kind="$3"
    local -n added_ref="$4"
    local -n skipped_ref="$5"
    local source_dir="$source_repo/results/$kind"
    local dest_dir="$archive_repo/results/$kind"
    local source_file relative_path dest_file tmp_file

    while IFS= read -r -d '' source_file; do
        relative_path="${source_file#"$source_dir"/}"
        dest_file="$dest_dir/$relative_path.gz"
        tmp_file="$dest_file.tmp"

        if [[ -e "$dest_file" ]]; then
            if gzip -cd -- "$dest_file" | cmp -s - "$source_file"; then
                ((skipped_ref += 1))
                continue
            fi

            echo "conflict: existing archive differs from source: $dest_file" >&2
            echo "source timestamped result files are immutable; refusing to overwrite" >&2
            exit 1
        fi

        if [[ -e "$tmp_file" ]]; then
            echo "conflict: temporary destination already exists: $tmp_file" >&2
            exit 1
        fi

        mkdir -p -- "$(dirname -- "$dest_file")"
        gzip -c -- "$source_file" >"$tmp_file"
        mv -- "$tmp_file" "$dest_file"
        git -C "$archive_repo" add -- "$dest_file"
        ((added_ref += 1))
    done < <(find "$source_dir" -type f \( -name '*.jsonl' -o -name '*.meta' \) -print0 | sort -z)
}

main() {
    if [[ "$#" -ne 1 ]]; then
        usage
        exit 2
    fi

    require_command git
    require_command git-lfs
    require_command gzip
    require_command cmp
    require_command find
    require_command sort

    local source_repo archive_repo source_dir added skipped

    source_repo="$(repo_root)"
    archive_repo="$(cd -- "$1" 2>/dev/null && pwd || true)"

    if [[ -z "$archive_repo" ]] || ! git -C "$archive_repo" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        echo "archive path is not a Git repository: $1" >&2
        exit 1
    fi

    if ! git -C "$archive_repo" lfs env >/dev/null 2>&1; then
        echo "Git LFS is not installed or initialized in archive repo: $archive_repo" >&2
        exit 1
    fi

    ensure_clean_archive_repo "$archive_repo"

    for source_dir in "$source_repo/results/full" "$source_repo/results/reduced"; do
        if [[ ! -d "$source_dir" ]]; then
            echo "source results directory is missing: $source_dir" >&2
            exit 1
        fi
    done

    added=0
    skipped=0

    sync_tree "$source_repo" "$archive_repo" full added skipped
    sync_tree "$source_repo" "$archive_repo" reduced added skipped

    echo "files added: $added"
    echo "files skipped: $skipped"
    echo "archive repo: $archive_repo"
    echo "suggested commit:"
    echo "  git -C \"$archive_repo\" commit -m \"chore: archive benchmark runs\""
}

main "$@"
