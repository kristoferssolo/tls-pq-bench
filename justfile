# Default recipe
default:
    @just --list

# Run all checks (fmt, clippy, docs, test)
check: fmt clippy docs test

alias f := fmt
# Format code
fmt:
    cargo fmt --all

# Check formatting without modifying
fmt-check:
    cargo fmt --all -- --check

# Run clippy
clippy:
    cargo clippy --all-targets --all-features -- -D warnings

alias d := docs
# Build documentation
docs:
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features

alias t := test
# Run tests with nextest
test:
    cargo nextest run --all-features
    cargo test --doc

alias b := build
# Build release binaries
build:
    cargo build --release

# Run server (default: x25519 on localhost:4433)
server mode="x25519" listen="127.0.0.1:4433":
    cargo run --release --bin server -- --mode {{mode}} --listen {{listen}}

# Run benchmark runner
runner server mode="x25519" payload="1024" iters="100" warmup="10":
    cargo run --release --bin runner -- \
        --server {{server}} \
        --mode {{mode}} \
        --payload-bytes {{payload}} \
        --iters {{iters}} \
        --warmup {{warmup}}

alias c := clean
# Clean build artifacts
clean:
    cargo clean

# Install dev dependencies
setup:
    cargo install cargo-nextest
