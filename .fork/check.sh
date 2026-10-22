#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export CARGO_INCREMENTAL=0
cargo fmt --all --check
cargo test --locked -p rustls --lib --test api --test unbuffered --test reality
cargo test --locked -p rustls --no-default-features --features std,ring,tls12 --lib --test api --test unbuffered
cargo check --locked -p rustls --no-default-features --features hashbrown,aws_lc_rs
cargo check --locked -p rustls --no-default-features --features hashbrown,ring
git diff --check
