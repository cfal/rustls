#!/usr/bin/env bash
set -euo pipefail
scripts=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$HOME/tmp"
scratch=$(mktemp -d "$HOME/tmp/rustls-rebase-test.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
git init -q --initial-branch=source "$scratch/repo"
cd "$scratch/repo"
git config user.name 'Rebase test'
git config user.email 'test@example.invalid'
git config commit.gpgsign false
git config core.hooksPath /dev/null
mkdir rustls
printf '[package]\nversion = "0.23.46"\n' > rustls/Cargo.toml
printf 'original\n' > shared
git add .
git commit -qm 'Upstream base'
git branch upstream
printf 'fork\n' > shared
git commit -qam 'Fork patch'
original=$(git rev-parse HEAD)

git switch -q upstream
printf '[package]\nversion = "0.23.47"\n' > rustls/Cargo.toml
printf 'upstream\n' > shared
git commit -qam 'First upstream upgrade'
git switch -q source
if bash "$scripts/rebase.sh" upstream "$scratch/conflict" > "$scratch/conflict.log" 2>&1; then
    printf 'Expected a rebase conflict\n' >&2
    exit 1
fi
grep -q 'git range-diff' "$scratch/conflict.log"
cd "$scratch/conflict"
printf 'resolved fork\n' > shared
git add shared
GIT_EDITOR=true git rebase --continue
[[ $(git merge-base HEAD upstream) == "$(git rev-parse upstream)" ]]

# The next upgrade must replay only the fork patch, even after manual recovery.
git -C "$scratch/repo" switch -q upstream
printf '[package]\nversion = "0.23.48"\n' > "$scratch/repo/rustls/Cargo.toml"
git -C "$scratch/repo" commit -qam 'Second upstream upgrade'
bash "$scripts/rebase.sh" upstream "$scratch/clean"
cd "$scratch/clean"
[[ $(git rev-list --count upstream..HEAD) == 1 ]]
[[ $(git -C "$scratch/repo" rev-parse source) == "$original" ]]
[[ $(cat shared) == 'resolved fork' ]]

printf 'committed trailing whitespace \n' > invalid
git add invalid
git commit -qm 'Invalid conflict resolution'
if bash "$scripts/check.sh" upstream > "$scratch/check.log" 2>&1; then
    printf 'Expected committed whitespace to fail validation\n' >&2
    exit 1
fi
grep -q 'trailing whitespace' "$scratch/check.log"

git -C "$scratch/repo" switch -qc breaking upstream
printf '[package]\nversion = "0.24.0"\n' > "$scratch/repo/rustls/Cargo.toml"
git -C "$scratch/repo" commit -qam 'Breaking upstream upgrade'
if bash "$scripts/rebase.sh" breaking "$scratch/breaking" > "$scratch/breaking.log" 2>&1; then
    printf 'Expected a breaking upgrade to be rejected\n' >&2
    exit 1
fi
grep -q 'Refusing a breaking upgrade' "$scratch/breaking.log"
[[ ! -e "$scratch/breaking" ]]
printf 'Rebase recovery, stable patch count, and committed-diff validation passed.\n'
