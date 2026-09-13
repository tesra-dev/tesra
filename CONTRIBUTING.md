# Contributing to Tesra

Thanks for helping. Tesra promises that every security claim is backed by a test, so contributions follow a few extra rules.

## Rules

1. **Prove each security control with a test named after its requirement.** Use `v<chapter>_<section>_<requirement>_<what_it_checks>`, for example `v7_2_4_new_session_token_on_login`. List the test on that requirement's row in `security/asvs-matrix.csv`.
2. **Passing tests mark rows verified, never an edit alone.** A row is `verified` only when its listed tests pass. `scripts/asvs_gate.py` enforces this and also rejects ASVS-named tests that aren't in the matrix.
3. **No new cryptography.** Use the crates chosen in `docs/research/`. A new security-relevant dependency needs a note in the research docs explaining why.
4. **Security tests are deterministic.** There are no retries, and a flaky test counts as a failure.
5. **UI components meet the definition of done** in `docs/blueprint.md` §7.2.
6. **Report vulnerabilities privately** as described in [SECURITY.md](SECURITY.md), never in issues or pull requests.

## Setup

You need:

- **Rust.** rustup installs the toolchain pinned in `rust-toolchain.toml` automatically.
- **Node.js 24 or newer.**
- **pnpm.** The version pinned in `package.json` is fetched automatically.
- **Python 3.12 or newer.**
- **cargo-nextest and cargo-deny.**

## The checks CI runs

```sh
# Rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo nextest run --workspace --all-features --locked --profile ci --no-tests=pass
cargo test --doc --workspace --all-features --locked
cargo deny --all-features check

# TypeScript
pnpm install --frozen-lockfile
pnpm run check:ci
pnpm run typecheck

# ASVS gate
python3 -m unittest discover -s scripts/tests
python3 scripts/asvs_gate.py --junit target/nextest/ci/junit.xml
```

`pnpm run format` applies formatting and safe lint fixes.

## License

Your contributions are dual-licensed under MIT OR Apache-2.0, like the rest of the code.
