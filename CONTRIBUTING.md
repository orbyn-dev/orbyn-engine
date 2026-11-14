# Contributing

## Titles

Pull request and issue titles use the Conventional Commits form `type(scope): summary`.

- Kinds: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`, `style` or `revert`. An issue may also use `question`.
- The scope is optional and lowercase. `!` before the colon marks a breaking change.
- The summary is a short imperative phrase with a lowercase first letter and no full stop. The whole title is at most 72 characters.
- A title never credits a tool or an assistant.

The [Title](.github/workflows/pr-title.yml) check enforces this.

## Branches and commits

- Branch from `main`: `feat/`, `fix/`, `docs/`, `chore/` or `refactor/` plus a purpose name.
- Write Conventional Commits subjects.
- No agent or tool attribution in commits or branch names. Record AI use in the pull request's AI usage section.

## Checks

```bash
python3 scripts/check_structure.py
cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

Tests that need Postgres read `DATABASE_URL`. `docker compose up -d postgres` starts one locally.

## Local runners

Three cheap Linux jobs (`changes`, `Cheap checks`, `Security audit`) can run on the organisation's self-hosted runners (group `orbyn-local`, labels `self-hosted, orbyn-local`). They do so only when the repository variable `CI_RUNNER` is `local`; unset, everything runs on GitHub-hosted runners as before. A pull request from a fork always runs hosted, whatever the variable says. The Rust lane (Postgres and SoftHSM service containers), the Docker image, macOS and Windows, and the title, AI usage, commit trailer and CLA workflows stay hosted.

To turn it on, set `CI_RUNNER=local` (Settings, Secrets and variables, Actions, Variables), **only after** the repository is private or the runner group allows this repository. The group currently excludes public repositories, so with the variable set a job would wait forever for a runner. Unset the variable to go back.

The runner image has git and Python 3.12 but no C compiler or `make`, no Rust and no `sudo`; the moved jobs install what they need without root (`dtolnay/rust-toolchain`, a prebuilt `cargo-audit`). A job that compiles C code must stay hosted.

## Structure

- One crate, one role: [crates/README.md](crates/README.md) lists them and the allowed dependency direction.
- One capability per folder under `crates/orbyn-core/src`; each group has a README and a row in [orbyn-core/README.md](crates/orbyn-core/README.md#groups).
- Transport validates, calls one owner operation and maps the result. It holds no product rule.
- Non-test source past 600 lines becomes a folder; [structure-baseline.json](scripts/structure-baseline.json) may only shrink.
- A pure move is its own commit and goes in [.git-blame-ignore-revs](.git-blame-ignore-revs). A move that also edits an import is not pure.

## Pull requests

- Fill in the template. Say what you verified and what you did not.
- Keep it short: bullets, under about 150 words outside AI usage.
- Merge with a merge commit once every required check is green.

## AI usage

Every pull request says how it was made. Tick "Written by hand", or give the harness and its version, every model by exact ID and what it did, the effort level, what a person decided, and every outside source. The [AI usage](.github/workflows/pr-ai-usage.yml) check fails while the section is empty. Dependabot is exempt.

## Dependencies

Dependabot opens weekly grouped minor and patch updates. Major versions are planned work in their own pull request. Pin GitHub Actions to a full commit SHA with the version in a comment.
