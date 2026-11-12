#!/usr/bin/env python3
"""Check crate ownership, capability-group READMEs and the file-size baseline.

Run from the repository root:

    python3 scripts/check_structure.py
    python3 scripts/check_structure.py --baseline

`--baseline` prints the current violations as JSON; it never writes the file.
Replace `scripts/structure-baseline.json` with that output only when the change
is deliberate. The baseline is a ratchet: a path at or below the cap must be
removed, and an entry above the current count must be lowered.

Test modules do not count toward the cap. Everything from the first
`#[cfg(test)] mod tests` to the end of the file is ignored; integration tests
under `crates/*/tests/` are not checked at all.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CAP = 600

# Every workspace dependency edge, by package name. A new crate or a new edge is
# a deliberate edit to this table, the same place the ownership map lives.
ALLOWED = {
    "orbyn-auth-client": {"orbyn-crypto"},
    "orbyn-cli": {
        "orbyn-core",
        "orbyn-keyservice",
        "orbyn-keyservice-client",
        "orbyn-server",
        "orbyn-store",
        "orbyn-worker",
    },
    "orbyn-client": {
        "orbyn-auth-client",
        "orbyn-contracts",
        "orbyn-crypto",
        "orbyn-planner",
        "orbyn-sync",
        "orbyn-translog",
    },
    "orbyn-contracts": set(),
    "orbyn-core": {"orbyn-auth-client", "orbyn-crypto"},
    "orbyn-crypto": set(),
    "orbyn-device-client": {
        "orbyn-auth-client",
        "orbyn-client",
        "orbyn-contracts",
        "orbyn-crypto",
        "orbyn-engineering",
        "orbyn-sync",
    },
    "orbyn-engineering": {"orbyn-sync"},
    "orbyn-keyservice": {"orbyn-crypto", "orbyn-translog"},
    "orbyn-keyservice-client": set(),
    "orbyn-keyservice-daemon": {
        "orbyn-crypto",
        "orbyn-keyservice",
        "orbyn-keyservice-client",
        "orbyn-keyservice-server",
        "orbyn-translog",
        "orbyn-witness",
    },
    "orbyn-keyservice-server": {"orbyn-translog"},
    "orbyn-planner": {"orbyn-sync"},
    "orbyn-server": {
        "orbyn-contracts",
        "orbyn-core",
        "orbyn-crypto",
        "orbyn-keyservice-client",
        "orbyn-store",
    },
    "orbyn-store": {"orbyn-auth-client", "orbyn-core", "orbyn-crypto"},
    "orbyn-sync": set(),
    "orbyn-translog": set(),
    "orbyn-wasm": {
        "orbyn-auth-client",
        "orbyn-client",
        "orbyn-contracts",
        "orbyn-crypto",
        "orbyn-planner",
        "orbyn-sync",
    },
    "orbyn-witness": {"orbyn-translog"},
    "orbyn-worker": {"orbyn-core", "orbyn-keyservice-client", "orbyn-store"},
}

TEST_MODULE = re.compile(
    r"(?m)^[ \t]*#\[cfg\(test\)\][ \t]*(?:\r?\n[ \t]*)?mod tests\b"
)


def workspace_packages():
    run = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps", "--locked"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if run.returncode != 0:
        print(run.stderr, file=sys.stderr)
        print("cargo metadata failed", file=sys.stderr)
        return None
    return json.loads(run.stdout)["packages"]


def check_edges(packages):
    problems = []
    by_name = {package["name"]: package for package in packages}
    for name in sorted(by_name):
        if name not in ALLOWED:
            problems.append(
                f"{name}: new crate is not in crates/README.md or the structure check"
            )
            continue
        actual = {
            dependency["name"]
            for dependency in by_name[name]["dependencies"]
            if dependency.get("kind") is None and dependency["name"] in ALLOWED
        }
        for dependency in sorted(actual - ALLOWED[name]):
            problems.append(
                f"{name} -> {dependency}: dependency is not allowed by the ownership map"
            )
        for dependency in sorted(ALLOWED[name] - actual):
            problems.append(
                f"{name} -> {dependency}: allowed edge is unused; remove it from ALLOWED"
            )
    for name in sorted(set(ALLOWED) - set(by_name)):
        problems.append(f"{name}: listed in ALLOWED but not in the workspace")
    return problems


def check_readmes():
    problems = []
    crates = sorted(
        path
        for path in (ROOT / "crates").iterdir()
        if path.is_dir() and (path / "Cargo.toml").is_file()
    )
    for crate in crates:
        if not (crate / "README.md").is_file():
            problems.append(f"{crate.relative_to(ROOT)}: crate has no README.md")
    groups = sorted(
        path for path in (ROOT / "crates/orbyn-core/src").iterdir() if path.is_dir()
    )
    for group in groups:
        if not (group / "README.md").is_file():
            problems.append(
                f"{group.relative_to(ROOT)}: capability group has no README.md"
            )
    return problems, len(crates), len(groups)


def source_lines(path):
    text = path.read_text(encoding="utf-8")
    test = TEST_MODULE.search(text)
    if test is not None:
        text = text[: test.start()]
    return len(text.splitlines())


def load_baseline():
    path = ROOT / "scripts/structure-baseline.json"
    if not path.is_file():
        return {}
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return {}
    return json.loads(text)


def check_sizes(baseline):
    problems = []
    over_cap = {}
    files = sorted((ROOT / "crates").glob("*/src/**/*.rs"))
    for path in files:
        lines = source_lines(path)
        relative = path.relative_to(ROOT).as_posix()
        if lines > CAP:
            over_cap[relative] = lines
            if relative not in baseline:
                problems.append(
                    f"{relative}: {lines} lines, over the {CAP}-line cap and not baselined"
                )
            elif lines > baseline[relative]:
                problems.append(
                    f"{relative}: grew from {baseline[relative]} to {lines} lines"
                )
            elif lines < baseline[relative]:
                problems.append(
                    f"{relative}: baseline is stale ({baseline[relative]}); lower it to {lines}"
                )
        elif relative in baseline:
            problems.append(
                f"{relative}: is now {lines} lines; remove its baseline entry"
            )
    for relative in sorted(set(baseline) - set(over_cap)):
        problems.append(
            f"{relative}: baseline entry does not match a source file over the cap"
        )
    return problems, over_cap, len(files)


def main(argv):
    generating = "--baseline" in argv
    baseline = {} if generating else load_baseline()
    size_problems, over_cap, file_count = check_sizes(baseline)
    if generating:
        print(json.dumps(over_cap, indent=2, sort_keys=True))
        return 0

    packages = workspace_packages()
    if packages is None:
        return 2
    edge_problems = check_edges(packages)
    readme_problems, crate_count, group_count = check_readmes()
    problems = edge_problems + readme_problems + size_problems
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return 1
    print(
        f"structure ok: {crate_count} crates, {group_count} capability groups, "
        f"{file_count} source files, {len(over_cap)} baselined"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
