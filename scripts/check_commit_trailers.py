#!/usr/bin/env python3
"""Fail when a commit message carries an AI attribution trailer.

Commits in this repository carry no AI attribution: no `Co-Authored-By` naming an AI tool and no
"Generated with" line. AI use is disclosed in the pull request's AI usage section instead.

Reads one JSON object per line from stdin or a file: {"sha": "...", "message": "..."}.
Exits 1 and names each offending commit and line.
"""
import json
import re
import sys

AI_NAMES = (
    r"claude|anthropic|openai|chatgpt|\bgpt[-\s\d]|copilot|gemini|codex|cursor|aider|devin|windsurf|"
    r"codeium|tabnine|cody|amazon q|kiro|junie|jules|grok|mistral|llama|deepseek|qwen"
)
CO_AUTHOR = re.compile(rf"^\s*co-authored-by:.*({AI_NAMES})", re.I)
GENERATED = re.compile(r"^\s*(\U0001F916\s*)?generated\s+(with|by)\b", re.I)


def offending_lines(message):
    return [
        line.strip()
        for line in message.splitlines()
        if CO_AUTHOR.search(line) or GENERATED.search(line)
    ]


def check(records):
    problems = []
    for record in records:
        for line in offending_lines(record.get("message") or ""):
            problems.append((record.get("sha", "")[:7], line))
    return problems


def main(argv):
    source = open(argv[1], encoding="utf-8") if len(argv) > 1 else sys.stdin
    records = [json.loads(line) for line in source if line.strip()]
    problems = check(records)
    for sha, line in problems:
        print(f"{sha}: {line}", file=sys.stderr)
    if problems:
        print(
            "Commits here carry no AI attribution. Reword the commit and force-push; "
            "disclose AI use in the pull request's AI usage section.",
            file=sys.stderr,
        )
        return 1
    print(f"commit messages ok: {len(records)} commits")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
