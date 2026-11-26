"""Print only Terraform's diagnostic blocks from a private log, with values redacted.

The full plan/apply logs stay in mode-restricted runner storage and are deleted.
This prints just enough to diagnose a failure in the public Actions log:
each "Error:" block (summary, resource address, file and line, detail),
capped in length, with key material, emails, tokens and long opaque strings removed.
GitHub also masks registered secret values on top of this.
"""
import re
import sys

MAX_LINES = 120
MAX_LINE_CHARS = 400

REDACTIONS = [
    (re.compile(r"ssh-(rsa|ed25519|dss)\s+[A-Za-z0-9+/=]+"), "ssh-<key redacted>"),
    (re.compile(r"-----BEGIN [A-Z ]+-----.*?(-----END [A-Z ]+-----|$)", re.S), "<pem redacted>"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "<email redacted>"),
    (re.compile(r"(?i)(bearer|token|password|secret|sig|signature|key)(\"?\s*[:=]\s*\"?)[^\s\",&]+"), r"\1\2<redacted>"),
    (re.compile(r"(?i)mongodb(\+srv)?://[^\s\"]+"), "mongodb://<redacted>"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*"), "<jwt redacted>"),
    (re.compile(r"[A-Za-z0-9+/_-]{60,}={0,2}"), "<long value redacted>"),
]

BLOCK_START = re.compile(r"^(?:│ )?Error: ")
OTHER_START = re.compile(r"^(?:│ )?(?:Warning: |Plan: |Apply complete|No changes)")


def redact(line: str) -> str:
    for pattern, replacement in REDACTIONS:
        line = pattern.sub(replacement, line)
    if len(line) > MAX_LINE_CHARS:
        line = line[:MAX_LINE_CHARS] + " <truncated>"
    return line


def excerpt(text: str) -> list[str]:
    out, inside = [], False
    for raw in text.splitlines():
        line = raw.rstrip()
        if BLOCK_START.match(line):
            inside = True
            if out:
                out.append("")
        elif inside and OTHER_START.match(line):
            inside = False
        if inside:
            out.append(redact(line))
    while out and not out[-1].strip():
        out.pop()
    if len(out) > MAX_LINES:
        out = out[:MAX_LINES] + [f"<{len(out) - MAX_LINES} more lines omitted>"]
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: error_excerpt.py LOG", file=sys.stderr)
        return 2
    try:
        with open(argv[1], encoding="utf-8", errors="replace") as handle:
            lines = excerpt(handle.read())
    except OSError:
        print("No diagnostic log was written.", file=sys.stderr)
        return 0
    if not lines:
        print("Terraform reported no Error block. Rerun the plan locally to diagnose.", file=sys.stderr)
        return 0
    print("::group::Terraform error (redacted)", file=sys.stderr)
    for line in lines:
        print(line, file=sys.stderr)
    print("::endgroup::", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
