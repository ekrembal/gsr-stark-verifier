"""Bottom-anchored addressing, macro compression and script checks with the `gsr` command of gsr-tooling, pinned to
the revision these scripts were measured with.

Install it with

    cargo install --locked --git https://github.com/bitcoin-gsr/gsr-tooling --rev bf31cc4ac70e440e49f9a3695a6fd05f7b2866d4

or set `GSR` to a `gsr` binary. The compressed scripts, and so the covenant and rollup addresses, depend on the
revision.
"""
import json
import os
import shutil
import subprocess

REPOSITORY = "https://github.com/bitcoin-gsr/gsr-tooling"
REVISION = "bf31cc4ac70e440e49f9a3695a6fd05f7b2866d4"


def run(*args: str, script: bytes) -> subprocess.CompletedProcess:
    binary = os.environ.get("GSR") or shutil.which("gsr")
    if not binary:
        raise RuntimeError(f"gsr not found: cargo install --locked --git {REPOSITORY} --rev {REVISION}, or set GSR")
    return subprocess.run([binary, *args], input=script.hex(), capture_output=True, text=True)


def compress(script: bytes, protect: tuple[int, int] = (0, 0)) -> tuple[bytes, dict]:
    """-> (compressed script, summary). `gsr anchor` first rewrites deep main-script reads to address the value from
    the stack bottom, so repeated reads become identical; it chooses how deep (or not at all) by compressing each
    candidate, and it proves that only one witness item count can succeed and refuses otherwise. `gsr compress` then moves repeats into macros; the result
    unrolls to exactly the anchored script and passes `check`. The main-script byte range `protect`, which must start
    at 0 (the rollup leaf's head and prologue), stays literal at its offsets, and the result does not depend on its
    values."""
    assert protect[0] == 0, "a protected range must start the main script"
    anchored, anchor = rewrite("anchor", "--protect", str(protect[1]), script=script)
    code, summary = rewrite("compress", "--protect", str(protect[1]), script=anchored)
    check(code)
    return code, {**summary, "anchor": anchor}


def rewrite(*args: str, script: bytes) -> tuple[bytes, dict]:
    """A `gsr` command that writes a script to stdout and a JSON summary to stderr."""
    p = run(*args, script=script)
    if p.returncode:
        raise RuntimeError(p.stderr.strip())
    return bytes.fromhex(p.stdout.strip()), json.loads(p.stderr)


def check(script: bytes) -> dict:
    """The `gsr check` report (consensus errors, policy warnings and lints, without executing the script); raises if
    it has errors, such as an OP_SUCCESSx, a malformed macro or an unrolled script over the size limit."""
    p = run("check", "--json", script=script)
    try:
        report = json.loads(p.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(p.stderr.strip() or p.stdout.strip()) from None
    if report["errors"]:
        raise RuntimeError("gsr check: " + "; ".join(f"{d['rule']} at byte {d['offset']}: {d['message']}"
                                                     for d in report["diagnostics"] if d["severity"] == "error"))
    return report
