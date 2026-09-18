#!/usr/bin/env python3
"""PoC for CWE-78 / Bandit B605 (examples/vulnerable.py: run_command).

Proves shell command injection through run_command's unsanitized use of
os.system: a payload with a shell metacharacter causes a second command
(touch of a marker file) to run alongside the intended "echo".

Usage:
    python poc_b605.py <path-to-module-under-test>

Exit codes:
    0 -> exploit succeeded (module is vulnerable)
    1 -> exploit blocked (module appears patched)
    2 -> could not run the PoC against this module
"""
from __future__ import annotations
import importlib.util
import os
import sys
import tempfile


def _load_module(path: str):
    spec = importlib.util.spec_from_file_location("target_under_test", path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception:
        return None
    return module


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: poc_b605.py <path-to-module-under-test>", file=sys.stderr)
        return 2

    module = _load_module(sys.argv[1])
    if module is None or not hasattr(module, "run_command"):
        print("could not load run_command from the target module", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory() as tmp:
        marker = os.path.join(tmp, "pwned")
        payload = f"hello; touch {marker}"
        try:
            module.run_command(payload)
        except Exception as e:
            print(f"run_command raised {e!r} — treating as blocked", file=sys.stderr)
            return 1

        if os.path.exists(marker):
            print("EXPLOIT SUCCEEDED: shell metacharacters were executed")
            return 0

        print("exploit blocked: no shell command execution detected")
        return 1


if __name__ == "__main__":
    sys.exit(main())
