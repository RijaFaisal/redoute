from __future__ import annotations
import argparse, sys
from pathlib import Path
from .auditor import Auditor, SEVERITY_ORDER
from .report import render
from .static_scan import run_bandit


def cmd_scan(args):
    path = Path(args.file)
    if not path.is_file():
        print(f"No such file: {path}", file=sys.stderr)
        return 2
    text = path.read_text(encoding="utf-8", errors="replace")
    static_findings = run_bandit(str(path))
    auditor = Auditor()
    print(
        f"Sending {path} to {auditor.model} at {auditor.endpoint} "
        f"({len(static_findings)} static finding(s) to triage) ..."
    )
    try:
        findings = auditor.audit(text, str(path), static_findings)
    except Exception as e:
        print(f"\nCould not complete the scan: {e}", file=sys.stderr)
        print("Is your model server running? Try: ollama serve", file=sys.stderr)
        return 2
    print(render(findings, str(path)))
    worst = max((SEVERITY_ORDER[f.severity] for f in findings), default=-1)
    return 1 if worst >= SEVERITY_ORDER["high"] else 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="redoute", description="Code security auditor")
    sub = parser.add_subparsers(dest="cmd", required=True)
    scan = sub.add_parser("scan", help="Audit a single file")
    scan.add_argument("file", help="Path to the source file to scan")
    scan.set_defaults(fn=cmd_scan)
    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
