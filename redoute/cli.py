from __future__ import annotations
import argparse, sys
from pathlib import Path
from .auditor import Auditor, SEVERITY_ORDER
from .report import render
from .static_scan import run_bandit
from .patcher import Patcher
from .validator import validate_patch


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


def _print_gates(result) -> None:
    for gate in result.gates:
        print(f"      Gate [{gate.name:<7}] {gate.status.upper():<8} {gate.reason}")


def _demo_bad_patch(path: Path, original_text: str) -> int:
    print(f"\n[--demo-bad-patch] Validating a deliberately broken patch for {path} ...\n")
    static_findings = run_bandit(str(path))
    target = next((f for f in static_findings if f.test_id == "B605"), None) \
        or next((f for f in static_findings if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER["high"]), None)
    if target is None:
        print("No high/critical static finding available to demo against.", file=sys.stderr)
        return 2

    print(f"Target finding: {target.title}")
    print(f"  line {target.line}, {target.severity}, {target.test_id or 'no test id'}, {target.cwe or 'no CWE'}\n")

    # A deliberately broken "patch": it claims to fix the issue but never
    # touches the vulnerable line, so validation must reject it.
    bad_patch_text = original_text.replace(
        "def run_command(user_input):",
        'def run_command(user_input):\n    # "sanitized" input (does nothing)',
    )
    print("Patch proposed: YES (synthetic — deliberately does not fix the vulnerability)")

    result = validate_patch(original_text, bad_patch_text, str(path), target)
    _print_gates(result)

    if result.accepted:
        print("\nUNEXPECTED: the broken patch was accepted.", file=sys.stderr)
        return 1
    print("\nREJECTED as expected: validation caught the broken patch before it could be written.")
    return 1


def cmd_patch(args):
    path = Path(args.file)
    if not path.is_file():
        print(f"No such file: {path}", file=sys.stderr)
        return 2
    original_text = path.read_text(encoding="utf-8", errors="replace")

    if args.demo_bad_patch:
        return _demo_bad_patch(path, original_text)

    static_findings = run_bandit(str(path))
    auditor = Auditor()
    print(
        f"Sending {path} to {auditor.model} at {auditor.endpoint} "
        f"({len(static_findings)} static finding(s) to triage) ..."
    )
    try:
        findings = auditor.audit(original_text, str(path), static_findings)
    except Exception as e:
        print(f"\nCould not complete the scan: {e}", file=sys.stderr)
        print("Is your model server running? Try: ollama serve", file=sys.stderr)
        return 2

    print(render(findings, str(path)))

    high_crit = [f for f in findings if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER["high"]]
    if not high_crit:
        print("\nNo high/critical findings — nothing to patch.")
        return 0

    high_crit.sort(key=lambda f: SEVERITY_ORDER[f.severity], reverse=True)
    patcher = Patcher(auditor)
    patches_dir = path.parent / "patches"
    all_accepted = True

    for i, finding in enumerate(high_crit, 1):
        print(f"\n--- Finding {i}/{len(high_crit)}: {finding.title} ---")
        print(f"    line {finding.line}, {finding.severity}, {finding.cwe or 'no CWE'}, "
              f"{finding.test_id or 'no test id'}, source: {finding.source}")

        try:
            patch = patcher.propose(original_text, str(path), finding)
        except Exception as e:
            print(f"    Patch proposed: NO (LLM call failed: {e})")
            all_accepted = False
            continue

        if patch is None:
            print("    Patch proposed: NO (model declined or returned an unusable response)")
            all_accepted = False
            continue

        print("    Patch proposed: YES")
        print(f"    Rationale: {patch.rationale}")

        result = validate_patch(original_text, patch.patched_file, str(path), finding)
        _print_gates(result)

        if result.accepted:
            patches_dir.mkdir(exist_ok=True)
            out_path = patches_dir / f"{path.name}.finding{i}.patched"
            out_path.write_text(patch.patched_file, encoding="utf-8")
            print(f"    ACCEPTED — written to {out_path} (original file untouched)")
        else:
            print("    REJECTED — patch not written")
            all_accepted = False

    return 0 if all_accepted else 1


def main(argv=None):
    parser = argparse.ArgumentParser(prog="redoute", description="Code security auditor")
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="Audit a single file")
    scan.add_argument("file", help="Path to the source file to scan")
    scan.set_defaults(fn=cmd_scan)

    patch = sub.add_parser("patch", help="Propose and validate fixes for high/critical findings")
    patch.add_argument("file", help="Path to the source file to patch")
    patch.add_argument(
        "--demo-bad-patch", action="store_true",
        help="Skip the LLM and validate a deliberately broken patch, to demonstrate rejection",
    )
    patch.set_defaults(fn=cmd_patch)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
