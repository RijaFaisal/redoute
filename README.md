# redoute

A local code security auditor that pairs deterministic static analysis with an LLM triage-and-patch layer — and never trusts either one without proof.

## The problem

AI coding assistants now write a large share of production code, and none of it becomes safer just because it runs. Security research is fairly consistent on the numbers:

- Nearly half of AI-generated code fails security testing, and a meaningful share of it reaches production before anyone reviews it for vulnerabilities.
- When automated code-repair is evaluated by execution — actually running the patched code and checking whether the vulnerability is closed, rather than judging the diff by eye — the best-performing model in one such evaluation fixed only about 23% of vulnerabilities.
- Automated vulnerability-repair systems have shown false discovery rates above 40% in industry testing: nearly half of what gets reported as "fixed" isn't.
- There's a second, structural problem underneath the first: an LLM-based auditor that reads source code to find vulnerabilities is itself reading untrusted input. Code under audit can contain text crafted to look like instructions to the model — the auditor is a prompt-injection surface by construction, not by accident.

Put those together and the naive pipeline — LLM scans the code, LLM writes a patch, the patch auto-merges — is worse than doing nothing. It runs a system that's wrong most of the time, in a domain where "wrong" and "right" look identical until something is exploited.

## Design

The core principle: **the LLM is a triage-and-explanation layer inside a system whose trust comes from deterministic tools and execution, not the model's confidence.** Nothing the model says is believed on its own; it's checked.

That principle drives three concrete decisions:

1. **Hybrid detection.** Bandit — a deterministic static analyzer — runs first and finds what it reliably finds. The LLM's job is triage, not discovery-from-scratch: confirm or dismiss each static finding with a reason, add anything the static pass plausibly missed, and write the plain-language threat vector and exploitation explanation. If the model's response is malformed, the static findings are what survive (see "How it works").
2. **Exploit-based validation.** A proposed patch is never accepted because it *looks* right. It goes through three gates: a Bandit re-scan (the original finding must be gone, and no new high/critical finding may appear), the original proof-of-concept exploit (it must now fail to exploit the patched code), and the project's test suite (it must still pass). A patch is accepted only if every applicable gate passes — checked by re-running the tools, not by re-asking the model.
3. **No auto-merge.** Even an accepted patch is written to a separate file (`patches/<file>.finding<N>.patched`), never applied in place and never committed. A human decides whether to merge it. The system's job is to do the checking that makes that decision cheap, not to make the decision.

**Prompt-injection defense.** Every prompt sent to the model — for triage and for patching — explicitly states that the file contents and any tool output being shown to it are untrusted data, not instructions, and that text inside them which looks like an instruction should be treated as something to report on, never something to obey.

## How it works

```
ingest file
    │
    ▼
static scan (Bandit)            deterministic, always runs
    │
    ▼
LLM triage                      confirm / dismiss / add findings
    │                           + merge & de-duplicate
    ▼
[scan] report + exit code       0 clean, 1 high/critical, 2 error
    │
    ▼  (patch command, high/critical findings only)
patch proposal (LLM)            minimal, behavior-preserving fix
    │
    ▼
three-gate validation           A: Bandit re-scan
                                 B: PoC exploit (if one exists)
                                 C: test suite (if one exists)
    │
    ▼
accept → patches/*.patched      reject → reported with the failing gate(s)
```

The system is built to degrade gracefully rather than fail loudly. If the LLM returns something that isn't parseable JSON at the triage step, the deterministic Bandit findings are kept as-is instead of being dropped — a malformed model response can't make the scan report *less* than static analysis alone found. At the patch step, the same failure mode returns "no patch proposed" rather than fabricating one. Small local models hit this path often; it's treated as the expected safe outcome, not an error to work around.

## Usage

### Setup

redoute needs a local [Ollama](https://ollama.com) model for the LLM triage/patch steps (the `scan --static-only` and Bandit-only paths work without one):

```bash
ollama pull qwen2.5-coder:7b
ollama serve   # if it isn't already running
```

### Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

This installs `requests`, `bandit`, and `pytest`, and exposes a `redoute` console command.

### Commands

```bash
# Full hybrid scan: Bandit + LLM triage, merged and de-duplicated
redoute scan examples/vulnerable.py

# Static-only scan: Bandit findings alone, no LLM call (what CI runs)
redoute scan --static-only examples/vulnerable.py

# Propose and validate patches for every high/critical finding
redoute patch examples/vulnerable.py

# Demonstrate the validator rejecting a broken patch (no LLM call needed)
redoute patch examples/vulnerable.py --demo-bad-patch
```

Exit codes are consistent across both commands: `0` nothing high/critical (or, for `patch`, every high/critical finding got an accepted patch), `1` a high/critical finding remains — unfixed, unpatched, or its patch was rejected, `2` couldn't run at all (missing file, unreachable model).

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `REDOUTE_LLM_MODEL` | `qwen2.5-coder:7b` | Which Ollama model to call |
| `REDOUTE_LLM_ENDPOINT` | `http://localhost:11434/v1/chat/completions` | OpenAI-compatible chat endpoint |
| `REDOUTE_LLM_API_KEY` | `not-needed` | Sent as a bearer token; irrelevant for local Ollama |

## Limitations

- Detection quality is bounded by two things: the static ruleset (currently Bandit, which is Python-only and pattern-based) and whichever LLM is doing triage. This is not comprehensive vulnerability coverage.
- Small local models frequently decline to propose a patch, or return output that fails JSON parsing before validation ever runs. That's the intended safe failure mode, not a bug — but it means smaller models produce few accepted patches in practice. Bigger models do better; none are trusted blindly.
- This is a proof-of-concept / portfolio project, not a production security tool. It hasn't been hardened, audited, or run at scale.
- Use it alongside established, maintained scanners (Semgrep, CodeQL, Bandit's full ruleset, etc.), not instead of them.

## License

MIT — see [LICENSE](LICENSE).
