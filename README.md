# DIF Defense

**Behavioral prompt-injection detection for bounded agent workflows.**

DIF Defense is an experimental Python prototype that evaluates observable agent behavior after untrusted content enters a workflow. It compares a recorded trace with a frozen Kernel of forbidden actions and returns one of three bounded verdicts:

- `clean`: no recognized Kernel violation appeared in this run
- `warn`: suspicious deviation appeared
- `compromised`: a critical Kernel violation appeared

> Text can be obfuscated in countless ways. Agent behavior is constrained by the tools, state, and outputs that the system exposes.

DIF Defense does not claim to understand hidden model reasoning. It evaluates the output and behavioral signals represented in the trace it actually records.

## Project status

**Working research prototype. Not a complete security boundary.**

The current probe harness:

- sends clean or untrusted content to an OpenAI-compatible LLM endpoint
- records model input and output
- derives simulated tool-use and protected-state signals from deterministic output parsing
- compares those signals with a frozen Kernel
- optionally compares an untrusted run with a known-clean baseline
- emits a structured diff report and containment result

The current `sandbox.py` does not execute arbitrary agent tools. It is not an operating-system, browser, container, or virtual-machine sandbox. Live tool-router interception is a future integration point.

## Pipeline

```text
known-clean content ──────► optional baseline trace
                                      │
untrusted content ─────────► constrained probe run
                                      │
                                      ▼
                              observable trace
                         model output + derived signals
                                      │
                                      ▼
                              Kernel comparison
                         clean | warn | compromised
                                      │
                                      ▼
                            discard or reset state
```

### 1. Kernel

A Kernel defines the bounded behavior expected from the agent:

- `forbidden_tools`
- `permitted_tools`
- `forbidden_output_patterns`
- `forbidden_state_mutations`

The Kernel is created before untrusted content enters the probe.

### 2. Optional baseline

A known-clean sample can be processed first. Its trace becomes a local reference for the same task and Kernel. Baseline comparison helps identify tool or state signals that appear only during the untrusted run.

### 3. Probe execution

The current harness records:

- model call
- model response
- final output
- simulated tool-use signals inferred from response patterns
- simulated protected-state mutation signals inferred from response patterns

This distinction matters. The prototype currently detects expressed or parsed action signals. It does not yet observe a live tool router executing real tools.

### 4. Behavioral diff

The diff engine checks the trace for:

1. forbidden tool signals
2. forbidden output patterns
3. forbidden protected-state mutation signals
4. deviation from an optional clean baseline

Each finding contains a check ID, severity, description, Kernel rule, and bounded evidence excerpt.

### 5. Containment

A `compromised` verdict triggers the configured crumple path.

- **API mode:** the compromised response is treated as disposable state. The current pipeline does not automatically persist and restore a complete message checkpoint.
- **llama.cpp KV mode:** DIF Defense can save a slot cache before the probe and reset the affected slot after compromise. A restore primitive exists in `crumple.py`, but automatic restore is not wired into every path.

The result reports whether the run was crumpled and whether saved state was available.

## Quickstart

### Requirements

- Python 3.10 or newer
- `httpx`
- an OpenAI-compatible chat-completions endpoint
- optionally, a local `llama-server` for KV-cache experiments

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install httpx
```

### Run the included demo

Against an already-running endpoint:

```bash
python demo.py --llm-url http://127.0.0.1:8080/v1
```

Or start the locally configured `llama-server`:

```bash
python demo.py \
  --start-server \
  --model-path /absolute/path/to/model.gguf
```

The demo evaluates:

1. `samples/clean_refund.html`
2. `samples/injected_refund.html`

It writes a combined result to `demo_result.json`.

### Run one comparison

```bash
python main.py \
  --clean samples/clean_refund.html \
  --injected samples/injected_refund.html \
  --task "Summarize the refund policy on this page" \
  --verbose
```

Use the browser-oriented stock Kernel:

```bash
python main.py \
  --kernel browser \
  --injected samples/injected_refund.html \
  --task "Summarize the refund policy on this page" \
  --verbose
```

Write a structured result:

```bash
python main.py \
  --injected samples/injected_refund.html \
  --out result.json
```

Try the llama.cpp KV-cache path:

```bash
python main.py \
  --clean samples/clean_refund.html \
  --injected samples/injected_refund.html \
  --kv-cache \
  --kv-url http://127.0.0.1:8080 \
  --verbose
```

`main.py` exits with code `1` for `compromised` and `0` for `clean` or `warn`.

## Stock Kernels

```python
from kernel import research_summarizer_kernel, safe_browser_kernel

research_kernel = research_summarizer_kernel()
browser_kernel = safe_browser_kernel()
```

Kernel quality determines what DIF Defense can and cannot recognize.

## Result shape

```json
{
  "pipeline_id": "dif_...",
  "kernel_id": "...",
  "baseline_run_id": "baseline_...",
  "trace_run_id": "probe_...",
  "verdict": "clean | warn | compromised",
  "findings_count": 0,
  "checks_run": 4,
  "checks_failed": 0,
  "diff_report": {},
  "crumple": {},
  "agent_output": "..."
}
```

The diff report carries its own claim boundary so downstream consumers do not silently turn a run result into a broader security claim.

## Agent Flight Recorder integration path

DIF Defense currently maintains its trace inside the probe process and returns structured JSON. It is not yet wired directly into [Agent Flight Recorder](https://github.com/cwwjacobs/agent-flight-recorder).

The intended division of responsibility is:

- **DIF Defense:** define the Kernel, run the probe, compare the trace, and issue a bounded verdict
- **Agent Flight Recorder:** preserve observable events, checkpoints, errors, artifacts, outputs, and reproduction receipts

## Repository layout

```text
kernel.py       frozen Kernel definitions and stock Kernels
sandbox.py      LLM probe harness and behavioral trace records
diff_engine.py  Kernel and baseline comparison
crumple.py      API-state and llama.cpp slot containment primitives
main.py         pipeline orchestration and command-line interface
demo.py         clean-versus-injected demonstration
samples/        example HTML inputs
```

## Claim boundary

A `clean` verdict means only that this specific trace did not contain a violation recognized by the selected Kernel and current instrumentation.

It does not prove that:

- the content contains no prompt injection
- another model or prompt would behave the same way
- an unobserved tool or state transition was safe
- the Kernel is complete
- the host, browser, container, or model server is isolated
- the system is certified secure

An injection can be missed when it does not trigger, produces a signal outside the Kernel, or acts through behavior the current probe does not instrument.

## Showcase guide

See [SHOWCASE.md](SHOWCASE.md) for the portfolio description, demo sequence, recording plan, and suggested repository metadata.

## License

This repository is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE). Noncommercial use, modification, and redistribution are permitted; commercial use requires permission. This is not the MIT License.

## Author

Corey Jacobs / Terminus Protocol
