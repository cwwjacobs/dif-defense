# DIF Defense

**Behavioral prompt-injection detection for bounded agent workflows.**

DIF Defense is an experimental Python prototype that evaluates what an agent
*does* after it receives untrusted content. It compares an observable trace
against a frozen Kernel of forbidden actions and returns one of three verdicts:

- `clean` — no Kernel violation was detected in this run
- `warn` — suspicious deviation was detected
- `compromised` — a critical Kernel violation was detected

The central idea is simple:

> Text can be obfuscated in countless ways. Agent behavior is constrained by the
> tools, state, and outputs that the system exposes.

DIF Defense does not claim to understand hidden model reasoning. It evaluates
observable output and the behavioral signals represented in its trace.

## Project status

This repository is a working research prototype, not a complete security
boundary.

The current probe harness:

- sends clean or untrusted content to an OpenAI-compatible LLM endpoint
- records model input and output
- derives simulated tool-use and state-change events from deterministic output
  parsing
- compares those events with a frozen Kernel
- optionally compares the untrusted run with a known-clean baseline
- emits a structured diff report and containment result

The current `sandbox.py` does **not** execute arbitrary agent tools and is not an
operating-system, container, browser, or virtual-machine sandbox. Structured
runtime tool interception is a future integration point.

## Pipeline

```text
Known-clean content ──────► optional baseline trace
                                   │
                                   ▼
Untrusted content ────────► constrained probe run
                                   │
                                   ▼
                         observable trace
                    model call / output / derived
                       tool and state signals
                                   │
                                   ▼
                        diff against Kernel
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
                  clean           warn       compromised
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

### 2. Baseline

A known-clean sample can be processed first. Its trace becomes a local reference
for the same task and Kernel.

Baseline comparison is optional. It is useful for identifying new tool or state
signals that appear only during the untrusted run.

### 3. Probe execution

The current harness sends the task and untrusted content to an OpenAI-compatible
chat-completions endpoint. It records:

- the model call
- the model response
- the final output
- simulated tool-use signals inferred from response patterns
- simulated protected-state mutation signals inferred from response patterns

This distinction matters: the prototype currently detects expressed or parsed
action signals. It does not yet observe a live tool router executing real tools.

### 4. Behavioral diff

The diff engine checks the trace for:

1. forbidden tool signals
2. forbidden output patterns
3. forbidden protected-state mutation signals
4. deviation from an optional clean baseline

Each finding contains a check ID, severity, description, Kernel rule, and bounded
evidence excerpt.

### 5. Containment

A `compromised` verdict triggers the configured crumple path.

- **API mode:** the compromised response is treated as disposable state. The
  current pipeline does not automatically persist and restore a complete message
  checkpoint.
- **llama.cpp KV mode:** DIF Defense can save a slot cache before the probe and
  reset the affected slot after compromise. A restore primitive exists in
  `crumple.py`, but automatic restore is not yet wired into every pipeline path.

The containment result reports whether the run was crumpled and whether saved
state was available.

## Quickstart

### Requirements

- Python 3.10 or newer
- `httpx`
- an OpenAI-compatible chat-completions endpoint
- optionally, a local `llama-server` for KV-cache experiments

Create an environment and install the current dependency:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install httpx
```

### Run the included demo

Use an already-running endpoint:

```bash
python demo.py --llm-url http://127.0.0.1:8080/v1
```

Or ask the demo launcher to start the locally configured `llama-server`:

```bash
python demo.py \
  --start-server \
  --model-path /absolute/path/to/model.gguf
```

The demo evaluates:

1. `samples/clean_refund.html`
2. `samples/injected_refund.html`

It writes a combined result to `demo_result.json`.

### Run a single comparison

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

Write the structured result to disk:

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

`main.py` exits with code `1` for a `compromised` verdict and `0` for `clean` or
`warn`.

## Stock Kernels

Two example Kernels are included:

```python
from kernel import research_summarizer_kernel, safe_browser_kernel

research_kernel = research_summarizer_kernel()
browser_kernel = safe_browser_kernel()
```

Create a custom Kernel by defining the forbidden and permitted behavioral
surface for the agent being tested. Kernel quality determines what DIF Defense
can and cannot detect.

## Result shape

A pipeline result includes:

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

The diff report also carries its own claim boundary so downstream consumers do
not silently turn a run result into a broader security claim.

## Agent Flight Recorder

DIF Defense currently maintains its trace inside the probe process and returns a
structured JSON result. It is not yet wired directly into
[Agent Flight Recorder](https://github.com/cwwjacobs/agent-flight-recorder).

The planned division of responsibility is:

- **DIF Defense:** define the Kernel, run the probe, compare the trace, and issue
  the bounded verdict
- **Agent Flight Recorder:** preserve observable events, checkpoints, errors,
  artifacts, outputs, and reproduction receipts

That integration would make a DIF run easier to inspect, replay at the event
level, compare before and after a repair, and package for maintainer review.
Agent Flight Recorder is an evidence layer; it is not the detector and does not
expose hidden reasoning.

## Repository layout

```text
kernel.py       Frozen Kernel definitions and stock Kernels
sandbox.py      LLM probe harness and behavioral trace records
diff_engine.py  Kernel and baseline comparison
crumple.py      API-state and llama.cpp slot containment primitives
main.py         Pipeline orchestration and command-line interface
demo.py         Clean-versus-injected demonstration
samples/        Example HTML inputs
```

## Claim boundary

A `clean` verdict means only that this specific trace did not contain a violation
recognized by the selected Kernel and current instrumentation.

It does **not** prove that:

- the content contains no prompt injection
- another model or prompt would behave the same way
- an unobserved tool or state transition was safe
- the Kernel is complete
- the host, browser, container, or model server is isolated
- the system is certified secure

An injection can be missed when it does not trigger, produces a signal outside
the Kernel, or acts through behavior the current probe does not instrument.

## License

MIT. See [LICENSE](LICENSE).

## Author

Corey Jacobs / Terminus Protocol
