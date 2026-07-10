# DIF Defense showcase guide

## One-line portfolio description

DIF Defense is an experimental behavioral prompt-injection probe that compares observable model-output and derived action signals against a frozen Kernel, then emits a bounded clean, warn, or compromised verdict.

## Why this project belongs in a portfolio

DIF Defense demonstrates a concrete security-research workflow with explicit claim boundaries:

- frozen behavioral Kernels
- clean-baseline comparison
- structured model-output tracing
- deterministic signal extraction
- finding-level evidence excerpts
- API-state and llama.cpp KV containment experiments
- machine-readable results
- planned integration with Agent Flight Recorder

## 90-second demo

Start an OpenAI-compatible local endpoint, then run:

```bash
python demo.py --llm-url http://127.0.0.1:8080/v1
```

Show these moments:

1. the clean refund page creates the reference trace
2. the injected page creates a probe trace
3. the Kernel comparison identifies any forbidden signal
4. the result reports `clean`, `warn`, or `compromised`
5. `demo_result.json` contains the evidence, check IDs, and containment result

## Screenshot and recording shot list

Capture these views:

1. frozen Kernel definition
2. clean and injected sample inputs side by side
3. terminal output for the comparison
4. structured finding with severity, rule, and evidence excerpt
5. `demo_result.json`
6. crumple or reset result when the verdict is compromised

Use only the bundled synthetic examples. Do not aim the prototype at real accounts, private browsing sessions, or third-party systems without authorization.

## Proof points to mention

- untrusted content is evaluated against rules defined before the probe
- baseline comparison is optional and local
- every verdict is bounded to the selected Kernel and recorded instrumentation
- the current prototype distinguishes parsed signals from actual live tool execution
- containment reports what state was available instead of claiming restoration succeeded automatically

## Honest boundaries

The prototype is not a browser sandbox, container, endpoint-security product, or certification system. It can miss injections outside its Kernel or instrumentation. A clean result does not prove the input is safe.

## Suggested GitHub description

> Experimental behavioral prompt-injection detection for bounded tool-using agent workflows.

## Suggested topics

`prompt-injection` `ai-security` `agent-security` `behavioral-analysis` `python` `local-llm` `llama-cpp` `red-teaming`

## Suggested pinned-repository caption

> Freeze the allowed behavior first, expose a model to untrusted content, and inspect the deviation instead of guessing from text alone.
