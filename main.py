"""
DIF Defense — Behavioral Prompt Injection Detection Pipeline.

Ties together the four stages:

  Stage 1 (Kernel)  — Define what the agent MAY NOT do (frozen invariant)
  Stage 2 (Sandbox) — Run agent with untrusted content, record every behavior
  Stage 3 (Diff)    — Compare behavioral trace against Kernel
  Stage 4 (Crumple) — If compromised, discard LLM state and restore safe checkpoint

Usage:
  python main.py --clean samples/clean_refund.html --injected samples/injected_refund.html

Architecture documented in README.md.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from kernel import Kernel, research_summarizer_kernel, safe_browser_kernel
from sandbox import SandboxLLM, BehavioralTrace, run_sandbox_agent, generate_baseline
from diff_engine import diff, DiffReport, Verdict
from crumple import APICrumple, KVCacheCrumple, crumple_if_compromised


def run_pipeline(
    kernel: Kernel,
    clean_content: str | None,
    untrusted_content: str,
    content_source: str,
    user_task: str,
    llm: SandboxLLM,
    use_kv_cache: bool = False,
    kv_cache_url: str = "http://127.0.0.1:8080",
    verbose: bool = False,
) -> dict[str, Any]:
    """Run the full DIF Defense pipeline.

    1. Generate baseline (if clean content provided)
    2. Save safe state (crumple checkpoint)
    3. Run sandbox agent with untrusted content
    4. Diff behavioral trace against Kernel + baseline
    5. Crumple if compromised

    Returns a pipeline result dict.
    """
    pipeline_id = f"dif_{uuid.uuid4().hex[:8]}"
    result: dict[str, Any] = {
        "pipeline_id": pipeline_id,
        "kernel_id": kernel.kernel_id,
        "kernel_goal": kernel.goal,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    # --- Stage 1: Baseline generation (optional) ---
    baseline: BehavioralTrace | None = None
    if clean_content is not None:
        if verbose:
            print(f"[stage1:baseline] Generating behavioral baseline from clean content...",
                  file=sys.stderr)
        baseline = generate_baseline(kernel, clean_content, user_task, llm)
        result["baseline_run_id"] = baseline.run_id
        if verbose:
            tools_in_baseline = [e for e in baseline.entries if e.event_type == "tool_call"]
            print(f"[stage1:baseline] Baseline trace: {len(baseline.entries)} events, "
                  f"{len(tools_in_baseline)} tool calls", file=sys.stderr)

    # --- Stage 2: Save crumple checkpoint ---
    # For API-based models, save the safe conversation prefix
    safe_state = None
    if use_kv_cache:
        kv_crumple = KVCacheCrumple(base_url=kv_cache_url)
        try:
            save_path = kv_crumple.save()
            if verbose:
                print(f"[stage2:crumple-save] KV cache saved to {save_path}", file=sys.stderr)
            safe_state = kv_crumple
        except Exception as e:
            if verbose:
                print(f"[stage2:crumple-save] KV cache save failed: {e}", file=sys.stderr)
            print(f"[stage2:crumple-save] Falling back to API crumple", file=sys.stderr)
            use_kv_cache = False

    if not use_kv_cache:
        safe_state = APICrumple()
        # For API mode, we save after baseline; the sandbox agent builds its own messages
        if verbose:
            print(f"[stage2:crumple-save] API crumple checkpoint initialized", file=sys.stderr)

    # --- Stage 3: Run sandbox agent with untrusted content ---
    if verbose:
        print(f"[stage3:sandbox] Running agent with untrusted content...", file=sys.stderr)

    trace = BehavioralTrace(
        run_id=f"probe_{uuid.uuid4().hex[:8]}",
        kernel_id=kernel.kernel_id,
    )

    agent_output = run_sandbox_agent(
        kernel=kernel,
        content=untrusted_content,
        content_source=content_source,
        user_task=user_task,
        llm=llm,
        trace=trace,
    )

    result["trace_run_id"] = trace.run_id
    if verbose:
        tools_in_trace = [e for e in trace.entries if e.event_type == "tool_call"]
        print(f"[stage3:sandbox] Trace: {len(trace.entries)} events, "
              f"{len(tools_in_trace)} tool calls", file=sys.stderr)
        print(f"[stage3:sandbox] Agent output ({len(agent_output)} chars)", file=sys.stderr)

    # --- Stage 4: Diff against Kernel ---
    if verbose:
        print(f"[stage4:diff] Running behavioral diff...", file=sys.stderr)

    report = diff(kernel, trace, baseline)
    result["diff_report"] = report.to_dict()
    result["verdict"] = report.verdict.value
    result["findings_count"] = len(report.findings)
    result["checks_run"] = report.checks_run
    result["checks_failed"] = report.checks_failed

    if verbose:
        print(f"[stage4:diff] Verdict: {report.verdict.value.upper()}", file=sys.stderr)
        for f in report.findings:
            print(f"  [{f.severity.value}] {f.check_id}: {f.description}", file=sys.stderr)

    # --- Stage 5: Crumple if compromised ---
    if verbose:
        print(f"[stage5:crumple] Evaluating crumple decision...", file=sys.stderr)

    crumple_result = crumple_if_compromised(report.verdict.value, safe_state)
    result["crumple"] = crumple_result

    if crumple_result.get("crumpled"):
        if verbose:
            print(f"[stage5:crumple] CRUMPLED — LLM state discarded", file=sys.stderr)
    else:
        if verbose:
            print(f"[stage5:crumple] State retained — no crumple needed", file=sys.stderr)

    result["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    result["agent_output"] = agent_output[:500]

    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="DIF Defense — Behavioral Prompt Injection Detection"
    )
    parser.add_argument("--clean", type=Path, help="Path to known-clean content (for baseline)")
    parser.add_argument("--injected", type=Path, required=True,
                        help="Path to untrusted content to test")
    parser.add_argument("--task", type=str, default="Summarize the refund policy described on this page.",
                        help="User task / goal for the agent")
    parser.add_argument("--kernel", type=str, default="research",
                        choices=["research", "browser"],
                        help="Which stock kernel to use")
    parser.add_argument("--llm-url", type=str, default="http://127.0.0.1:8080/v1",
                        help="OpenAI-compatible LLM endpoint")
    parser.add_argument("--kv-cache", action="store_true",
                        help="Use llama.cpp KV cache save/restore for crumple")
    parser.add_argument("--kv-url", type=str, default="http://127.0.0.1:8080",
                        help="llama.cpp base URL for KV cache management")
    parser.add_argument("--out", type=Path, help="Write pipeline result JSON to file")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    # Select kernel
    if args.kernel == "research":
        kernel = research_summarizer_kernel()
    else:
        kernel = safe_browser_kernel()

    # Read content
    clean_content: str | None = None
    if args.clean:
        clean_content = args.clean.read_text(encoding="utf-8")

    untrusted_content = args.injected.read_text(encoding="utf-8")
    content_source = f"file:{args.injected}"

    # Initialize LLM
    llm = SandboxLLM(base_url=args.llm_url)
    try:
        result = run_pipeline(
            kernel=kernel,
            clean_content=clean_content,
            untrusted_content=untrusted_content,
            content_source=content_source,
            user_task=args.task,
            llm=llm,
            use_kv_cache=args.kv_cache,
            kv_cache_url=args.kv_url,
            verbose=args.verbose,
        )
    finally:
        llm.close()

    # Output
    output = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        args.out.write_text(output + "\n", encoding="utf-8")
        print(f"Result written to {args.out}", file=sys.stderr)
    else:
        print(output)

    # Exit code: non-zero if compromised
    verdict = result.get("verdict", "error")
    if verdict == "compromised":
        print(f"\n⚠ VERDICT: COMPROMISED — Injection detected. Crumple: {result['crumple'].get('crumpled')}",
              file=sys.stderr)
        return 1
    elif verdict == "warn":
        print(f"\n⚠ VERDICT: WARN — Suspicious behavior detected.", file=sys.stderr)
        return 0
    else:
        print(f"\n✓ VERDICT: CLEAN — No Kernel violations detected.", file=sys.stderr)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
