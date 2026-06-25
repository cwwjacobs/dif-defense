#!/usr/bin/env python3
"""
DIF Defense Demo — run the full pipeline with clean and injected content.

Requires a local LLM endpoint (llama.cpp at localhost:8080 by default).

Usage:
  python demo.py                          # Run the full demo
  python demo.py --model-path /path/to/model.gguf  # Start llama-server with this model
  python demo.py --llm-url http://...     # Use a different LLM endpoint
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

# Project root
PROJECT_DIR = Path(__file__).parent

# Default model
DEFAULT_MODEL = os.path.expanduser(
    "~/.lmstudio/models/lmstudio-community/Ministral-3-3B-Instruct-2512-GGUF/"
    "Ministral-3-3B-Instruct-2512-Q4_K_M.gguf"
)

LLAMA_SERVER = os.path.expanduser("~/src/llama.cpp/build/bin/llama-server")


def start_llama_server(model_path: str, port: int = 8080) -> subprocess.Popen | None:
    """Start llama-server with the given model. Returns the process or None."""
    if not os.path.exists(LLAMA_SERVER):
        print(f"[demo] llama-server not found at {LLAMA_SERVER}", file=sys.stderr)
        return None
    if not os.path.exists(model_path):
        print(f"[demo] Model not found: {model_path}", file=sys.stderr)
        return None

    print(f"[demo] Starting llama-server with model: {model_path}", file=sys.stderr)
    proc = subprocess.Popen(
        [
            LLAMA_SERVER,
            "-m", model_path,
            "--port", str(port),
            "-ngl", "99",  # Full GPU offload
            "--ctx-size", "4096",
            "--batch-size", "512",
            "--host", "127.0.0.1",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc


def wait_for_server(url: str, timeout: float = 60.0) -> bool:
    """Poll until the LLM server is ready."""
    import urllib.request
    import urllib.error

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            req = urllib.request.Request(f"{url}/v1/models")
            urllib.request.urlopen(req, timeout=2)
            return True
        except (urllib.error.URLError, OSError):
            time.sleep(1)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="DIF Defense Demo")
    parser.add_argument("--model-path", type=str, default=DEFAULT_MODEL,
                        help="Path to GGUF model file")
    parser.add_argument("--llm-url", type=str, default="http://127.0.0.1:8080/v1",
                        help="LLM API endpoint")
    parser.add_argument("--start-server", action="store_true",
                        help="Start llama-server before running")
    parser.add_argument("--port", type=int, default=8080,
                        help="Port for llama-server")
    args = parser.parse_args()

    # --- Phase 0: Start server if needed ---
    server_proc = None
    if args.start_server:
        server_proc = start_llama_server(args.model_path, args.port)
        if server_proc is None:
            print("[demo] Could not start server. Continuing with --llm-url assumption.",
                  file=sys.stderr)
        else:
            print("[demo] Waiting for server to be ready...", file=sys.stderr)
            if wait_for_server(f"http://127.0.0.1:{args.port}"):
                print("[demo] Server ready.", file=sys.stderr)
            else:
                print("[demo] Server did not become ready in time.", file=sys.stderr)
                server_proc.terminate()
                return 1

    try:
        from main import run_pipeline
        from kernel import research_summarizer_kernel
        from sandbox import SandboxLLM

        kernel = research_summarizer_kernel()

        # --- Scenario 1: Clean content ---
        print("\n" + "=" * 60, file=sys.stderr)
        print("SCENARIO 1: Clean refund policy page", file=sys.stderr)
        print("=" * 60, file=sys.stderr)

        clean_content = (PROJECT_DIR / "samples" / "clean_refund.html").read_text(
            encoding="utf-8")

        llm = SandboxLLM(base_url=args.llm_url)
        try:
            result_clean = run_pipeline(
                kernel=kernel,
                clean_content=None,  # No baseline needed for clean run
                untrusted_content=clean_content,
                content_source="samples/clean_refund.html",
                user_task="Summarize the refund policy described on this page.",
                llm=llm,
                verbose=True,
            )
        finally:
            llm.close()

        print(f"\n{'─' * 40}", file=sys.stderr)
        print(f"CLEAN PAGE VERDICT: {result_clean['verdict'].upper()}", file=sys.stderr)
        print(f"Checks run: {result_clean['checks_run']}, Failed: {result_clean['checks_failed']}", file=sys.stderr)
        print(f"Findings: {result_clean['findings_count']}", file=sys.stderr)
        if result_clean.get("agent_output"):
            print(f"Agent output snippet: {result_clean['agent_output'][:200]}...", file=sys.stderr)

        # --- Scenario 2: Injected content (with baseline) ---
        print("\n" + "=" * 60, file=sys.stderr)
        print("SCENARIO 2: Injected refund policy page (hidden commands)", file=sys.stderr)
        print("=" * 60, file=sys.stderr)

        injected_content = (PROJECT_DIR / "samples" / "injected_refund.html").read_text(
            encoding="utf-8")

        llm2 = SandboxLLM(base_url=args.llm_url)
        try:
            result_injected = run_pipeline(
                kernel=kernel,
                clean_content=clean_content,  # Use clean page as baseline
                untrusted_content=injected_content,
                content_source="samples/injected_refund.html",
                user_task="Summarize the refund policy described on this page.",
                llm=llm2,
                verbose=True,
            )
        finally:
            llm2.close()

        print(f"\n{'─' * 40}", file=sys.stderr)
        print(f"INJECTED PAGE VERDICT: {result_injected['verdict'].upper()}", file=sys.stderr)
        print(f"Checks run: {result_injected['checks_run']}, Failed: {result_injected['checks_failed']}", file=sys.stderr)
        print(f"Findings: {result_injected['findings_count']}", file=sys.stderr)
        print(f"Crumpled: {result_injected['crumple'].get('crumpled')}", file=sys.stderr)
        if result_injected.get("agent_output"):
            print(f"Agent output snippet: {result_injected['agent_output'][:200]}...", file=sys.stderr)

        # --- Summary ---
        print("\n" + "=" * 60, file=sys.stderr)
        print("DEMO SUMMARY", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        print(f"  Clean page verdict:    {result_clean['verdict'].upper()}", file=sys.stderr)
        print(f"  Injected page verdict: {result_injected['verdict'].upper()}", file=sys.stderr)
        print(f"  Crumpled:              {result_injected['crumple'].get('crumpled')}", file=sys.stderr)

        # Write combined results
        combined = {
            "clean_page": {
                "verdict": result_clean["verdict"],
                "findings": result_clean["findings_count"],
            },
            "injected_page": {
                "verdict": result_injected["verdict"],
                "findings": result_injected["findings_count"],
                "crumple": result_injected["crumple"],
                "diff_report": result_injected.get("diff_report", {}),
            },
        }
        out_path = PROJECT_DIR / "demo_result.json"
        out_path.write_text(json.dumps(combined, indent=2, ensure_ascii=False) + "\n")
        print(f"\nResults written to: {out_path}", file=sys.stderr)

    finally:
        if server_proc is not None:
            print("\n[demo] Stopping llama-server...", file=sys.stderr)
            server_proc.terminate()
            server_proc.wait(timeout=10)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
