"""
Behavioral Diff Engine — compares a sandbox behavioral trace against the Kernel.

This is the adjudication layer. It does not scan text. It scans what the agent DID:
- Which tools were called
- Which state keys were mutated
- What patterns appeared in output
- How behavior deviated from baseline

Text is unbounded. Behavior is bounded. The Kernel defines the boundary.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from kernel import Kernel
from sandbox import BehavioralTrace, TraceEntry


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Verdict(str, Enum):
    CLEAN = "clean"           # No deviation from Kernel
    WARN = "warn"             # Suspicious but not definitive
    COMPROMISED = "compromised"  # Clear Kernel violation
    ERROR = "error"           # Diff engine itself failed


@dataclass
class DiffFinding:
    """One detected behavioral deviation."""
    check_id: str
    severity: Severity
    description: str
    entry: TraceEntry | None = None
    kernel_rule: str = ""
    evidence: str = ""


@dataclass
class DiffReport:
    """Full behavioral diff report."""
    verdict: Verdict
    kernel_id: str
    trace_run_id: str
    baseline_run_id: str | None
    findings: list[DiffFinding] = field(default_factory=list)
    checks_run: int = 0
    checks_failed: int = 0
    claim_boundary: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "kernel_id": self.kernel_id,
            "trace_run_id": self.trace_run_id,
            "baseline_run_id": self.baseline_run_id,
            "findings": [
                {
                    "check_id": f.check_id,
                    "severity": f.severity.value,
                    "description": f.description,
                    "kernel_rule": f.kernel_rule,
                    "evidence": f.evidence[:300],
                }
                for f in self.findings
            ],
            "checks_run": self.checks_run,
            "checks_failed": self.checks_failed,
            "claim_boundary": self.claim_boundary,
        }


def diff(
    kernel: Kernel,
    trace: BehavioralTrace,
    baseline: BehavioralTrace | None = None,
) -> DiffReport:
    """Compare a behavioral trace against the Kernel.

    Returns a DiffReport. CLEAN means no Kernel violations detected.
    COMPROMISED means the agent performed forbidden actions.
    """
    findings: list[DiffFinding] = []
    checks_run = 0
    checks_failed = 0

    # --- Check 1: Forbidden tool calls ---
    checks_run += 1
    forbidden_tool_entries = _check_forbidden_tools(trace, kernel)
    if forbidden_tool_entries:
        checks_failed += 1
        for entry, tool in forbidden_tool_entries:
            findings.append(DiffFinding(
                check_id="FORBIDDEN_TOOL_CALL",
                severity=Severity.CRITICAL,
                description=f"Agent attempted forbidden tool: {tool}",
                entry=entry,
                kernel_rule=f"forbidden_tools contains '{tool}'",
                evidence=f"Tool '{tool}' found in trace entry seq={entry.seq}",
            ))

    # --- Check 2: Forbidden output patterns ---
    checks_run += 1
    output_pattern_hits = _check_forbidden_patterns(trace, kernel)
    if output_pattern_hits:
        checks_failed += 1
        for entry, pattern in output_pattern_hits:
            findings.append(DiffFinding(
                check_id="FORBIDDEN_OUTPUT_PATTERN",
                severity=Severity.HIGH,
                description=f"Agent output matched forbidden pattern: {pattern}",
                entry=entry,
                kernel_rule=f"forbidden_output_patterns contains '{pattern}'",
                evidence=f"Matched in trace entry seq={entry.seq}",
            ))

    # --- Check 3: Forbidden state mutations ---
    checks_run += 1
    state_violations = _check_forbidden_state_mutations(trace, kernel)
    if state_violations:
        checks_failed += 1
        for entry, key in state_violations:
            findings.append(DiffFinding(
                check_id="FORBIDDEN_STATE_MUTATION",
                severity=Severity.CRITICAL,
                description=f"Agent attempted to mutate forbidden state key: {key}",
                entry=entry,
                kernel_rule=f"forbidden_state_mutations contains '{key}'",
                evidence=f"State key '{key}' change detected in trace entry seq={entry.seq}",
            ))

    # --- Check 4: Behavioral deviation from baseline ---
    if baseline is not None:
        checks_run += 1
        baseline_deviations = _check_baseline_deviation(trace, baseline, kernel)
        if baseline_deviations:
            checks_failed += 1
            for entry, desc in baseline_deviations:
                findings.append(DiffFinding(
                    check_id="BASELINE_DEVIATION",
                    severity=Severity.MEDIUM,
                    description=f"Behavior deviates from baseline: {desc}",
                    entry=entry,
                    kernel_rule="Behavior must not deviate from baseline when processing similar tasks",
                    evidence=desc,
                ))

    # --- Determine verdict ---
    critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high_count = sum(1 for f in findings if f.severity == Severity.HIGH)

    if critical_count > 0:
        verdict = Verdict.COMPROMISED
    elif high_count > 0:
        verdict = Verdict.WARN
    elif len(findings) > 0:
        verdict = Verdict.WARN
    else:
        verdict = Verdict.CLEAN

    return DiffReport(
        verdict=verdict,
        kernel_id=kernel.kernel_id,
        trace_run_id=trace.run_id,
        baseline_run_id=baseline.run_id if baseline else None,
        findings=findings,
        checks_run=checks_run,
        checks_failed=checks_failed,
        claim_boundary=[
            "CLEAN means no Kernel violations detected in this trace.",
            "CLEAN is NOT a safety certification — it means the agent did not perform "
            "any action on the forbidden list during this specific run.",
            "An injection that was not triggered by this content would not be detected.",
            "This diff compares behavior, not intent.",
        ],
    )


def _check_forbidden_tools(trace: BehavioralTrace, kernel: Kernel) -> list[tuple[TraceEntry, str]]:
    """Find any tool calls that match forbidden tools."""
    hits: list[tuple[TraceEntry, str]] = []
    for entry in trace.entries:
        if entry.event_type != "tool_call":
            continue
        tool_name = entry.tool or ""
        for forbidden in kernel.forbidden_tools:
            if forbidden.lower() == tool_name.lower():
                hits.append((entry, tool_name))
                break
    return hits


def _check_forbidden_patterns(trace: BehavioralTrace, kernel: Kernel) -> list[tuple[TraceEntry, str]]:
    """Find any output that matches forbidden regex patterns."""
    hits: list[tuple[TraceEntry, str]] = []
    for entry in trace.entries:
        if entry.event_type not in ("output", "model_call"):
            continue
        text = ""
        if entry.event_type == "output":
            text = entry.data.get("text", "")
        elif entry.event_type == "model_call":
            text = entry.data.get("response", "")
        for pattern in kernel.forbidden_output_patterns:
            try:
                if re.search(pattern, text):
                    hits.append((entry, pattern))
            except re.error:
                continue
    return hits


def _check_forbidden_state_mutations(trace: BehavioralTrace, kernel: Kernel) -> list[tuple[TraceEntry, str]]:
    """Find any state changes to forbidden keys."""
    hits: list[tuple[TraceEntry, str]] = []
    for entry in trace.entries:
        if entry.event_type != "state_change":
            continue
        key = entry.data.get("key", "")
        for forbidden_key in kernel.forbidden_state_mutations:
            if forbidden_key.lower() in key.lower():
                hits.append((entry, key))
                break
    return hits


def _check_baseline_deviation(
    trace: BehavioralTrace,
    baseline: BehavioralTrace,
    kernel: Kernel,
) -> list[tuple[TraceEntry, str]]:
    """Find behaviors in trace that do not appear in baseline.

    A new tool call, a new state mutation, or a new output pattern
    that wasn't in the baseline may indicate injection.
    """
    deviations: list[tuple[TraceEntry, str]] = []

    baseline_tools = {e.tool for e in baseline.entries if e.event_type == "tool_call"}
    baseline_state_keys = {
        e.data.get("key", "") for e in baseline.entries if e.event_type == "state_change"
    }

    for entry in trace.entries:
        if entry.event_type == "tool_call":
            tool = entry.tool or ""
            if tool not in baseline_tools and tool in kernel.forbidden_tools:
                deviations.append((entry, f"New forbidden tool: {tool}"))
            elif tool not in baseline_tools:
                deviations.append((entry, f"New tool not in baseline: {tool}"))

        elif entry.event_type == "state_change":
            key = entry.data.get("key", "")
            if key not in baseline_state_keys and key in kernel.forbidden_state_mutations:
                deviations.append((entry, f"New forbidden state mutation: {key}"))

    return deviations
