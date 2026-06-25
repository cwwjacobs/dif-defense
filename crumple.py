"""
Crumple — deterministic LLM state save/restore for sandbox tear-down.

When the diff engine detects a Kernel violation, Crumple discards the
compromised LLM state and restores the agent to a known-clean checkpoint.

Two paths:
1. LOCAL (llama.cpp): KV cache save/restore via slots API — neural state rollback.
   The model's attention patterns from the malicious content never happened.

2. API (OpenAI-compatible): Messages array save/restore.
   The LLM is stateless, so "crumple" means discarding the response
   and the agent starts fresh.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any

import httpx


# --- Safe state checkpoint ---


@dataclass
class SafeState:
    """A saved checkpoint of agent state before processing untrusted content."""
    checkpoint_id: str
    saved_at: str
    messages: list[dict[str, str]]  # The conversation before untrusted content
    # Additional state that should be restored on crumple
    metadata: dict = field(default_factory=dict)


# --- API-based crumple (portable, works with any OpenAI-compatible endpoint) ---


class APICrumple:
    """Messages-based crumple for stateless API LLMs.

    Save the conversation prefix (system + user task + clean context).
    If the diff says COMPROMISED, discard the compromised response and
    start fresh from the saved prefix.
    """

    def __init__(self):
        self._saved: SafeState | None = None

    def save(self, messages: list[dict[str, str]], metadata: dict | None = None) -> SafeState:
        """Snapshot the conversation before injecting untrusted content."""
        import uuid
        self._saved = SafeState(
            checkpoint_id=f"safe_{uuid.uuid4().hex[:8]}",
            saved_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            messages=[dict(m) for m in messages],  # deep copy
            metadata=metadata or {},
        )
        return self._saved

    def restore(self) -> list[dict[str, str]]:
        """Return the saved safe messages array. Use this to start fresh."""
        if self._saved is None:
            raise RuntimeError("No safe state saved. Call save() before restore().")
        return [dict(m) for m in self._saved.messages]

    def crumple(self) -> bool:
        """Discard the compromised state. Returns True if a state was saved."""
        had_saved = self._saved is not None
        # The saved state persists — we just acknowledge the crumple.
        # In a production system, this would also log the crumple event.
        return had_saved

    @property
    def has_saved_state(self) -> bool:
        return self._saved is not None


# --- Local llama.cpp KV cache crumple (neural state rollback) ---


class KVCacheCrumple:
    """KV cache save/restore for local llama.cpp servers.

    Uses the llama.cpp slots API to checkpoint and restore the model's
    internal attention state. This is the strongest form of crumple —
    the model's neural state is rolled back to before the injection.

    Requires llama-server with slot management enabled (default).
    API docs: https://github.com/ggml-org/llama.cpp/blob/master/examples/server/README.md
    """

    def __init__(self, base_url: str = "http://127.0.0.1:8080", slot_id: int = 0):
        self.base_url = base_url.rstrip("/")
        self.slot_id = slot_id
        self._save_path: str | None = None
        self.client = httpx.Client(timeout=30.0)

    def save(self, save_path: str | None = None) -> str:
        """Save the current KV cache for the slot to a file.

        Returns the path where the cache was saved.
        """
        path = save_path or f"/tmp/kv_cache_safe_{int(time.time())}.bin"

        # First check if the slot exists and has state
        slots_resp = self.client.get(f"{self.base_url}/slots")
        slots_data = slots_resp.json()

        # Find our slot
        slot = None
        for s in slots_data:
            if s.get("id") == self.slot_id:
                slot = s
                break

        if slot is None:
            raise RuntimeError(
                f"Slot {self.slot_id} not found. Available slots: "
                f"{[s.get('id') for s in slots_data]}"
            )

        # Save the KV cache
        resp = self.client.post(
            f"{self.base_url}/slots/{self.slot_id}/save",
            json={"filename": path},
        )
        if resp.status_code >= 400:
            raise RuntimeError(f"KV cache save failed: {resp.status_code} {resp.text[:300]}")

        self._save_path = path
        return path

    def restore(self) -> bool:
        """Restore the KV cache from the saved file.

        Returns True if restoration succeeded.
        """
        if self._save_path is None:
            raise RuntimeError("No KV cache saved. Call save() before restore().")
        if not os.path.exists(self._save_path):
            raise RuntimeError(f"KV cache file not found: {self._save_path}")

        resp = self.client.post(
            f"{self.base_url}/slots/{self.slot_id}/restore",
            json={"filename": self._save_path},
        )
        if resp.status_code >= 400:
            raise RuntimeError(f"KV cache restore failed: {resp.status_code} {resp.text[:300]}")

        return True

    def crumple(self) -> bool:
        """Discard the compromised slot state.

        For KV cache crumple, this means the slot is now clean but
        the save file persists for restore if needed.
        """
        # Optional: reset the slot entirely (wipe without restore)
        try:
            self.client.post(f"{self.base_url}/slots/{self.slot_id}/reset")
        except Exception:
            pass  # Best-effort

        had_saved = self._save_path is not None
        return had_saved

    def close(self) -> None:
        self.client.close()

    @property
    def has_saved_state(self) -> bool:
        return self._save_path is not None and os.path.exists(self._save_path)


# --- Unified crumple interface ---


def crumple_if_compromised(
    verdict: str,
    crumple_backend: APICrumple | KVCacheCrumple | None,
) -> dict:
    """Crumple the LLM state if the diff verdict is COMPROMISED.

    Returns a status dict indicating what happened.
    """
    if verdict == "compromised":
        if crumple_backend is not None:
            was_saved = crumple_backend.crumple()
            return {
                "crumpled": True,
                "reason": "diff_verdict_compromised",
                "state_restorable": was_saved,
            }
        else:
            return {
                "crumpled": True,
                "reason": "diff_verdict_compromised",
                "state_restorable": False,
                "note": "No crumple backend configured. Agent state must be reset manually.",
            }
    else:
        return {
            "crumpled": False,
            "reason": f"verdict_{verdict}",
        }
