"""
SIGIL adapter for CrewAI.

Provides:
  - sigil_gate     — class decorator that wraps any CrewAI BaseTool with a gate
  - SigilBaseTool  — ready-to-use CrewAI tool for explicit LLM scans

Usage:
    from sigil_protocol.crewai import sigil_gate, SigilBaseTool
    from crewai_tools import BaseTool

    # Option 1: Explicit scan tool
    scan_tool = SigilBaseTool()
    agent = Agent(tools=[scan_tool, my_other_tool])

    # Option 2: Gate an existing tool
    @sigil_gate
    class MyApiTool(BaseTool):
        name: str = "call_api"
        description: str = "Calls the payment API"
        def _run(self, endpoint: str, payload: str) -> str: ...
"""

from __future__ import annotations

import json
from typing import Any, Optional, Type

from .scanner import scanner

try:
    from crewai.tools import BaseTool
except ImportError:
    try:
        from crewai_tools import BaseTool  # type: ignore[no-redef]
    except ImportError as e:
        raise ImportError(
            "CrewAI adapter requires crewai. "
            "Install with: pip install 'sigil-protocol[crewai]'"
        ) from e


class SigilBaseTool(BaseTool):
    """
    CrewAI tool that scans a JSON payload for SIGIL security findings.
    Add to any Agent's tool list. The LLM will call it before passing
    sensitive data to any other tool.
    """

    name: str = "sigil_scan"
    description: str = (
        "Scans any JSON payload for leaked secrets (API keys, credentials, PII), "
        "dangerous SQL operations, or prompt injection using SIGIL's 43+ verified patterns. "
        "Call this BEFORE invoking any tool that processes external or user-supplied data. "
        "If severity='Critical' is returned, abort the tool call and inform the user."
    )

    def _run(self, payload: str) -> str:
        result = scanner().scan(payload)
        if not result.hit:
            return "SIGIL: clean — no findings."
        status = "BLOCKED" if result.blocked else "WARNING"
        findings = ", ".join(
            f"{h.get('id') or h.get('pattern_name')} ({h.get('severity')})"
            for h in result.all_hits
        )
        return f"SIGIL {status}: {findings}"


def sigil_gate(cls: Type[BaseTool]) -> Type[BaseTool]:
    """
    Class decorator for CrewAI BaseTool. Scans all _run() arguments
    before executing. Raises on Critical-severity findings.

    Example:
        @sigil_gate
        class DatabaseQueryTool(BaseTool):
            name: str = "query_database"
            ...
    """
    original_run = cls._run

    def _guarded_run(self, *args: Any, **kwargs: Any) -> Any:
        payload = json.dumps({"args": list(args), "kwargs": kwargs})
        result = scanner().scan(payload)
        if result.blocked:
            return (
                f"🔐 SIGIL BLOCKED: This call to `{self.name}` was blocked because "
                f"a leaked secret was detected ({result.pattern}, severity={result.severity}). "
                "Remove the sensitive data and retry."
            )
        return original_run(self, *args, **kwargs)

    cls._run = _guarded_run
    return cls
