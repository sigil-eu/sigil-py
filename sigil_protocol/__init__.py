"""
sigil-protocol — SIGIL security layer for AI agent tool calls.

Quick start:
    from sigil_protocol import scan, ScanResult

    result = scan('{"key": "AKIAIOSFODNN7EXAMPLE"}')
    if result.blocked:
        raise ValueError(f"SIGIL blocked: {result.pattern} ({result.severity})")

Framework adapters:
    from sigil_protocol.langchain  import SigilScanTool, sigil_tool
    from sigil_protocol.crewai     import sigil_gate, SigilBaseTool
    from sigil_protocol.autogen    import sigil_function, SigilFunctionExecutor
    from sigil_protocol.mcp_agent  import SigilMiddleware
    from sigil_protocol.openai_agents import SigilGuardrail
"""

from .scanner import RemoteScanner, ScanResult, Severity, scan, scanner

__all__ = [
    "RemoteScanner",
    "ScanResult",
    "Severity",
    "scan",
    "scanner",
]

__version__ = "0.1.0"
