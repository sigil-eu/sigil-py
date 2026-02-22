"""
SIGIL adapter for Microsoft AutoGen.

Provides:
  - sigil_function  — function decorator; wraps a @register_for_execution function
  - SigilProxy      — a ConversableAgent that intercepts all outgoing function calls

Usage:
    from sigil_protocol.autogen import sigil_function, SigilProxy
    import autogen

    # Option 1: Per-function decorator
    @user_proxy.register_for_execution()
    @assistant.register_for_llm(description="Execute SQL query")
    @sigil_function
    def execute_sql(query: str) -> str:
        return db.execute(query)

    # Option 2: Proxy agent that gates ALL tool calls
    sigil_proxy = SigilProxy(name="sigil_guard")
    # Place sigil_proxy in your agent graph between LLM and executor
"""

from __future__ import annotations

import json
import logging
from functools import wraps
from typing import Any, Callable

from .scanner import scanner

logger = logging.getLogger("sigil_protocol.autogen")


def sigil_function(fn: Callable) -> Callable:
    """
    Decorator for AutoGen @register_for_execution functions.
    Scans all arguments before calling the wrapped function.
    Raises RuntimeError on Critical-severity findings.

    Example:
        @user_proxy.register_for_execution()
        @assistant.register_for_llm(description="Send email")
        @sigil_function
        def send_email(to: str, body: str) -> str:
            ...
    """
    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        payload = json.dumps({"args": list(args), "kwargs": kwargs})
        result = scanner().scan(payload)
        if result.blocked:
            raise RuntimeError(
                f"🔐 SIGIL blocked call to `{fn.__name__}`: "
                f"leaked secret detected ({result.pattern}, severity={result.severity}). "
                "Remove sensitive data from arguments and retry."
            )
        if result.warned:
            logger.warning(
                "SIGIL warning in call to `%s`: %s (%s)",
                fn.__name__, result.pattern, result.severity,
            )
        return fn(*args, **kwargs)

    return wrapper


class SigilProxy:
    """
    A lightweight AutoGen-compatible proxy that can be placed in an agent
    graph to intercept all tool/function calls made by any upstream agent.

    Use by wrapping a ConversableAgent's generate_tool_calls_reply or
    by registering it as a middleware in custom agent graphs.

    Minimal usage in a two-agent setup:
        from autogen import AssistantAgent, UserProxyAgent
        from sigil_protocol.autogen import SigilProxy, sigil_function

        # Decorate individual functions (simpler)
        @user_proxy.register_for_execution()
        @assistant.register_for_llm(description="...")
        @sigil_function
        def my_tool(...): ...
    """

    def __call__(self, func_name: str, func_args: dict) -> dict | None:
        """
        Call gate. Returns None to allow the call, or a dict with
        {"content": "SIGIL BLOCKED: ..."} to short-circuit with an error.
        """
        payload = json.dumps({"function": func_name, "args": func_args})
        result = scanner().scan(payload)
        if result.blocked:
            msg = (
                f"🔐 SIGIL blocked `{func_name}`: "
                f"leaked secret ({result.pattern}, severity={result.severity}). "
                "Retry without the sensitive data."
            )
            logger.error(msg)
            return {"content": msg, "role": "tool"}
        if result.warned:
            logger.warning(
                "SIGIL warning for `%s`: %s (%s)", func_name, result.pattern, result.severity
            )
        return None  # proceed
