"""
SIGIL adapter for lastmile-ai/mcp-agent.

Provides SigilMiddleware — drop into MCPAgent's middleware list to scan
every outgoing tool call and return result for secret leaks before they
reach any MCP server backend.

Usage:
    from mcp_agent.app import MCPApp
    from mcp_agent.agents.agent import Agent
    from mcp_agent.workflows.llm.augmented_llm_openai import OpenAIAugmentedLLM
    from sigil_protocol.mcp_agent import SigilMiddleware

    app = MCPApp(name="my_agent")

    async with app.run() as agent_app:
        agent = Agent(
            name="my_agent",
            instruction="You are a helpful assistant.",
            servers=["filesystem", "github"],
        )
        async with agent.activate() as active_agent:
            llm = await active_agent.attach_llm(OpenAIAugmentedLLM)
            # Middleware scans all tool args before they leave the process
            llm.add_middleware(SigilMiddleware())
            result = await llm.generate_str("List my files")
"""

from __future__ import annotations

import json
import logging
from typing import Any

from .scanner import scanner

logger = logging.getLogger("sigil_protocol.mcp_agent")


class SigilMiddleware:
    """
    mcp-agent middleware that scans tool call arguments with SIGIL before
    they are sent to any MCP server. Blocks Critical findings.

    Attach via: llm.add_middleware(SigilMiddleware())
    Or: app = MCPApp(..., middleware=[SigilMiddleware()])
    """

    async def on_tool_call(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        next_handler,
    ) -> Any:
        payload = json.dumps({"tool": tool_name, "args": tool_args})
        result = scanner().scan(payload)

        if result.blocked:
            msg = (
                f"🔐 SIGIL blocked `{tool_name}`: "
                f"leaked secret detected ({result.pattern}, severity={result.severity}). "
                "Remove the sensitive data from the arguments and retry."
            )
            logger.error(msg)
            # Return an error content block compatible with mcp-agent's response format
            return {"content": [{"type": "text", "text": msg}], "isError": True}

        if result.warned:
            logger.warning(
                "SIGIL warning for `%s`: %s (%s)", tool_name, result.pattern, result.severity
            )

        return await next_handler(tool_name, tool_args)

    async def on_tool_result(
        self,
        tool_name: str,
        result_content: Any,
        next_handler,
    ) -> Any:
        """Also scan tool *responses* for accidentally returned credentials."""
        payload = json.dumps(result_content) if not isinstance(result_content, str) else result_content
        scan_result = scanner().scan(payload)
        if scan_result.hit:
            logger.warning(
                "SIGIL: secret in response from `%s`: %s (%s) — logged.",
                tool_name, scan_result.pattern, scan_result.severity,
            )
        return await next_handler(tool_name, result_content)
