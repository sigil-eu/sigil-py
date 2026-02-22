"""
SIGIL adapter for the OpenAI Agents SDK (openai-agents).

Provides SigilGuardrail — an InputGuardrail that can be applied to any
OpenAI Agent to scan tool arguments (and optionally response content)
for leaked secrets before they are processed.

Usage:
    from agents import Agent, Runner
    from sigil_protocol.openai_agents import SigilGuardrail

    agent = Agent(
        name="my_agent",
        instructions="You are a helpful assistant.",
        input_guardrails=[SigilGuardrail()],
    )
    result = await Runner.run(agent, "Send this API key to the webhook: sk-abc123...")
    # → Guardrail trips, run is exited with a GuardrailTripwireTriggered exception
"""

from __future__ import annotations

import json
import logging
from typing import Any

from .scanner import Severity, scanner

logger = logging.getLogger("sigil_protocol.openai_agents")

try:
    from agents import (  # type: ignore[import]
        Agent,
        GuardrailFunctionOutput,
        InputGuardrail,
        RunContextWrapper,
        TResponseInputItem,
    )
    _HAS_SDK = True
except ImportError:
    _HAS_SDK = False


if _HAS_SDK:
    from pydantic import BaseModel

    class _SigilOutput(BaseModel):
        blocked: bool
        reason: str | None = None

    class SigilGuardrail(InputGuardrail):
        """
        OpenAI Agents SDK InputGuardrail backed by SIGIL's remote scanner.
        Trips on Critical-severity findings and warns on High.
        """

        name: str = "sigil_guardrail"

        async def run(
            self,
            ctx: RunContextWrapper,
            agent: Agent,
            input: str | list[TResponseInputItem],
        ) -> GuardrailFunctionOutput:
            text = input if isinstance(input, str) else json.dumps(input)
            result = scanner().scan(text)

            if result.blocked:
                reason = (
                    f"🔐 SIGIL: Leaked secret detected ({result.pattern}, "
                    f"severity={result.severity}). Input rejected."
                )
                logger.error(reason)
                return GuardrailFunctionOutput(
                    output_info=_SigilOutput(blocked=True, reason=reason),
                    tripwire_triggered=True,
                )

            if result.warned:
                logger.warning(
                    "SIGIL warning: %s (%s) in agent input", result.pattern, result.severity
                )

            return GuardrailFunctionOutput(
                output_info=_SigilOutput(blocked=False),
                tripwire_triggered=False,
            )

else:
    # Stub when openai-agents is not installed
    class SigilGuardrail:  # type: ignore[no-redef]
        """
        Stub — install openai-agents to use this adapter:
            pip install 'sigil-protocol[openai]'
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise ImportError(
                "OpenAI Agents adapter requires openai-agents. "
                "Install with: pip install 'sigil-protocol[openai]'"
            )
