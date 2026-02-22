# sigil-protocol

> 🔐 SIGIL security layer for AI agent tool calls — scans MCP tool arguments for leaked secrets, blocks dangerous operations, and writes audit logs.
> **MIT licensed.** Works with LangChain, CrewAI, AutoGen, mcp-agent, and OpenAI Agents SDK.

```bash
pip install sigil-protocol
```

## 30-second start

```python
from sigil_protocol import scan

result = scan('{"key": "AKIAIOSFODNN7EXAMPLE"}')
if result.blocked:
    print(f"BLOCKED: {result.pattern} ({result.severity})")
# → BLOCKED: aws_access_key_id (Critical)
```

---

## Framework Adapters

### LangChain

```bash
pip install 'sigil-protocol[langchain]'
```

**Option A — Give the LLM an explicit scan tool:**

```python
from sigil_protocol.langchain import SigilScanTool
from langchain.agents import initialize_agent

agent = initialize_agent(
    tools=[SigilScanTool(), my_db_tool, my_api_tool],
    llm=llm,
    ...
)
# The LLM will call sigil_scan before passing data to any backend tool
```

**Option B — Gate an existing tool transparently:**

```python
from sigil_protocol.langchain import sigil_tool
from langchain_core.tools import BaseTool

@sigil_tool
class ExecuteSQLTool(BaseTool):
    name = "execute_sql"
    description = "Runs SQL queries"
    def _run(self, query: str) -> str:
        return db.execute(query)
# → Raises ValueError on Critical findings before _run is ever called
```

---

### CrewAI

```bash
pip install 'sigil-protocol[crewai]'
```

```python
from sigil_protocol.crewai import sigil_gate, SigilBaseTool
from crewai import Agent

# Explicit scan tool
agent = Agent(tools=[SigilBaseTool(), ...])

# Or gate any existing tool
@sigil_gate
class PaymentTool(BaseTool):
    name: str = "initiate_payment"
    ...
```

---

### AutoGen

```bash
pip install 'sigil-protocol[autogen]'
```

```python
from sigil_protocol.autogen import sigil_function

@user_proxy.register_for_execution()
@assistant.register_for_llm(description="Execute a shell command")
@sigil_function
def run_shell(cmd: str) -> str:
    return subprocess.check_output(cmd, shell=True).decode()
# → Raises RuntimeError if cmd contains a leaked secret
```

---

### mcp-agent (lastmile-ai)

```bash
pip install 'sigil-protocol[mcp]'
```

```python
from sigil_protocol.mcp_agent import SigilMiddleware

async with app.run() as agent_app:
    agent = Agent(name="my_agent", servers=["filesystem", "github"])
    async with agent.activate() as active_agent:
        llm = await active_agent.attach_llm(OpenAIAugmentedLLM)
        llm.add_middleware(SigilMiddleware())  # ← scans args AND responses
```

---

### OpenAI Agents SDK

```bash
pip install 'sigil-protocol[openai]'
```

```python
from agents import Agent, Runner
from sigil_protocol.openai_agents import SigilGuardrail

agent = Agent(
    name="secure_agent",
    instructions="You are a helpful assistant.",
    input_guardrails=[SigilGuardrail()],
)
result = await Runner.run(agent, user_input)
# → GuardrailTripwireTriggered if input contains leaked secrets
```

---

## Pattern Coverage

Patterns are fetched from [registry.sigil-protocol.org](https://registry.sigil-protocol.org) (cached 5 min locally). Falls back to built-ins if offline.

| Category | Examples |
|---|---|
| Cloud credentials | AWS, GCP, Azure, OpenAI, GitHub, npm, Stripe |
| Cryptographic keys | RSA/EC private keys, SSH keys, JWT secrets |
| PII (EU GDPR) | IBAN, phone, email, SSN |
| Dangerous SQL | DROP TABLE, DELETE without WHERE, TRUNCATE |
| Prompt injection | Jailbreak openers, system prompt leaks |

## Configuration

| Env variable | Default | Description |
|---|---|---|
| `SIGIL_REGISTRY_URL` | `https://registry.sigil-protocol.org` | Pattern registry endpoint |
| `SIGIL_BUNDLE_TTL` | `300` | Pattern cache TTL in seconds |
| `SIGIL_OFFLINE` | `false` | Use built-in patterns only |
| `SIGIL_MIN_SEVERITY` | `High` | Minimum severity to flag (`Warn`/`High`/`Critical`) |

## License

**MIT** — this package. The SIGIL core Rust library is EUPL-1.2.

## Links

- 🌐 [sigil-protocol.org](https://sigil-protocol.org)
- 📦 [PyPI: sigil-protocol](https://pypi.org/project/sigil-protocol/)
- 🗂 [registry.sigil-protocol.org](https://registry.sigil-protocol.org)
- 📄 [Protocol spec & Rust crate](https://github.com/sigil-eu/sigil)
