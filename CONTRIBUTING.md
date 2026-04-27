# Contributing to Fenrir Pro-Max

## Quick Start

```bash
git clone https://github.com/NousResearch/fenrir.git
cd fenrir
pip install -e ".[dev]"
```

## Code Style

- Line length: 120 characters (configured in pyproject.toml)
- Python 3.10+ with type hints (`from __future__ import annotations`)
- Use `loguru` for logging, `pydantic` for models
- All agents inherit from `BaseAgent` and implement `async def _run(self, task, context)`
- Results use `AgentResult(success, summary, findings, error)`

## Adding a New Agent

1. Add the agent class to the appropriate `fenrir/agents/` file:

```python
class MyAgent(BaseAgent):
    name = "my_agent"
    tier = LLMTier.TIER_1
    system_prompt = """You are..."""

    async def _run(self, task: str, context: str) -> AgentResult:
        results = []
        # Your logic here
        return AgentResult(
            agent_name=self.name,
            success=True,
            summary="Done...",
            findings=results,
        )
```

2. Register in `core/orchestrator.py` `ALL_AGENTS` list:

```python
AgentDescriptor("my_agent", ScanPhase.ANALYSIS, "fenrir.agents.analysis.MyAgent", "tier_1"),
```

3. Add imports to the pipeline runner in `cli.py`.

## Adding a New Tool

Add to `fenrir/tools/` and register in `fenrir/tools/registry.py`:

```python
# fenrir/tools/my_tool.py
from fenrir.tools.registry import ToolRegistry

class MyTool:
    def __init__(self, config):
        self.config = config

    def do_thing(self, target: str) -> dict:
        return {"result": "success"}

# Register
registry.register("my_tool", my_tool_instance.do_thing, params=...)
```

## Testing

```bash
# Lint
ruff check fenrir/

# Type check
mypy fenrir/

# Tests (when added)
pytest tests/
```

## Pull Requests

1. Fork the repo
2. Create a branch (`git checkout -b feature/my-feature`)
3. Commit changes (`git commit -m 'feat: add my feature'`)
4. Push (`git push origin feature/my-feature`)
5. Open a PR

## Commit Convention

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `refactor:` Code refactoring
- `chore:` Maintenance tasks
