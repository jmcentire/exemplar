# Standard Operating Procedures: Exemplar

## Code Standards
- Python 3.12+, type hints throughout
- Pydantic v2 with frozen=True for all data models
- StrEnum for enumerated types
- Protocol classes for interfaces (runtime_checkable)
- Async/await for I/O operations
- No ABC — use Protocol

## Project Structure
```
src/exemplar/
    __init__.py
    schemas.py          # Frozen models, StrEnums
    config.py           # YAML + Pydantic config
    intake.py           # Diff parsing, field classification
    circuit.py          # Baton-style stage routing
    assessor.py         # Merge assessments, trust scoring
    reporter.py         # Format reports (JSON, Markdown, GitHub)
    chronicle.py        # Chronicler event emission
    learner.py          # Apprentice integration
    cli.py              # argparse entry point
    mcp_server.py       # MCP tools (stdio)
    reviewers/
        __init__.py
        base.py         # ReviewerProtocol
        security.py     # OWASP, secret detection
        correctness.py  # Logic errors, null checks
        style.py        # Convention violations
        architecture.py # Coupling, layer violations
```

## Testing
- pytest + pytest-asyncio
- One test file per module in tests/
- No mocking of core logic — mock only external I/O
- No GPU, API keys, or network required

## Naming
- Models: PascalCase
- Functions: snake_case
- Constants: UPPER_SNAKE_CASE
- Files: snake_case matching module name
- Package namespace: exemplar (all imports: from exemplar.X import Y)

## Governance Stack Integration
- Each integration must be a real, functional integration point
- Fire-and-forget for optional integrations (unreachable services don't block)
- PACT keys embedded in all public methods for Sentinel attribution
- Chronicler events at every stage boundary
- Deterministic reporter output for testability
