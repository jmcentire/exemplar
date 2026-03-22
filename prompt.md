# Exemplar: Governed Code Review Service

Build a code review service that demonstrates the full FOSS governance stack. The service accepts PR diffs, routes them through multi-stage analysis (security, correctness, style, architecture), and produces verified review reports with full audit trails.

## Core Requirements

**Primary Function**: CLI + MCP tool that reviews code changes. Each review stage is a pluggable reviewer behind a Protocol. Assessments are trust-scored and merged into a sealed report.

**Architecture**: Circuit routing (Baton pattern) through reviewer stages. Each reviewer scoped by Agent-Safe policy tokens. Assessments weighted by Arbiter trust scores. Reports sealed by Tessera hash chains.

**Governance**: Every integration point is real. Chronicler events at stage boundaries. Stigmergy signals for pattern detection. Apprentice shadow mode for learning. Kindex for knowledge persistence. Sentinel for production monitoring.

## Technical Stack

- Python 3.12+ with async/await
- Pydantic v2 frozen models
- PyYAML for configuration
- aiohttp for async HTTP
- Protocol classes for all interfaces
- Works fully offline (no external APIs required)

## CLI Interface

```bash
exemplar review <diff-file> [--config path] [--format json|md|github]
exemplar trust                                    # Show reviewer trust scores
exemplar history [--query "security findings"]    # Kindex query
exemplar adopt [project-path]                     # Cartographer discovery
```

## Success Criteria

1. All governance stack integrations are functional, not stubs
2. A user reading the code can learn every stack pattern
3. Deterministic output for testability
4. Works offline with local reviewer implementations
5. Each component shows exactly one governance pattern clearly
