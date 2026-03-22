# Exemplar: Full-Stack Governance Showcase

## What This Is

Exemplar is a governed code review service that demonstrates how all 17+ projects in the FOSS governance stack compose into a working system. It's not a toy — it solves a real problem (automated code review) while showing every integration pattern.

A user examining Exemplar sees exactly how to use Pact, Constrain, Baton, Sentinel, Ledger, Arbiter, Chronicler, Stigmergy, Apprentice, Kindex, Cartographer, Agent-Safe, Signet, and Tessera together.

## How Each Project Appears

| Project | Role in Exemplar | Pattern Demonstrated |
|---------|-----------------|---------------------|
| **Constrain** | Defined all project boundaries before any code existed | Specification before implementation |
| **Pact** | Decomposed into contracts, generated tests, verified implementation | Contract-first engineering |
| **Baton** | Routes diffs through review stages (circuit routing) | Topology-first orchestration |
| **Sentinel** | Monitors review quality drift in production | Production attribution via PACT keys |
| **Ledger** | Classifies diff hunks (secrets, PII, internal APIs) | Field-level data governance |
| **Arbiter** | Trust-scores reviewer outputs, resolves conflicts | Six-factor trust model |
| **Chronicler** | Events at every stage boundary → story assembly | Event correlation into narratives |
| **Stigmergy** | Detects recurring code smells, reviewer blind spots | Organizational pattern discovery |
| **Apprentice** | Shadow mode: compare AI review to human decisions | Adaptive model distillation |
| **Kindex** | Stores review patterns, codebase context | Persistent knowledge graph |
| **Cartographer** | Discovers existing review config in projects | Stack adoption tooling |
| **Agent-Safe** | Policy tokens scope each reviewer's access | Authorization policy language |
| **Signet** | Credentials for each reviewer agent | Personal sovereign agent identity |
| **Tessera** | Hash-chain sealed review reports | Self-validating documents |
| **BlindDB** | Encrypted storage patterns for review data | Client-side encryption model |
| **HermesP2P** | Reviewer-to-reviewer negotiation on conflicts | Decentralized agent messaging |

## Architecture

```
PR Diff → Intake (Ledger classification)
       → Circuit (Baton routing)
       → [Security, Correctness, Style, Architecture] (Agent-Safe scoped reviewers)
       → Assessor (Arbiter trust-weighted merge)
       → Reporter (Tessera-sealed output)
       → Chronicle (Chronicler events at every step)
       → Learner (Apprentice shadow/canary/primary)
       → Kindex (persistent knowledge capture)
```

## Universal Conventions (from all 17 projects)

- Python 3.12+, Pydantic v2, frozen=True
- StrEnum for enumerated types
- Protocol classes (not ABC) for all interfaces
- src/package_name/ layout
- YAML config with Pydantic validation, fail-fast on invalid
- JSONL for append-only persistence
- asyncio for I/O-bound operations
- Fire-and-forget for optional integrations
- pytest with one test file per module

## Package

- **Package**: exemplar
- **PyPI name**: exemplar-review
- **Version**: 0.1.0
- **License**: MIT
- **Entry point**: `exemplar = "exemplar.cli:main"`
- **Dependencies**: pydantic>=2.0, pyyaml>=6.0, aiohttp>=3.9
