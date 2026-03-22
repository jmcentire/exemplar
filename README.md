# Exemplar

Reference implementation of the governance stack. A governed code review service built with every tool in the stack — not as a demo, but as the actual product.

## What This Is

A CLI and MCP tool that accepts pull request diffs, routes them through multi-stage analysis (security, correctness, style, architecture), and produces verified review reports with full audit trails. Every component was specified by Constrain, decomposed by Pact, routed by Baton, trust-scored by Arbiter, and sealed by Tessera. Works fully offline — no external APIs required.

See [ECOSYSTEM.md](ECOSYSTEM.md) for the full governance stack guide.

## Quick Start

```bash
pip install exemplar-review

# Review a diff
exemplar review my_changes.diff

# Review with markdown output
exemplar review my_changes.diff --format md

# Show reviewer trust scores
exemplar trust

# Query past review patterns
exemplar history
```

## Components

| # | Component | What It Does |
|---|-----------|-------------|
| 1 | **schemas** | Frozen Pydantic v2 models, StrEnums, field classifications |
| 2 | **config** | YAML config with fail-fast validation |
| 3 | **intake** | Diff parsing, hunk classification |
| 4 | **circuit** | Baton-style stage routing, circuit breakers |
| 5 | **reviewers** | Security, Correctness, Style, Architecture — each policy-scoped |
| 6 | **assessor** | Trust-weighted merge of conflicting assessments |
| 7 | **reporter** | JSON/Markdown/GitHub output with Tessera hash-chain seal |
| 8 | **chronicle** | Structured events at every stage boundary |
| 9 | **learner** | Shadow-mode comparison against human ground truth |
| 10 | **governance** | Signet-Eval preflight: red lines and plan Bs before implementation |
| 11 | **cli** | Entry point, Kindex history, Cartographer adoption scanning |
| 12 | **mcp_server** | MCP tools: exemplar_review, exemplar_trust, exemplar_history |

## What You'll See

Each source file demonstrates a specific governance pattern.

| File | Pattern | What to Look For |
|------|---------|-----------------|
| `schemas.py` | Pact + Ledger | Frozen models, field classifications, StrEnums |
| `config.py` | Constrain | YAML validation, fail-fast, constraint boundaries |
| `intake.py` | Ledger | Diff parsing, field-level classification |
| `circuit.py` | Baton | Stage routing, circuit breaker, parallel execution |
| `reviewers.py` | Agent-Safe + Signet | Policy-scoped analysis, credentials |
| `assessor.py` | Arbiter | Trust-weighted merge, conflict resolution |
| `reporter.py` | Tessera | Deterministic output, hash-chain seal |
| `governance.py` | Signet-Eval | Preflight red lines, plan Bs, Kindex lessons |
| `learner.py` | Apprentice + Stigmergy | Shadow comparison, pattern recording |
| `cli.py` | Pact + Kindex + Cartographer | PACT keys, history, adoption |

## Tests

**1,979 passing** across 43 test files covering contracts, emissions, and Goodhart (hidden adversarial) suites.

```bash
python -m pytest tests/
```

## The Stack

| Project | What It Does |
|---------|-------------|
| **Constrain** | Interviews you about boundaries, produces constraint artifacts before code exists |
| **Pact** | Contract-first decomposition, typed interfaces, visible + hidden tests |
| **Signet-Eval** | Preflight red lines and contingency plans, established before goal pressure |
| **Baton** | Circuit orchestration — stage routing, circuit breakers, taint analysis |
| **Sentinel** | Production monitoring, error attribution via PACT keys, contract tightening |
| **Ledger** | Schema registry with field-level data classification (PII, SECRET, INTERNAL, PUBLIC) |
| **Arbiter** | Trust scoring — six-factor model, conflict resolution by weighted merge |
| **Chronicler** | Event collection, story assembly from correlated events |
| **Stigmergy** | Organizational pattern discovery via ART neural networks |
| **Apprentice** | Adaptive model distillation — shadow, canary, primary, autonomous |
| **Kindex** | Persistent knowledge graph across sessions |
| **Cartographer** | Stack adoption scanning for existing codebases |
| **Agent-Safe** | Authorization policy language — SPL in ~2 microseconds, Ed25519 signing |
| **Signet** | Sovereign agent identity — encrypted vault, ZK selective disclosure |
| **Tessera** | Self-validating documents — SHA-256 hash chain, Ed25519 signatures |
| **BlindDB** | Client-side encryption — server stores opaque blobs |
| **HermesP2P** | Decentralized agent messaging — ephemeral, Ed25519 signed |

See [ECOSYSTEM.md](ECOSYSTEM.md) for the full guide — how they compose, integration contracts, invariants, and how to build your own.

## License

MIT
