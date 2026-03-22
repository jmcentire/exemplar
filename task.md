# Task: Build Exemplar

Build a **governed code review service** — a CLI + MCP tool that accepts pull request diffs, routes them through multi-stage analysis (security, correctness, style, architecture), and produces verified review reports with full audit trails. Every stage is governed by the FOSS governance stack.

This is the reference implementation for the stack. A user reading this project sees: "This is how you build software when you have Pact, Constrain, Baton, Sentinel, Ledger, Arbiter, Chronicler, Stigmergy, Apprentice, Kindex, Cartographer, Agent-Safe, Signet, and Tessera available." Each integration is real — not a demo stub, not a bolted-on example. The governance IS the product.

## Why Code Review

Code review naturally exercises every governance concern:

- **Multiple analysis stages** → Baton routes diffs through circuits (security → correctness → style → architecture)
- **Trust and authority** → Arbiter scores reviewer agents, weighs conflicting assessments
- **Data classification** → Ledger classifies diff fields (secrets, PII, internal APIs)
- **Constraint boundaries** → Constrain defines what reviewers can/can't flag
- **Contract-first design** → Pact decomposes the service, generates tests
- **Production monitoring** → Sentinel watches for review quality drift
- **Event storytelling** → Chronicler assembles the story of each review (from PR open → analysis → decision)
- **Pattern discovery** → Stigmergy detects recurring code smells, reviewer blind spots
- **Model distillation** → Apprentice learns which review comments get accepted vs dismissed
- **Knowledge capture** → Kindex stores review patterns, codebase context
- **Stack adoption** → Cartographer discovers existing review tooling, proposes migration
- **Authorization** → Agent-Safe policy tokens control which reviewers see which repos
- **Agent identity** → Signet credentials for each reviewer agent
- **Verified results** → Tessera self-validating review documents (tamper-proof audit trail)
- **Encrypted storage** → BlindDB patterns for storing review data at rest
- **Agent communication** → HermesP2P for reviewer-to-reviewer negotiation on conflicts

## Core Architecture

```
PR Diff → Intake → Circuit (Baton) → [Security, Correctness, Style, Architecture]
                                        ↓ each stage
                                    Reviewer Agent (Agent-Safe scoped)
                                        ↓
                                    Assessment (Arbiter trust-scored)
                                        ↓
                                    Chronicler event → Stigmergy signal
                                        ↓
                               Merge assessments → Tessera-sealed report
```

## Components

1. **schemas** — Frozen Pydantic v2 models: DiffHunk, ReviewRequest, Assessment, ReviewReport, ReviewerCredential, TrustScore. StrEnums: Severity, Confidence, ReviewStage.

2. **config** — YAML + Pydantic config: reviewer circuits (which stages, thresholds), Ledger field classifications, Arbiter trust weights, Apprentice routing config. Fail-fast validation.

3. **intake** — Parse unified diffs into DiffHunk records. Extract file paths, changed lines, context. Classify hunks via Ledger field rules (secrets? PII? internal APIs?). Async.

4. **circuit** — Baton-style circuit routing. Routes DiffHunks through configured review stages. Parallel where independent, sequential where ordered. Handles stage failures gracefully (circuit breaker pattern).

5. **reviewers** — ReviewerProtocol (runtime_checkable). Implementations: SecurityReviewer (OWASP patterns, secret detection), CorrectnessReviewer (logic errors, null checks, off-by-ones), StyleReviewer (convention violations), ArchitectureReviewer (coupling, layer violations). Each scoped by Agent-Safe policy token.

6. **assessor** — Merge multiple reviewer assessments into a single ReviewReport. Uses Arbiter trust-scoring: reviewers with higher trust get more weight. Handles conflicting assessments (security says block, style says pass). Produces confidence scores.

7. **reporter** — Format ReviewReport as JSON, Markdown, or GitHub-compatible comment. Deterministic output. Includes Tessera seal (hash-chain proof that the report hasn't been tampered with).

8. **chronicle** — Emit Chronicler events at each stage (review.started, stage.complete, assessment.merged, report.sealed). Enables story assembly: "the full lifecycle of PR #42's review."

9. **learner** — Apprentice integration. Shadow mode: compare AI review to human review. Track which comments get accepted/dismissed. Feed patterns back to reviewers. Phase progression: shadow → canary → primary.

10. **cli** — Entry point: `exemplar review <diff-file> [--config path] [--format json|md|github]`. Also: `exemplar trust` (show reviewer trust scores), `exemplar history` (Kindex query of past reviews), `exemplar adopt` (Cartographer: discover existing review config).

11. **mcp_server** — MCP tools: exemplar_review, exemplar_trust, exemplar_history. Stdio transport.

## Package

- Package: exemplar (at src/exemplar/)
- PyPI name: exemplar-review
- Version: 0.1.0
- Python >=3.12
- Dependencies: pydantic>=2.0, pyyaml>=6.0, aiohttp>=3.9
- Works fully offline (no external APIs required — local reviewer implementations)

## What This Demonstrates to Users

A user examining Exemplar should be able to say:

1. "Constrain defined what the service can and can't do before any code was written."
2. "Pact decomposed it into contracts, generated tests, and verified the implementation."
3. "Baton routes diffs through the review circuit — I can see how to build my own circuits."
4. "Sentinel monitors review quality in production — same pattern I'd use for my service."
5. "Ledger classifies data fields — now I know how to protect PII in my project."
6. "Arbiter trust-scores outputs — this is how I'd handle conflicting AI assessments."
7. "Chronicler tells the story of each review — I see how events become narratives."
8. "Stigmergy finds patterns — it detects things no single component can see."
9. "Apprentice learns from outcomes — this is how distillation works in practice."
10. "Kindex remembers everything — persistent knowledge across sessions."
11. "Agent-Safe controls what agents can do — real authorization, not toy ACLs."
12. "Tessera makes the output tamper-proof — self-validating documents."
13. "The whole thing was built with the stack. I can do this too."
