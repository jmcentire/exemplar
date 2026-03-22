# The Governance Stack

This document explains every project in the stack, how they compose, and how Exemplar demonstrates each one. If you're reading this, you're holding a working example of what governed software looks like.

## The Problem

Software built by AI agents has a trust problem. The agent writes code — but who verifies it? Who monitors it in production? Who detects when it drifts? Who classifies the data it touches? Who controls what it can access? Who proves the output hasn't been tampered with?

No single tool solves this. It requires a stack — each tool with one job, composing through well-defined interfaces.

## The Lifecycle

Every governed project moves through these phases:

```
DEFINE ──→ DECOMPOSE ──→ BUILD ──→ PREFLIGHT ──→ DEPLOY ──→ MONITOR ──→ LEARN
  │            │            │          │            │          │           │
Constrain    Pact         Pact    Signet-Eval    Baton    Sentinel    Apprentice
              │                                             │         Stigmergy
           Ledger                                       Chronicler
           Arbiter                                          │
                                                         Kindex
```

**Define**: What can this system do? What must it NOT do? What data does it touch? Who do we trust?
**Decompose**: Break it into components. Define contracts. Generate tests. Before any code exists.
**Build**: Implement each component. Verify against contracts. Catch gaming with hidden tests.
**Preflight**: Before implementation begins, establish red lines and contingency plans. Commitments made before goal pressure exists.
**Deploy**: Route traffic through circuits. Classify data fields. Score trust.
**Monitor**: Watch production. Attribute errors. Detect drift. Assemble stories.
**Learn**: Discover patterns. Distill models. Remember everything.

## The Projects

### Constrain — Specification Before Code

**What it does**: Interviews you about your project's boundaries. Produces five artifacts that define what you're building before any code exists.

**Artifacts**:
- `constraints.yaml` — Hard rules the system must follow
- `trust_policy.yaml` — Who and what you trust, and how much
- `component_map.yaml` — The system's parts and their relationships
- `schema_hints.yaml` — Data shapes and validation rules
- `prompt.md` — The synthesized project brief

**Why it exists**: Code written without constraints drifts. LLMs especially need boundaries — they'll build anything you ask for, including things you didn't mean. Constrain captures intent before implementation can distort it.

**In Exemplar**: The `constraints.yaml`, `trust_policy.yaml`, `component_map.yaml`, `schema_hints.yaml`, and `prompt.md` files at the project root ARE Constrain's output. They were produced before any code was written. Every component in Exemplar traces back to a constraint.

**Install**: `pip install constrain-elicit`
**CLI**: `constrain new` (start interview), `constrain show` (display artifacts)

---

### Pact — Contract-First Engineering

**What it does**: Decomposes a task into components, generates typed interface contracts for each one, generates executable tests (visible + hidden), and verifies implementations against those contracts. No code is written until the contracts exist.

**Key concepts**:
- **Interview**: Identifies risks, ambiguities, and assumptions. Asks clarifying questions.
- **Decomposition**: Task → component tree (2-7 components per level)
- **Type registry**: Canonical shared types generated once, enforced mechanically across all components
- **Contract**: Function signatures, preconditions, postconditions, error cases, side effects
- **Interface stub**: Code-shaped reference document — looks like actual code, not JSON schema
- **Goodhart tests**: Hidden adversarial tests that catch implementations that "teach to the visible tests"
- **Processing register**: The cognitive mode governing all agent work

**Why it exists**: Without contracts, AI agents produce code that passes the tests they can see while violating the spec in ways they can't. Pact separates specification from implementation. The contracts are the law; the tests enforce the law; the hidden tests catch cheaters.

**In Exemplar**: The `contracts/` directory contains Pact-generated contracts for every component. The `tests/` directory contains Pact-generated test suites. The `decomposition/` directory shows the interview, decomposition tree, and type registry. The entire project structure was determined by Pact before any implementation code existed.

**Install**: `pip install pact-agents`
**CLI**: `pact run <project>` (full pipeline), `pact status <project>`, `pact build <project> <component>`

---

### Baton — Circuit Orchestration

**What it does**: Routes requests through service stages. Topology-first design — you define the circuit (which services, in what order, with what fallbacks), and Baton handles routing, A/B testing, canary deployment, circuit breakers, and taint analysis.

**Key concepts**:
- **Circuit**: A directed graph of service stages
- **Smart adapters**: Transform data between stages
- **Circuit breaker**: A failing stage degrades gracefully instead of crashing the pipeline
- **Taint analysis**: Track which data touched which services
- **DORA metrics**: Deployment frequency, lead time, change failure rate, recovery time

**Why it exists**: Services don't exist in isolation. They compose into circuits. Baton makes the composition explicit and manageable — you can see the circuit, reason about it, and change it without touching the services themselves.

**In Exemplar**: `circuit.py` implements the Baton pattern. Diff hunks are routed through review stages (security → correctness → style → architecture). If a reviewer fails, the circuit breaker records a degraded result instead of crashing the pipeline.

**Install**: `pip install baton-circuit`
**CLI**: `baton deploy <circuit.yaml>`, `baton status`, `baton metrics`

---

### Sentinel — Production Monitoring & Attribution

**What it does**: Watches production for errors, attributes them to the component that caused them using PACT keys, and spawns fixer agents. Can push tightened contracts back to Pact when production reveals gaps in the spec.

**Key concepts**:
- **PACT keys**: String literals embedded in code. When an error occurs, the key identifies which component produced it.
- **Attribution**: Maps errors to components via PACT keys
- **Contract tightening**: When production reveals a gap, Sentinel generates a tighter contract
- **Budget enforcement**: Multi-window spend caps prevent runaway remediation

**Why it exists**: Tests verify code before deployment. Sentinel verifies code after deployment. The gap between "passes all tests" and "works in production" is where most failures hide.

**In Exemplar**: Every public method embeds a PACT key. The `chronicle.py` module emits structured events with these keys. Sentinel would attribute every event to the exact function that produced it.

**Install**: `pip install sentinel-monitor`
**CLI**: `sentinel watch <project>`, `sentinel report <error>`

---

### Ledger — Schema Registry & Data Classification

**What it does**: Registers data schemas with field-level classifications. Every field gets a classification (PII, SECRET, INTERNAL, PUBLIC). These classifications propagate to every other tool.

**Why it exists**: Data governance fails when it's coarse-grained. "This service handles PII" tells you nothing actionable. "The `email` field in `UserProfile` is PII and must be masked on egress" — that's actionable. Ledger makes it field-level.

**In Exemplar**: `intake.py` classifies diff hunks using Ledger's pattern — each hunk gets classification tags (contains secrets? references internal APIs? modifies PII-adjacent code?).

**Install**: `pip install ledger-registry`
**CLI**: `ledger register <schema>`, `ledger classify <field>`

---

### Arbiter — Trust Scoring & Access Auditing

**What it does**: Scores trust for every output in the system. Six-factor model: base weight, age, consistency, taint, review, decay. Resolves conflicts by weighting outputs by trust score.

**Why it exists**: AI agents produce outputs, but not all outputs are equally trustworthy. A reviewer that's been consistently accurate for 100 reviews has earned more trust than one that just started. Arbiter makes trust computable, not assumed.

**In Exemplar**: `assessor.py` implements the Arbiter pattern. Each reviewer's Assessment carries a trust score. When assessments conflict, the assessor resolves by trust-weighted merge.

**Install**: `pip install arbiter-trust`
**CLI**: `arbiter scores`, `arbiter blast-radius <component>`

---

### Chronicler — Event Collection & Story Assembly

**What it does**: Collects events from multiple sources (webhooks, OTLP traces, log files, Sentinel incidents), correlates them into stories using configurable rules, and emits completed stories downstream.

**Key concepts**:
- **Event**: A single timestamped, content-addressable fact
- **Story**: A sequence of correlated events that form a narrative
- **Correlation rules**: group_by keys, timeout, terminal events, chain_by

**Why it exists**: Logs are noise. Events are facts. Stories are meaning. Chronicler turns noise into narrative.

**In Exemplar**: `chronicle.py` emits events at every stage boundary: `review.started`, `intake.complete`, `stage.started`, `stage.complete`, `assessment.merged`, `report.sealed`.

**Install**: `pip install chronicler`
**CLI**: `chronicler start <config.yaml>`, `chronicler stories --type request`

---

### Stigmergy — Organizational Pattern Discovery

**What it does**: Processes signals from across the system to detect organizational patterns that no single tool can see. Uses Adaptive Resonance Theory (ART) neural networks with consensus voting.

**Why it exists**: Individual tools see individual problems. Stigmergy sees patterns across problems. "Security findings are correlated with the new team's PRs, and that team has no security reviewer assigned" — that's a Stigmergy pattern.

**In Exemplar**: Review signals feed into Stigmergy. Over time, patterns emerge: "Architecture reviewer rarely finds anything in test files" or "Security findings in the payments directory have a 95% acceptance rate."

**Install**: `pip install stigmergy`
**CLI**: `stigmergy pulse`, `stigmergy insights`

---

### Apprentice — Adaptive Model Distillation

**What it does**: Routes between frontier API and local model. Shadow → canary → primary → autonomous progression based on quality metrics.

**Why it exists**: Frontier models are expensive. Apprentice bridges the gap by learning from the frontier model's decisions and progressively replacing it.

**In Exemplar**: `learner.py` implements shadow mode. Both Exemplar reviewers and a frontier model review the same diff. The learner compares outputs against human ground truth.

**Install**: `pip install apprentice-distill`
**CLI**: `apprentice status`, `apprentice phase`

---

### Kindex — Persistent Knowledge Graph

**What it does**: Indexes conversations, projects, and intellectual work into a persistent knowledge graph. Hybrid search (full-text + graph traversal). Session lifecycle tracking.

**Why it exists**: Knowledge decays between sessions. Kindex captures discoveries as they happen and surfaces them when relevant.

**In Exemplar**: `exemplar history` queries Kindex for past review patterns. Review results are stored as knowledge nodes.

**Install**: `pip install kindex`
**CLI**: `kin search "topic"`, `kin add "discovery"`

---

### Cartographer — Stack Adoption & Discovery

**What it does**: Scans existing codebases and discovers what's already there. Produces draft artifacts for stack adoption. Read-only invariant.

**Why it exists**: Adopting a governance stack is daunting from zero. Cartographer meets you where you are.

**In Exemplar**: `exemplar adopt <path>` scans for existing review tool configs and reports findings.

**Install**: `pip install cartographer-scan`
**CLI**: `cartographer discover <path>`

---

### Agent-Safe — Authorization Policy Language

**What it does**: Defines what agents can and cannot do. SPL evaluates in ~2 microseconds. Ed25519 signing, Merkle proofs, hash-chain offline budgets.

**Why it exists**: AI agents need authorization, not just authentication. Agent-Safe makes authorization fast, verifiable, and offline-capable.

**In Exemplar**: Each reviewer has a policy token defining its scope. The circuit checks tokens before routing hunks to reviewers.

**Available**: 6 SDKs (TypeScript, Python, Rust, Go, Java, Swift)

---

### Signet-Eval Preflight — Operational Red Lines

**What it does**: Before an agent implements a component, it establishes inviolable constraints and contingency plans — red lines and plan Bs. Submitted via MCP, HMAC-signed, time-locked. 5+ violations escalates to ASK-everything mode. Human override requires vault passphrase.

**Key concepts**:
- **Red lines**: Commitments made before goal pressure exists (no test deletion, no contract modification, no eval())
- **Plan Bs**: When a rule fires, redirect instead of just block (rm → trash, force-push → force-with-lease)
- **Timed lockout**: Plan is immutable for a configurable duration after submission
- **Escalation**: 5+ violations → agent must ask permission for everything
- **Kindex integration**: Previous run failures inform the next preflight

**Why it exists**: AI agents have get-there-itis. The fix isn't better judgment under pressure — it's commitments made before the pressure exists. Like a pilot's preflight checklist.

**In Exemplar**: `governance.py` includes preflight submission. Before any component is implemented, Pact's preflight phase queries Kindex for lessons, establishes red lines, and submits the plan to signet-eval.

**MCP tools**: signet_preflight_submit, signet_preflight_active, signet_preflight_history, signet_preflight_violations, signet_preflight_test

---

### Signet — Personal Sovereign Agent Stack

**What it does**: Sovereign identity for AI agents. Encrypted vault, steward agent, ZK proofs for selective disclosure.

**Why it exists**: Agents need identity that isn't just an API key. Signet makes agent identity sovereign.

**In Exemplar**: Each reviewer has a `ReviewerCredential` with identity, authorized stages, and trust tier.

---

### Tessera — Self-Validating Documents

**What it does**: Documents that prove their own integrity. SHA-256 hash chain, Ed25519 signatures, embedded validators.

**Why it exists**: Reports and audit trails need to be tamper-evident.

**In Exemplar**: `reporter.py` seals every ReviewReport with a hash-chain proof. `verify_seal()` confirms integrity.

**Available**: Rust crate + CLI

---

### BlindDB & HermesP2P — Stretch Goals

**BlindDB**: Client-side encryption — data encrypted before leaving the client, server stores opaque blobs.

**HermesP2P**: Decentralized agent messaging — Ed25519 signatures, X25519 key exchange, ephemeral by design.

Both are documented patterns, not yet implemented in Exemplar v0.1.0.

---

## How They Compose

### Integration Contracts

| From | To | What Flows | Format |
|------|-----|-----------|--------|
| Constrain | Pact | Project boundaries | YAML artifacts |
| Pact | Implementation | Typed contracts | Interface stubs + tests |
| Signet-Eval Preflight | Implementation agents | Red lines + contingencies | PreflightPlan JSON |
| Ledger | Everyone | Field classifications | Schema registry |
| Baton | Services | Routed requests | Circuit config |
| Sentinel | Pact | Tightened contracts | Contract JSON |
| Sentinel | Stigmergy | Error signals | Signal events |
| Chronicler | Stigmergy | Completed stories | Story JSON |
| Chronicler | Apprentice | Training sequences | Event sequences |
| Chronicler | Kindex | Knowledge | Story summaries |
| Arbiter | Assessor | Trust scores | Score objects |
| Agent-Safe | Circuit | Policy decisions | Allow/deny |
| Tessera | Reporter | Integrity seal | Hash chain |

### The Invariants

1. **Specification before code.** Constrain defines boundaries. Pact defines contracts. Implementation comes last.
2. **Trust is computed, not assumed.** Arbiter scores everything.
3. **Data classification is field-level.** Ledger classifies fields, not tables.
4. **Failures are graceful.** Every integration is fire-and-forget.
5. **Output is tamper-evident.** Tessera seals make modification detectable.
6. **Everything is remembered.** Kindex captures across sessions.
7. **Patterns emerge from signals.** Stigmergy discovers, not searches.
8. **Models get cheaper over time.** Apprentice replaces API calls with local inference.
9. **Agents declare constraints before execution.** Preflight plans are established at task-specification time, not under goal pressure.

## Reading the Code

| File | Governance Pattern | Look For |
|------|-------------------|----------|
| `schemas.py` | Pact + Ledger | Frozen models, field classifications, StrEnums |
| `config.py` | Constrain | YAML validation, fail-fast, constraint boundaries |
| `intake.py` | Ledger | Diff parsing, field-level classification |
| `circuit.py` | Baton | Stage routing, circuit breaker, parallel execution |
| `reviewers/*.py` | Agent-Safe + Signet | Policy-scoped analysis, credentials |
| `assessor.py` | Arbiter | Trust-weighted merge, conflict resolution |
| `reporter.py` | Tessera | Deterministic output, hash-chain seal |
| `chronicle.py` | Chronicler | Stage-boundary events, correlation keys |
| `learner.py` | Apprentice + Stigmergy | Shadow comparison, pattern recording |
| `cli.py` | Pact + Kindex + Cartographer | PACT keys, history, adoption |

## Building Your Own

1. **Start with Constrain.** `constrain new` — answer the interview. Get your artifacts.
2. **Feed them to Pact.** `pact run <dir>` — interviews, decomposes, contracts, tests.
3. **Implement.** Let Pact's code_author implement, or implement manually against contracts.
4. **Run preflight.** Before implementation begins, submit red lines and plan Bs to signet-eval. Query Kindex for lessons from previous runs.
5. **Add Ledger classifications.** Annotate models with field-level classifications.
6. **Wire Baton.** Define your circuit — stages, order, fallbacks.
7. **Embed PACT keys.** Add attribution to public functions.
8. **Emit Chronicler events.** Structured events at stage boundaries.
9. **Configure Sentinel.** Point it at your logs.
10. **Let the rest emerge.** Stigmergy discovers patterns. Apprentice learns. Kindex remembers. Arbiter scores. They activate as data flows.

You don't need all 17 projects on day one. Start with Constrain + Pact. Add Baton when you deploy. Add Sentinel when you monitor. The rest follows naturally.

---

*Built by Jeremy McEntire. Constrained, decomposed, implemented, verified, governed.*
