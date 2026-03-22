# AGENTS.md — Machine-Readable Project Primer

## Identity

- Package: exemplar | PyPI: exemplar-review | Version: 0.1.0
- Namespace: exemplar.* (via conftest.py sys.path injection from src/)
- Python >=3.12 | Deps: pydantic>=2.0, PyYAML>=6.0, aiohttp>=3.9 | Optional: mcp>=1.0
- 12 components (11 + root) | 2027 tests (276+126+158+117+152+154+176+185+163+172+227+145 per component, hidden goodhart tests not counted separately)
- Governed code review service: CLI + MCP that routes PR diffs through multi-stage analysis

## What This Is

A reference implementation demonstrating the full governance stack: Pact (contracts), Constrain (boundaries), Baton (circuits), Sentinel (monitoring), Ledger (classification), Arbiter (trust), Chronicler (events), Stigmergy (patterns), Apprentice (distillation), Kindex (knowledge), Agent-Safe (authorization), Signet (identity), Tessera (seals), Signet-Eval (preflight).

Pipeline: `Diff -> intake -> circuit -> [security, correctness, style, architecture] reviewers -> assessor merge -> reporter seal -> output`

## Import Map

Each component lives at `src/{component}/{component}.py`. The conftest.py at root wires `exemplar.{component}` -> `src/{component}`.

```
exemplar.schemas    -> src/schemas/schemas.py      # _ExemplarBase, all frozen models, 9 StrEnums, 16 domain models
exemplar.config     -> src/config/config.py        # YAML+Pydantic, ExemplarConfig, load_config(), default_config()
exemplar.intake     -> src/intake/intake.py        # parse_diff(), classify_hunks(), run_intake()
exemplar.circuit    -> src/circuit/circuit.py      # ReviewCircuit class, run(), resolve_execution_plan()
exemplar.reviewers  -> src/reviewers/reviewers.py  # ReviewerProtocol + Security/Correctness/Style/Architecture impls
exemplar.assessor   -> src/assessor/assessor.py    # merge_assessments() — Arbiter trust-weighted merge
exemplar.reporter   -> src/reporter/reporter.py    # format_report(), seal_report(), verify_seal() — Tessera
exemplar.chronicle  -> (emitted via governance)    # Chronicler events at stage boundaries
exemplar.learner    -> src/learner/learner.py      # record_decision(), detect_patterns(), check_phase_progression()
exemplar.governance -> src/governance/governance.py # seal, emit, filter_hunks, check_token, score, classify, kindex ops
exemplar.cli        -> src/cli/cli.py              # build_parser(), main(), handle_review/trust/history/adopt
exemplar.mcp_server -> src/mcp_server/mcp_server.py # create_server(), run_server(), handle_review/trust/history
```

## Dependency Graph

```
schemas     -> (no internal deps — leaf node, everything depends on this)
config      -> schemas (ExemplarConfig references ReviewStage, ClassificationLabel, LearnerPhase, Severity)
governance  -> schemas (TesseraSeal, ChroniclerEvent, PolicyToken, ReviewerCredential, StigmergySignal, KindexEntry, TrustScore, ClassificationLabel)
intake      -> schemas, config (DiffHunk, ReviewRequest, ClassificationLabel; LedgerConfig rules)
reviewers   -> schemas, config (ReviewerProtocol produces Assessment/Finding; PolicyToken scopes access)
circuit     -> schemas, config, reviewers (ReviewCircuit invokes ReviewerProtocol impls per CircuitConfig)
assessor    -> schemas, config (merges list[Assessment] -> ReviewReport using TrustScore weights)
reporter    -> schemas (formats ReviewReport; seals via TesseraSeal; verify_seal)
learner     -> schemas, config (LearningRecord, StigmergySignal, ApprenticeConfig, LearnerPhase)
cli         -> schemas, config, intake, circuit, reviewers, assessor, reporter, learner, governance
mcp_server  -> schemas, config, intake, circuit, reviewers, assessor, reporter, learner, governance
root        -> (integration/orchestration of all components)
```

## Type Registry (29 shared types from decomposition/type_registry.json)

### Enums (9) — all StrEnum
| Type | Variants | Owner |
|------|----------|-------|
| Severity | critical, high, medium, low, info | schemas |
| Confidence | high, medium, low | schemas |
| ReviewStage | security, correctness, style, architecture | schemas |
| ReviewDecision | block, warn, pass | schemas |
| LearnerPhase | shadow, canary, primary | schemas |
| OutputFormat | json, md, github | schemas |
| ClassificationLabel | secret, pii, internal_api, public | schemas |
| ChroniclerEventType | review.started, stage.started, stage.complete, assessment.merged, report.sealed, review.complete, policy.violation, pattern.detected, learning.recorded | schemas |
| CliExitCode | 0, 1, 2, 3 | schemas |
| StigmergyVerb | deposit, reinforce, decay, query | schemas |

### Structs (19) — all frozen=True, extra="forbid"
| Type | Owner | Key Fields |
|------|-------|------------|
| _ExemplarBase | schemas | PACT_KEY ClassVar, canonical_bytes(), canonical_hash() |
| DiffHunk | schemas | id, file_path, start_line_old/new, added_lines, removed_lines, classifications, language |
| ReviewRequest | schemas | id, source, hunks: list[DiffHunk], file_paths, created_at, metadata |
| Finding | schemas | id, hunk_id, file_path, line_number, severity, confidence, title, description, suggestion, rule_id, stage |
| Assessment | schemas | id, review_request_id, stage, reviewer_id, decision, findings, confidence, is_partial, duration_ms |
| TrustScore | schemas | reviewer_id, stage, weight: float [0.0-1.0], accepted_count, dismissed_count |
| TesseraSeal | schemas | content_hash, previous_hash, chain_hash, sealed_at, sealer_id |
| ReviewReport | schemas | id, review_request_id, decision, findings, assessments, confidence, trust_scores, conflict_notes, summary, seal |
| ReviewerCredential | schemas | reviewer_id, display_name, stage, public_key_hex, is_active |
| PolicyToken | schemas | token_id, reviewer_id, allowed/denied_file_patterns, allowed_classifications, max_severity, expires_at |
| ChroniclerEvent | schemas | event_id, event_type, review_request_id, timestamp, stage, reviewer_id, payload, message |
| StigmergySignal | schemas | signal_id, pattern_key, description, occurrences, first/last_seen_at, reviewer_id, stage |
| LearningRecord | schemas | record_id, finding_id, reviewer_id, stage, rule_id, severity, accepted: bool, human_comment |
| KindexEntry | schemas | key, kind, summary, data, tags, created_at, updated_at |
| PipelineResult | schemas | review_request, assessments, report, events, formatted_output, output_format, exit_code |
| ExemplarConfig | config | circuit, reviewers, ledger, apprentice, chronicle_log_path, kindex_store_path, stigmergy_store_path, seal_chain_path |
| CircuitConfig | config | stages, parallel_stages, stage_timeout_ms, block_threshold, warn_threshold |
| ReviewerConfig | config | enabled, stage, default_trust_weight, allowed/denied_file_patterns, allowed_classifications, max_severity |
| LedgerFieldRule | config | pattern (regex), label: ClassificationLabel, description |
| LedgerConfig | config | rules: list[LedgerFieldRule], default_label |
| ApprenticeConfig | config | phase: LearnerPhase, storage_path, shadow_to_canary_threshold, canary_to_primary_threshold |

## Contract Locations

```
contracts/{component}/interface.json   — typed function signatures (DO NOT MODIFY)
contracts/{component}/interface.py     — code-shaped stub (DO NOT MODIFY)
contracts/{component}/history/         — contract revision history
```

Components with contracts: schemas, config, intake, circuit, reviewers, assessor, reporter, learner, cli, mcp_server, governance, root

## Test Locations

```
tests/{component}/contract_test.py                — visible contract tests
tests/{component}/goodhart/goodhart_test.py        — hidden adversarial tests (catch gaming)
tests/{component}/goodhart/goodhart_test_suite.json — goodhart test definitions
tests/{component}/emission_test.py                 — structured event emission tests
```

Some components have additional conftest.py: intake, learner, config/goodhart, reporter/goodhart, reviewers/goodhart, learner/goodhart

### Test Counts Per Component
| Component | Tests |
|-----------|-------|
| schemas | 276 |
| config | 126 |
| intake | 158 |
| circuit | 117 |
| reviewers | 152 |
| assessor | 154 |
| reporter | 176 |
| learner | 185 |
| cli | 163 |
| mcp_server | 172 |
| governance | 227 |
| root | 145 |

## Run Tests

```bash
# All tests (exclude root integration tests)
python3 -m pytest tests/ --import-mode=importlib --ignore-glob="**/root/*" -q

# Single component
python3 -m pytest tests/schemas/ --import-mode=importlib -q

# Only contract tests
python3 -m pytest tests/schemas/contract_test.py --import-mode=importlib -q

# Only goodhart tests
python3 -m pytest tests/schemas/goodhart/goodhart_test.py --import-mode=importlib -q

# Only emission tests
python3 -m pytest tests/schemas/emission_test.py --import-mode=importlib -q
```

## Governance Pattern Map

| File | Pattern | Stack Tool | What To Look For |
|------|---------|------------|------------------|
| src/schemas/schemas.py | Pact + Ledger | Pact, Ledger | frozen models, field classifications, StrEnums, PACT_KEY ClassVar |
| src/config/config.py | Constrain | Constrain | YAML validation, fail-fast, constraint boundaries |
| src/intake/intake.py | Ledger | Ledger | Diff parsing, field-level classification via regex rules |
| src/circuit/circuit.py | Baton | Baton | Stage routing, circuit breaker, parallel execution, timeout |
| src/reviewers/reviewers.py | Agent-Safe + Signet | Agent-Safe, Signet | ReviewerProtocol, policy-scoped analysis, credentials |
| src/assessor/assessor.py | Arbiter | Arbiter | Trust-weighted merge, conflict resolution |
| src/reporter/reporter.py | Tessera | Tessera | Deterministic output, hash-chain seal, verify_seal |
| src/governance/governance.py | Chronicler + Agent-Safe + Signet + Arbiter + Ledger + Stigmergy + Kindex + Tessera | Multiple | Unified governance module: seal, emit, filter, classify, score, kindex ops |
| src/learner/learner.py | Apprentice + Stigmergy | Apprentice, Stigmergy | Shadow comparison, pattern recording, phase progression |
| src/cli/cli.py | Pact + Kindex + Cartographer | Pact, Kindex, Cartographer | PACT keys, history query, adoption scanning |
| src/mcp_server/mcp_server.py | MCP | MCP | stdio transport, exemplar_review/trust/history tools |

## Red Lines (from signet-eval preflight)

- Do NOT modify `contracts/**/*.json` — these are the law
- Do NOT modify `contracts/**/*.py` — code-shaped stubs, not implementation
- Do NOT delete anything under `tests/`
- Do NOT use `eval()`, `exec()`, or `__import__()`
- Do NOT silence `ImportError` with `try/except/pass`
- Do NOT modify `decomposition/type_registry.json` or `decomposition/tree.json`
- Do NOT modify `constraints.yaml`, `trust_policy.yaml`, `component_map.yaml`, `schema_hints.yaml`, or `prompt.md` (Constrain output)

## Key Conventions

- All models: `frozen=True`, `extra="forbid"` via Pydantic v2 ConfigDict
- All enums: `StrEnum` (never plain `Enum`)
- All interfaces: `Protocol` with `@runtime_checkable` (never ABC)
- All async: `asyncio` — fire-and-forget for optional integrations (unreachable services never block)
- PACT keys: `PACT:exemplar:{component}:{method}` — embedded in all public methods for Sentinel attribution
- Chronicler events: fire-and-forget, never block pipeline
- Timestamps: ISO 8601 strings validated via `IsoTimestamp` annotated type
- IDs: deterministic from content where possible (hunk IDs from content hash)
- Config: YAML-driven, fail-fast validation at load time
- CLI exit codes: 0=pass, 1=issues found, 2=config error, 3=runtime error
- Output formats: json, markdown, github (deterministic, sorted keys)
- Seal chain: SHA-256 hash chain via Tessera pattern, previous_hash links seals

## Source File Layout

```
src/
  {component}/
    __init__.py          # package init
    {component}.py       # implementation
```

Implementation files are self-contained — each component reimplements its own Pydantic models and enums internally rather than cross-importing from schemas. The canonical types in `decomposition/type_registry.json` define the contract; implementations must be structurally compatible.

## Build Order (by dependency depth)

1. schemas (leaf — no deps)
2. config (depends on: schemas)
3. governance (depends on: schemas)
4. intake (depends on: schemas, config)
5. reviewers (depends on: schemas, config)
6. circuit (depends on: schemas, config, reviewers)
7. assessor (depends on: schemas, config)
8. reporter (depends on: schemas)
9. learner (depends on: schemas, config)
10. cli (depends on: all above)
11. mcp_server (depends on: all above)
12. root (integration orchestration)

## Quick Reference: Function Signatures Per Component

### schemas
`severity_rank()`, `confidence_rank()`, `learner_phase_rank()`, `canonical_bytes()`, `canonical_hash()`, `validate_iso_timestamp()`

### config
`default_config() -> ExemplarConfig`, `resolve_config_path() -> Path`, `load_config(path) -> ExemplarConfig`, `config_to_yaml(config) -> str`

### intake
`parse_diff(raw) -> list[DiffHunk]`, `classify_hunks(hunks, config) -> list[DiffHunk]`, `run_intake(raw, config) -> ReviewRequest`, `generate_hunk_id()`, `generate_request_id()`, `detect_language(path) -> str|None`

### circuit
`ReviewCircuit.__init__(config, reviewers)`, `run(request) -> list[Assessment]`, `resolve_execution_plan()`, `invoke_reviewer(reviewer, hunks)`, `get_stage_timeout()`, `get_execution_plan()`

### reviewers
`filter_hunks_by_policy(hunks, token)`, `derive_decision(findings)`, `build_assessment(...)`, `SecurityReviewer.review(hunks)`, `CorrectnessReviewer.review(hunks)`, `StyleReviewer.review(hunks)`, `ArchitectureReviewer.review(hunks)`, `get_all_reviewers()`, `get_reviewer_by_stage(stage)`

### assessor
`merge_assessments(assessments, trust_scores) -> ReviewReport`

### reporter
`canonicalize(report) -> bytes`, `seal_report(report, prev_hash?) -> ReviewReport`, `verify_seal(report) -> bool`, `format_report(report, fmt) -> str`, `render_json(report)`, `render_markdown(report)`, `render_github(report)`

### learner
`record_decision(finding, accepted)`, `record_human_decisions(decisions)`, `get_trust_adjustments()`, `check_phase_progression()`, `detect_patterns()`, `get_current_phase()`, `should_apply_adjustments()`, `get_stats()`, `initialize_state()`

### governance
`seal(content)`, `verify_seal(content, seal)`, `emit(event)`, `query_events(filter)`, `filter_hunks(hunks, token)`, `check_token(token)`, `create_credential()`, `verify_credential()`, `score(reviewer_id)`, `update_trust()`, `classify(hunk)`, `classify_all(hunks)`, `record_signal()`, `query_signals()`, `kindex_get(key)`, `kindex_put(key, entry)`, `kindex_query_by_tags(tags)`

### cli
`build_parser()`, `parse_and_validate_args()`, `handle_review()`, `handle_trust()`, `handle_history()`, `handle_adopt()`, `build_dispatch_table()`, `map_decision_to_exit_code(decision) -> int`, `main()`

### mcp_server
`create_server()`, `run_server()`, `handle_review()`, `handle_trust()`, `handle_history()`, `build_tool_error()`, `build_success_result()`
