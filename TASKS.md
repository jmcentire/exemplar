# TASKS — exemplar
Progress: 36/95 completed (38%)

## Phase: Setup

- [ ] T001 Initialize project directory structure
- [ ] T002 Verify environment and dependencies

## Phase: Foundational

- [ ] T003 [P] Define shared type: Assessment
- [ ] T004 [P] Define shared type: ChroniclerEvent
- [ ] T005 [P] Define shared type: ChroniclerEventType
- [ ] T006 [P] Define shared type: CircuitConfig
- [ ] T007 [P] Define shared type: ClassificationLabel
- [ ] T008 [P] Define shared type: CliExitCode
- [ ] T009 [P] Define shared type: Confidence
- [ ] T010 [P] Define shared type: DiffHunk
- [ ] T011 [P] Define shared type: FilePath
- [ ] T012 [P] Define shared type: Finding
- [ ] T013 [P] Define shared type: KindexEntry
- [ ] T014 [P] Define shared type: LearnerPhase
- [ ] T015 [P] Define shared type: LearningRecord
- [ ] T016 [P] Define shared type: LedgerConfig
- [ ] T017 [P] Define shared type: LedgerFieldRule
- [ ] T018 [P] Define shared type: OutputFormat
- [ ] T019 [P] Define shared type: PactKey
- [ ] T020 [P] Define shared type: PolicyToken
- [ ] T021 [P] Define shared type: ReviewDecision
- [ ] T022 [P] Define shared type: ReviewReport
- [ ] T023 [P] Define shared type: ReviewRequest
- [ ] T024 [P] Define shared type: ReviewRequestId
- [ ] T025 [P] Define shared type: ReviewStage
- [ ] T026 [P] Define shared type: ReviewerCredential
- [ ] T027 [P] Define shared type: ReviewerId
- [ ] T028 [P] Define shared type: RuleId
- [ ] T029 [P] Define shared type: Severity
- [ ] T030 [P] Define shared type: StigmergySignal
- [ ] T031 [P] Define shared type: TesseraSeal
- [ ] T032 [P] Define shared type: TrustScore
- [ ] T033 [P] Define shared type: TrustWeight

## Phase: Component

- [x] T034 [P] [schemas] Review contract for Data Models & Schemas (contracts/schemas/interface.json)
- [x] T035 [schemas] Set up test harness for Data Models & Schemas
- [x] T036 [schemas] Write contract tests for Data Models & Schemas
- [x] T037 [schemas] Implement Data Models & Schemas (implementations/schemas/src/)
- [ ] T038 [schemas] Run tests and verify Data Models & Schemas
- [x] T039 [config] Review contract for Configuration System (contracts/config/interface.json)
- [x] T040 [config] Set up test harness for Configuration System
- [x] T041 [config] Write contract tests for Configuration System
- [x] T042 [config] Implement Configuration System (implementations/config/src/)
- [ ] T043 [config] Run tests and verify Configuration System
- [x] T044 [governance] Review contract for Governance Primitives (contracts/governance/interface.json)
- [x] T045 [governance] Set up test harness for Governance Primitives
- [x] T046 [governance] Write contract tests for Governance Primitives
- [x] T047 [governance] Implement Governance Primitives (implementations/governance/src/)
- [ ] T048 [governance] Run tests and verify Governance Primitives
- [x] T049 [intake] Review contract for Diff Intake & Classification (contracts/intake/interface.json)
- [x] T050 [intake] Set up test harness for Diff Intake & Classification
- [x] T051 [intake] Write contract tests for Diff Intake & Classification
- [x] T052 [intake] Implement Diff Intake & Classification (implementations/intake/src/)
- [ ] T053 [intake] Run tests and verify Diff Intake & Classification
- [x] T054 [reviewers] Review contract for Reviewer Implementations (contracts/reviewers/interface.json)
- [x] T055 [reviewers] Set up test harness for Reviewer Implementations
- [x] T056 [reviewers] Write contract tests for Reviewer Implementations
- [x] T057 [reviewers] Implement Reviewer Implementations (implementations/reviewers/src/)
- [ ] T058 [reviewers] Run tests and verify Reviewer Implementations
- [x] T059 [circuit] Review contract for Baton Circuit Router (contracts/circuit/interface.json)
- [x] T060 [circuit] Set up test harness for Baton Circuit Router
- [x] T061 [circuit] Write contract tests for Baton Circuit Router
- [x] T062 [circuit] Implement Baton Circuit Router (implementations/circuit/src/)
- [ ] T063 [circuit] Run tests and verify Baton Circuit Router
- [x] T064 [assessor] Review contract for Assessment Merger & Trust Scoring (contracts/assessor/interface.json)
- [x] T065 [assessor] Set up test harness for Assessment Merger & Trust Scoring
- [x] T066 [assessor] Write contract tests for Assessment Merger & Trust Scoring
- [x] T067 [assessor] Implement Assessment Merger & Trust Scoring (implementations/assessor/src/)
- [ ] T068 [assessor] Run tests and verify Assessment Merger & Trust Scoring
- [x] T069 [reporter] Review contract for Report Formatter & Sealer (contracts/reporter/interface.json)
- [x] T070 [reporter] Set up test harness for Report Formatter & Sealer
- [x] T071 [reporter] Write contract tests for Report Formatter & Sealer
- [x] T072 [reporter] Implement Report Formatter & Sealer (implementations/reporter/src/)
- [ ] T073 [reporter] Run tests and verify Report Formatter & Sealer
- [ ] T074 [learner] Review contract for Apprentice Learning Module (contracts/learner/interface.json)
- [ ] T075 [learner] Set up test harness for Apprentice Learning Module
- [ ] T076 [learner] Write contract tests for Apprentice Learning Module
- [ ] T077 [learner] Implement Apprentice Learning Module (implementations/learner/src/)
- [ ] T078 [learner] Run tests and verify Apprentice Learning Module
- [ ] T079 [cli] Review contract for CLI Entry Point (contracts/cli/interface.json)
- [ ] T080 [cli] Set up test harness for CLI Entry Point
- [ ] T081 [cli] Write contract tests for CLI Entry Point
- [ ] T082 [cli] Implement CLI Entry Point (implementations/cli/src/)
- [ ] T083 [cli] Run tests and verify CLI Entry Point
- [x] T084 [mcp_server] Review contract for MCP Server (contracts/mcp_server/interface.json)
- [x] T085 [mcp_server] Set up test harness for MCP Server
- [x] T086 [mcp_server] Write contract tests for MCP Server
- [x] T087 [mcp_server] Implement MCP Server (implementations/mcp_server/src/)
- [ ] T088 [mcp_server] Run tests and verify MCP Server

---
CHECKPOINT: All leaf components verified

## Phase: Integration

- [ ] T089 [root] Review integration contract for Root
- [ ] T090 [P] [root] Write integration tests for Root
- [ ] T091 [root] Wire children for Root
- [ ] T092 [root] Run integration tests for Root

---
CHECKPOINT: All integrations verified

## Phase: Polish

- [ ] T093 Run full contract validation gate
- [ ] T094 Cross-artifact analysis
- [ ] T095 Update design document
