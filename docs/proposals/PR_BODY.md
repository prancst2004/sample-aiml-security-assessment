# OWASP LLM Top 10 (2025) coverage for AI/ML Security Assessment

Adds OWASP Top 10 for LLM Applications (2025) coverage to the framework: a
new compliance-mapping schema, 17 new security checks (OW-01..OW-18, with a
reserved gap), a Compliance Dashboard in the HTML report, a dedicated
`owasp_assessments/` Lambda, and all supporting infrastructure and docs.

Total customer-visible checks grow from **51 → 69**, all OWASP LLM 2025
categories (LLM01..LLM10) covered, with honest scope signalling for
application-layer dimensions.

---

## What's in this PR

**Commits (8, on a single feature branch):**

| # | Commit | Summary |
|---|---|---|
| 1 | `2318475` | feat(schema): add `Compliance_Mappings` field and OWASP LLM 2025 tags for 52 existing checks |
| 2 | `7b883c2` | feat(report): add Compliance Dashboard + OWASP LLM Top 10 section to report UI |
| 3 | `c38c87b` | feat(owasp): add 7 OWASP LLM checks via BR-05 / BR-07 / AC-05 extensions |
| 4 | `d934ed8` | fix(csv): serialize `Compliance_Mappings` through the CSV round-trip |
| 5 | `60ed506` | feat(owasp): Phase 2b — OWASP Lambda with 4 exemplar checks + 8 Phase 2b.2 stubs |
| 6 | `937c69f` | feat(owasp): Phase 2b.2 — implement all 8 Phase 2b stubs as real checks |
| 7 | `abbab9f` | docs(owasp): Phase 3 — polish docs, SECURITY_CHECKS matrix, and sample report |
| 8 | `7c4054e` | fix(owasp): accept both `words` and `wordsConfig` in Bedrock guardrail response (live-validation fix) |

**Diff summary:** 49 files changed, +9219 / −3463 lines.

---

## The 17 new checks (OW-01..OW-18, one reserved gap)

| OWASP | ID | Name | Severity | Module |
|-------|---|---|---|---|
| LLM01 | OW-01 | Guardrail Prompt-Attack Filter Strength | High | bedrock (inline) |
| LLM01 / LLM03 | OW-02 | Knowledge Base Source Trust | Medium | owasp_assessments |
| LLM02 | OW-03 | Guardrail PII Redaction | Medium | bedrock (inline) |
| LLM02 | OW-04 | Invocation Log Retention & Access | Medium / High | owasp_assessments |
| LLM03 | OW-05 | Imported / Custom Model Provenance | Medium | owasp_assessments |
| LLM03 | OW-06 | SageMaker JumpStart & Marketplace Inventory | Low (inventory) | owasp_assessments |
| LLM04 | OW-07 | KB Ingestion Role Scope | High | owasp_assessments |
| LLM05 (compensating) | OW-08 | Guardrail Output Filter | Medium | bedrock (inline) |
| LLM06 | OW-09 | Agent Action-Group Wildcard Scope | High | owasp_assessments |
| LLM06 | OW-10 | Human-in-the-Loop & Confirmation Flow | Informational | owasp_assessments |
| LLM07 (partial-app-layer) | OW-11 | System Prompt Protection | Medium | bedrock (inline) |
| LLM08 | OW-12 | Vector Store Network Isolation | High | owasp_assessments |
| LLM08 | OW-13 | Multi-Tenant Knowledge Base Isolation | Medium | owasp_assessments |
| LLM09 | OW-14 | Contextual Grounding Guardrail | Medium | bedrock (inline) |
| LLM10 | OW-15 | Invocation Rate, Token & Cost Controls | Medium | bedrock (proactive) + owasp_assessments (detective) |
| LLM03 | OW-16 | Container Image Scanning | Medium | agentcore (inline) |
| LLM02 | OW-17 | KB Retrieval Access Policy | High | owasp_assessments |
| LLM06 (multi-agent) | OW-18 | Multi-Agent Sub-Agent Inventory | Medium | owasp_assessments |

**Delivery split:** 7 checks folded into existing Lambdas as extensions
(no new API call beyond a per-resource GET that was often already there),
11 checks in the dedicated `owasp_assessments/` Lambda.

---

## Architecture

- **Schema** — every `Finding` now carries an optional `Compliance_Mappings:
  List[ComplianceMapping]` list. Each entry is
  `{framework, framework_version, control_id, coverage_type}`.
  Three coverage types (`full`, `compensating`, `partial-app-layer`)
  distinguish honest scope — LLM03 and LLM05 can never show green
  because their primary control surfaces are outside the AWS control
  plane. The mapping is resolved automatically inside `create_finding()`
  from a per-module declarative table.

- **OWASP Lambda** (`owasp_assessments/`) — new 4th parallel branch in
  `statemachine/assessments.asl.json`. Writes
  `owasp_security_report_{execution_id}.csv` to the shared bucket.

- **Compliance Dashboard + OWASP detail table** — new sections in
  `report_template.py`:
    * 4-card dashboard (OWASP populated; NIST AI RMF, MITRE ATLAS, HIPAA
      shown as planned placeholders with mappings ready to light up).
    * 10-row OWASP detail table (LLM01..LLM10) with per-category status.
    * New Compliance column on every findings table.
    * New OWASP filter on the All Findings view.

- **CSV round-trip** — new `_serialize_compliance_mappings` helper in
  every Lambda's CSV writer; the consolidator's `parse_csv_content`
  decodes the JSON back into a list of dicts. Round-trip is covered by
  both unit tests and an end-to-end smoke test.

---

## Infrastructure changes

- `aiml-security-assessment/template.yaml` and `template-multi-account.yaml`
  — new `OwaspSecurityAssessmentFunction` resource; invoke-policy +
  state-machine substitution updates.
- `aiml-security-assessment/statemachine/assessments.asl.json` — 4th
  parallel branch.
- `deployment/1-aiml-security-member-roles.yaml` and
  `deployment/aiml-security-single-account.yaml` — incremental IAM
  additions (all read-only):
    * `bedrock-agent:{ListDataSources, GetDataSource, GetResourcePolicy,
      ListAgents, GetAgent, ListAgentVersions, ListAgentActionGroups,
      GetAgentActionGroup}`
    * `lambda:GetFunction` (for OW-09 action-group role resolution)
    * `iam:{GetRole, ListRolePolicies, GetRolePolicy, ListAttachedRolePolicies,
      GetPolicy, GetPolicyVersion}` (for OW-07 and OW-09)
    * `s3:{GetBucketPolicy, GetBucketPolicyStatus, GetBucketAcl,
      GetBucketPublicAccessBlock}` (for OW-02 and OW-04 S3 destination)
    * `cloudwatch:DescribeAlarms`, `budgets:{DescribeBudgets, ViewBudget}`
      (for OW-15 detective leg)
- `functions/security/generate_consolidated_report/app.py` — lists
  `owasp_security_report_*` objects alongside the existing three.

---

## Documentation

- **`README.md`** — headline count 51 → 69; OWASP service row added;
  S3 key documentation updated; state-machine description expanded.
- **`docs/SECURITY_CHECKS.md`** — 18 new entries in a new "OWASP LLM Top 10
  Extensions" section, each with severity, OWASP mapping, and
  description. Check ID Convention updated with OW-XX prefix.
- **`docs/DEVELOPER_GUIDE.md`** — new "OWASP LLM Top 10 Extensions" section
  covering: two delivery paths (inline vs dedicated Lambda), recipe for
  adding new OWASP checks, Compliance_Mappings shape, three
  coverage_types, and a recipe for adding new framework mappings (NIST /
  MITRE / HIPAA / FSI).
- **`docs/proposals/OWASP_LLM_TOP10_PROPOSAL.md`** — the full proposal
  that drove this work (also available as DOCX).
- **`sample-reports/security_assessment_single_account.html`** —
  regenerated end-to-end through the real
  `generate_html_report()` with a curated fixture that exercises all 18
  OW-XX checks. 149 KB, self-contained.

---

## Testing

### Unit tests

152 passing tests across 9 test files:

| Module | File | Tests |
|---|---|---|
| bedrock_assessments | test_compliance_mappings.py | 17 |
| bedrock_assessments | test_owasp_extensions.py | 24 (includes live-API regression test) |
| sagemaker_assessments | test_compliance_mappings.py | 17 |
| agentcore_assessments | test_compliance_mappings.py | 17 |
| agentcore_assessments | test_owasp_extensions.py | 6 |
| generate_consolidated_report | test_compliance_aggregator.py | 23 |
| generate_consolidated_report | test_generate_report.py | 3 (+ 1 pre-existing upstream failure, unchanged) |
| owasp_assessments | test_owasp_checks.py | 20 |
| owasp_assessments | test_owasp_checks_phase2b2.py | 25 |

All tests use `unittest.mock.MagicMock` injected into the check
functions — no `moto` dependency, no network.

### End-to-end smoke test

`smoke_test_owasp_lambda.py` patches boto3 for every required client,
invokes `lambda_handler`, and verifies statusCode 200, the expected S3
key is written, and the CSV round-trips through the consolidator's
`parse_csv_content` with `Compliance_Mappings` decoded back to a list of
dicts. 12 findings emitted (exactly the expected OW-XX set for the
OWASP Lambda path).

### Live AWS validation (account 676206921018 / us-east-1)

**Empty-account baseline** — OWASP Lambda runs cleanly, 12 findings,
2 real FAILEDs from actual account state (`Bedrock Invocation Logging
Disabled`, `Detective Consumption Controls Missing`). No permission
errors, no boto3 API-shape mismatches, 2.7s end-to-end.

**Seeded run** — seeded a Bedrock guardrail (mixed config: strong
PROMPT_ATTACK input / NONE output; PII with EMAIL/PHONE/SSN but missing
CREDIT_DEBIT_CARD_NUMBER; GROUNDING+RELEVANCE grounding; wordPolicy
with two terms), a CloudWatch log group with 7-day retention + Bedrock
invocation logging targeting it, and an AWS Budget scoped to Amazon
Bedrock. Observed transitions matched spec exactly:

| Check | Transition | Why |
|---|---|---|
| OW-04 | Disabled → CW Retention Insufficient | 7 day retention < 30 day minimum |
| OW-15 | Detective Missing → Detective Present | Budget scoped to Bedrock |
| OW-01 | — → Failed (High) | PROMPT_ATTACK output=NONE, should be HIGH |
| OW-03 | — → Failed (Medium) | Missing CREDIT_DEBIT_CARD_NUMBER |
| OW-08 | — → Passed | Word policy present |
| OW-14 | — → Passed | Grounding + Relevance filters |
| OW-15 (proactive) | — → Passed | Word policy present |
| OW-11 | — → Passed | No managed prompts (informational) |

Teardown verified: all 5 resources (guardrail, log group, IAM role,
Bedrock logging config, Budget) removed; post-teardown state matches
the initial empty-account baseline.

**One real bug surfaced and fixed during live validation** — the
Bedrock `GetGuardrail` API returns `wordPolicy.words` (not
`wordPolicy.wordsConfig` as the request schema uses). Fixed in commit
`7c4054e` with a compatibility layer that accepts either. New
regression test `test_live_api_response_shape_words_passes` covers
both code paths.

---

## Backward compatibility

- Every new OW-XX Check_ID is additive. No existing SM-XX / BR-XX /
  AC-XX Check_ID changed.
- `Compliance_Mappings` is an optional field; findings that don't carry
  it continue to work.
- CSV schema extended with one new column; the consolidator's round-trip
  parser handles the field gracefully when empty.
- All existing unit tests continue to pass (confirmed at each commit).
- The pre-existing upstream `service-badge` assertion in
  `test_generate_report.py` continues to fail with an unrelated message
  (not caused by this work) — see commit `abbab9f` for details.

---

## Follow-ups / not in this PR

- **Screenshots**: `sample-reports/dashboard-overview-{light,dark}.png`
  and `findings-table.png` could be regenerated with the new fixture,
  but the playwright+chromium dev workflow is a maintainer-owned step —
  happy to do this as a follow-up.
- **Multi-account sample report**: same fixture pattern works, but
  needs 3 account IDs + a merged consolidator run.
- **NIST AI RMF / MITRE ATLAS / HIPAA mappings**: the schema and
  dashboard placeholders are ready; adding real mappings is a
  separate (smaller) PR.

---

Credit: proposal authored and implementation by Pranjit Biswas. Reviewed
by Agasthi Kothurkar (aiml-security-assessment-enhancements channel).
