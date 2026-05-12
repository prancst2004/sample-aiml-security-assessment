# Proposal: OWASP Top 10 for LLM Applications (2025) Coverage

**Owner:** Pranjit Biswas
**Reviewer:** Agasthi Kothurkar
**Status:** Draft for internal review — v3 (reuse analysis + UI direction per Agasthi feedback)
**Target repo:** [sample-aiml-security-assessment](https://github.com/aws-samples/sample-aiml-security-assessment)
**Reference:** [OWASP GenAI Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/)

---

## v3 Update — Reviewer Direction Incorporated

Per Agasthi's feedback (Slack, 7:36 AM):

> "See if you can reuse any existing checks for the OWASP standards before implementing newer ones."
> "Use the prototype UI just as an initial reference on how the compliance section should be displayed. Feel free to iterate and make it better."
> "Test it out thoroughly before opening a PR."
> "Fork the current aws-samples repo into your own GitHub handle and then create a feature branch."

What v3 changes:

- **Reuse before rebuild.** Section 5a adds a reuse analysis against the actual Lambda code (not just the docs). Of the 17 new checks in v2, **6 fold into extensions of existing checks** rather than net-new logic. Net-new check count stays at 17 (customer-visible), but **net-new Lambda code drops by ~35%**.
- **Prototype-grounded UX.** Section 6 has been rewritten around the `security_assessment_compliance_prototype-v1.0.html` prototype Agasthi supplied. Key realization: the prototype is a **multi-framework** compliance UI (OWASP, NIST AI RMF, MITRE ATLAS, HIPAA) — not OWASP-only. This meaningfully reshapes the schema and the report structure for the better. Details in §6.
- **Test strategy added.** Section 7b spells out unit, integration, and end-to-end tests we commit to before opening the PR.
- **Fork + branch workflow documented.** Section 7c.
- **Scope expanded to multi-framework extensibility.** The proposal still delivers OWASP LLM Top 10 in this phase, but the data model and report plumbing we build is explicitly designed to accommodate NIST AI RMF (Neil's FSI lens territory), MITRE ATLAS, and HIPAA as follow-on phases without rework. This answers v2 open question #5 decisively.

---

## 1. Executive Summary

The AI/ML Security Assessment framework today runs **52 AWS-native security checks** across Amazon Bedrock, SageMaker AI, and Bedrock AgentCore, mapped to the AWS Well-Architected Generative AI Lens. It does an excellent job of catching **infrastructure and identity misconfigurations** (encryption, VPC, IAM, logging).

Gap: it does **not yet speak the language customers are being audited against**. Security, risk, and compliance teams at our AWS customers increasingly reference the **OWASP Top 10 for LLM Applications (2025)** in their AI governance programs, vendor questionnaires, and internal AI risk frameworks. Today we can tell a customer "your Bedrock guardrail is configured" but not "you are covered against LLM01 Prompt Injection."

This proposal adds a new **OWASP LLM Top 10 coverage dimension** to the framework. It does not replace the existing Well-Architected checks. It layers on top of them so each finding can be tagged, filtered, and reported against an OWASP category, and so we close real coverage gaps in four underserved areas: **system prompt leakage, vector/embedding weaknesses, unbounded consumption, and misinformation/grounding**.

### What we are proposing

1. Tag every existing check with the OWASP LLM category it maps to (metadata-only).
2. Add **17 new checks** (prefix `OW-`) that cover OWASP categories where AWS-native controls exist but we do not inspect them today.
3. Extend the HTML report with an **OWASP coverage view** alongside the existing severity/service views.
4. Ship it as a new parallel branch in the existing Step Functions workflow to preserve the current extensibility pattern.

### Honest coverage statement

Not every OWASP category is fully assessable from the AWS control plane. **LLM05 (Improper Output Handling)** is fundamentally an application-layer concern — it's about what the consuming application does with LLM output (e.g., passing it into `eval()`, SQL queries, shell commands). AWS has no API that tells us whether a customer's application sanitizes LLM output before using it. We therefore treat LLM05 as **partial coverage**: our guardrail-based checks are compensating controls that reduce the risk, not a full assessment. This is spelled out in the coverage matrix and in the report itself.

Similarly, **LLM03 (Supply Chain)** has application-layer dimensions (model hub integrity, dependency CVEs in the calling service) that go beyond what AWS APIs expose. We cover what we can and clearly label the rest.

### Why this matters for customer engagements

- **Audit-ready artifact:** customers hand our report to their AppSec / AI governance team and it speaks their framework.
- **Field differentiation:** no AWS-first-party OWASP LLM scanner exists today. This becomes a talking point for SAs running GenAI security reviews.
- **Continues the FSI lens direction:** pairs cleanly with Neil's FSI compliance work. The plumbing we add for OWASP tagging is the same plumbing FSI will use.

---

## 2. Scope & Non-Goals

### In scope
- New OWASP-mapped checks that can be determined from **AWS control-plane APIs** (read-only, no data-plane probes).
- Metadata mapping of existing 52 checks to OWASP categories.
- Report UI changes to surface OWASP coverage, including **explicit labeling of partial-coverage categories**.
- Documentation updates (`SECURITY_CHECKS.md`, `DEVELOPER_GUIDE.md`, README badge).

### Out of scope (for this iteration)
- **Active red-teaming / prompt injection probes.** Sending adversarial prompts to customer models is a separate tool class, needs data-plane permissions, and risks triggering customer WAF/guardrail alerts. Tracked as a future "Phase 2: Active Testing."
- **Application-layer output handling (LLM05).** Cannot be assessed without access to customer application code. Compensating controls only.
- **Model behavior evaluation** (bias, hallucination rates, toxicity). Belongs in SageMaker Clarify / Bedrock Evaluations, not here.
- **Third-party model marketplace deep scanning** beyond what AWS exposes via API.
- **Agentic workflow simulation.** Inspecting an agent's tool list is in scope. Executing the agent is not.

### Design principles (inherited from existing framework)
- **Read-only** control-plane calls.
- **No customer data leaves the account.** Findings are metadata only.
- **Idempotent.** Safe to re-run.
- **Least privilege.** New IAM permissions added surgically, not broadly.

---

## 3. OWASP LLM Top 10 (2025) — Recap

For reviewers who haven't read the OWASP doc recently:

| ID | Category |
|---|---|
| **LLM01** | Prompt Injection (direct and indirect) |
| **LLM02** | Sensitive Information Disclosure |
| **LLM03** | Supply Chain |
| **LLM04** | Data and Model Poisoning |
| **LLM05** | Improper Output Handling |
| **LLM06** | Excessive Agency (expanded in 2025 to include multi-agent orchestration) |
| **LLM07** | System Prompt Leakage |
| **LLM08** | Vector and Embedding Weaknesses |
| **LLM09** | Misinformation |
| **LLM10** | Unbounded Consumption |

Source: [OWASP GenAI Security Project](https://genai.owasp.org/llm-top-10/). Content rephrased for compliance with licensing restrictions.

---

## 4. Current Coverage Matrix

Mapping every existing check in the repo (`docs/SECURITY_CHECKS.md`) against OWASP LLM 2025. "Partial" means the existing check addresses one vector of the OWASP category but not all. "Partial — application-layer gap" means AWS control-plane cannot fully assess this category.

| OWASP Category | Covered by existing checks | Coverage | Gap |
|---|---|---|---|
| **LLM01 Prompt Injection** | BR-05 (Guardrails), BR-13 (Flows Guardrails), BR-10 (Guardrail IAM enforcement) | Partial | No check that guardrails have PII/prompt-attack filters **enabled at strong tier**, no coverage of Knowledge Base prompt injection via ingested docs, AgentCore action group input validation. |
| **LLM02 Sensitive Info Disclosure** | BR-09 (KB encryption), BR-11, BR-12, SM-03, SM-15–SM-20, AC-05, AC-07, AC-11, AC-12 | Partial | Encryption covered well. **Guardrail PII masking/redaction not verified.** **Who can query a KB (RAG retrieval disclosure) not checked.** No check for invocation log retention. |
| **LLM03 Supply Chain** | BR-03 (Marketplace access), BR-11 (Custom model encryption), SM-14 (Container repo), AC-05 (ECR encryption) | **Partial — application-layer gap** | No check for custom/imported model provenance, **ECR image CVE scanning**, or SageMaker JumpStart model source verification. Python/OS package CVEs in customer's calling service are out of scope. |
| **LLM04 Data and Model Poisoning** | SM-22 (Model approval), SM-23 (Drift), SM-25 (Lineage), SM-06 (Clarify) | Partial | **Knowledge Base data source hygiene** not checked (S3 bucket public? KB ingestion role scoped?). Fine-tuning data access not audited — see Section 11 Q4 for decision needed on scope. |
| **LLM05 Improper Output Handling** | BR-05, BR-13 (Guardrails) — **compensating controls only** | **Partial — application-layer gap** | LLM05 is fundamentally about **downstream application code** that consumes LLM output without sanitization (e.g., piping output into `eval()`, SQL, or shell). Guardrails reduce the risk by filtering output content but do not assess customer application behavior. AWS control-plane cannot inspect this. Report must label this clearly. |
| **LLM06 Excessive Agency** | BR-08 (Agent IAM), AC-02 (IAM full access), AC-10 (Resource policies), BR-01 | Partial | No check for agent action group scope (wildcards, cross-service reach), AgentCore gateway tool allow-lists, or human-in-the-loop configuration. **Multi-agent trust boundaries** (a 2025 addition to LLM06 — sub-agents trusting orchestrator inputs) not covered. |
| **LLM07 System Prompt Leakage** | — | **None** | Brand new gap. No check on Bedrock Prompt resource policies, agent instruction presence, or prompt versioning discipline. |
| **LLM08 Vector & Embedding Weaknesses** | BR-09 (KB encryption) | **Very partial** | Encryption alone. No check for KB access scoping, OpenSearch/Aurora vector store network isolation, embedding model provenance, per-tenant data isolation in multi-tenant KBs. |
| **LLM09 Misinformation** | SM-06 (Clarify), SM-07 (Model Monitor) | Partial (SageMaker only) | Nothing on the Bedrock side. No check for grounding (Bedrock KB citations enabled), contextual grounding guardrail policy, or model evaluation jobs configured. |
| **LLM10 Unbounded Consumption** | — | **None** | No check on Bedrock provisioned throughput quotas, **guardrail input-size limits (prevents oversized-input DoS)**, SageMaker endpoint auto-scaling bounds, AgentCore runtime rate limits, or CloudWatch alarms / Budgets on invocation spend. |

### Summary of gaps

- **Fully uncovered today:** LLM07, LLM10.
- **Very thinly covered:** LLM08, LLM09 (Bedrock side).
- **Structurally partial due to application-layer scope:** LLM03, LLM05.
- **Partially covered, closeable with targeted checks:** LLM01, LLM02, LLM04, LLM06.

---

## 5a. Reuse Analysis — What the existing code already gathers

Before writing any new Lambda, we inspected `bedrock_assessments/app.py`, `sagemaker_assessments/app.py`, and `agentcore_assessments/app.py` end to end. Several of the v2 proposed checks are **not net-new scans** — they're **additional assertions on data already fetched** by existing checks. Folding them in keeps runtime cost low and avoids duplicate API calls.

### Reuse map

| v2 Proposed Check | Existing check that already fetches the data | Reuse approach |
|---|---|---|
| **OW-01** Guardrail Prompt Attack Filter Strength | `check_bedrock_guardrails()` — already calls `list_guardrails()` but discards per-guardrail detail | **Extend BR-05**: add `get_guardrail()` call per guardrail in the existing loop and inspect `contentPolicy.filters` in the same function. Emits additional findings under OW-01 without a second API pass. |
| **OW-03** Guardrail PII Redaction | Same as OW-01 — BR-05's list + new per-guardrail get | **Extend BR-05**: inspect `sensitiveInformationPolicy` in the same loop. |
| **OW-08** Guardrail Output Filtering (compensating control for LLM05) | Same as OW-01 | **Extend BR-05**: inspect `contentPolicy` INPUT/OUTPUT scope in the same loop. |
| **OW-11** System Prompt Protection (Bedrock Prompt side) | `check_bedrock_prompt_management()` (BR-07) — already calls `list_prompts()` + `get_prompt()` per prompt | **Extend BR-07**: the existing loop already pulls full prompt detail. Add a resource-policy fetch (`get_resource_policy`) and emit OW-11 findings from the same function. |
| **OW-14** Contextual Grounding Guardrail | Same as OW-01 | **Extend BR-05**: inspect `contextualGroundingPolicy` in the same per-guardrail loop. |
| **OW-15 (part a)** Guardrail Input Size Limit | Same as OW-01 | **Extend BR-05**: inspect `wordPolicy` in the same loop. Part (b) — CloudWatch/Budgets — stays as new logic. |
| **OW-16** Container Image Scanning | `check_agentcore_encryption()` (AC-05) — already calls `ecr:describe_repositories` and iterates AgentCore-tagged repos | **Extend AC-05**: inspect `imageScanningConfiguration.scanOnPush` on the same repos. Also add a SageMaker-side pass (new, small) for SageMaker-associated ECR repos. |

### Net effect on engineering effort

- **6 checks** (OW-01, OW-03, OW-08, OW-11, OW-14, part of OW-15, OW-16) are delivered as **extensions to BR-05, BR-07, AC-05**. The refactor pattern is: existing `list_*()` calls stay; we add a `get_*()` call inside the existing loop, emit additional findings, and tag them with the OWASP category.
- **11 checks** are net-new Lambda logic in a new `owasp_assessments/` module: OW-02, OW-04, OW-05, OW-06, OW-07, OW-09, OW-10, OW-12, OW-13, OW-17, OW-18, and part (b) of OW-15.
- **Customer-visible total** stays at 17 new checks (OW-01 through OW-18).
- **Net-new Lambda code is roughly 35% less** than v2 estimated, because the six folded-in checks ride on existing API calls and permission scopes.

### Implication for Step Functions workflow

v2 proposed a fourth parallel branch (`OWASP`). With reuse in mind, v3 recommends a **hybrid**:
- BR-05, BR-07, AC-05 grow in place in the Bedrock and AgentCore branches.
- A new `owasp_assessments` Lambda runs as the fourth branch, handling only the 11 net-new checks (KB retrieval policies, vector store isolation, agent action groups, cost alarms, etc.).

This is cheaper to build, cheaper to run, and keeps service-specific logic close to its existing neighbors.

### Implication for IAM

Several permissions are already granted to the existing roles. The incremental IAM delta shrinks accordingly. Updated list in §7.

---

## 5. Proposed New Checks

New check prefix: **`OW-`**. Each new check reuses the existing `Finding` schema (`Check_ID`, `Severity`, `Status`, `Reference`, etc.). A small, backward-compatible schema extension is required — see Section 7 for the exact delta. The existing `Check_ID` validator regex (`^[A-Z]{2,3}-\d{2}$`) already accepts the `OW-XX` prefix without modification, so no regex changes are needed.

Severity is my proposal, open to debate in review.

### LLM01 Prompt Injection — 2 new checks

| ID | Name | Severity | What it checks | AWS API |
|---|---|---|---|---|
| **OW-01** | Guardrail Prompt Attack Filter Strength | High | For every Bedrock guardrail, verify `contentPolicy.filters` includes `PROMPT_ATTACK` with strength = `HIGH` for both input and output. Fails if filter absent or set to `NONE`/`LOW`. | `bedrock:GetGuardrail` |
| **OW-02** | Knowledge Base Source Trust | Medium | For each Bedrock Knowledge Base, check that its data source S3 bucket is **not public** and has bucket policy restricting write to a narrow principal set. Surfaces indirect prompt injection risk via poisoned KB documents. Uses **Block Public Access settings** as primary signal. | `bedrock-agent:GetKnowledgeBase`, `bedrock-agent:GetDataSource`, `s3:GetBucketPublicAccessBlock`, `s3:GetBucketPolicyStatus`, `s3:GetBucketPolicy`, `s3:GetBucketAcl` |

### LLM02 Sensitive Information Disclosure — 3 new checks

| ID | Name | Severity | What it checks | AWS API |
|---|---|---|---|---|
| **OW-03** | Guardrail PII Redaction Enabled | Medium (with tunable severity) | Verify guardrails have `sensitiveInformationPolicy` configured with `BLOCK` or `ANONYMIZE` for common PII entities (EMAIL, PHONE, SSN, CREDIT_DEBIT_CARD_NUMBER). **N/A path:** produces N/A if no guardrails exist in the account. **Informational path:** customers can tag the workload as `non-pii` via a CloudFormation parameter or resource tag to downgrade this finding to Informational for internal-only, non-personal-data agents. Default severity is Medium (not High) to avoid alarming dev accounts; customers handling regulated data can elevate via tagging. | `bedrock:GetGuardrail` |
| **OW-04** | Invocation Log Retention & Access | Medium | Confirm Bedrock invocation logs (CloudWatch / S3) have retention ≥ 30 days and destination bucket/log group has restrictive resource policy. Prevents logs themselves becoming an exfil channel. | `bedrock:GetModelInvocationLoggingConfiguration`, `logs:DescribeLogGroups`, `s3:GetBucketPolicy` |
| **OW-17** | Knowledge Base Retrieval Access Policy | High | For each Bedrock Knowledge Base, verify a resource-based policy exists restricting `bedrock-agent:Retrieve` and `bedrock-agent:RetrieveAndGenerate` to specific IAM principals. A KB with no resource policy allows any identity with Bedrock invoke permissions to query it — direct RAG retrieval disclosure risk. | `bedrock-agent:GetKnowledgeBase` (resource policy field), `bedrock-agent:GetResourcePolicy` |

### LLM03 Supply Chain — 3 new checks

| ID | Name | Severity | What it checks | AWS API |
|---|---|---|---|---|
| **OW-05** | Imported/Custom Model Provenance | Medium | List Bedrock custom models and imported models. Flag any where the source (`modelSourceConfiguration`) points to an S3 bucket the account does not own, or where no model provenance tags are set. | `bedrock:ListCustomModels`, `bedrock:GetImportedModel` |
| **OW-06** | SageMaker JumpStart & Marketplace Usage Review | Low | Enumerate endpoints running Marketplace or JumpStart-sourced model packages. Informational finding that lists them for customer review. Not a fail by default. | `sagemaker:ListModelPackages`, `sagemaker:DescribeModelPackage` |
| **OW-16** | Container Image Scanning for SageMaker & AgentCore | Medium | Verify ECR repositories used by SageMaker models and AgentCore runtimes have `imageScanningConfiguration.scanOnPush = true`. Unscanned images may contain known CVEs exploitable at inference time. Zero new IAM permissions required — ECR read access already present via AC-05. | `ecr:DescribeRepositories`, `ecr:GetRepositoryPolicy`, `ecr:DescribeImageScanFindings` |

### LLM04 Data and Model Poisoning — 1 new check

| ID | Name | Severity | What it checks | AWS API |
|---|---|---|---|---|
| **OW-07** | Knowledge Base Ingestion Role Scope | High | Inspect the IAM role attached to Bedrock KB data sources. Fails if role has `s3:*` on `*`, allows write to the vector store, or is shared across unrelated KBs. | `bedrock-agent:GetKnowledgeBase`, `iam:GetRole`, `iam:ListAttachedRolePolicies` |

> **Note on fine-tuning data access audit:** out of scope for this phase. Tracked as future work (SageMaker training job data source S3 bucket public-access check — `sagemaker:DescribeTrainingJob` + `s3:GetBucketPublicAccessBlock`). See Section 11 Q4 for explicit decision point.

### LLM05 Improper Output Handling — 1 new compensating control check

| ID | Name | Severity | What it checks | AWS API |
|---|---|---|---|---|
| **OW-08** | Guardrail Output Filtering Configured (**compensating control for LLM05**) | Medium | Existing BR-05 confirms a guardrail exists. OW-08 confirms its `contentPolicy` applies to **OUTPUT** (not just INPUT) and that `wordPolicy`/`topicPolicy` are non-empty where appropriate. **Explicit caveat:** this is a compensating control. LLM05 is fundamentally about downstream application code sanitizing LLM output before using it (e.g., in `eval()`, SQL, shell). AWS control plane cannot assess that. The HTML report displays LLM05 with a visible "partial coverage — application-layer assessment required" badge. | `bedrock:GetGuardrail` |

### LLM06 Excessive Agency — 3 new checks

| ID | Name | Severity | What it checks | AWS API |
|---|---|---|---|---|
| **OW-09** | Agent Action Group Wildcard Scope | High | For Bedrock Agents and AgentCore runtimes, inspect action group Lambda IAM roles. Fail on wildcard `Resource: "*"` actions or cross-service wildcards (`s3:*`, `dynamodb:*`). | `bedrock-agent:ListAgents`, `bedrock-agent:GetAgentActionGroup`, `iam:GetRolePolicy` |
| **OW-10** | Human-in-the-Loop & Confirmation Flow | Low | Informational check that looks for confirmation-required flags on agent action groups. No pass/fail, just inventory for customer review. | `bedrock-agent:GetAgentActionGroup` |
| **OW-18** | Multi-Agent Sub-Agent Inventory | Informational | Enumerate Bedrock Agents that appear as callees from other agents' action groups (sub-agent / agent-calling-agent patterns). Does not fail — it flags these for manual review of trust assumptions (per LLM06's 2025 expansion on multi-agent orchestration risk: a sub-agent should not blindly trust the orchestrator's inputs). | `bedrock-agent:ListAgents`, `bedrock-agent:ListAgentAliases`, `bedrock-agent:GetAgentActionGroup` |

### LLM07 System Prompt Leakage — 1 new check (revised from v1)

| ID | Name | Severity | What it checks | AWS API |
|---|---|---|---|---|
| **OW-11** | System Prompt Protection | High | **Revised implementation** (v1 proposed a topic-name heuristic, which is unreliable — topic policy names are free-text and cannot be programmatically identified as "system prompt protection"). New logic has two concrete, implementable signals: (1) **Bedrock Prompt resources** (`bedrock:ListPrompts`, `bedrock:GetPrompt`) must not have public or overly permissive resource-based policies, and **versioned prompts** should be in use (vs. hardcoded inline system prompts in application code, which are unprotected by any AWS control). (2) For every Bedrock Agent, verify `bedrock-agent:GetAgent` returns a non-empty `instruction` field (agent has a managed system prompt that is protectable) and that agent access is restricted via IAM. **Fails** if Prompt resources are public, or if agents exist without managed instructions. **Informational** finding recommending Bedrock Prompt Management if inline prompts are suspected. | `bedrock:ListPrompts`, `bedrock:GetPrompt`, `bedrock-agent:GetAgent`, `bedrock-agent:ListAgents` |

### LLM08 Vector & Embedding Weaknesses — 2 new checks

| ID | Name | Severity | What it checks | AWS API |
|---|---|---|---|---|
| **OW-12** | Vector Store Network Isolation | High | For each Bedrock KB, resolve its vector store (OpenSearch Serverless collection, Aurora cluster, Pinecone via secret). Fail if OpenSearch collection allows public network access, or Aurora is publicly accessible. | `bedrock-agent:GetKnowledgeBase`, `aoss:BatchGetCollection`, `aoss:GetSecurityPolicy`, `rds:DescribeDBClusters` |
| **OW-13** | Multi-Tenant KB Isolation | Medium | Heuristic: when multiple KBs share a single vector store collection, warn that per-tenant filtering is the customer's responsibility and list affected KBs. Informational-to-medium severity. | `bedrock-agent:ListKnowledgeBases` |

### LLM09 Misinformation — 1 new check

| ID | Name | Severity | What it checks | AWS API |
|---|---|---|---|---|
| **OW-14** | Contextual Grounding Guardrail | Medium | Verify at least one guardrail has `contextualGroundingPolicy` enabled with `GROUNDING` and `RELEVANCE` thresholds set. This is Bedrock's native hallucination mitigation — customers often don't know it exists. | `bedrock:GetGuardrail` |

### LLM10 Unbounded Consumption — 1 new check (expanded in v2)

| ID | Name | Severity | What it checks | AWS API |
|---|---|---|---|---|
| **OW-15** | Invocation Rate, Token, and Cost Controls | **Medium** (revised from High in v1 — missing alarms is observability, not a direct exploit path; consistent with BR-04 Medium and BR-06 Medium) | Two vectors checked: **(a) Proactive rate/token controls** — at least one active guardrail has `wordPolicy` or equivalent token-length limit configured to block adversarial oversized inputs that exhaust context windows; **(b) Detective cost/rate monitoring** — one of: Bedrock provisioned throughput configured, CloudWatch alarm on `InvocationCount` / `InputTokenCount` metrics, or Budgets alarm scoped to Bedrock/SageMaker. Fails if **neither** a proactive nor a detective control is present. Separates "you block the attack vector" from "you alert after the fact." | `bedrock:GetGuardrail`, `cloudwatch:DescribeAlarms`, `budgets:DescribeBudgets`, `bedrock:ListProvisionedModelThroughputs` |

**Total new checks: 17** (OW-01 through OW-18, with one ID gap reserved for future work — numbering is contiguous in the final table). Added to the existing 52, the framework would run **69 checks**.

---

## 6. Report & UX — Prototype-Grounded Design

Agasthi supplied `security_assessment_compliance_prototype-v1.0.html` as the initial reference. We studied it and are adopting its compliance UX as the direction, with iterations noted below.

### What the prototype establishes

The prototype is a **multi-framework compliance UI**, not an OWASP-only add-on. It includes:

1. **Sidebar nav with a dedicated "Compliance Frameworks" group** — OWASP Top 10 LLM, NIST AI RMF 1.0, MITRE ATLAS, HIPAA AI/ML. Each framework has its own anchor and page section.
2. **Compliance Dashboard tile group** (`#compliance-dashboard`) — one `compliance-card` per framework showing a big compliance rate percentage, color-coded by threshold (high/medium/low), plus a breakdown strip (`Compliant / Partial / Non-Compliant`).
3. **Top-level executive metrics strip** — pairs security metrics with compliance metrics: `Security Checks (51) · Compliance Controls (54) · Security Findings (89) · Compliance Gaps (31) · Overall Compliance (63%)`.
4. **Per-framework detail section** — for OWASP: a table of all 10 categories with ID, Vulnerability, Description, AWS Controls, Status (`Compliant / Partial / Non-Compliant`). Same pattern for NIST AI RMF, ATLAS, HIPAA.
5. **Multi-framework badges on individual findings** — each row in the findings table carries `<span class="framework-badge owasp">LLM01</span>`, `<span class="framework-badge nist">MANAGE 2.1</span>`, `<span class="framework-badge hipaa">§164.312(a)(2)</span>` etc. in a `mapping-tags` container. One finding → N frameworks.
6. **Extended severity/compliance legend** — the prototype's legend table pairs each security severity with a compliance meaning and a remediation timeline. This makes the security-vs-compliance distinction explicit.

### What this means for our data model

v2 proposed a single `OWASP_Category` field. The prototype implies something richer, and the fact that Neil's FSI lens (likely NIST AI RMF + HIPAA) is a parallel workstream confirms we should build for multi-framework from day one.

**Revised schema extension for `Finding`:**

```python
# Replaces the v2 single-field proposal
Compliance_Mappings: Optional[List[ComplianceMapping]] = Field(
    default_factory=list,
    description="List of compliance-framework mappings. One finding can map to multiple frameworks."
)

class ComplianceMapping(BaseModel):
    framework: Literal["OWASP-LLM", "NIST-AI-RMF", "MITRE-ATLAS", "HIPAA", "FSI"]
    framework_version: str            # e.g., "2025", "1.0"
    control_id: str                   # e.g., "LLM01", "GOVERN 1.1", "§164.312(a)(2)"
    coverage_type: Literal["full", "compensating", "partial-app-layer"]
```

Still backward-compatible (new field, defaults to empty list). But now OWASP is just the first framework lit up, and Neil's FSI work drops into the same slot without a second schema migration.

### What the OWASP coverage section looks like in our report

Adopting the prototype's pattern. For the OWASP LLM Top 10 section specifically:

- **Table of 10 rows** — ID, Vulnerability, Description, AWS Controls (short list naming the Bedrock/SageMaker/AgentCore checks and OW-XX checks covering it), Status (`Compliant / Partial / Non-Compliant / Partial — application-layer`).
- **LLM03 and LLM05** display with an explicit **"Partial — application-layer"** status badge. Per the v2 feedback, these must never show as green.
- **Each row clickable** — deep-links to the findings table pre-filtered to that OWASP category.

### Iterations we propose on top of the prototype

1. **`Partial — application-layer` as a distinct status value**, not just "Partial." The prototype currently has three states (Compliant, Partial, Non-Compliant). LLM03 and LLM05 need visual differentiation so customers don't read "Partial" as "we scanned 60% of it" when the reality is "60% is scanned, 40% is application-layer and outside AWS control plane."
2. **`OWASP_Coverage_Type` as a column-level data point** surfaced as a tooltip on the status badge. Hover tells the customer what "Partial — application-layer" means in plain English.
3. **"Unable to assess" status** for checks where the customer's IAM role couldn't read a resource (rare but real). Distinguishing this from genuine failures avoids false-negative customer reactions.
4. **Compliance gap-to-finding drill-down** — clicking a Non-Compliant OWASP row filters the findings table to rows tagged with that framework control. Prototype supports this via anchor-based nav; we'd extend with JS filter state.
5. **Export view** — add an OWASP-filtered CSV export alongside the existing CSV exports so customers can feed the data into their GRC tools.
6. **Multi-framework findings table** — when a finding has multiple framework badges (per the prototype), we sort badges by framework priority (OWASP first in this phase, others as they land).

### What stays in the existing `report_template.py` (single source of truth)

- HTML/CSS/JS additions live in `report_template.py`. Both the single-account Lambda report and the multi-account consolidated report pick up the compliance section automatically — same pattern as today.
- New CSS classes needed (mostly already in the prototype): `.framework-badge.owasp`, `.compliance-grid`, `.compliance-card`, `.mapping-tags`, `.status.non-compliant`, `.status.partial`, `.status.compliant`.
- New JS for the pre-filtered drill-down nav from compliance cards into findings table.
- Dark mode: prototype already supports CSS variables; our existing report supports dark mode. We verify parity.

### What we intentionally de-scope from the prototype for Phase 1

The prototype renders four frameworks populated. We ship **OWASP populated**. NIST/ATLAS/HIPAA tiles appear in the Compliance Dashboard as "Planned" / greyed-out placeholders tied to Neil's FSI lens work. This keeps Phase 1 scope honest and gives Neil a concrete integration point.

---

## 7. Implementation Approach

Staying faithful to the repo's existing extensibility pattern (documented in `docs/DEVELOPER_GUIDE.md`).

### Schema change (backward-compatible, multi-framework)

**There is one data-model change required.** (Correcting v1, which contradicted itself on this point. v3 revises the v2 single-field proposal to a multi-framework shape grounded in the prototype.)

Add one optional field to `Finding` in each `schema.py`, plus a new nested model:

```python
from typing import List, Optional, Literal
from pydantic import BaseModel, Field

class ComplianceMapping(BaseModel):
    framework: Literal["OWASP-LLM", "NIST-AI-RMF", "MITRE-ATLAS", "HIPAA", "FSI"]
    framework_version: str
    control_id: str                                     # e.g., "LLM01", "GOVERN 1.1"
    coverage_type: Literal["full", "compensating", "partial-app-layer"]

# Add to Finding:
Compliance_Mappings: Optional[List[ComplianceMapping]] = Field(
    default_factory=list,
    description="Compliance-framework mappings. One finding can map to multiple frameworks."
)
```

Backward-compatible: the field is optional with an empty-list default. Existing `create_finding(...)` calls continue to work unchanged. The consolidator ignores missing or empty mappings.

The existing `Check_ID` validator regex (`^[A-Z]{2,3}-\d{2}$`) **already accepts** `OW-01` through `OW-18` without modification — `OW` is a 2-character prefix, `XX` is 2 digits. No regex change required.

**Why multi-framework now instead of OWASP-only:** Agasthi's prototype explicitly shows NIST AI RMF, MITRE ATLAS, and HIPAA tiles. Neil's FSI lens workstream will populate NIST/HIPAA. Building the schema as a list-of-mappings from day one means OWASP lands cleanly AND FSI drops in without a second migration.

### Three delivery phases (revised for reuse)

**Phase 1 — Schema + prototype-aligned UX (no new scan logic)**
- Add `ComplianceMapping` model and `Compliance_Mappings` field to each `schema.py`.
- Annotate all 52 existing checks with their OWASP mappings (appendix has the full list).
- Port the prototype's compliance section into `report_template.py`: Compliance Dashboard tile group, per-framework section for OWASP, framework badges on findings rows, extended legend, partial-coverage badges for LLM03/LLM05.
- Ship NIST/ATLAS/HIPAA tiles as "Planned" placeholders so Neil's FSI work has a defined integration point.
- Update `docs/SECURITY_CHECKS.md` with the OWASP mapping.
- **Demoable state:** Phase 1 alone produces an OWASP-mapped report customers can use, before any new scan logic ships.

**Phase 2a — Extend existing checks (reuse)**
- BR-05 grows to emit OW-01, OW-03, OW-08, OW-14, and OW-15(a) from the same per-guardrail loop.
- BR-07 grows to emit OW-11 from the same per-prompt loop.
- AC-05 grows to emit OW-16 from the same ECR repo loop, plus a SageMaker-side ECR pass.
- Small, surgical PRs per service.
- **Demoable state:** 6 OWASP checks live, no new Lambda function yet.

**Phase 2b — New `owasp_assessments/` Lambda (11 net-new checks)**
- New Lambda: `functions/security/owasp_assessments/` following the existing `app.py` + `schema.py` + `requirements.txt` pattern.
- Covers: OW-02, OW-04, OW-05, OW-06, OW-07, OW-09, OW-10, OW-12, OW-13, OW-15(b), OW-17, OW-18.
- Add as a **fourth parallel branch** in `statemachine/assessments.asl.json`.
- Add `OwaspAssessmentFunction` to `template.yaml` and `template-multi-account.yaml`.
- Extend `AIMLSecurityMemberRole` with the incremental permissions in §7 (slimmer than v2 because extensions reuse existing permissions).
- Split into logical PRs per OWASP category for smaller reviews.

**Phase 3 — Polish**
- Fine-tune the Compliance Dashboard based on end-to-end test reports.
- Refresh `sample-reports/` with an example multi-framework run (OWASP populated, others placeholder).
- README badge, screenshot update in `sample-reports/scripts/capture_screenshots.py`.

### Workflow diagram (target state)

Hybrid per §5a: existing branches grow in place for folded-in checks (OW-01/03/08/11/14/15a/16), new branch handles net-new checks.

```
Cleanup S3 Bucket
      │
      ▼
IAM Permission Caching
      │
      ▼
┌──────────────── Parallel ────────────────────────┐
│                                                   │
│  Bedrock       SageMaker      AgentCore           │
│  (+OW-01,      (+OW-16        (+OW-16             │
│   03, 08,       pass for       pass for           │
│   11, 14,       SageMaker      AgentCore)         │
│   15a)          ECR)                              │
│                                                   │
│  OWASP (new) ◄── 11 net-new checks                │
│  (OW-02,04,05,06,07,09,10,12,13,15b,17,18)        │
│                                                   │
└─────────────────────┬─────────────────────────────┘
                      ▼
           Generate Consolidated Report
           (with multi-framework compliance view)
```

### IAM permission delta — incremental after reuse

Several permissions that v2 listed are **already granted** by existing checks. v3 shows only the true delta for the `AIMLSecurityMemberRole`:

```
# Already present (extended usage, no new permission needed):
bedrock:GetGuardrail                               # used by BR-05 extensions (OW-01/03/08/14/15a)
bedrock:ListPrompts                                # used by BR-07 extensions (OW-11 part 1)
bedrock:GetPrompt                                  # used by BR-07 extensions (OW-11 part 1)
ecr:DescribeRepositories                           # used by AC-05 extension (OW-16)
iam:GetRolePolicy
iam:ListAttachedRolePolicies

# Net-new permissions (for the owasp_assessments Lambda):
bedrock:ListCustomModels
bedrock:GetImportedModel
bedrock:GetModelInvocationLoggingConfiguration
bedrock:ListProvisionedModelThroughputs
bedrock-agent:ListKnowledgeBases
bedrock-agent:GetKnowledgeBase
bedrock-agent:GetDataSource
bedrock-agent:GetResourcePolicy
bedrock-agent:ListAgents
bedrock-agent:GetAgent
bedrock-agent:ListAgentAliases
bedrock-agent:GetAgentActionGroup
aoss:BatchGetCollection
aoss:ListSecurityPolicies
aoss:GetSecurityPolicy
rds:DescribeDBClusters
s3:GetBucketPolicy
s3:GetBucketPolicyStatus
s3:GetBucketAcl
s3:GetBucketPublicAccessBlock
ecr:GetRepositoryPolicy
ecr:DescribeImageScanFindings
cloudwatch:DescribeAlarms
budgets:DescribeBudgets
logs:DescribeLogGroups
```

All read-only. No new write permissions anywhere.

---

## 7b. Test Strategy — Before Opening a PR

Per Agasthi's direction ("test it out thoroughly before opening a PR"), here is the test plan we commit to. Each phase gates on these before the PR is filed.

### Unit tests (pytest)

- Extend existing `test_generate_report.py` to cover:
  - `ComplianceMapping` schema validation (valid/invalid framework, version, control_id, coverage_type).
  - `Finding` serialization with zero, one, and multiple `Compliance_Mappings`.
  - Consolidator behavior when mappings are missing (backward compat).
- New `test_owasp_assessments.py` per check:
  - Mocked boto3 response → assert correct finding(s) emitted with correct severity/status/mapping.
  - N/A paths: empty guardrails, empty KB list, no agents, etc.
  - Error paths: API throws `AccessDenied` → emits "Unable to assess" finding, doesn't crash.
- Target: ≥90% line coverage on new code, no regression on existing coverage.

### Integration tests (moto / localstack)

- Spin up mock Bedrock / SageMaker / AgentCore / ECR / IAM using `moto` where supported.
- Run each OWASP Lambda end-to-end against the mocks.
- Assert produced CSV matches expected structure and content.
- Integration test for BR-05 extension: same guardrail input → both BR-05 finding and OW-01/03/08/14/15a findings emitted.

### End-to-end test (sandbox AWS account)

- Deploy SAM stack to a dedicated test account with seeded resources:
  - At least one Bedrock guardrail with mixed policy configuration (some filters set, some not).
  - At least one Bedrock Knowledge Base with an OpenSearch Serverless backend and one with a public-S3 source.
  - At least one Bedrock Agent with a wildcard-IAM action group.
  - At least one AgentCore runtime with an unscanned ECR image.
  - At least one SageMaker endpoint.
- Trigger the Step Functions state machine.
- Verify:
  - All expected findings appear in the CSV outputs.
  - Consolidated HTML report renders without errors.
  - Compliance Dashboard shows correct per-framework rates.
  - OWASP section renders all 10 categories with correct statuses.
  - Framework badges render correctly on multi-framework findings.
  - Dark mode still works.
  - Report is functional in Chrome, Firefox, Safari.
- Clean up test resources after run.

### Multi-account end-to-end test

- If access to a test AWS Organizations setup is available: run multi-account flow against 2–3 seeded accounts.
- Verify `consolidate_html_reports.py` produces a consolidated report with the compliance section populated across accounts.

### Regression checks

- Run existing 52-check suite before and after changes; CSV diffs limited to new `Compliance_Mappings` field additions only.
- Run `ruff`, `cfn-lint`, `sam validate` per the repo's existing CI (GitHub Actions workflow).
- Run CodeQL / ASH security scan locally before pushing.

### Performance sanity

- Compare Step Functions execution duration pre/post change. Budget: new branch adds ≤ 60s to total wall-clock. If over budget, parallelize within the OWASP Lambda rather than serializing.

---

## 7c. Fork & Branch Workflow

Per Agasthi's direction and standard `aws-samples` contribution pattern:

1. **Fork** `aws-samples/sample-aiml-security-assessment` under the contributor's GitHub handle.
2. **Clone the fork locally.** Add upstream remote:
   ```
   git remote add upstream https://github.com/aws-samples/sample-aiml-security-assessment.git
   ```
3. **Create an umbrella tracking issue** on upstream titled something like `Feature: OWASP LLM Top 10 (2025) Coverage`, referencing this proposal.
4. **Feature branch per phase**:
   - `feature/owasp-llm-phase1-schema-and-ui`
   - `feature/owasp-llm-phase2a-br05-br07-ac05-extensions`
   - `feature/owasp-llm-phase2b-new-owasp-lambda` (itself split into sub-PRs per OWASP category group: LLM01-05, LLM06-07, LLM08-10)
   - `feature/owasp-llm-phase3-polish`
5. **PR target:** upstream `main`. Each PR references the umbrella issue. Each PR is small enough to review in one sitting (target ≤ 500 lines changed where possible, exclusive of HTML template).
6. **Sync with upstream** before each PR: `git fetch upstream && git rebase upstream/main`.
7. **Pre-PR checklist** per phase:
   - All tests in §7b pass locally.
   - `ruff`, `cfn-lint`, `sam validate` clean.
   - Sample report generated and screenshotted (attached to PR).
   - `SECURITY_CHECKS.md` updated.
   - `DEVELOPER_GUIDE.md` updated if new extension patterns introduced.

---

## 8. Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| OWASP categories update and our mappings drift | Medium | Low | Keep mapping table in `SECURITY_CHECKS.md` as single source of truth, reviewed yearly. Version-tag in check metadata (e.g., `OWASP_Version: "2025"`). |
| False positives annoying customers | Medium | Medium | Every new check has a documented remediation link. N/A path is mandatory when no resources exist. Checks that are heuristic (OW-13, OW-06, OW-18) default to Informational severity. **OW-03 has an explicit "non-PII workload" tag path to Informational.** |
| **Customers misread partial-coverage categories as fully assessed** | **Medium** | **High** | **Explicit "partial — application-layer" badge in report tile, wording in executive summary, `OWASP_Coverage_Type` metadata field, and a glossary entry in the HTML report footer. LLM03 and LLM05 must never show a green checkmark.** |
| Scope creep into active prompt-injection testing | Medium | High | Explicit non-goal in Section 2. If we want active testing later, it's a separate tool with a different threat model. |
| New IAM permissions slow StackSet rollout | Low | Medium | Permissions added surgically, ship in a single deployment template update, document in troubleshooting guide. |
| Customer concerns about log/data access | Low | High | Reinforce read-only, control-plane-only in README. No invocation payloads are ever read. |
| Maintenance burden of 17 new checks | Medium | Low | Each check follows the existing schema and test patterns. `test_generate_report.py` gets extended. Ownership lives with the OWASP branch contributor. |
| **OW-11 logic relies on assumptions about inline vs. managed prompts** | **Medium** | **Low** | **Inline prompt usage is unknowable from AWS APIs. OW-11 surfaces what IS detectable (Bedrock Prompt resource policies, agent instruction presence) and recommends Prompt Management as a best practice via an Informational sub-finding. The report text is explicit that inline prompts require application-layer review.** |

---

## 9. Success Criteria

- **Coverage:**
  - 10/10 OWASP LLM 2025 categories have at least one check tagged.
  - **LLM03 and LLM05 are acknowledged as partial-coverage categories** with application-layer gaps explicitly documented in the report (no false "all-green" signal).
- **Customer signal:** In the first 3 customer engagements post-release, at least 2 cite the OWASP view as useful.
- **No regressions:** existing 52 checks continue to pass their validation tests.
- **Documentation parity:** every new check has an entry in `SECURITY_CHECKS.md` matching the existing format, with AWS doc reference link.
- **Report parity:** OWASP view works in both single-account and multi-account consolidated reports, with partial-coverage badges visible in both modes.

---

## 10. Rough Timeline

Assuming one engineer at ~50% capacity. Calendar estimates, not committed dates. v3 shortens the timeline slightly because Phase 2a (extensions) is faster than building equivalent new Lambdas.

| Phase | Scope | Estimate |
|---|---|---|
| Phase 1 — Schema + prototype-aligned UX | `ComplianceMapping` schema, tag 52 existing checks, port prototype compliance section into `report_template.py`, partial-coverage UX, `SECURITY_CHECKS.md` update | ~2 weeks |
| Phase 2a — Extensions (reuse path) | BR-05, BR-07, AC-05 extensions covering OW-01, 03, 08, 11, 14, 15a, 16 | ~1.5 weeks |
| Phase 2b — New `owasp_assessments/` Lambda | 11 net-new checks (OW-02, 04, 05, 06, 07, 09, 10, 12, 13, 15b, 17, 18), Step Functions branch, SAM template, IAM delta | ~2.5 weeks |
| Phase 3 — Polish | Sample report refresh, screenshots, README badge, docs | ~1 week |
| **Total** | 17 new checks + tagging + multi-framework UX | **~7 weeks** |

Each phase ends with a demoable state. Phase 1 alone already gives customers an OWASP-mapped report. Phase 2a lands 6 OWASP checks without standing up a new Lambda.

---

## 11. Open Questions for Agasthi / Team

Resolved in v3 (carried forward for visibility):
- ~~**Multi-framework schema:** build for multi-framework from day one vs OWASP-only~~ → **Resolved in v3 §6/§7:** multi-framework `Compliance_Mappings` list, grounded in the supplied prototype.
- ~~**Reuse existing checks:** yes/no~~ → **Resolved in v3 §5a:** 6 checks delivered as extensions, 11 as new Lambda.

Still open:

1. **OWASP check prefix:** `OW-` feels clean, but should we instead prefix by the target service (`BR-OW-01`, `AC-OW-01`) to align with existing BR/SM/AC conventions? Either works — preference?
2. **Severity calibration:** v2 dropped OW-15 from High to Medium. OW-03 dropped from High to Medium with tunable-to-Informational for non-PII. OW-07, OW-09, OW-11, OW-17 remain High. Aligned?
3. **Phase 2 active testing scope:** worth opening a parallel proposal for adversarial prompt probes (out of scope here), or park it?
4. **Fine-tuning data access audit (LLM04):** explicitly descope for this phase, or add a 20th check? Recommendation: descope, track as follow-up.
5. **FSI hand-off timing:** should Neil's FSI lens start immediately after Phase 1 (schema + UX) lands so NIST/HIPAA tiles populate in parallel with Phase 2, or sequence FSI after Phase 3? Preference for coordination?
6. **Test AWS account for end-to-end:** is there a dedicated sandbox account we can use, or do we provision one?

---

## 12. Appendix A — Proposed OWASP Mapping for Existing 52 Checks

Quick reference for Phase 1 tagging. Final mapping lives in `SECURITY_CHECKS.md` post-implementation. Coverage type in brackets: `[full]` = AWS control plane fully assesses; `[comp]` = compensating control only; `[partial]` = part of a broader OWASP category.

| Check | OWASP Primary | OWASP Secondary |
|---|---|---|
| BR-01 IAM Least Privilege | LLM06 [full] | — |
| BR-02 VPC Endpoint | LLM02 [full] | — |
| BR-03 Marketplace Access | LLM03 [partial] | — |
| BR-04 Model Invocation Logging | LLM02 [full] | LLM09 [partial] |
| BR-05 Guardrail Configuration | LLM01 [full] | LLM05 [comp] |
| BR-06 CloudTrail Logging | LLM02 [full] | — |
| BR-07 Prompt Management | LLM07 [partial] | — |
| BR-08 Agent IAM | LLM06 [full] | — |
| BR-09 KB Encryption | LLM02 [full] | LLM08 [partial] |
| BR-10 Guardrail IAM Enforcement | LLM01 [full] | — |
| BR-11 Custom Model Encryption | LLM02 [full] | LLM03 [partial] |
| BR-12 Invocation Log Encryption | LLM02 [full] | — |
| BR-13 Flows Guardrails | LLM01 [full] | LLM05 [comp] |
| BR-14 Stale Bedrock Access | LLM06 [full] | — |
| SM-01 Internet Access | LLM02 [full] | — |
| SM-02 IAM Permissions | LLM06 [full] | — |
| SM-03 Data Protection | LLM02 [full] | — |
| SM-04 GuardDuty | LLM02 [full] | — |
| SM-05 MLOps | LLM04 [partial] | — |
| SM-06 Clarify | LLM09 [partial] | LLM04 [partial] |
| SM-07 Model Monitor | LLM04 [partial] | LLM09 [partial] |
| SM-08 Model Registry | LLM03 [partial] | LLM04 [partial] |
| SM-09 Notebook Root Access | LLM06 [full] | — |
| SM-10 Notebook VPC | LLM02 [full] | — |
| SM-11 Model Network Isolation | LLM02 [full] | — |
| SM-12 Endpoint Instance Count | LLM10 [partial] | — |
| SM-13 Monitoring Network Isolation | LLM02 [full] | — |
| SM-14 Model Container Repo | LLM03 [partial] | — |
| SM-15–SM-20 Encryption (various) | LLM02 [full] | — |
| SM-21 AutoML Network Isolation | LLM02 [full] | — |
| SM-22 Model Approval | LLM04 [partial] | LLM03 [partial] |
| SM-23 Model Drift | LLM04 [partial] | LLM09 [partial] |
| SM-24 A/B & Shadow | LLM04 [partial] | — |
| SM-25 Lineage | LLM04 [partial] | LLM03 [partial] |
| AC-01 Runtime VPC | LLM02 [full] | — |
| AC-02 IAM Full Access | LLM06 [full] | — |
| AC-03 Stale Access | LLM06 [full] | — |
| AC-04 Observability | LLM02 [full] | LLM09 [partial] |
| AC-05 ECR Encryption | LLM02 [full] | LLM03 [partial] |
| AC-06 Browser Tool Recording | LLM02 [full] | — |
| AC-07 Memory Encryption | LLM02 [full] | — |
| AC-08 VPC Endpoints | LLM02 [full] | — |
| AC-09 Service-Linked Role | LLM06 [full] | — |
| AC-10 Resource-Based Policies | LLM06 [full] | — |
| AC-11 Policy Engine Encryption | LLM02 [full] | — |
| AC-12 Gateway Encryption | LLM02 [full] | — |
| AC-13 Gateway Configuration | LLM06 [full] | — |

---

## 13. Appendix B — Summary of v1 → v2 Changes

This version incorporates expert OWASP LLM Top 10 review feedback. Changes:

| # | Type | Section | Change |
|---|---|---|---|
| 1 | Critical | §1, §4, §5 (OW-08) | Reframed LLM05 as application-layer gap; OW-08 explicitly labeled as compensating control. Report will not show LLM05 as fully passed. |
| 2 | Critical | §5 (OW-11) | Replaced fragile topic-name heuristic with concrete, implementable check on Bedrock Prompt resource policies and agent instruction presence. |
| 3 | Critical | §5 intro, §7 | Resolved schema-change contradiction. Section 7 now states explicitly: there is a schema change, it is backward-compatible, and the existing regex already accepts `OW-XX`. |
| 4 | Add check | §5 LLM03 | Added OW-16: ECR image scanning for SageMaker/AgentCore containers. |
| 5 | Add check | §5 LLM02 | Added OW-17: KB retrieval resource policy (addresses RAG retrieval disclosure). |
| 6 | Strengthen | §5 OW-15 | Added guardrail word/token length limit as a second, proactive vector for LLM10 (was observability-only). |
| 7 | Acknowledge | §4, §5 | Added OW-18 informational multi-agent sub-agent inventory check; coverage matrix explicitly notes LLM06 2025 multi-agent trust boundary expansion. |
| 8 | Severity | §5 OW-15 | Changed High → Medium with rationale (missing alarms is observability, consistent with BR-04/BR-06 Medium). |
| 9 | API list | §5 OW-02, §7 IAM delta | Added `s3:GetBucketPublicAccessBlock` as the primary signal for bucket public-access verification. |
| 10 | N/A path | §5 OW-03 | Documented N/A path (no guardrails) and tunable-Informational path (non-PII workloads). Default severity dropped from High to Medium. |
| 11 | Gap | §4 LLM04, §5 OW-07 note | Explicitly scoped fine-tuning data access audit as future work (tracked in Section 11 Q4). |
| 12 | Success criteria | §9 | LLM03 and LLM05 qualified as partial-coverage categories, preventing false "all-green" customer interpretation. |

**Net effect:** total new checks 15 → **17**. Total framework checks 67 → **69**. Timeline ~6.5 weeks → ~8 weeks.

---

## 14. Appendix C — Summary of v2 → v3 Changes

v3 incorporates Agasthi's direction (reuse existing checks, use prototype UI as initial reference, test thoroughly, fork-and-branch) and the multi-framework realization from studying the prototype.

| # | Type | Section | Change |
|---|---|---|---|
| 1 | Reuse | §5a (new) | Added reuse analysis showing 6 of 17 checks fold into BR-05/BR-07/AC-05 extensions rather than new Lambda code. Net-new Lambda code drops ~35%. |
| 2 | Architecture | §7 workflow diagram | Hybrid approach: existing service branches grow for folded-in checks; new `owasp_assessments` Lambda handles 11 net-new checks. |
| 3 | Schema | §6, §7 | Revised single-field `OWASP_Category` to multi-framework `Compliance_Mappings: List[ComplianceMapping]` based on the prototype's framework-agnostic design. Answers v2 Q5 and unblocks Neil's FSI lens integration. |
| 4 | UX | §6 (rewritten) | Replaced ASCII coverage-tile sketch with prototype-grounded design: Compliance Dashboard tile group per framework, per-framework detail sections, multi-framework badges on findings, extended severity/compliance legend. |
| 5 | UX iteration | §6 | Added "Partial — application-layer" as a distinct status, status-hover tooltips, "Unable to assess" state, drill-down from compliance row → filtered findings table, OWASP-filtered CSV export. |
| 6 | Scope | §6 | Phase 1 ships OWASP populated + NIST/ATLAS/HIPAA tiles as "Planned" placeholders — honest scope, concrete hand-off point for FSI lens. |
| 7 | IAM delta | §7 | Trimmed delta to show only truly incremental permissions; 6 already-granted permissions called out explicitly. |
| 8 | Testing | §7b (new) | Formal test strategy: unit (moto-backed), integration, end-to-end in sandbox account, multi-account, regression, performance budget. Gates each PR. |
| 9 | Workflow | §7c (new) | Fork + feature-branch + PR-per-phase process, umbrella tracking issue, pre-PR checklist. |
| 10 | Timeline | §10 | Adjusted to ~7 weeks (Phase 2a extensions faster than equivalent new Lambdas). |

**Net effect:** customer-visible output is the same (17 new OWASP checks, 69 total). Internal implementation is leaner, schema is future-proof for multi-framework, UX is concrete and grounded in the supplied prototype.

---

*End of proposal. Ready for review.*
