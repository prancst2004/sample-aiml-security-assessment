# Security Checks Reference

This document provides a comprehensive reference for all 69 security checks performed by the AI/ML Security Assessment framework (51 service-level checks plus 18 OWASP LLM Top 10 extensions).

## Table of Contents

- [Overview](#overview)
- [Check ID Convention](#check-id-convention)
- [Severity Levels](#severity-levels)
- [Status Values](#status-values)
- [Amazon SageMaker AI Security Checks (25)](#amazon-sagemaker-ai-security-checks-25)
- [Amazon Bedrock Security Checks (13)](#amazon-bedrock-security-checks-13)
- [Amazon Bedrock AgentCore Security Checks (13)](#amazon-bedrock-agentcore-security-checks-13)
- [OWASP LLM Top 10 Extensions (18)](#owasp-llm-top-10-extensions-18)

---

## Overview

The framework evaluates your AI/ML workloads against AWS security best practices across three services:

| Service | Number of Checks | Focus Areas |
|---------|------------------|-------------|
| Amazon SageMaker AI | 25 | Security Hub controls, encryption, network isolation, IAM, MLOps |
| Amazon Bedrock | 13 | Guardrails, encryption, VPC endpoints, IAM permissions, logging |
| Amazon Bedrock AgentCore | 13 | VPC configuration, encryption, observability, resource policies |
| OWASP LLM Top 10 Extensions | 18 | Prompt injection, sensitive info disclosure, supply chain, data/model poisoning, improper output handling, excessive agency, system prompt leakage, vector/embedding weaknesses, misinformation, unbounded consumption |

---

## Check ID Convention

Each security check has a unique identifier with a service prefix:

| Prefix | Service | Example |
|--------|---------|---------|
| **SM-XX** | Amazon SageMaker | SM-01, SM-25 |
| **BR-XX** | Amazon Bedrock | BR-01, BR-13 |
| **AC-XX** | Amazon Bedrock AgentCore | AC-01, AC-13 |
| **OW-XX** | OWASP LLM Top 10 Extensions | OW-01, OW-18 |

---

## Severity Levels

| Severity | Description | Action Required |
|----------|-------------|-----------------|
| **High** | Critical security issues that could lead to data exposure, unauthorized access, or compliance violations | Immediate remediation recommended |
| **Medium** | Important security improvements that strengthen your security posture | Address in next maintenance window |
| **Low** | Minor optimizations and best practice recommendations | Address when convenient |
| **Informational** | Advisory information about your configuration | No action required |
| **N/A** | Check not applicable (no resources to assess) | No action required |

---

## Status Values

| Status | Description |
|--------|-------------|
| **Failed** | Security issue identified that requires remediation |
| **Passed** | Checked resources met the assessed best practice at time of scan |
| **N/A** | No resources exist to check (for example, no notebooks, no guardrails configured) |

---

## Amazon SageMaker AI Security Checks (25)

### SM-01: Internet Access

- **Severity:** High
- **AWS Security Hub Control:** SageMaker.2
- **Description:** Checks for direct internet access on notebooks and domains.

### SM-02: AWS IAM Permissions

- **Severity:** High
- **Description:** Identifies overly permissive policies, stale access, and IAM Identity Center configuration.

### SM-03: Data Protection

- **Severity:** High
- **AWS Security Hub Control:** SageMaker.1
- **Description:** Verifies encryption at rest and in transit for notebooks and domains.

### SM-04: Amazon GuardDuty Integration

- **Severity:** Medium
- **Description:** Verifies Amazon GuardDuty runtime threat detection is enabled.

### SM-05: MLOps Features

- **Severity:** Low
- **Description:** Checks MLOps pipelines, experiment tracking, and model registry usage.

### SM-06: Clarify Usage

- **Severity:** Low
- **Description:** Validates SageMaker Clarify for bias detection and explainability.

### SM-07: Model Monitor

- **Severity:** Medium
- **Description:** Checks Model Monitor configuration for drift detection.

### SM-08: Model Registry

- **Severity:** Medium
- **Description:** Validates model registry usage and permissions.

### SM-09: Notebook Root Access

- **Severity:** High
- **AWS Security Hub Control:** SageMaker.3
- **Description:** Validates root access is disabled on notebooks.

### SM-10: Notebook Amazon VPC Deployment

- **Severity:** High
- **AWS Security Hub Control:** SageMaker.2
- **Description:** Ensures notebooks are deployed within an Amazon VPC.

### SM-11: Model Network Isolation

- **Severity:** Medium
- **AWS Security Hub Control:** SageMaker.4
- **Description:** Checks inference containers have network isolation.

### SM-12: Endpoint Instance Count

- **Severity:** Medium
- **AWS Security Hub Control:** SageMaker.5
- **Description:** Verifies endpoints have 2+ instances for high availability.

### SM-13: Monitoring Network Isolation

- **Severity:** Medium
- **Description:** Checks monitoring job network isolation.

### SM-14: Model Container Repository

- **Severity:** Medium
- **Description:** Validates model container repository access.

### SM-15: Feature Store Encryption

- **Severity:** High
- **Description:** Checks feature group encryption settings.

### SM-16: Data Quality Encryption

- **Severity:** Medium
- **Description:** Validates data quality job encryption.

### SM-17: Processing Job Encryption

- **Severity:** Medium
- **Description:** Verifies processing job encryption.

### SM-18: Transform Job Encryption

- **Severity:** Medium
- **Description:** Checks transform job volume encryption.

### SM-19: Hyperparameter Tuning Encryption

- **Severity:** Medium
- **Description:** Validates hyperparameter tuning job encryption.

### SM-20: Compilation Job Encryption

- **Severity:** Medium
- **Description:** Checks compilation job encryption.

### SM-21: AutoML Network Isolation

- **Severity:** Medium
- **Description:** Validates AutoML job network isolation.

### SM-22: Model Approval Workflow

- **Severity:** Medium
- **Description:** Checks model approval and governance workflow.

### SM-23: Model Drift Detection

- **Severity:** Medium
- **Description:** Validates model drift monitoring configuration.

### SM-24: A/B Testing and Shadow Deployment

- **Severity:** Low
- **Description:** Checks for safe deployment patterns.

### SM-25: ML Lineage Tracking

- **Severity:** Low
- **Description:** Validates experiment tracking and lineage.

---

## Amazon Bedrock Security Checks (13)

### BR-01: AWS IAM Least Privilege

- **Severity:** High
- **Description:** Identifies roles with AmazonBedrockFullAccess policy.

### BR-02: Amazon VPC Endpoint Configuration

- **Severity:** High
- **Description:** Validates Bedrock Amazon VPC endpoints exist for private connectivity.

### BR-03: Marketplace Subscription Access

- **Severity:** Medium
- **Description:** Checks for overly permissive marketplace subscription access.

### BR-04: Model Invocation Logging

- **Severity:** Medium
- **Description:** Checks invocation logging is enabled.

### BR-05: Guardrail Configuration

- **Severity:** High
- **Description:** Verifies guardrails are configured and enforced.

### BR-06: AWS CloudTrail Logging

- **Severity:** Medium
- **Description:** Validates AWS CloudTrail logging for Bedrock API calls.

### BR-07: Prompt Management

- **Severity:** Low
- **Description:** Validates Bedrock Prompt template usage and variants.

### BR-08: Agent AWS IAM Configuration

- **Severity:** Medium
- **Description:** Checks agent execution role permissions.

### BR-09: Knowledge Base Encryption

- **Severity:** High
- **Description:** Checks knowledge base encryption settings.

### BR-10: Guardrail AWS IAM Enforcement

- **Severity:** Medium
- **Description:** Verifies guardrails are enforced through AWS IAM conditions.

### BR-11: Custom Model Encryption

- **Severity:** High
- **Description:** Validates custom models use customer-managed AWS KMS keys.

### BR-12: Invocation Log Encryption

- **Severity:** Medium
- **Description:** Verifies logs are encrypted with AWS KMS.

### BR-13: Flows Guardrails

- **Severity:** Medium
- **Description:** Validates Bedrock Flows have guardrails attached.

---

## Amazon Bedrock AgentCore Security Checks (13)

### AC-01: Runtime Amazon VPC Configuration

- **Severity:** High
- **Description:** Validates agent runtimes have proper Amazon VPC settings.

### AC-02: AWS IAM Full Access

- **Severity:** High
- **Description:** Checks for overly permissive AgentCore AWS IAM policies.

### AC-03: Stale Access

- **Severity:** Low
- **Description:** Detects unused AgentCore permissions.

### AC-04: Observability

- **Severity:** Medium
- **Description:** Verifies Amazon CloudWatch Logs and AWS X-Ray tracing configuration.

### AC-05: Amazon ECR Repository Encryption

- **Severity:** High
- **Description:** Validates Amazon ECR repositories use encryption.

### AC-06: Browser Tool Recording

- **Severity:** Medium
- **Description:** Checks storage configuration for browser tools.

### AC-07: Memory Encryption

- **Severity:** High
- **Description:** Checks agent memory encryption with AWS KMS.

### AC-08: Amazon VPC Endpoints

- **Severity:** High
- **Description:** Validates Amazon VPC endpoints for AgentCore services.

### AC-09: Service-Linked Role

- **Severity:** Medium
- **Description:** Verifies the AgentCore service-linked role exists.

### AC-10: Resource-Based Policies

- **Severity:** Medium
- **Description:** Checks runtime and gateway resource policies.

### AC-11: Policy Engine Encryption

- **Severity:** Medium
- **Description:** Validates policy engine encryption settings.

### AC-12: Gateway Encryption

- **Severity:** Medium
- **Description:** Verifies gateway encryption settings.

### AC-13: Gateway Configuration

- **Severity:** Medium
- **Description:** Validates gateway security configuration.

---

## OWASP LLM Top 10 Extensions (18)

These checks extend the service assessments with targeted controls mapped to the [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/). Findings emitted by these checks carry framework mappings in the `Compliance_Mappings` field and drive the Compliance Dashboard + OWASP detail sections of the HTML report.

Seven checks (OW-01, OW-03, OW-08, OW-11, OW-14, OW-15, OW-16) ride on existing service Lambdas by extending BR-05 / BR-07 / AC-05. The remaining eleven run in a dedicated `owasp_assessments/` Lambda.

### OW-01: Guardrail Prompt-Attack Filter Strength

- **Severity:** High
- **OWASP Mapping:** LLM01 Prompt Injection
- **Description:** Verifies every Bedrock guardrail includes a PROMPT_ATTACK content filter with HIGH input and output strength.

### OW-02: Knowledge Base Source Trust

- **Severity:** Medium
- **OWASP Mapping:** LLM01 Prompt Injection / LLM03 Supply Chain
- **Description:** For each Bedrock Knowledge Base S3 data source, checks that the source bucket is not public (complete Block Public Access + no public bucket policy). Public source buckets are an indirect prompt-injection vector.

### OW-03: Guardrail PII Redaction

- **Severity:** Medium
- **OWASP Mapping:** LLM02 Sensitive Information Disclosure
- **Description:** Verifies guardrails have `sensitiveInformationPolicy` configured with BLOCK or ANONYMIZE for EMAIL, PHONE, SSN, and CREDIT_DEBIT_CARD_NUMBER at minimum.

### OW-04: Invocation Log Retention & Access

- **Severity:** Medium (High when S3 destination is public)
- **OWASP Mapping:** LLM02 Sensitive Information Disclosure
- **Description:** Confirms Bedrock model-invocation logging is enabled. Validates CloudWatch log-group retention is at least 30 days; validates S3 destination buckets are not public.

### OW-05: Imported / Custom Model Provenance

- **Severity:** Medium
- **OWASP Mapping:** LLM03 Supply Chain
- **Description:** Lists Bedrock custom models and flags any whose training-data source bucket is unreachable (cross-account signal) or whose provenance is undocumented.

### OW-06: SageMaker JumpStart & Marketplace Inventory

- **Severity:** Low (informational)
- **OWASP Mapping:** LLM03 Supply Chain
- **Description:** Enumerates SageMaker model packages sourced from JumpStart or AWS Marketplace for customer supply-chain review. No hard pass/fail.

### OW-07: Knowledge Base Ingestion Role Scope

- **Severity:** High
- **OWASP Mapping:** LLM04 Data and Model Poisoning
- **Description:** Inspects the IAM role attached to KB data-source ingestion. Fails when inline policies use dangerous wildcards (`s3:*` on `*`, `Action: "*"` on `Resource: "*"`).

### OW-08: Guardrail Output Filter (Compensating)

- **Severity:** Medium
- **OWASP Mapping:** LLM05 Improper Output Handling (compensating)
- **Description:** Verifies each guardrail has at least one output-side control — content filter outputStrength, wordPolicy, or topicPolicy. Does not replace application-layer output sanitization.

### OW-09: Agent Action-Group Wildcard Scope

- **Severity:** High
- **OWASP Mapping:** LLM06 Excessive Agency
- **Description:** For every Bedrock Agent action group, resolves the executor Lambda's execution role and flags inline policies with `Action: "*"` / `service:*` on `Resource: "*"`.

### OW-10: Human-in-the-Loop & Confirmation Flow

- **Severity:** Informational
- **OWASP Mapping:** LLM06 Excessive Agency
- **Description:** Per-agent inventory of action groups with `requireConfirmation = ENABLED` vs. those that run without confirmation. Surfaces autonomy posture for customer review.

### OW-11: System Prompt Protection

- **Severity:** Medium
- **OWASP Mapping:** LLM07 System Prompt Leakage (partial / application-layer)
- **Description:** Detects whether Bedrock Prompt Management is in use. Inline prompts in application code are outside AWS control-plane scope.

### OW-12: Vector Store Network Isolation

- **Severity:** High
- **OWASP Mapping:** LLM08 Vector and Embedding Weaknesses
- **Description:** Resolves each Bedrock KB's vector store. Fails on OpenSearch Serverless collections with `AllowFromPublic=true` network policies, or on Aurora instances with `PubliclyAccessible=true`. External stores (Pinecone, Redis, MongoDB Atlas) emit N/A.

### OW-13: Multi-Tenant Knowledge Base Isolation

- **Severity:** Medium
- **OWASP Mapping:** LLM08 Vector and Embedding Weaknesses
- **Description:** Heuristic — warns when multiple Bedrock KBs share a single OpenSearch Serverless collection. Per-tenant filtering becomes the application's responsibility.

### OW-14: Contextual Grounding Guardrail

- **Severity:** Medium
- **OWASP Mapping:** LLM09 Misinformation
- **Description:** Verifies each Bedrock guardrail has `contextualGroundingPolicy` enabled with GROUNDING + RELEVANCE filters for RAG workloads.

### OW-15: Invocation Rate, Token & Cost Controls

- **Severity:** Medium
- **OWASP Mapping:** LLM10 Unbounded Consumption
- **Description:** Two-legged check: (a) proactive leg (in Bedrock Lambda) — guardrail `wordPolicy` blocks oversized inputs; (b) detective leg (in OWASP Lambda) — CloudWatch alarms on `AWS/Bedrock` / `AWS/SageMaker` metrics OR AWS Budgets scoped to those services. Fails if neither is present.

### OW-16: Container Image Scanning

- **Severity:** Medium
- **OWASP Mapping:** LLM03 Supply Chain
- **Description:** Verifies ECR repositories used by SageMaker models and AgentCore runtimes have `imageScanningConfiguration.scanOnPush = true`.

### OW-17: Knowledge Base Retrieval Access Policy

- **Severity:** High
- **OWASP Mapping:** LLM02 Sensitive Information Disclosure
- **Description:** For each Bedrock KB, checks for a resource-based policy restricting `bedrock-agent:Retrieve` and `RetrieveAndGenerate` to named IAM principals.

### OW-18: Multi-Agent Sub-Agent Inventory

- **Severity:** Medium
- **OWASP Mapping:** LLM06 Excessive Agency (2025 multi-agent revision)
- **Description:** Detects orchestrator agents by flagging those whose action-group Lambda role is permitted `bedrock-agent:InvokeAgent`. Surfaces agent-calling-agent trust boundaries for review.

---

## Additional Resources

- [Amazon SageMaker Security Best Practices](https://docs.aws.amazon.com/sagemaker/latest/dg/security.html)
- [Amazon Bedrock Security](https://docs.aws.amazon.com/bedrock/latest/userguide/security.html)
- [AWS Security Hub SageMaker Controls](https://docs.aws.amazon.com/securityhub/latest/userguide/sagemaker-controls.html)
- [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/)
- [AWS Well-Architected Framework - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
