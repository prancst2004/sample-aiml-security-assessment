"""
Compliance aggregation helpers for the AI/ML Security Assessment report.

Single responsibility: turn the raw findings list (each with
Compliance_Mappings attached) into the shapes the HTML template
consumes for the Compliance Dashboard and per-framework detail
sections.

All functions are pure — no I/O, no mutation of inputs. Easy to unit test.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

# ---------------------------------------------------------------------------
# OWASP LLM Top 10 (2025) descriptive catalog
#
# The report always renders all 10 categories so customers see complete
# coverage, even when no findings map to a given control. The descriptions
# are rephrased from the OWASP GenAI LLM Top 10 2025 spec (rephrased for
# compliance with licensing restrictions).
# ---------------------------------------------------------------------------

OWASP_LLM_CATALOG: List[Dict[str, str]] = [
    {
        "control_id": "LLM01",
        "name": "Prompt Injection",
        "description": "Crafted inputs that override model instructions or exfiltrate data. Includes direct prompts and indirect content (e.g., poisoned Knowledge Base documents).",
        "aws_controls": "Bedrock Guardrails prompt-attack filter, Flows guardrail attachment, IAM guardrail enforcement",
    },
    {
        "control_id": "LLM02",
        "name": "Sensitive Information Disclosure",
        "description": "Responses or retrievals that leak PII, credentials, proprietary data, or internal context to unauthorized parties.",
        "aws_controls": "Guardrails PII filters, KMS encryption, VPC endpoints, invocation log retention",
    },
    {
        "control_id": "LLM03",
        "name": "Supply Chain",
        "description": "Risks from third-party models, marketplace sources, training data, plugins, or dependencies. Has application-layer dimensions outside AWS control plane.",
        "aws_controls": "Marketplace access controls, custom-model encryption, ECR encryption, Model Registry",
    },
    {
        "control_id": "LLM04",
        "name": "Data and Model Poisoning",
        "description": "Manipulation of training, fine-tuning, or Knowledge-Base data to bias or backdoor model behavior.",
        "aws_controls": "Model Registry approval workflows, drift detection, lineage tracking, Clarify bias checks",
    },
    {
        "control_id": "LLM05",
        "name": "Improper Output Handling",
        "description": "Downstream code that consumes LLM output without sanitization (e.g., eval, SQL, shell). AWS control plane cannot fully assess this — application-layer review required.",
        "aws_controls": "Guardrails output filters (compensating control only)",
    },
    {
        "control_id": "LLM06",
        "name": "Excessive Agency",
        "description": "LLMs or agents granted broad permissions, tool access, or autonomy beyond what the use case requires. 2025 revision also covers multi-agent trust boundaries.",
        "aws_controls": "IAM least privilege, agent action-group scope, AgentCore IAM, resource policies",
    },
    {
        "control_id": "LLM07",
        "name": "System Prompt Leakage",
        "description": "Exposure of system instructions or business logic embedded in prompts. Protectable via managed Prompt resources and access controls.",
        "aws_controls": "Bedrock Prompt Management, agent instruction protection, IAM",
    },
    {
        "control_id": "LLM08",
        "name": "Vector and Embedding Weaknesses",
        "description": "Retrieval-augmented systems compromised by poisoned vectors, cross-tenant leakage, or public vector-store endpoints.",
        "aws_controls": "Knowledge Base encryption, OpenSearch Serverless isolation, retrieval access policies",
    },
    {
        "control_id": "LLM09",
        "name": "Misinformation",
        "description": "Hallucinations or ungrounded outputs presented as fact, leading to downstream harm.",
        "aws_controls": "Contextual grounding guardrails, Model Monitor, SageMaker Clarify",
    },
    {
        "control_id": "LLM10",
        "name": "Unbounded Consumption",
        "description": "Resource exhaustion via oversized inputs, excessive invocations, or runaway cost. Requires both proactive (limits) and detective (alarms) controls.",
        "aws_controls": "Guardrails word/token limits, CloudWatch alarms, AWS Budgets, provisioned throughput",
    },
]


# ---------------------------------------------------------------------------
# Framework placeholder catalog
#
# OWASP LLM Top 10 is fully populated. NIST AI RMF, MITRE ATLAS, and
# HIPAA are informational placeholders for future framework coverage.
# ---------------------------------------------------------------------------

FRAMEWORK_PLACEHOLDERS: List[Dict[str, str]] = [
    {
        "framework_id": "OWASP-LLM",
        "short_name": "OWASP",
        "display_name": "OWASP Top 10 for LLM",
        "version": "2025",
        "status": "active",
        "accent_class": "owasp",
    },
    {
        "framework_id": "NIST-AI-RMF",
        "short_name": "NIST",
        "display_name": "NIST AI RMF",
        "version": "1.0",
        "status": "planned",
        "accent_class": "nist",
    },
    {
        "framework_id": "MITRE-ATLAS",
        "short_name": "ATLAS",
        "display_name": "MITRE ATLAS",
        "version": "",
        "status": "planned",
        "accent_class": "atlas",
    },
    {
        "framework_id": "HIPAA",
        "short_name": "HIPAA",
        "display_name": "HIPAA AI/ML",
        "version": "",
        "status": "planned",
        "accent_class": "hipaa",
    },
]


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def _finding_status_lower(finding: Dict) -> str:
    return (finding.get("status") or finding.get("Status") or "").lower()


def _finding_mappings(finding: Dict) -> List[Dict]:
    """Return Compliance_Mappings, tolerating different cases."""
    return (
        finding.get("Compliance_Mappings")
        or finding.get("compliance_mappings")
        or []
    )


def aggregate_owasp_coverage(findings: List[Dict]) -> Dict[str, Dict]:
    """
    For each OWASP LLM control LLM01..LLM10, aggregate pass/fail/na counts
    across findings mapped to that control.

    Returns:
        {
            "LLM01": {
                "name": "Prompt Injection",
                "description": "...",
                "aws_controls": "...",
                "passed": int,
                "failed": int,
                "na": int,
                "total": int,
                "status": "compliant" | "partial" | "non-compliant" | "not-assessed",
                "coverage_type": "full" | "compensating" | "partial-app-layer",
            },
            ...
        }

    `status` rules:
      - If all mapped findings passed AND total > 0: "compliant"
      - If any mapped finding failed: "non-compliant"
      - If mapped findings include some passed + some N/A: "partial"
      - If total == 0: "not-assessed"
      - Override: if the underlying coverage_type is "partial-app-layer" or
        "compensating", cap at "partial" even if all passed. This enforces
        the honest scope signaling from the proposal (LLM03 and LLM05 are
        never shown as fully compliant).
    """
    result: Dict[str, Dict] = {}

    for entry in OWASP_LLM_CATALOG:
        control_id = entry["control_id"]
        result[control_id] = {
            "name": entry["name"],
            "description": entry["description"],
            "aws_controls": entry["aws_controls"],
            "passed": 0,
            "failed": 0,
            "na": 0,
            "total": 0,
            "coverage_type": "full",
            "status": "not-assessed",
        }

    # Track the strictest coverage type we see for each control
    strictness_order = {"full": 0, "compensating": 1, "partial-app-layer": 2}

    for finding in findings:
        status = _finding_status_lower(finding)
        for mapping in _finding_mappings(finding):
            if mapping.get("framework") != "OWASP-LLM":
                continue
            ctrl = mapping.get("control_id")
            if ctrl not in result:
                continue

            result[ctrl]["total"] += 1
            if status == "passed":
                result[ctrl]["passed"] += 1
            elif status == "failed":
                result[ctrl]["failed"] += 1
            else:
                result[ctrl]["na"] += 1

            mapping_coverage = mapping.get("coverage_type", "full")
            if strictness_order.get(mapping_coverage, 0) > strictness_order.get(
                result[ctrl]["coverage_type"], 0
            ):
                result[ctrl]["coverage_type"] = mapping_coverage

    # Derive status per control
    for ctrl_id, row in result.items():
        if row["total"] == 0:
            row["status"] = "not-assessed"
        elif row["failed"] > 0:
            row["status"] = "non-compliant"
        elif row["coverage_type"] in ("compensating", "partial-app-layer"):
            # Even if all passed, cap at partial to signal scope limitation
            row["status"] = "partial"
        elif row["na"] > 0 and row["passed"] == 0:
            row["status"] = "partial"
        else:
            row["status"] = "compliant"

    return result


def calculate_owasp_compliance_rate(
    owasp_coverage: Dict[str, Dict]
) -> Tuple[int, int, int, int, int]:
    """
    Given per-control aggregation, compute:
      (compliant_count, partial_count, non_compliant_count, not_assessed_count, rate_percent)

    `rate_percent` = compliant / (compliant + partial + non-compliant) * 100,
    rounded. Controls with status "not-assessed" are excluded from the
    denominator (honest: we can't claim compliance for controls we didn't
    actually check).
    """
    compliant = sum(1 for r in owasp_coverage.values() if r["status"] == "compliant")
    partial = sum(1 for r in owasp_coverage.values() if r["status"] == "partial")
    non_compliant = sum(
        1 for r in owasp_coverage.values() if r["status"] == "non-compliant"
    )
    not_assessed = sum(
        1 for r in owasp_coverage.values() if r["status"] == "not-assessed"
    )

    assessable = compliant + partial + non_compliant
    rate = round((compliant / assessable * 100)) if assessable > 0 else 0

    return compliant, partial, non_compliant, not_assessed, rate


def count_total_controls(owasp_coverage: Dict[str, Dict]) -> int:
    """Always 10 for OWASP LLM; kept as a function so UI code never hardcodes."""
    return len(owasp_coverage)


def framework_badges_for_finding(finding: Dict) -> List[Tuple[str, str]]:
    """
    For a single finding, return [(framework_class, control_id)] tuples to
    render as badges. framework_class is one of: owasp, nist, atlas, hipaa
    (lowercased short name). Unknown frameworks default to 'other'.
    """
    mapping_class = {
        "OWASP-LLM": "owasp",
        "NIST-AI-RMF": "nist",
        "MITRE-ATLAS": "atlas",
        "HIPAA": "hipaa",
        "FSI": "nist",  # FSI lens will land as NIST/HIPAA mappings; placeholder
    }
    badges: List[Tuple[str, str]] = []
    for m in _finding_mappings(finding):
        framework = m.get("framework", "")
        control_id = m.get("control_id", "")
        if not control_id:
            continue
        badges.append((mapping_class.get(framework, "other"), control_id))
    return badges


def frameworks_data_attr_for_finding(finding: Dict) -> str:
    """
    Return a space-separated string of `framework:control_id` tokens to put
    on the <tr data-frameworks="..."> attribute so JS filtering works:
        data-frameworks="owasp:LLM01 owasp:LLM05 nist:MANAGE-2.1"
    """
    tokens = [f"{cls}:{ctrl}" for cls, ctrl in framework_badges_for_finding(finding)]
    return " ".join(tokens)
