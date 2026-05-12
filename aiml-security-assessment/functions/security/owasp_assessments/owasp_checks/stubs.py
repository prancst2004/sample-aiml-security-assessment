"""
Phase 2b.2 placeholder checks.

Each function here emits one N/A finding per OW-XX check ID so the OWASP
coverage dashboard renders a complete 10-row picture of LLM01..LLM10
without pretending the underlying logic is implemented. These will be
replaced with real logic in Phase 2b.2.

Design intent:
    - Keep the stubs tightly self-contained: one function per check, no
      cross-module wiring.
    - Use INFORMATIONAL severity + N/A status so no stub degrades the
      overall pass rate.
    - Surface a clear Finding_Details string explaining what is coming.
"""

from __future__ import annotations

from typing import Any, Dict, List

try:
    from ..schema import create_finding, SeverityEnum, StatusEnum
except ImportError:  # pragma: no cover
    from schema import create_finding, SeverityEnum, StatusEnum  # type: ignore

_GENERIC_REF = "https://genai.owasp.org/llm-top-10/"


def _planned(check_id: str, name: str, summary: str, reference: str) -> Dict[str, Any]:
    return create_finding(
        check_id=check_id,
        finding_name=f"{name} (Planned Phase 2b.2)",
        finding_details=(
            f"{summary} This check is scheduled for Phase 2b.2 and currently "
            f"emits an N/A finding so the OWASP coverage dashboard remains "
            f"honest about scope."
        ),
        resolution="No action required; implementation is planned.",
        reference=reference,
        severity=SeverityEnum.INFORMATIONAL,
        status=StatusEnum.NA,
    )


def stub_ow04() -> List[Dict[str, Any]]:
    """OW-04: Invocation log retention & access."""
    return [_planned(
        "OW-04",
        "Invocation Log Retention & Access",
        "Verifies Bedrock invocation log retention ≥ 30 days and restrictive "
        "access policies on log destinations (CloudWatch / S3).",
        "https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html",
    )]


def stub_ow05() -> List[Dict[str, Any]]:
    """OW-05: Imported / custom model provenance."""
    return [_planned(
        "OW-05",
        "Imported/Custom Model Provenance",
        "Enumerates Bedrock custom and imported models and flags any whose "
        "source points to a bucket the account does not own, or that lack "
        "provenance tags.",
        "https://docs.aws.amazon.com/bedrock/latest/userguide/custom-models.html",
    )]


def stub_ow06() -> List[Dict[str, Any]]:
    """OW-06: SageMaker JumpStart / Marketplace inventory."""
    return [_planned(
        "OW-06",
        "SageMaker JumpStart & Marketplace Usage Review",
        "Lists SageMaker endpoints running Marketplace or JumpStart model "
        "packages so customers can validate supply-chain trust.",
        "https://docs.aws.amazon.com/sagemaker/latest/dg/jumpstart-supply-chain.html",
    )]


def stub_ow07() -> List[Dict[str, Any]]:
    """OW-07: KB ingestion role scope."""
    return [_planned(
        "OW-07",
        "Knowledge Base Ingestion Role Scope",
        "Inspects the IAM role used by Bedrock KB data source ingestion. "
        "Fails when the role has s3:* on * or is shared across unrelated "
        "KBs.",
        "https://docs.aws.amazon.com/bedrock/latest/userguide/kb-data-source.html",
    )]


def stub_ow10() -> List[Dict[str, Any]]:
    """OW-10: Human-in-the-loop / confirmation flags."""
    return [_planned(
        "OW-10",
        "Human-in-the-Loop & Confirmation Flow",
        "Informational inventory of Bedrock Agent action groups that require "
        "user confirmation before execution.",
        "https://docs.aws.amazon.com/bedrock/latest/userguide/agents-action-groups.html",
    )]


def stub_ow12() -> List[Dict[str, Any]]:
    """OW-12: Vector store network isolation."""
    return [_planned(
        "OW-12",
        "Vector Store Network Isolation",
        "Resolves each Bedrock KB to its vector store (OpenSearch "
        "Serverless collection, Aurora cluster, Pinecone via Secrets "
        "Manager) and fails when the store allows public network access.",
        "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-network.html",
    )]


def stub_ow13() -> List[Dict[str, Any]]:
    """OW-13: Multi-tenant KB isolation."""
    return [_planned(
        "OW-13",
        "Multi-Tenant KB Isolation",
        "Heuristic that warns when multiple Bedrock KBs share a single "
        "vector store collection — per-tenant filtering becomes the "
        "customer's responsibility.",
        "https://docs.aws.amazon.com/bedrock/latest/userguide/kb-multi-tenant.html",
    )]


def stub_ow18() -> List[Dict[str, Any]]:
    """OW-18: Multi-agent sub-agent inventory."""
    return [_planned(
        "OW-18",
        "Multi-Agent Sub-Agent Inventory",
        "Enumerates Bedrock Agents that appear as callees from other "
        "agents' action groups (agent-calling-agent / sub-agent patterns) "
        "for manual review of trust assumptions.",
        "https://docs.aws.amazon.com/bedrock/latest/userguide/agents-multi-agent.html",
    )]
