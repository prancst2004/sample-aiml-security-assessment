"""
OW-07: Knowledge Base Ingestion Role Scope.

For every Bedrock Knowledge Base, identify its ingestion IAM role
(ARN returned by GetKnowledgeBase.roleArn) and inspect its inline
policies for dangerous wildcard patterns. Reuses the same wildcard
detector as OW-09 — an ingestion role with s3:* on * can write the
vector store and exfiltrate via any bucket, which is a direct LLM04
Data/Model Poisoning risk.

Required IAM:
    bedrock-agent:ListKnowledgeBases
    bedrock-agent:GetKnowledgeBase
    iam:ListRolePolicies
    iam:GetRolePolicy
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from botocore.exceptions import ClientError

try:
    from ..schema import create_finding, SeverityEnum, StatusEnum
except ImportError:  # pragma: no cover
    from schema import create_finding, SeverityEnum, StatusEnum  # type: ignore

try:
    from .llm06_agent_agency import _role_name_from_arn, _evaluate_role_policies
except ImportError:  # pragma: no cover
    from llm06_agent_agency import (  # type: ignore
        _role_name_from_arn, _evaluate_role_policies,
    )

logger = logging.getLogger(__name__)

_REF = "https://docs.aws.amazon.com/bedrock/latest/userguide/kb-permissions.html"


def evaluate_kb_ingestion_role(
    bedrock_agent_client: Any,
    iam_client: Any,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    try:
        resp = bedrock_agent_client.list_knowledge_bases()
        summaries = resp.get("knowledgeBaseSummaries", [])
    except ClientError as e:
        logger.warning("list_knowledge_bases failed: %s", e)
        summaries = []

    if not summaries:
        findings.append(create_finding(
            check_id="OW-07",
            finding_name="KB Ingestion Role Scope — No KBs",
            finding_details=(
                "No Bedrock Knowledge Bases found. OW-07 is not applicable."
            ),
            resolution="No action required.",
            reference=_REF,
            severity=SeverityEnum.INFORMATIONAL,
            status=StatusEnum.NA,
        ))
        return findings

    for kb_summary in summaries:
        kb_id = kb_summary.get("knowledgeBaseId")
        kb_name = kb_summary.get("name", kb_id)
        if not kb_id:
            continue
        try:
            detail = bedrock_agent_client.get_knowledge_base(knowledgeBaseId=kb_id)
        except ClientError as e:
            logger.warning("get_knowledge_base failed for %s: %s", kb_id, e)
            continue

        kb = detail.get("knowledgeBase") or {}
        role_arn = kb.get("roleArn")
        role_name = _role_name_from_arn(role_arn)
        if not role_name:
            findings.append(create_finding(
                check_id="OW-07",
                finding_name=f"KB Ingestion Role Undeterminable: {kb_name}",
                finding_details=(
                    f"KB '{kb_name}' has no resolvable ingestion role ARN "
                    f"(roleArn was '{role_arn}')."
                ),
                resolution=(
                    "Grant the assessment role bedrock-agent:GetKnowledgeBase "
                    "and retry."
                ),
                reference=_REF,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            ))
            continue

        reasons = _evaluate_role_policies(iam_client, role_name)
        if reasons:
            findings.append(create_finding(
                check_id="OW-07",
                finding_name=f"KB Ingestion Role Over-Permissive: {kb_name}",
                finding_details=(
                    f"KB '{kb_name}' uses ingestion role '{role_name}' which "
                    f"has overly permissive inline policies: {'; '.join(reasons)}. "
                    f"A poisoning attack via this role could write to the "
                    f"vector store or exfiltrate documents — OWASP LLM04."
                ),
                resolution=(
                    "Scope the ingestion role's inline policies to the exact "
                    "source buckets, vector-store resources, and KMS keys "
                    "required. Remove Action wildcards and Resource '*'."
                ),
                reference=_REF,
                severity=SeverityEnum.HIGH,
                status=StatusEnum.FAILED,
            ))
        else:
            findings.append(create_finding(
                check_id="OW-07",
                finding_name=f"KB Ingestion Role Scoped: {kb_name}",
                finding_details=(
                    f"KB '{kb_name}' uses ingestion role '{role_name}' with "
                    f"no dangerous wildcard inline policies."
                ),
                resolution="No action required.",
                reference=_REF,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.PASSED,
            ))

    return findings
