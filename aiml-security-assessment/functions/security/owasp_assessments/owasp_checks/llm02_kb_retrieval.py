"""
OW-17: Knowledge Base Retrieval Access Policy.

For each Bedrock Knowledge Base, verify a resource-based policy exists
that restricts bedrock-agent:Retrieve and bedrock-agent:RetrieveAndGenerate
to a specific IAM principal set. A KB with no resource policy allows any
identity with bedrock-agent invoke permissions to query it — a direct
RAG-retrieval disclosure vector under OWASP LLM02 (Sensitive Information
Disclosure).

Required IAM:
    bedrock-agent:ListKnowledgeBases
    bedrock-agent:GetKnowledgeBase
    bedrock-agent:GetResourcePolicy    # May not exist in every region yet
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from botocore.exceptions import ClientError

try:
    from ..schema import create_finding, SeverityEnum, StatusEnum
except ImportError:  # pragma: no cover
    from schema import create_finding, SeverityEnum, StatusEnum  # type: ignore

logger = logging.getLogger(__name__)

_REF = "https://docs.aws.amazon.com/bedrock/latest/userguide/kb-permissions.html"

_RETRIEVAL_ACTIONS = {
    "bedrock-agent:Retrieve",
    "bedrock-agent:RetrieveAndGenerate",
    "bedrock-agent:*",
    "bedrock:*",
    "*",
}


def _policy_restricts_retrieval(policy_doc: Dict[str, Any]) -> bool:
    """Return True when the policy has at least one Allow statement that
    names specific principals AND grants retrieval actions.

    A policy that allows '*' principals or uses a wildcard without a
    Condition does not count.
    """
    for stmt in _as_list(policy_doc.get("Statement", [])):
        if stmt.get("Effect") != "Allow":
            continue

        actions = _as_list(stmt.get("Action", []))
        if not any(a in _RETRIEVAL_ACTIONS for a in actions):
            continue

        principal = stmt.get("Principal")
        # Wildcard principal with no condition is not a restriction
        if principal == "*" or principal == {"AWS": "*"}:
            if not stmt.get("Condition"):
                continue

        if principal:
            return True
    return False


def _as_list(v: Any) -> List[Any]:
    if isinstance(v, list):
        return v
    if v is None:
        return []
    return [v]


def evaluate_kb_retrieval_policy(
    bedrock_agent_client: Any,
) -> List[Dict[str, Any]]:
    """Return findings for OW-17 across every KB."""
    findings: List[Dict[str, Any]] = []

    try:
        resp = bedrock_agent_client.list_knowledge_bases()
        kb_summaries = resp.get("knowledgeBaseSummaries", [])
    except ClientError as e:
        logger.warning("list_knowledge_bases failed: %s", e)
        kb_summaries = []

    if not kb_summaries:
        findings.append(create_finding(
            check_id="OW-17",
            finding_name="KB Retrieval Policy — No KBs",
            finding_details=(
                "No Bedrock Knowledge Bases found; OW-17 is not applicable."
            ),
            resolution="No action required.",
            reference=_REF,
            severity=SeverityEnum.INFORMATIONAL,
            status=StatusEnum.NA,
        ))
        return findings

    api_unavailable = False

    for kb_summary in kb_summaries:
        kb_id = kb_summary.get("knowledgeBaseId")
        kb_name = kb_summary.get("name", kb_id)
        if not kb_id:
            continue

        kb_arn = f"knowledge-base/{kb_id}"  # best-effort logical identifier
        try:
            kb_detail = bedrock_agent_client.get_knowledge_base(knowledgeBaseId=kb_id)
            kb_arn = (
                (kb_detail.get("knowledgeBase") or {}).get("knowledgeBaseArn")
                or kb_arn
            )
        except ClientError as e:
            logger.warning("get_knowledge_base failed for %s: %s", kb_id, e)

        # Attempt to read the resource policy
        try:
            rp_resp = bedrock_agent_client.get_resource_policy(resourceArn=kb_arn)
            policy_str = rp_resp.get("policy") or rp_resp.get("Policy") or ""
        except AttributeError:
            # API not present in this boto3 version / region
            api_unavailable = True
            break
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("ResourceNotFoundException", "NoSuchPolicy"):
                # No resource policy at all
                findings.append(create_finding(
                    check_id="OW-17",
                    finding_name=f"KB Retrieval Policy Missing: {kb_name}",
                    finding_details=(
                        f"Knowledge Base '{kb_name}' has no resource-based policy. "
                        f"Any principal with bedrock-agent:Retrieve permission can "
                        f"query it — direct RAG disclosure risk under OWASP LLM02."
                    ),
                    resolution=(
                        "Attach a resource-based policy to the KB that restricts "
                        "bedrock-agent:Retrieve and bedrock-agent:RetrieveAndGenerate "
                        "to the specific IAM roles that need to query it."
                    ),
                    reference=_REF,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                ))
                continue
            elif code in ("AccessDeniedException", "AccessDenied"):
                findings.append(create_finding(
                    check_id="OW-17",
                    finding_name=f"KB Retrieval Policy Undeterminable: {kb_name}",
                    finding_details=(
                        f"Assessment role was denied bedrock-agent:GetResourcePolicy "
                        f"on KB '{kb_name}'. The policy may still be missing."
                    ),
                    resolution=(
                        "Grant the assessment role bedrock-agent:GetResourcePolicy "
                        "or manually inspect the KB's resource policy."
                    ),
                    reference=_REF,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                ))
                continue
            else:
                logger.warning("get_resource_policy failed for %s: %s", kb_id, e)
                continue

        # Policy present — inspect contents
        try:
            policy_doc = json.loads(policy_str) if policy_str else {}
        except (json.JSONDecodeError, TypeError):
            policy_doc = {}

        if _policy_restricts_retrieval(policy_doc):
            findings.append(create_finding(
                check_id="OW-17",
                finding_name=f"KB Retrieval Policy Restrictive: {kb_name}",
                finding_details=(
                    f"Knowledge Base '{kb_name}' has a resource policy that names "
                    f"specific principals and grants the retrieval actions. "
                    f"Retrieval disclosure risk is mitigated at the control plane."
                ),
                resolution="No action required.",
                reference=_REF,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.PASSED,
            ))
        else:
            findings.append(create_finding(
                check_id="OW-17",
                finding_name=f"KB Retrieval Policy Permissive: {kb_name}",
                finding_details=(
                    f"Knowledge Base '{kb_name}' has a resource policy but it does "
                    f"not restrict bedrock-agent:Retrieve / RetrieveAndGenerate to "
                    f"specific principals (or uses '*' without conditions)."
                ),
                resolution=(
                    "Tighten the KB resource policy: name the exact IAM principals "
                    "that require retrieval access, and remove wildcard principals "
                    "unless they are paired with scoped Conditions "
                    "(aws:PrincipalOrgID, aws:SourceVpce, etc.)."
                ),
                reference=_REF,
                severity=SeverityEnum.HIGH,
                status=StatusEnum.FAILED,
            ))

    if api_unavailable:
        findings.append(create_finding(
            check_id="OW-17",
            finding_name="KB Retrieval Policy API Unavailable",
            finding_details=(
                "bedrock-agent:GetResourcePolicy is not available in this region "
                "or boto3 version. OW-17 cannot be evaluated."
            ),
            resolution=(
                "Upgrade boto3 / run the assessment from a region where "
                "bedrock-agent:GetResourcePolicy is supported."
            ),
            reference=_REF,
            severity=SeverityEnum.INFORMATIONAL,
            status=StatusEnum.NA,
        ))

    return findings
