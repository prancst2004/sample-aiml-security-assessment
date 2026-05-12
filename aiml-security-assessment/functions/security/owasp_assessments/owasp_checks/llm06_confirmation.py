"""
OW-10: Human-in-the-Loop & Confirmation Flow.

Informational inventory: for every Bedrock Agent action group, check
whether `requireConfirmation` is set to "ENABLED". Emit one finding per
agent summarising how many action groups run without confirmation — no
pass/fail verdict, just visibility for customer review (OWASP LLM06).

Required IAM:
    bedrock-agent:ListAgents
    bedrock-agent:ListAgentActionGroups
    bedrock-agent:GetAgentActionGroup
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from botocore.exceptions import ClientError

try:
    from ..schema import create_finding, SeverityEnum, StatusEnum
except ImportError:  # pragma: no cover
    from schema import create_finding, SeverityEnum, StatusEnum  # type: ignore

logger = logging.getLogger(__name__)

_REF = "https://docs.aws.amazon.com/bedrock/latest/userguide/agents-action-groups.html"


def evaluate_confirmation_flows(
    bedrock_agent_client: Any,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    try:
        resp = bedrock_agent_client.list_agents()
        agents = resp.get("agentSummaries", [])
    except ClientError as e:
        logger.warning("list_agents failed: %s", e)
        agents = []

    if not agents:
        findings.append(create_finding(
            check_id="OW-10",
            finding_name="Human-in-the-Loop — No Agents",
            finding_details=(
                "No Bedrock Agents found. OW-10 is not applicable."
            ),
            resolution="No action required.",
            reference=_REF,
            severity=SeverityEnum.INFORMATIONAL,
            status=StatusEnum.NA,
        ))
        return findings

    for agent in agents:
        agent_id = agent.get("agentId")
        agent_name = agent.get("agentName", agent_id)
        if not agent_id:
            continue

        version = "DRAFT"
        try:
            ag_list = bedrock_agent_client.list_agent_action_groups(
                agentId=agent_id, agentVersion=version,
            )
            action_groups = ag_list.get("actionGroupSummaries", [])
        except ClientError as e:
            logger.info("list_agent_action_groups failed for %s: %s", agent_id, e)
            continue

        if not action_groups:
            continue

        total = len(action_groups)
        requires_confirm: List[str] = []
        no_confirm: List[str] = []

        for ag_summary in action_groups:
            ag_id = ag_summary.get("actionGroupId")
            ag_name = ag_summary.get("actionGroupName", ag_id)
            try:
                detail = bedrock_agent_client.get_agent_action_group(
                    agentId=agent_id,
                    agentVersion=version,
                    actionGroupId=ag_id,
                )
                data = detail.get("agentActionGroup") or {}
            except ClientError as e:
                logger.warning(
                    "get_agent_action_group failed for %s/%s: %s",
                    agent_id, ag_id, e,
                )
                continue

            if (data.get("requireConfirmation") or "").upper() == "ENABLED":
                requires_confirm.append(ag_name)
            else:
                no_confirm.append(ag_name)

        detail_parts: List[str] = []
        if requires_confirm:
            detail_parts.append(
                f"require confirmation: {', '.join(requires_confirm[:5])}"
                + ("..." if len(requires_confirm) > 5 else "")
            )
        if no_confirm:
            detail_parts.append(
                f"no confirmation: {', '.join(no_confirm[:5])}"
                + ("..." if len(no_confirm) > 5 else "")
            )

        findings.append(create_finding(
            check_id="OW-10",
            finding_name=f"Action Group Confirmation Inventory: {agent_name}",
            finding_details=(
                f"Agent '{agent_name}' has {total} action group(s); "
                f"{len(requires_confirm)} require human confirmation, "
                f"{len(no_confirm)} run without confirmation. "
                + ("; ".join(detail_parts) if detail_parts else "")
            ),
            resolution=(
                "Review whether high-impact action groups (writes, "
                "payments, sends) run without requireConfirmation=ENABLED "
                "and add confirmation for agents that act autonomously on "
                "behalf of users."
            ),
            reference=_REF,
            severity=SeverityEnum.INFORMATIONAL,
            status=StatusEnum.PASSED,
        ))

    if not findings:
        findings.append(create_finding(
            check_id="OW-10",
            finding_name="Human-in-the-Loop — No Action Groups",
            finding_details=(
                f"Examined {len(agents)} Bedrock Agent(s); none have "
                f"inspectable action groups."
            ),
            resolution="No action required.",
            reference=_REF,
            severity=SeverityEnum.INFORMATIONAL,
            status=StatusEnum.NA,
        ))

    return findings
