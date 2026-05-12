"""
OW-18: Multi-Agent Sub-Agent Inventory.

Enumerate Bedrock Agents and identify cases where one agent's action
group invokes a Lambda that in turn calls another Bedrock Agent
(agent-calling-agent / sub-agent patterns). OWASP LLM06 (2025 revision)
calls these out because a sub-agent may trust its caller's inputs
implicitly and transitively propagate malicious instructions.

Narrow signal used here: an action-group Lambda whose execution role
is permitted to invoke `bedrock-agent:InvokeAgent` is almost certainly
an orchestrator. We enumerate those and emit an informational finding
per agent so customers can review the trust boundaries.

Required IAM:
    bedrock-agent:ListAgents
    bedrock-agent:ListAgentActionGroups
    bedrock-agent:GetAgentActionGroup
    iam:GetRole / iam:ListRolePolicies / iam:GetRolePolicy
    lambda:GetFunction
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

try:
    from .llm06_agent_agency import (
        _role_name_from_arn,
        _lambda_arn_from_action_group,
        _lambda_role_arn,
        _as_list,
    )
except ImportError:  # pragma: no cover
    from llm06_agent_agency import (  # type: ignore
        _role_name_from_arn,
        _lambda_arn_from_action_group,
        _lambda_role_arn,
        _as_list,
    )

logger = logging.getLogger(__name__)

_REF = "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/"


def _role_can_invoke_agent(iam_client: Any, role_name: str) -> bool:
    """Return True if any inline policy on the role allows bedrock-agent:InvokeAgent."""
    try:
        resp = iam_client.list_role_policies(RoleName=role_name)
        policy_names = resp.get("PolicyNames", [])
    except ClientError:
        return False

    for policy_name in policy_names:
        try:
            gp = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            doc = gp.get("PolicyDocument") or {}
        except ClientError:
            continue
        if isinstance(doc, str):
            try:
                doc = json.loads(doc)
            except (ValueError, TypeError):
                continue
        for stmt in _as_list(doc.get("Statement", [])):
            if stmt.get("Effect") != "Allow":
                continue
            actions = [a for a in _as_list(stmt.get("Action", [])) if isinstance(a, str)]
            for action in actions:
                if action in (
                    "bedrock-agent:InvokeAgent",
                    "bedrock:InvokeAgent",
                    "bedrock-agent:*",
                    "bedrock:*",
                    "*",
                ):
                    return True
    return False


def evaluate_sub_agent_inventory(
    bedrock_agent_client: Any,
    iam_client: Any,
    lambda_client: Any,
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
            check_id="OW-18",
            finding_name="Sub-Agent Inventory — No Agents",
            finding_details=(
                "No Bedrock Agents found in this account/region. OW-18 is "
                "not applicable."
            ),
            resolution="No action required.",
            reference=_REF,
            severity=SeverityEnum.INFORMATIONAL,
            status=StatusEnum.NA,
        ))
        return findings

    orchestrators: List[str] = []

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
        except ClientError:
            continue

        for ag_summary in action_groups:
            ag_id = ag_summary.get("actionGroupId")
            if not ag_id:
                continue
            try:
                detail = bedrock_agent_client.get_agent_action_group(
                    agentId=agent_id,
                    agentVersion=version,
                    actionGroupId=ag_id,
                )
                data = detail.get("agentActionGroup") or {}
            except ClientError:
                continue

            lambda_arn = _lambda_arn_from_action_group(data)
            if not lambda_arn:
                continue
            role_arn = _lambda_role_arn(lambda_client, lambda_arn)
            role_name = _role_name_from_arn(role_arn)
            if not role_name:
                continue
            if _role_can_invoke_agent(iam_client, role_name):
                orchestrators.append(agent_name)
                break  # one action-group is enough to mark this agent

    if orchestrators:
        findings.append(create_finding(
            check_id="OW-18",
            finding_name="Multi-Agent Orchestrator Agents Detected",
            finding_details=(
                f"Bedrock Agents that appear to call other agents (one of "
                f"their action-group Lambdas is permitted bedrock-agent:InvokeAgent): "
                f"{', '.join(orchestrators)}. Under OWASP LLM06 (2025 "
                f"revision), verify that each sub-agent does not blindly "
                f"trust orchestrator-supplied inputs."
            ),
            resolution=(
                "For each orchestrator agent: (1) document which sub-agents "
                "are allowed callees; (2) ensure sub-agent system prompts "
                "validate incoming parameters; (3) consider scoping the "
                "orchestrator's IAM role to specific sub-agent ARNs rather "
                "than '*'."
            ),
            reference=_REF,
            severity=SeverityEnum.MEDIUM,
            status=StatusEnum.FAILED,
        ))
    else:
        findings.append(create_finding(
            check_id="OW-18",
            finding_name="No Multi-Agent Orchestrator Pattern Detected",
            finding_details=(
                f"Examined {len(agents)} Bedrock Agent(s); none have "
                f"action-group Lambda roles with bedrock-agent:InvokeAgent "
                f"permission. Multi-agent orchestration is not in use."
            ),
            resolution="No action required.",
            reference=_REF,
            severity=SeverityEnum.INFORMATIONAL,
            status=StatusEnum.PASSED,
        ))

    return findings
