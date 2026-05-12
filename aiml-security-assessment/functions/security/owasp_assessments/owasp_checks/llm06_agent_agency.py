"""
OW-09: Agent Action Group Wildcard Scope.

For every Bedrock Agent, enumerate its action groups. For each action
group that has an associated Lambda, inspect the Lambda's execution role
inline policies for wildcard actions on wildcard resources. Fail on
patterns like:
    - Action: "*"     Resource: "*"
    - Action: "s3:*"  Resource: "*"
    - Action: "dynamodb:*"  Resource: "*"

These are direct Excessive Agency risks (OWASP LLM06 2025).

Required IAM:
    bedrock-agent:ListAgents
    bedrock-agent:GetAgent
    bedrock-agent:ListAgentVersions (fallback)
    bedrock-agent:ListAgentActionGroups
    bedrock-agent:GetAgentActionGroup
    iam:GetRole
    iam:ListRolePolicies
    iam:GetRolePolicy
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

try:
    from ..schema import create_finding, SeverityEnum, StatusEnum
except ImportError:  # pragma: no cover
    from schema import create_finding, SeverityEnum, StatusEnum  # type: ignore

logger = logging.getLogger(__name__)

_REF = "https://docs.aws.amazon.com/bedrock/latest/userguide/agents-permissions.html"

_DANGEROUS_WILDCARD_SERVICES = {
    "s3", "dynamodb", "iam", "ec2", "kms", "secretsmanager", "ssm", "lambda",
    "rds", "bedrock", "bedrock-agent", "sagemaker",
}


def _as_list(v: Any) -> List[Any]:
    if isinstance(v, list):
        return v
    if v is None:
        return []
    return [v]


def _role_name_from_arn(arn: Optional[str]) -> Optional[str]:
    if not arn:
        return None
    # arn:aws:iam::123:role/path/name
    m = re.match(r"arn:aws[\w-]*:iam::\d+:role/(.+)", arn)
    if not m:
        return None
    # Strip leading path components — GetRole uses the name only
    return m.group(1).split("/")[-1]


def _policy_has_wildcard_risk(policy_doc: Dict[str, Any]) -> List[str]:
    """Return a list of human-readable reasons the policy is risky.

    Empty list means the policy is fine.
    """
    reasons: List[str] = []
    for stmt in _as_list(policy_doc.get("Statement", [])):
        if stmt.get("Effect") != "Allow":
            continue
        actions = [a for a in _as_list(stmt.get("Action", [])) if isinstance(a, str)]
        resources = [r for r in _as_list(stmt.get("Resource", [])) if isinstance(r, str)]
        if not actions or not resources:
            continue

        wildcard_resource = "*" in resources
        for action in actions:
            if action == "*" and wildcard_resource:
                reasons.append("Action '*' on Resource '*'")
                continue
            if action.endswith(":*") and wildcard_resource:
                service = action.split(":", 1)[0].lower()
                if service in _DANGEROUS_WILDCARD_SERVICES:
                    reasons.append(f"Action '{action}' on Resource '*'")
    return reasons


def _lambda_arn_from_action_group(action_group: Dict[str, Any]) -> Optional[str]:
    """Extract the Lambda ARN from an action group's executor config."""
    executor = action_group.get("actionGroupExecutor", {}) or {}
    return executor.get("lambda")


def _lambda_role_arn(lambda_client: Any, function_arn: str) -> Optional[str]:
    try:
        resp = lambda_client.get_function(FunctionName=function_arn)
        return (resp.get("Configuration") or {}).get("Role")
    except ClientError as e:
        logger.warning("lambda:get_function failed for %s: %s", function_arn, e)
        return None


def _evaluate_role_policies(
    iam_client: Any, role_name: str,
) -> List[str]:
    """Return the list of risky-policy reasons for every inline policy
    attached to the role. Managed policies are out of scope for this
    check to keep blast radius small."""
    reasons: List[str] = []
    try:
        resp = iam_client.list_role_policies(RoleName=role_name)
        policy_names = resp.get("PolicyNames", [])
    except ClientError as e:
        logger.warning("iam:list_role_policies failed for %s: %s", role_name, e)
        return reasons

    for policy_name in policy_names:
        try:
            gp = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            doc = gp.get("PolicyDocument") or {}
        except ClientError as e:
            logger.warning(
                "iam:get_role_policy failed for %s/%s: %s", role_name, policy_name, e,
            )
            continue
        # iam:GetRolePolicy may return the document as JSON string in some boto3 versions
        if isinstance(doc, str):
            try:
                import json
                doc = json.loads(doc)
            except (ValueError, TypeError):
                continue
        policy_reasons = _policy_has_wildcard_risk(doc)
        for r in policy_reasons:
            reasons.append(f"{policy_name}: {r}")
    return reasons


def evaluate_action_group_wildcards(
    bedrock_agent_client: Any,
    iam_client: Any,
    lambda_client: Any,
) -> List[Dict[str, Any]]:
    """Return findings for OW-09."""
    findings: List[Dict[str, Any]] = []

    try:
        resp = bedrock_agent_client.list_agents()
        agent_summaries = resp.get("agentSummaries", [])
    except ClientError as e:
        logger.warning("list_agents failed: %s", e)
        agent_summaries = []

    if not agent_summaries:
        findings.append(create_finding(
            check_id="OW-09",
            finding_name="Agent Action Group Wildcards — No Agents",
            finding_details=(
                "No Bedrock Agents found in this account/region. OW-09 not "
                "applicable."
            ),
            resolution="No action required.",
            reference=_REF,
            severity=SeverityEnum.INFORMATIONAL,
            status=StatusEnum.NA,
        ))
        return findings

    total_action_groups = 0
    for agent in agent_summaries:
        agent_id = agent.get("agentId")
        agent_name = agent.get("agentName", agent_id)
        if not agent_id:
            continue

        # Identify the version to use. Prefer DRAFT; otherwise use the
        # most recent published version.
        version = "DRAFT"
        try:
            ag_list = bedrock_agent_client.list_agent_action_groups(
                agentId=agent_id, agentVersion=version,
            )
            action_groups = ag_list.get("actionGroupSummaries", [])
        except ClientError as e:
            logger.info(
                "list_agent_action_groups(DRAFT) failed for %s: %s", agent_id, e,
            )
            # Try the published version
            try:
                versions = bedrock_agent_client.list_agent_versions(agentId=agent_id)
                summaries = versions.get("agentVersionSummaries", [])
                if summaries:
                    version = summaries[0].get("agentVersion", "DRAFT")
                    ag_list = bedrock_agent_client.list_agent_action_groups(
                        agentId=agent_id, agentVersion=version,
                    )
                    action_groups = ag_list.get("actionGroupSummaries", [])
                else:
                    action_groups = []
            except ClientError as e2:
                logger.warning(
                    "list_agent_action_groups fallback failed for %s: %s",
                    agent_id, e2,
                )
                action_groups = []

        for ag_summary in action_groups:
            ag_id = ag_summary.get("actionGroupId")
            ag_name = ag_summary.get("actionGroupName", ag_id)
            if not ag_id:
                continue
            total_action_groups += 1

            try:
                ag_detail = bedrock_agent_client.get_agent_action_group(
                    agentId=agent_id,
                    agentVersion=version,
                    actionGroupId=ag_id,
                )
                ag_data = ag_detail.get("agentActionGroup") or {}
            except ClientError as e:
                logger.warning(
                    "get_agent_action_group failed for %s/%s: %s",
                    agent_id, ag_id, e,
                )
                continue

            lambda_arn = _lambda_arn_from_action_group(ag_data)
            if not lambda_arn:
                # No Lambda (could be RETURN_CONTROL or API-schema only)
                continue

            role_arn = _lambda_role_arn(lambda_client, lambda_arn)
            role_name = _role_name_from_arn(role_arn)
            if not role_name:
                findings.append(create_finding(
                    check_id="OW-09",
                    finding_name=f"Action Group Role Undeterminable: {agent_name}/{ag_name}",
                    finding_details=(
                        f"Action group '{ag_name}' on agent '{agent_name}' uses "
                        f"Lambda '{lambda_arn}' but its execution role could not be "
                        f"resolved."
                    ),
                    resolution=(
                        "Grant the assessment role lambda:GetFunction on the action-"
                        "group Lambda and re-run the assessment."
                    ),
                    reference=_REF,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                ))
                continue

            reasons = _evaluate_role_policies(iam_client, role_name)
            if reasons:
                findings.append(create_finding(
                    check_id="OW-09",
                    finding_name=f"Action Group Has Wildcard Permissions: {agent_name}/{ag_name}",
                    finding_details=(
                        f"Action group '{ag_name}' on agent '{agent_name}' runs "
                        f"Lambda role '{role_name}' which has overly permissive "
                        f"inline policies: {'; '.join(reasons)}. Excessive Agency "
                        f"risk under OWASP LLM06."
                    ),
                    resolution=(
                        "Rewrite the Lambda role's inline policies to scope actions "
                        "to the minimum AWS services required and restrict "
                        "Resource to specific ARNs rather than '*'."
                    ),
                    reference=_REF,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                ))
            else:
                findings.append(create_finding(
                    check_id="OW-09",
                    finding_name=f"Action Group Scoped: {agent_name}/{ag_name}",
                    finding_details=(
                        f"Action group '{ag_name}' on agent '{agent_name}' uses "
                        f"Lambda role '{role_name}'. Inline policies did not "
                        f"contain dangerous wildcard patterns."
                    ),
                    resolution="No action required.",
                    reference=_REF,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.PASSED,
                ))

    if not findings:
        if total_action_groups == 0:
            detail = (
                f"Examined {len(agent_summaries)} Bedrock Agent(s); none have "
                f"action groups. OW-09 not applicable."
            )
        else:
            detail = (
                f"Examined {len(agent_summaries)} Bedrock Agent(s) with "
                f"{total_action_groups} action group(s); none use Lambda "
                f"executors (RETURN_CONTROL / API-schema only). OW-09 only "
                f"evaluates Lambda-backed action groups."
            )
        findings.append(create_finding(
            check_id="OW-09",
            finding_name="Agent Action Group Wildcards — No Lambda Executors",
            finding_details=detail,
            resolution="No action required.",
            reference=_REF,
            severity=SeverityEnum.INFORMATIONAL,
            status=StatusEnum.NA,
        ))

    return findings
