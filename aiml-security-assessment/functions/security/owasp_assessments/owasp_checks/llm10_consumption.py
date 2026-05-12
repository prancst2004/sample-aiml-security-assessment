"""
OW-15b: Invocation Rate, Token, and Cost Detective Controls.

OW-15 in Phase 2a covered the *proactive* leg (guardrail wordPolicy blocks
oversized inputs). OW-15b is the *detective* leg: even if proactive limits
are present, customers need after-the-fact visibility. This check passes
when at least one of the following is present for Bedrock or SageMaker
usage:

    1. CloudWatch alarm with namespace starting with "AWS/Bedrock" or
       "AWS/SageMaker" and metric InvocationCount / InvocationsFailed /
       InputTokenCount / OutputTokenCount / 4XXError / 5XXError.
    2. AWS Budget filtered to service "Amazon Bedrock" or
       "Amazon SageMaker".

The check keeps the same OW-15 Check_ID as Phase 2a so the OWASP dashboard
aggregates one "LLM10 Unbounded Consumption" row; Phase 2b emits findings
with a distinct Finding name so the two legs are independently visible in
the findings tables.

Required IAM:
    cloudwatch:DescribeAlarms
    budgets:DescribeBudgets
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List

from botocore.exceptions import ClientError

try:
    from ..schema import create_finding, SeverityEnum, StatusEnum
except ImportError:  # pragma: no cover
    from schema import create_finding, SeverityEnum, StatusEnum  # type: ignore

logger = logging.getLogger(__name__)

_REF = "https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring-cw.html"

_BEDROCK_SAGEMAKER_NAMESPACES = ("AWS/Bedrock", "AWS/SageMaker")
_RELEVANT_METRICS = {
    "InvocationCount",
    "Invocations",
    "InvocationsFailed",
    "InputTokenCount",
    "OutputTokenCount",
    "Invocation4XXErrors",
    "Invocation5XXErrors",
    "ModelLatency",
}


def _has_relevant_alarm(cloudwatch_client: Any) -> List[str]:
    """Return a list of alarm names that cover Bedrock or SageMaker
    invocation / token / error metrics."""
    matches: List[str] = []
    try:
        paginator = cloudwatch_client.get_paginator("describe_alarms")
        pages = paginator.paginate(AlarmTypes=["MetricAlarm"])
    except AttributeError:
        pages = [cloudwatch_client.describe_alarms()]
    except ClientError as e:
        logger.warning("describe_alarms failed: %s", e)
        return matches

    try:
        for page in pages:
            for alarm in page.get("MetricAlarms", []):
                ns = alarm.get("Namespace", "")
                metric = alarm.get("MetricName", "")
                if any(ns.startswith(n) for n in _BEDROCK_SAGEMAKER_NAMESPACES):
                    if metric in _RELEVANT_METRICS or not metric:
                        matches.append(alarm.get("AlarmName", "<unnamed>"))
    except ClientError as e:
        logger.warning("describe_alarms iteration failed: %s", e)

    return matches


def _has_relevant_budget(budgets_client: Any) -> List[str]:
    """Return a list of budget names scoped to Bedrock or SageMaker."""
    matches: List[str] = []
    account_id = os.environ.get("AWS_ACCOUNT_ID")
    if not account_id:
        # Fall back to STS
        try:
            import boto3
            sts = boto3.client("sts")
            account_id = sts.get_caller_identity().get("Account")
        except Exception as e:  # pragma: no cover — never fail the check
            logger.info("Unable to resolve AWS account id for Budgets: %s", e)
            return matches
    if not account_id:
        return matches

    try:
        paginator = budgets_client.get_paginator("describe_budgets")
        pages = paginator.paginate(AccountId=account_id)
    except AttributeError:
        try:
            pages = [budgets_client.describe_budgets(AccountId=account_id)]
        except ClientError as e:
            logger.warning("describe_budgets failed: %s", e)
            return matches
    except ClientError as e:
        logger.warning("describe_budgets failed: %s", e)
        return matches

    try:
        for page in pages:
            for budget in page.get("Budgets", []):
                cf = budget.get("CostFilters", {}) or {}
                services = cf.get("Service", []) or []
                for s in services:
                    if "bedrock" in s.lower() or "sagemaker" in s.lower():
                        matches.append(budget.get("BudgetName", "<unnamed>"))
                        break
    except ClientError as e:
        logger.warning("describe_budgets iteration failed: %s", e)

    return matches


def evaluate_detective_consumption_controls(
    cloudwatch_client: Any,
    budgets_client: Any,
) -> List[Dict[str, Any]]:
    """Return OW-15 findings for the detective leg."""
    findings: List[Dict[str, Any]] = []

    alarms = _has_relevant_alarm(cloudwatch_client)
    budgets = _has_relevant_budget(budgets_client)

    if alarms or budgets:
        bits = []
        if alarms:
            bits.append(f"{len(alarms)} CloudWatch alarm(s): {', '.join(alarms[:5])}")
        if budgets:
            bits.append(f"{len(budgets)} Budget(s): {', '.join(budgets[:5])}")
        findings.append(create_finding(
            check_id="OW-15",
            finding_name="Detective Consumption Controls Present",
            finding_details=(
                "After-the-fact cost / rate monitoring for Bedrock or SageMaker is "
                "configured: " + "; ".join(bits) + "."
            ),
            resolution="No action required.",
            reference=_REF,
            severity=SeverityEnum.INFORMATIONAL,
            status=StatusEnum.PASSED,
        ))
    else:
        findings.append(create_finding(
            check_id="OW-15",
            finding_name="Detective Consumption Controls Missing",
            finding_details=(
                "No CloudWatch alarms on Bedrock / SageMaker invocation metrics "
                "and no AWS Budgets scoped to Bedrock / SageMaker were found. "
                "An Unbounded Consumption (OWASP LLM10) event could run for "
                "hours before it is noticed."
            ),
            resolution=(
                "Configure at least one of the following:\n"
                "  1. CloudWatch alarm on AWS/Bedrock InvocationCount or "
                "InputTokenCount with an appropriate threshold and SNS action.\n"
                "  2. AWS Budget filtered to service 'Amazon Bedrock' or "
                "'Amazon SageMaker' with notifications at 80% and 100%.\n"
                "  3. Both — in general a cost budget AND a throughput alarm "
                "give the best coverage."
            ),
            reference=_REF,
            severity=SeverityEnum.MEDIUM,
            status=StatusEnum.FAILED,
        ))

    return findings
