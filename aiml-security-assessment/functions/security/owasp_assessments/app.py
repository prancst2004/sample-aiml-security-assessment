"""
OWASP LLM Top 10 Security Assessment Lambda.

Aggregates the OW-XX checks that do not fit naturally into an existing
per-service Lambda (Bedrock, SageMaker, AgentCore). See
docs/proposals/OWASP_LLM_TOP10_PROPOSAL.md §5 for the full matrix.

Phase 2b delivers 4 fully-implemented exemplar checks (OW-02, OW-09,
OW-15b, OW-17) plus 8 Phase 2b.2 stubs (OW-04, OW-05, OW-06, OW-07,
OW-10, OW-12, OW-13, OW-18). The Lambda emits one CSV report to the
shared assessment bucket under key:
    owasp_security_report_{execution_id}.csv

Mirrors the pattern in agentcore_assessments/app.py — same CloudWatch
metrics namespace prefix (AIMLSecurity/OWASP), same CSV Compliance_Mappings
serialization, same timeout budget.
"""

import boto3
import csv
import json
import logging
import os
import time
from io import StringIO
from datetime import datetime, timezone
from typing import Any, Dict, List

from botocore.config import Config

from schema import create_finding, SeverityEnum, StatusEnum
from owasp_checks.llm02_kb_trust import evaluate_kb_source_trust
from owasp_checks.llm02_kb_retrieval import evaluate_kb_retrieval_policy
from owasp_checks.llm06_agent_agency import evaluate_action_group_wildcards
from owasp_checks.llm10_consumption import evaluate_detective_consumption_controls
from owasp_checks.stubs import (
    stub_ow04,
    stub_ow05,
    stub_ow06,
    stub_ow07,
    stub_ow10,
    stub_ow12,
    stub_ow13,
    stub_ow18,
)

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Configure boto3 with adaptive retry mode
boto3_config = Config(retries=dict(max_attempts=10, mode="adaptive"))

# Initialize AWS clients
s3_client = boto3.client("s3", config=boto3_config)
iam_client = boto3.client("iam", config=boto3_config)
cloudwatch_client = boto3.client("cloudwatch", config=boto3_config)
budgets_client = boto3.client("budgets", config=boto3_config)
lambda_client = boto3.client("lambda", config=boto3_config)

# Initialize Bedrock clients — may be region-limited
try:
    bedrock_agent_client = boto3.client("bedrock-agent", config=boto3_config)
    logger.info("Successfully initialized bedrock-agent client")
except Exception as e:  # pragma: no cover
    logger.warning(f"Failed to initialize bedrock-agent client: {e}")
    bedrock_agent_client = None

try:
    bedrock_client = boto3.client("bedrock", config=boto3_config)
    logger.info("Successfully initialized bedrock client")
except Exception as e:  # pragma: no cover
    logger.warning(f"Failed to initialize bedrock client: {e}")
    bedrock_client = None


# Environment variables
BUCKET_NAME = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")

# Execution tracking
start_time: float | None = None


def get_current_utc_date() -> str:
    return datetime.now(timezone.utc).isoformat()


def check_timeout() -> bool:
    """True while execution is comfortably within the Lambda's timeout."""
    if start_time is None:
        return True
    elapsed = time.time() - start_time
    if elapsed > 480:  # 8 min warning
        logger.warning(f"Approaching timeout: {elapsed}s elapsed")
    return elapsed < 540  # 9 min hard stop


def _serialize_compliance_mappings(row: Dict[str, Any]) -> Dict[str, Any]:
    """Return a shallow copy of *row* with Compliance_Mappings JSON-serialised.

    csv.DictWriter can only emit strings; the in-memory findings carry a list
    of dicts. The consolidator reverses this by json.loads() on read.
    """
    out = dict(row)
    mappings = out.get("Compliance_Mappings")
    if mappings is None or mappings == "":
        out["Compliance_Mappings"] = ""
    elif isinstance(mappings, (list, tuple)):
        out["Compliance_Mappings"] = json.dumps(list(mappings))
    # else: already a string — leave alone
    return out


def generate_csv_report(findings: List[Dict[str, Any]]) -> str:
    output = StringIO()
    fieldnames = [
        "Check_ID",
        "Finding",
        "Finding_Details",
        "Resolution",
        "Reference",
        "Severity",
        "Status",
        "Compliance_Mappings",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for finding in findings:
        writer.writerow(_serialize_compliance_mappings(finding))
    csv_content = output.getvalue()
    logger.info(f"Generated CSV report with {len(findings)} findings")
    return csv_content


def write_to_s3(execution_id: str, csv_content: str, bucket_name: str) -> str:
    key = f"owasp_security_report_{execution_id}.csv"
    s3_client.put_object(
        Bucket=bucket_name,
        Key=key,
        Body=csv_content.encode("utf-8"),
        ContentType="text/csv",
    )
    s3_url = f"s3://{bucket_name}/{key}"
    logger.info(f"Successfully uploaded report to {s3_url}")
    return s3_url


# ---------------------------------------------------------------------------
# Check wrappers
#
# Each wrapper catches exceptions and converts them to a single error
# finding so one flaky check never takes down the whole Lambda.
# ---------------------------------------------------------------------------


def _safe(check_id: str, name: str, fn, *args, **kwargs) -> List[Dict[str, Any]]:
    try:
        return fn(*args, **kwargs)
    except Exception as exc:  # pragma: no cover — defensive
        logger.error("OWASP check %s failed: %s", check_id, exc, exc_info=True)
        return [create_finding(
            check_id=check_id,
            finding_name=f"{name} — Execution Error",
            finding_details=(
                f"The OWASP check {check_id} raised an unexpected exception: {exc}"
            ),
            resolution="Investigate error and retry assessment.",
            reference="https://genai.owasp.org/llm-top-10/",
            severity=SeverityEnum.MEDIUM,
            status=StatusEnum.FAILED,
        )]


def _guard_bedrock_agent_client(check_id: str, name: str) -> List[Dict[str, Any]]:
    return [create_finding(
        check_id=check_id,
        finding_name=f"{name} — bedrock-agent client unavailable",
        finding_details=(
            "bedrock-agent client is not available in this region. "
            f"{check_id} cannot be evaluated."
        ),
        resolution="Deploy in a region where Amazon Bedrock Agents are supported.",
        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/agents.html",
        severity=SeverityEnum.INFORMATIONAL,
        status=StatusEnum.NA,
    )]


def lambda_handler(event, context):
    """OWASP LLM Top 10 assessment Lambda handler."""
    global start_time
    start_time = time.time()

    try:
        execution_id = event.get("Execution", {}).get("Name", "unknown")
        logger.info(
            f"Starting OWASP LLM Top 10 assessment for execution: {execution_id}"
        )

        all_findings: List[Dict[str, Any]] = []

        # ---- Exemplar checks ----
        if bedrock_agent_client is not None:
            all_findings.extend(_safe(
                "OW-02", "KB Source Trust",
                evaluate_kb_source_trust,
                bedrock_agent_client, s3_client,
            ))
            all_findings.extend(_safe(
                "OW-17", "KB Retrieval Policy",
                evaluate_kb_retrieval_policy,
                bedrock_agent_client,
            ))
            all_findings.extend(_safe(
                "OW-09", "Agent Action Group Wildcards",
                evaluate_action_group_wildcards,
                bedrock_agent_client, iam_client, lambda_client,
            ))
        else:
            all_findings.extend(_guard_bedrock_agent_client("OW-02", "KB Source Trust"))
            all_findings.extend(_guard_bedrock_agent_client("OW-17", "KB Retrieval Policy"))
            all_findings.extend(_guard_bedrock_agent_client(
                "OW-09", "Agent Action Group Wildcards",
            ))

        all_findings.extend(_safe(
            "OW-15", "Detective Consumption Controls",
            evaluate_detective_consumption_controls,
            cloudwatch_client, budgets_client,
        ))

        # ---- Phase 2b.2 stubs ----
        for name, fn in (
            ("OW-04", stub_ow04),
            ("OW-05", stub_ow05),
            ("OW-06", stub_ow06),
            ("OW-07", stub_ow07),
            ("OW-10", stub_ow10),
            ("OW-12", stub_ow12),
            ("OW-13", stub_ow13),
            ("OW-18", stub_ow18),
        ):
            if not check_timeout():
                logger.warning("Timeout approaching; skipping remaining stubs")
                break
            all_findings.extend(_safe(name, name, fn))

        # ---- Generate and upload report ----
        logger.info(f"Generating CSV report with {len(all_findings)} total findings")
        csv_content = generate_csv_report(all_findings)
        if not BUCKET_NAME:
            raise ValueError("AIML_ASSESSMENT_BUCKET_NAME environment variable is required")
        s3_url = write_to_s3(execution_id, csv_content, BUCKET_NAME)

        total_duration = time.time() - start_time
        logger.info(f"OWASP assessment completed in {total_duration:.2f}s")

        # CloudWatch metrics
        try:
            cloudwatch_client.put_metric_data(
                Namespace="AIMLSecurity/OWASP",
                MetricData=[
                    {
                        "MetricName": "AssessmentDuration",
                        "Value": total_duration,
                        "Unit": "Seconds",
                    },
                    {
                        "MetricName": "FindingsCount",
                        "Value": len(all_findings),
                        "Unit": "Count",
                    },
                ],
            )
        except Exception as e:  # pragma: no cover
            logger.warning(f"Failed to publish CloudWatch metrics: {e}")

        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "OWASP LLM Top 10 assessment completed successfully",
                "s3_url": s3_url,
                "execution_id": execution_id,
                "findings_count": len(all_findings),
                "duration_seconds": total_duration,
            }),
        }

    except Exception as e:
        logger.error(f"Fatal error in lambda_handler: {e}", exc_info=True)
        return {
            "statusCode": 500,
            "body": json.dumps({
                "message": "OWASP LLM Top 10 assessment failed",
                "error": str(e),
            }),
        }
