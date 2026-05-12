"""
OWASP LLM Top 10 Security Assessment Lambda.

Aggregates the OW-XX checks that do not fit naturally into an existing
per-service Lambda (Bedrock, SageMaker, AgentCore). See
docs/proposals/OWASP_LLM_TOP10_PROPOSAL.md §5 for the full matrix.

Phase 2b delivered the scaffolding and 4 exemplar checks. Phase 2b.2
replaces the 8 stubs with full implementations:

    OW-04  Invocation log retention & access       (llm02_log_retention)
    OW-05  Imported/custom model provenance        (llm03_model_provenance)
    OW-06  JumpStart / Marketplace inventory       (llm03_jumpstart_inventory)
    OW-07  KB ingestion role scope                 (llm04_kb_ingestion_role)
    OW-10  Human-in-the-loop confirmation flows    (llm06_confirmation)
    OW-12  Vector store network isolation          (llm08_vector_isolation)
    OW-13  Multi-tenant KB isolation               (llm08_vector_isolation)
    OW-18  Multi-agent sub-agent inventory         (llm06_sub_agent_inventory)

Plus the 4 exemplar checks from Phase 2b:
    OW-02  Knowledge Base source trust
    OW-09  Agent action group wildcards
    OW-15  Detective consumption controls
    OW-17  KB retrieval resource policy

Writes one CSV report per execution to the shared assessment bucket at:
    owasp_security_report_{execution_id}.csv
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

# Phase 2b exemplar checks
from owasp_checks.llm02_kb_trust import evaluate_kb_source_trust
from owasp_checks.llm02_kb_retrieval import evaluate_kb_retrieval_policy
from owasp_checks.llm06_agent_agency import evaluate_action_group_wildcards
from owasp_checks.llm10_consumption import evaluate_detective_consumption_controls

# Phase 2b.2 checks
from owasp_checks.llm02_log_retention import evaluate_invocation_log_retention
from owasp_checks.llm03_model_provenance import evaluate_model_provenance
from owasp_checks.llm03_jumpstart_inventory import evaluate_jumpstart_marketplace_inventory
from owasp_checks.llm04_kb_ingestion_role import evaluate_kb_ingestion_role
from owasp_checks.llm06_confirmation import evaluate_confirmation_flows
from owasp_checks.llm08_vector_isolation import evaluate_vector_store_isolation
from owasp_checks.llm06_sub_agent_inventory import evaluate_sub_agent_inventory


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
logs_client = boto3.client("logs", config=boto3_config)
sts_client = boto3.client("sts", config=boto3_config)
sagemaker_client = boto3.client("sagemaker", config=boto3_config)

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

# Optional — vector store isolation (OW-12)
try:
    aoss_client = boto3.client("opensearchserverless", config=boto3_config)
except Exception as e:  # pragma: no cover
    logger.info(f"opensearchserverless client unavailable: {e}")
    aoss_client = None

try:
    rds_client = boto3.client("rds", config=boto3_config)
except Exception as e:  # pragma: no cover
    logger.info(f"rds client unavailable: {e}")
    rds_client = None


# Environment variables
BUCKET_NAME = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")

# Execution tracking
start_time: float | None = None


def get_current_utc_date() -> str:
    return datetime.now(timezone.utc).isoformat()


def check_timeout() -> bool:
    if start_time is None:
        return True
    elapsed = time.time() - start_time
    if elapsed > 480:
        logger.warning(f"Approaching timeout: {elapsed}s elapsed")
    return elapsed < 540


def _serialize_compliance_mappings(row: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(row)
    mappings = out.get("Compliance_Mappings")
    if mappings is None or mappings == "":
        out["Compliance_Mappings"] = ""
    elif isinstance(mappings, (list, tuple)):
        out["Compliance_Mappings"] = json.dumps(list(mappings))
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


def _safe(check_id: str, name: str, fn, *args, **kwargs) -> List[Dict[str, Any]]:
    """Execute a check defensively — one flaky check never fails the whole Lambda."""
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


def _guard(check_id: str, name: str, reason: str) -> List[Dict[str, Any]]:
    return [create_finding(
        check_id=check_id,
        finding_name=f"{name} — Prerequisite Missing",
        finding_details=reason,
        resolution="Deploy in a region where the required service is supported.",
        reference="https://genai.owasp.org/llm-top-10/",
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

        # ---- Bedrock-agent-dependent checks ----
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
            all_findings.extend(_safe(
                "OW-07", "KB Ingestion Role Scope",
                evaluate_kb_ingestion_role,
                bedrock_agent_client, iam_client,
            ))
            all_findings.extend(_safe(
                "OW-10", "Human-in-the-Loop Confirmation",
                evaluate_confirmation_flows,
                bedrock_agent_client,
            ))
            all_findings.extend(_safe(
                "OW-12+13", "Vector Store Isolation",
                evaluate_vector_store_isolation,
                bedrock_agent_client, aoss_client, rds_client,
            ))
            all_findings.extend(_safe(
                "OW-18", "Sub-Agent Inventory",
                evaluate_sub_agent_inventory,
                bedrock_agent_client, iam_client, lambda_client,
            ))
        else:
            for cid, nm in (
                ("OW-02", "KB Source Trust"),
                ("OW-07", "KB Ingestion Role Scope"),
                ("OW-09", "Agent Action Group Wildcards"),
                ("OW-10", "Human-in-the-Loop Confirmation"),
                ("OW-12", "Vector Store Network Isolation"),
                ("OW-13", "Multi-Tenant KB Isolation"),
                ("OW-17", "KB Retrieval Policy"),
                ("OW-18", "Sub-Agent Inventory"),
            ):
                all_findings.extend(_guard(
                    cid, nm, "bedrock-agent client not available in this region.",
                ))

        # ---- Bedrock (model plane) checks ----
        if bedrock_client is not None:
            all_findings.extend(_safe(
                "OW-04", "Invocation Log Retention & Access",
                evaluate_invocation_log_retention,
                bedrock_client, logs_client, s3_client,
            ))
            all_findings.extend(_safe(
                "OW-05", "Model Provenance",
                evaluate_model_provenance,
                bedrock_client, s3_client, sts_client,
            ))
        else:
            all_findings.extend(_guard(
                "OW-04", "Invocation Log Retention", "bedrock client not available.",
            ))
            all_findings.extend(_guard(
                "OW-05", "Model Provenance", "bedrock client not available.",
            ))

        # ---- SageMaker supply chain ----
        all_findings.extend(_safe(
            "OW-06", "JumpStart / Marketplace Inventory",
            evaluate_jumpstart_marketplace_inventory,
            sagemaker_client,
        ))

        # ---- Detective consumption controls (no bedrock dependency) ----
        all_findings.extend(_safe(
            "OW-15", "Detective Consumption Controls",
            evaluate_detective_consumption_controls,
            cloudwatch_client, budgets_client,
        ))

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
