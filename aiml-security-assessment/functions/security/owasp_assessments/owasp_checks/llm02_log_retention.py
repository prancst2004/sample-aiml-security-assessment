"""
OW-04: Invocation Log Retention & Access.

Confirms Bedrock invocation logging is configured and its destination
has reasonable retention / access controls:

    - If invocation logging is disabled, flag as Failed (no audit trail).
    - If enabled to CloudWatch, verify the log group has retention ≥ 30
      days.
    - If enabled to S3, verify the bucket is not public (uses the same
      Block Public Access primary signal as OW-02).

Absence of retention is the narrow scope here; tamper-resistance
(CloudTrail KMS, bucket object-lock) is out of scope for this check and
tracked as a Phase 3 follow-up.

Required IAM:
    bedrock:GetModelInvocationLoggingConfiguration
    logs:DescribeLogGroups
    s3:GetBucketPolicyStatus
    s3:GetBucketPublicAccessBlock
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

_REF = "https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html"
_MIN_RETENTION_DAYS = 30


def _log_group_name_from_arn(arn: str) -> str:
    # arn:aws:logs:region:acct:log-group:/aws/bedrock/invocations:*
    if ":log-group:" in arn:
        return arn.split(":log-group:")[-1].split(":")[0]
    return arn


def _cw_retention_ok(logs_client: Any, log_group_name: str) -> Dict[str, Any]:
    try:
        resp = logs_client.describe_log_groups(logGroupNamePrefix=log_group_name)
    except ClientError as e:
        logger.warning("describe_log_groups failed for %s: %s", log_group_name, e)
        return {"ok": None, "reason": f"API error: {e}"}

    groups = resp.get("logGroups", [])
    match = next(
        (g for g in groups if g.get("logGroupName") == log_group_name),
        None,
    )
    if match is None:
        return {"ok": False, "reason": f"log group '{log_group_name}' not found"}

    retention = match.get("retentionInDays")
    if retention is None:
        return {
            "ok": False,
            "reason": "retention is unset (logs never expire — but equally, Bedrock invocation logs are not actively managed)",
        }
    if retention < _MIN_RETENTION_DAYS:
        return {
            "ok": False,
            "reason": f"retention is {retention} days (< {_MIN_RETENTION_DAYS} minimum)",
        }
    return {"ok": True, "reason": f"retention = {retention} days"}


def _s3_destination_ok(s3_client: Any, bucket_name: str) -> Dict[str, Any]:
    """Reuse the Block-Public-Access primary signal from OW-02."""
    try:
        pab = s3_client.get_public_access_block(Bucket=bucket_name)
        cfg = pab.get("PublicAccessBlockConfiguration", {}) or {}
        missing = [
            key for key in (
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            )
            if not cfg.get(key, False)
        ]
        if missing:
            return {
                "ok": False,
                "reason": f"Block Public Access incomplete (missing: {', '.join(missing)})",
            }
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code == "NoSuchPublicAccessBlockConfiguration":
            return {"ok": False, "reason": "no Block Public Access on bucket"}
        if code in ("AccessDenied", "AllAccessDisabled"):
            return {"ok": None, "reason": "access denied on bucket"}
        return {"ok": None, "reason": f"API error: {e}"}

    try:
        ps = s3_client.get_bucket_policy_status(Bucket=bucket_name)
        if ps.get("PolicyStatus", {}).get("IsPublic", False):
            return {"ok": False, "reason": "bucket policy marks bucket as public"}
    except ClientError as e:
        if e.response.get("Error", {}).get("Code", "") in ("AccessDenied", "AllAccessDisabled"):
            return {"ok": None, "reason": "access denied on bucket policy status"}

    return {"ok": True, "reason": "bucket private"}


def evaluate_invocation_log_retention(
    bedrock_client: Any,
    logs_client: Any,
    s3_client: Any,
) -> List[Dict[str, Any]]:
    """Return findings for OW-04."""
    findings: List[Dict[str, Any]] = []

    try:
        cfg_resp = bedrock_client.get_model_invocation_logging_configuration()
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("ValidationException", "ResourceNotFoundException"):
            # Config has never been set
            findings.append(create_finding(
                check_id="OW-04",
                finding_name="Bedrock Invocation Logging Disabled",
                finding_details=(
                    "Bedrock model invocation logging is not configured. No "
                    "audit trail exists for who invoked which model with what "
                    "prompt, which limits incident investigation under OWASP "
                    "LLM02."
                ),
                resolution=(
                    "Enable Bedrock model invocation logging to CloudWatch "
                    "Logs or S3. Set a retention policy of at least 30 days "
                    "on the destination and restrict access to the log store."
                ),
                reference=_REF,
                severity=SeverityEnum.MEDIUM,
                status=StatusEnum.FAILED,
            ))
            return findings
        logger.warning("GetModelInvocationLoggingConfiguration failed: %s", e)
        findings.append(create_finding(
            check_id="OW-04",
            finding_name="Invocation Logging Configuration Undeterminable",
            finding_details=(
                f"Could not read Bedrock invocation logging configuration: {e}"
            ),
            resolution=(
                "Grant the assessment role bedrock:GetModelInvocationLoggingConfiguration "
                "and retry."
            ),
            reference=_REF,
            severity=SeverityEnum.INFORMATIONAL,
            status=StatusEnum.NA,
        ))
        return findings

    config = cfg_resp.get("loggingConfig") or {}
    if not config:
        findings.append(create_finding(
            check_id="OW-04",
            finding_name="Bedrock Invocation Logging Disabled",
            finding_details="Bedrock invocation logging configuration is empty.",
            resolution=(
                "Enable Bedrock model invocation logging to CloudWatch Logs "
                "or S3."
            ),
            reference=_REF,
            severity=SeverityEnum.MEDIUM,
            status=StatusEnum.FAILED,
        ))
        return findings

    # CloudWatch destination
    cw = config.get("cloudWatchConfig") or {}
    if cw:
        log_group_name = cw.get("logGroupName")
        if log_group_name:
            result = _cw_retention_ok(logs_client, log_group_name)
            if result["ok"] is True:
                findings.append(create_finding(
                    check_id="OW-04",
                    finding_name="Invocation Log Retention (CloudWatch) OK",
                    finding_details=(
                        f"Bedrock invocation logs go to CloudWatch log group "
                        f"'{log_group_name}' — {result['reason']}."
                    ),
                    resolution="No action required.",
                    reference=_REF,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.PASSED,
                ))
            elif result["ok"] is False:
                findings.append(create_finding(
                    check_id="OW-04",
                    finding_name="Invocation Log Retention (CloudWatch) Insufficient",
                    finding_details=(
                        f"Bedrock invocation logs go to CloudWatch log group "
                        f"'{log_group_name}' — {result['reason']}."
                    ),
                    resolution=(
                        "Set CloudWatch log group retention to at least 30 "
                        "days via PutRetentionPolicy."
                    ),
                    reference=_REF,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.FAILED,
                ))
            else:
                findings.append(create_finding(
                    check_id="OW-04",
                    finding_name="Invocation Log Retention Undeterminable",
                    finding_details=(
                        f"Could not read retention for log group "
                        f"'{log_group_name}': {result['reason']}."
                    ),
                    resolution=(
                        "Grant the assessment role logs:DescribeLogGroups "
                        "and retry."
                    ),
                    reference=_REF,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                ))

    # S3 destination
    s3_dest = config.get("s3Config") or {}
    if s3_dest:
        bucket_name = s3_dest.get("bucketName")
        if bucket_name:
            result = _s3_destination_ok(s3_client, bucket_name)
            if result["ok"] is True:
                findings.append(create_finding(
                    check_id="OW-04",
                    finding_name="Invocation Log Destination (S3) Private",
                    finding_details=(
                        f"Bedrock invocation logs go to S3 bucket "
                        f"'{bucket_name}' — {result['reason']}."
                    ),
                    resolution="No action required.",
                    reference=_REF,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.PASSED,
                ))
            elif result["ok"] is False:
                findings.append(create_finding(
                    check_id="OW-04",
                    finding_name="Invocation Log Destination (S3) Public",
                    finding_details=(
                        f"Bedrock invocation logs go to S3 bucket "
                        f"'{bucket_name}' — {result['reason']}. The log "
                        f"store itself is an exfil channel."
                    ),
                    resolution=(
                        "Enable full Block Public Access on the log "
                        "destination bucket and remove any public bucket "
                        "policy statements."
                    ),
                    reference=_REF,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                ))
            else:
                findings.append(create_finding(
                    check_id="OW-04",
                    finding_name="Invocation Log Destination (S3) Undeterminable",
                    finding_details=(
                        f"Could not verify access controls on log bucket "
                        f"'{bucket_name}': {result['reason']}."
                    ),
                    resolution=(
                        "Grant the assessment role S3 Get*PublicAccessBlock / "
                        "GetBucketPolicyStatus and retry."
                    ),
                    reference=_REF,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                ))

    if not findings:
        findings.append(create_finding(
            check_id="OW-04",
            finding_name="Invocation Logging Enabled (No Destination)",
            finding_details=(
                "Bedrock invocation logging is configured but neither a "
                "CloudWatch log group nor an S3 bucket destination could be "
                "identified. The config may be partially set."
            ),
            resolution=(
                "Review the Bedrock model-invocation-logging configuration "
                "and ensure exactly one destination (CloudWatch or S3) is "
                "fully specified."
            ),
            reference=_REF,
            severity=SeverityEnum.MEDIUM,
            status=StatusEnum.FAILED,
        ))

    return findings
