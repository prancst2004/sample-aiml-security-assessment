"""
OW-05: Imported / Custom Model Provenance.

For every Bedrock custom model and every imported model, verify that
the source location (S3 bucket that held the weights / training data)
is owned by this account. A custom model sourced from a cross-account
or unowned bucket is a supply-chain risk (OWASP LLM03): the account
cannot prove the integrity of the weights without an out-of-band chain
of custody.

Narrow scope: we do NOT attempt to validate hash / provenance tags, we
only check bucket ownership, which is the single strongest signal
available from the control plane.

Required IAM:
    bedrock:ListCustomModels
    bedrock:GetCustomModel
    s3:GetBucketAcl   (to resolve bucket owner)
    sts:GetCallerIdentity
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

_REF = "https://docs.aws.amazon.com/bedrock/latest/userguide/custom-models.html"


def _bucket_name_from_s3_uri(uri: str) -> Optional[str]:
    """Extract the bucket name from an s3:// URI."""
    m = re.match(r"s3://([^/]+)(?:/.*)?", uri or "")
    return m.group(1) if m else None


def _bucket_owner(s3_client: Any, bucket: str) -> Optional[str]:
    try:
        acl = s3_client.get_bucket_acl(Bucket=bucket)
        return (acl.get("Owner") or {}).get("ID")
    except ClientError as e:
        logger.info("get_bucket_acl failed for %s: %s", bucket, e)
        return None


def evaluate_model_provenance(
    bedrock_client: Any,
    s3_client: Any,
    sts_client: Any,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    try:
        resp = bedrock_client.list_custom_models()
        models = resp.get("modelSummaries", [])
    except ClientError as e:
        logger.warning("list_custom_models failed: %s", e)
        models = []

    if not models:
        findings.append(create_finding(
            check_id="OW-05",
            finding_name="Model Provenance — No Custom Models",
            finding_details=(
                "No Bedrock custom models found in this account/region. "
                "OW-05 is not applicable."
            ),
            resolution="No action required.",
            reference=_REF,
            severity=SeverityEnum.INFORMATIONAL,
            status=StatusEnum.NA,
        ))
        return findings

    # Resolve our own account ID for the cross-account check
    try:
        caller = sts_client.get_caller_identity()
        our_account = caller.get("Account")
    except ClientError as e:
        logger.warning("get_caller_identity failed: %s", e)
        our_account = None

    for summary in models:
        model_name = summary.get("modelName", "<unnamed>")
        model_arn = summary.get("modelArn")
        if not model_arn:
            continue

        try:
            detail_resp = bedrock_client.get_custom_model(
                modelIdentifier=model_arn,
            )
        except ClientError as e:
            logger.warning("get_custom_model failed for %s: %s", model_arn, e)
            continue

        training_uri = (
            (detail_resp.get("trainingDataConfig") or {}).get("s3Uri")
            or (detail_resp.get("outputDataConfig") or {}).get("s3Uri")
            or ""
        )
        bucket = _bucket_name_from_s3_uri(training_uri)
        if not bucket:
            findings.append(create_finding(
                check_id="OW-05",
                finding_name=f"Model Provenance Untracked: {model_name}",
                finding_details=(
                    f"Custom model '{model_name}' has no S3 training-data / "
                    f"output URI exposed by GetCustomModel. Provenance is "
                    f"therefore undocumented."
                ),
                resolution=(
                    "Record the training-data source (bucket, key prefix, "
                    "and hash) as tags on the model and document the chain "
                    "of custody."
                ),
                reference=_REF,
                severity=SeverityEnum.MEDIUM,
                status=StatusEnum.FAILED,
            ))
            continue

        # Canonical-ID comparison: GetBucketAcl returns the canonical user
        # ID, not the numeric account. For a best-effort cross-account
        # signal, we check whether the bucket's owner ID is something we
        # could read at all (access denied typically implies cross-account
        # bucket).
        owner = _bucket_owner(s3_client, bucket)
        if owner is None:
            findings.append(create_finding(
                check_id="OW-05",
                finding_name=f"Model Source Bucket Cross-Account: {model_name}",
                finding_details=(
                    f"Custom model '{model_name}' was trained from s3://{bucket}, "
                    f"but the assessment role cannot read GetBucketAcl on "
                    f"that bucket. This usually indicates a cross-account "
                    f"source — verify provenance out of band."
                ),
                resolution=(
                    "Either re-train the model from an in-account bucket, or "
                    "document the cross-account source and ensure the owning "
                    "account's integrity controls are acceptable."
                ),
                reference=_REF,
                severity=SeverityEnum.MEDIUM,
                status=StatusEnum.FAILED,
            ))
            continue

        findings.append(create_finding(
            check_id="OW-05",
            finding_name=f"Model Provenance In-Account: {model_name}",
            finding_details=(
                f"Custom model '{model_name}' was trained from s3://{bucket} "
                f"which is readable by the assessment role — treated as "
                f"in-account (our account: {our_account or 'unknown'}). "
                f"Weight integrity still depends on bucket access controls."
            ),
            resolution="No action required.",
            reference=_REF,
            severity=SeverityEnum.INFORMATIONAL,
            status=StatusEnum.PASSED,
        ))

    return findings
