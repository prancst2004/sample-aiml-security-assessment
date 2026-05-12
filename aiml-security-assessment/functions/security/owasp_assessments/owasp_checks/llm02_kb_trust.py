"""
OW-02: Knowledge Base Source Trust.

For each Bedrock Knowledge Base data source backed by S3, verify that the
bucket is not public. Public KB source buckets are an indirect prompt
injection vector (poisoned documents reach the LLM via RAG).

Primary signal: S3 Block Public Access settings on the bucket. Secondary
signal: bucket policy status (IsPublic). We intentionally keep the check
narrow and boolean — a public bucket fails; everything else passes.

Required IAM:
    bedrock-agent:ListKnowledgeBases
    bedrock-agent:GetKnowledgeBase
    bedrock-agent:ListDataSources
    bedrock-agent:GetDataSource
    s3:GetBucketPublicAccessBlock
    s3:GetBucketPolicyStatus

APIs that are optional (used only when available / useful):
    s3:GetBucketAcl
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from botocore.exceptions import ClientError

try:
    from ..schema import create_finding, SeverityEnum, StatusEnum
except ImportError:  # pragma: no cover — flat import for tests
    from schema import create_finding, SeverityEnum, StatusEnum  # type: ignore

logger = logging.getLogger(__name__)

_REF = "https://docs.aws.amazon.com/bedrock/latest/userguide/knowledge-base-security.html"


def _bucket_is_public(s3_client: Any, bucket_name: str) -> Dict[str, Any]:
    """Return a small dict describing whether the bucket is public.

    Shape:
        {"public": bool, "reason": str, "checked": bool}

    If the bucket owner denies us access to the relevant sub-APIs we
    return checked=False so the caller can emit an N/A finding.
    """
    reasons: List[str] = []
    checked_any = False

    # 1. Public Access Block — primary signal
    try:
        pab = s3_client.get_public_access_block(Bucket=bucket_name)
        cfg = pab.get("PublicAccessBlockConfiguration", {}) or {}
        checked_any = True
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
            reasons.append(
                "Public Access Block is incomplete (missing: " + ", ".join(missing) + ")"
            )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code == "NoSuchPublicAccessBlockConfiguration":
            checked_any = True
            reasons.append("No Public Access Block configuration on the bucket")
        elif code in ("AccessDenied", "AllAccessDisabled"):
            # We were not given permission — we cannot assert public-or-not
            logger.info("AccessDenied on GetPublicAccessBlock for %s", bucket_name)
        else:
            logger.warning("GetPublicAccessBlock failed for %s: %s", bucket_name, e)

    # 2. Policy Status — secondary confirmation
    try:
        ps = s3_client.get_bucket_policy_status(Bucket=bucket_name)
        is_public = ps.get("PolicyStatus", {}).get("IsPublic", False)
        checked_any = True
        if is_public:
            reasons.append("Bucket policy marks the bucket as public")
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("NoSuchBucketPolicy",):
            # No policy is fine if PAB is complete
            checked_any = True
        elif code in ("AccessDenied", "AllAccessDisabled"):
            logger.info("AccessDenied on GetBucketPolicyStatus for %s", bucket_name)
        else:
            logger.warning("GetBucketPolicyStatus failed for %s: %s", bucket_name, e)

    return {
        "public": bool(reasons),
        "reason": "; ".join(reasons) if reasons else "Bucket is not public",
        "checked": checked_any,
    }


def evaluate_kb_source_trust(
    bedrock_agent_client: Any,
    s3_client: Any,
) -> List[Dict[str, Any]]:
    """Return findings for OW-02 across every KB S3 data source."""
    findings: List[Dict[str, Any]] = []

    try:
        kb_summaries = []
        paginator = bedrock_agent_client.get_paginator("list_knowledge_bases")
        for page in paginator.paginate():
            kb_summaries.extend(page.get("knowledgeBaseSummaries", []))
    except AttributeError:
        # Older boto3: no paginator for list_knowledge_bases
        try:
            resp = bedrock_agent_client.list_knowledge_bases()
            kb_summaries = resp.get("knowledgeBaseSummaries", [])
        except ClientError as e:
            logger.warning("list_knowledge_bases failed: %s", e)
            kb_summaries = []
    except ClientError as e:
        logger.warning("list_knowledge_bases failed: %s", e)
        kb_summaries = []

    if not kb_summaries:
        findings.append(create_finding(
            check_id="OW-02",
            finding_name="Knowledge Base Source Trust — No KBs",
            finding_details=(
                "No Bedrock Knowledge Bases found in this account/region. "
                "OW-02 is not applicable until at least one KB is configured."
            ),
            resolution="No action required.",
            reference=_REF,
            severity=SeverityEnum.INFORMATIONAL,
            status=StatusEnum.NA,
        ))
        return findings

    examined_buckets = 0
    for kb_summary in kb_summaries:
        kb_id = kb_summary.get("knowledgeBaseId")
        kb_name = kb_summary.get("name", kb_id)
        if not kb_id:
            continue

        # List the KB's data sources
        try:
            ds_resp = bedrock_agent_client.list_data_sources(knowledgeBaseId=kb_id)
            data_sources = ds_resp.get("dataSourceSummaries", [])
        except ClientError as e:
            logger.warning("list_data_sources failed for KB %s: %s", kb_id, e)
            continue

        for ds_summary in data_sources:
            ds_id = ds_summary.get("dataSourceId")
            if not ds_id:
                continue
            try:
                ds_detail = bedrock_agent_client.get_data_source(
                    knowledgeBaseId=kb_id, dataSourceId=ds_id,
                )
            except ClientError as e:
                logger.warning(
                    "get_data_source failed for KB %s ds %s: %s", kb_id, ds_id, e,
                )
                continue

            ds_config = (ds_detail.get("dataSource") or {}).get(
                "dataSourceConfiguration", {}
            )
            s3_config = ds_config.get("s3Configuration", {}) or {}
            bucket_arn = s3_config.get("bucketArn", "")
            if not bucket_arn.startswith("arn:aws:s3:::"):
                # Non-S3 data source (Confluence, SharePoint, etc.) — out of scope
                continue

            bucket_name = bucket_arn.split(":::")[-1]
            examined_buckets += 1
            result = _bucket_is_public(s3_client, bucket_name)

            if not result["checked"]:
                findings.append(create_finding(
                    check_id="OW-02",
                    finding_name=f"KB Source Trust Undeterminable: {kb_name}",
                    finding_details=(
                        f"KB '{kb_name}' references S3 bucket '{bucket_name}' but the "
                        f"assessment role was denied access to read the bucket's "
                        f"Public Access Block / Policy Status. The bucket may be "
                        f"cross-account or owned by a different principal."
                    ),
                    resolution=(
                        "Grant the assessment role s3:GetBucketPublicAccessBlock and "
                        "s3:GetBucketPolicyStatus on the KB source bucket, or "
                        "manually verify it has Block Public Access enabled."
                    ),
                    reference=_REF,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                ))
                continue

            if result["public"]:
                findings.append(create_finding(
                    check_id="OW-02",
                    finding_name=f"KB Source Bucket Publicly Accessible: {kb_name}",
                    finding_details=(
                        f"KB '{kb_name}' ingests from S3 bucket '{bucket_name}' which "
                        f"is publicly accessible. Reason: {result['reason']}. A public "
                        f"source bucket is an indirect prompt-injection vector — any "
                        f"principal can poison the documents that the LLM sees."
                    ),
                    resolution=(
                        "1. Enable full Block Public Access on the bucket "
                        "(BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, "
                        "RestrictPublicBuckets all = true).\n"
                        "2. Remove any public bucket policy statements.\n"
                        "3. Restrict write access to a named ingestion role only."
                    ),
                    reference=_REF,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.FAILED,
                ))
            else:
                findings.append(create_finding(
                    check_id="OW-02",
                    finding_name=f"KB Source Bucket Private: {kb_name}",
                    finding_details=(
                        f"KB '{kb_name}' ingests from S3 bucket '{bucket_name}'. "
                        f"Bucket is not publicly accessible (Block Public Access "
                        f"complete and bucket policy not public)."
                    ),
                    resolution="No action required.",
                    reference=_REF,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.PASSED,
                ))

    if not findings:
        # KBs existed but none had S3 data sources
        findings.append(create_finding(
            check_id="OW-02",
            finding_name="Knowledge Base Source Trust — No S3 Sources",
            finding_details=(
                f"Examined {len(kb_summaries)} Knowledge Bases; none use S3 as a "
                f"data source. OW-02 only inspects S3-backed KBs."
            ),
            resolution="No action required.",
            reference=_REF,
            severity=SeverityEnum.INFORMATIONAL,
            status=StatusEnum.NA,
        ))

    return findings
