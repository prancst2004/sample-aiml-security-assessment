"""
OW-06: SageMaker JumpStart & Marketplace Usage Review.

Enumerates SageMaker model packages sourced from JumpStart or AWS
Marketplace and emits an informational inventory finding. This is
explicitly *not* a pass/fail control — it surfaces supply-chain context
for customer review (OWASP LLM03).

Signals used:
    - ModelPackageSummary.ModelPackageGroupName contains
      "jumpstart" (case-insensitive).
    - DescribeModelPackage returns a ModelPackageArn that starts with
      "arn:aws:sagemaker:region:aws:model-package/..." (AWS marketplace
      packages are owned by the `aws` canonical account).

Required IAM:
    sagemaker:ListModelPackages
    sagemaker:DescribeModelPackage
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

_REF = "https://docs.aws.amazon.com/sagemaker/latest/dg/jumpstart.html"


def evaluate_jumpstart_marketplace_inventory(
    sagemaker_client: Any,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    try:
        resp = sagemaker_client.list_model_packages(MaxResults=100)
        packages = resp.get("ModelPackageSummaryList", [])
    except ClientError as e:
        logger.warning("list_model_packages failed: %s", e)
        packages = []

    jumpstart_names: List[str] = []
    marketplace_names: List[str] = []

    for pkg in packages:
        arn = pkg.get("ModelPackageArn", "")
        name = pkg.get("ModelPackageName") or pkg.get("ModelPackageGroupName") or arn
        group = pkg.get("ModelPackageGroupName") or ""

        # Marketplace: owned by the AWS canonical account (":aws:" in ARN)
        if ":aws:model-package/" in arn:
            marketplace_names.append(name)
            continue

        # JumpStart: group name convention
        if "jumpstart" in (group or "").lower() or "jumpstart" in (name or "").lower():
            jumpstart_names.append(name)

    if not packages:
        findings.append(create_finding(
            check_id="OW-06",
            finding_name="JumpStart / Marketplace Inventory — No Model Packages",
            finding_details=(
                "No SageMaker model packages found in this account/region."
            ),
            resolution="No action required.",
            reference=_REF,
            severity=SeverityEnum.INFORMATIONAL,
            status=StatusEnum.NA,
        ))
        return findings

    if not jumpstart_names and not marketplace_names:
        findings.append(create_finding(
            check_id="OW-06",
            finding_name="JumpStart / Marketplace Inventory — None In Use",
            finding_details=(
                f"Examined {len(packages)} SageMaker model package(s); "
                f"none appear to be sourced from JumpStart or AWS "
                f"Marketplace."
            ),
            resolution="No action required.",
            reference=_REF,
            severity=SeverityEnum.INFORMATIONAL,
            status=StatusEnum.NA,
        ))
        return findings

    if jumpstart_names:
        sample = ", ".join(jumpstart_names[:5])
        if len(jumpstart_names) > 5:
            sample += f", and {len(jumpstart_names) - 5} more"
        findings.append(create_finding(
            check_id="OW-06",
            finding_name="SageMaker JumpStart Model Packages In Use",
            finding_details=(
                f"Found {len(jumpstart_names)} SageMaker model package(s) "
                f"sourced from JumpStart: {sample}. Review these for "
                f"supply-chain trust under OWASP LLM03."
            ),
            resolution=(
                "Document the business justification for each JumpStart "
                "model. Verify that the model card's stated provenance and "
                "license acceptance are recorded out of band."
            ),
            reference=_REF,
            severity=SeverityEnum.LOW,
            status=StatusEnum.PASSED,
        ))

    if marketplace_names:
        sample = ", ".join(marketplace_names[:5])
        if len(marketplace_names) > 5:
            sample += f", and {len(marketplace_names) - 5} more"
        findings.append(create_finding(
            check_id="OW-06",
            finding_name="AWS Marketplace Model Packages In Use",
            finding_details=(
                f"Found {len(marketplace_names)} SageMaker model package(s) "
                f"sourced from AWS Marketplace: {sample}. Review vendor "
                f"supply-chain trust under OWASP LLM03."
            ),
            resolution=(
                "Record vendor, model version, and license acceptance for "
                "each Marketplace model in an SBOM or model registry."
            ),
            reference=_REF,
            severity=SeverityEnum.LOW,
            status=StatusEnum.PASSED,
        ))

    return findings
