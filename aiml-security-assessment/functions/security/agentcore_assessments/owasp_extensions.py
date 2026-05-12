"""
OWASP LLM Top 10 (2025) extensions for the AgentCore assessments Lambda.

Rides on top of check_agentcore_encryption() which already calls
ecr:DescribeRepositories and iterates the AgentCore-tagged repo set.
OW-16 inspects the same repositories for scan-on-push configuration
without any additional API calls.

Coverage:
    OW-16 — ECR Image Scanning for SageMaker & AgentCore (LLM03 partial-app-layer)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

try:
    from .schema import create_finding
except ImportError:  # pragma: no cover — flat import for direct runs
    from schema import create_finding  # type: ignore

logger = logging.getLogger(__name__)

_ECR_SCANNING_REF = (
    "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html"
)


def evaluate_ecr_scan_on_push(
    agentcore_repos: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Evaluate OW-16 against AgentCore-tagged ECR repositories.

    Args:
        agentcore_repos: the list of repo dicts already filtered down
            from ecr:DescribeRepositories by check_agentcore_encryption().

    Returns:
        List of finding dicts. One summary finding plus per-repo
        findings where scan-on-push is disabled.
    """
    findings: List[Dict[str, Any]] = []

    if not agentcore_repos:
        findings.append(create_finding(
            check_id="OW-16",
            finding_name="ECR Image Scanning — No AgentCore Repositories",
            finding_details=(
                "No AgentCore-related ECR repositories were found. OW-16 will be "
                "re-evaluated once AgentCore runtimes with container images exist."
            ),
            resolution="No action required.",
            reference=_ECR_SCANNING_REF,
            severity="Informational",
            status="N/A",
        ))
        return findings

    unscanned: List[str] = []
    scanned: List[str] = []
    for repo in agentcore_repos:
        name = repo.get("repositoryName", "unknown")
        scan_cfg = repo.get("imageScanningConfiguration") or {}
        if scan_cfg.get("scanOnPush") is True:
            scanned.append(name)
        else:
            unscanned.append(name)

    if unscanned:
        findings.append(create_finding(
            check_id="OW-16",
            finding_name="ECR Scan-on-Push Disabled",
            finding_details=(
                f"{len(unscanned)} AgentCore-related ECR repositor{'y' if len(unscanned)==1 else 'ies'} "
                f"have scanOnPush disabled: {sorted(unscanned)}. Unscanned container "
                f"images used by AgentCore runtimes may contain known CVEs "
                f"exploitable at inference time. OWASP LLM03 (Supply Chain) "
                f"mitigation benefits from automated image scanning."
            ),
            resolution=(
                "Enable scan-on-push for each affected repository:\n"
                "  aws ecr put-image-scanning-configuration --repository-name <name> "
                "--image-scanning-configuration scanOnPush=true\n\n"
                "For enhanced scanning across the account, consider Amazon Inspector "
                "continuous ECR scanning."
            ),
            reference=_ECR_SCANNING_REF,
            severity="Medium",
            status="Failed",
        ))

    if scanned and not unscanned:
        findings.append(create_finding(
            check_id="OW-16",
            finding_name="ECR Scan-on-Push Enabled",
            finding_details=(
                f"All {len(scanned)} AgentCore-related ECR repositor"
                f"{'y' if len(scanned)==1 else 'ies'} have scanOnPush enabled: "
                f"{sorted(scanned)}."
            ),
            resolution="No action required.",
            reference=_ECR_SCANNING_REF,
            severity="Informational",
            status="Passed",
        ))
    elif scanned and unscanned:
        # Partial pass informational so the passed repos are recorded too.
        findings.append(create_finding(
            check_id="OW-16",
            finding_name="ECR Scan-on-Push Partial",
            finding_details=(
                f"{len(scanned)} repositor{'y has' if len(scanned)==1 else 'ies have'} "
                f"scanOnPush enabled: {sorted(scanned)}. See the failed finding "
                f"for repos that still need scan-on-push turned on."
            ),
            resolution="Apply the same fix as the failed finding to remaining repositories.",
            reference=_ECR_SCANNING_REF,
            severity="Informational",
            status="Passed",
        ))

    return findings
