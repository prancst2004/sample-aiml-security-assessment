"""
Compliance framework mappings for AI/ML security assessment findings.

This module is the single source of truth for mapping each check
(identified by Check_ID) to the compliance frameworks and control IDs it
supports. It is deliberately declarative so that:

1. Retagging a check is a one-line edit.
2. A missing check_id in the mapping table is safe (findings simply carry
   no mappings — no crash, no schema drift).
3. Future frameworks (NIST AI RMF, MITRE ATLAS, HIPAA, FSI) can be added
   without touching any check implementation code.

The coverage_type qualifier distinguishes three cases:
    - "full":              AWS control plane fully assesses this control.
    - "compensating":      The check is a partial / compensating control
                           that reduces the risk but does not fully assess
                           the underlying OWASP category (e.g., OWASP LLM05
                           Improper Output Handling is fundamentally an
                           application-layer concern).
    - "partial-app-layer": The OWASP category has application-layer
                           dimensions that are outside AWS control plane
                           scope. The check contributes what is assessable.
"""

from __future__ import annotations

from typing import Dict, List, Literal, TypedDict

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

Framework = Literal["OWASP-LLM", "NIST-AI-RMF", "MITRE-ATLAS", "HIPAA", "FSI"]
CoverageType = Literal["full", "compensating", "partial-app-layer"]


class ComplianceMapping(TypedDict):
    """A single compliance-framework mapping attached to a finding."""

    framework: Framework
    framework_version: str
    control_id: str
    coverage_type: CoverageType


# ---------------------------------------------------------------------------
# Mapping table
# ---------------------------------------------------------------------------

# Constants for framework versions kept in one place so bumping a framework
# version is a one-line change.
OWASP_LLM_VERSION = "2025"

# Mapping of Check_ID -> list of ComplianceMapping.
#
# A check with no entry here will simply have an empty mapping list on its
# findings. That is intentionally permissive: the framework keeps working if
# somebody adds a new check but forgets to tag it.
CHECK_TO_COMPLIANCE_MAPPINGS: Dict[str, List[ComplianceMapping]] = {
    # ---- Amazon Bedrock ---------------------------------------------------
    "BR-01": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM06", "coverage_type": "full"},
    ],
    "BR-02": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
    ],
    "BR-03": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM03", "coverage_type": "partial-app-layer"},
    ],
    "BR-04": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM09", "coverage_type": "partial-app-layer"},
    ],
    "BR-05": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM01", "coverage_type": "full"},
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM05", "coverage_type": "compensating"},
    ],
    "BR-06": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
    ],
    "BR-07": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM07", "coverage_type": "partial-app-layer"},
    ],
    "BR-08": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM06", "coverage_type": "full"},
    ],
    "BR-09": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM08", "coverage_type": "partial-app-layer"},
    ],
    "BR-10": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM01", "coverage_type": "full"},
    ],
    "BR-11": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM03", "coverage_type": "partial-app-layer"},
    ],
    "BR-12": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
    ],
    "BR-13": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM01", "coverage_type": "full"},
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM05", "coverage_type": "compensating"},
    ],
    "BR-14": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM06", "coverage_type": "full"},
    ],

    # ---- Amazon SageMaker AI ---------------------------------------------
    "SM-01": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
    ],
    "SM-02": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM06", "coverage_type": "full"},
    ],
    "SM-03": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
    ],
    "SM-04": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
    ],
    "SM-05": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM04", "coverage_type": "partial-app-layer"},
    ],
    "SM-06": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM09", "coverage_type": "partial-app-layer"},
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM04", "coverage_type": "partial-app-layer"},
    ],
    "SM-07": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM04", "coverage_type": "partial-app-layer"},
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM09", "coverage_type": "partial-app-layer"},
    ],
    "SM-08": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM03", "coverage_type": "partial-app-layer"},
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM04", "coverage_type": "partial-app-layer"},
    ],
    "SM-09": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM06", "coverage_type": "full"},
    ],
    "SM-10": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
    ],
    "SM-11": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
    ],
    "SM-12": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM10", "coverage_type": "partial-app-layer"},
    ],
    "SM-13": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
    ],
    "SM-14": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM03", "coverage_type": "partial-app-layer"},
    ],
    "SM-15": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
    ],
    "SM-16": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
    ],
    "SM-17": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
    ],
    "SM-18": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
    ],
    "SM-19": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
    ],
    "SM-20": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
    ],
    "SM-21": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
    ],
    "SM-22": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM04", "coverage_type": "partial-app-layer"},
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM03", "coverage_type": "partial-app-layer"},
    ],
    "SM-23": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM04", "coverage_type": "partial-app-layer"},
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM09", "coverage_type": "partial-app-layer"},
    ],
    "SM-24": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM04", "coverage_type": "partial-app-layer"},
    ],
    "SM-25": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM04", "coverage_type": "partial-app-layer"},
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM03", "coverage_type": "partial-app-layer"},
    ],

    # ---- Amazon Bedrock AgentCore ---------------------------------------
    # Note: AC-00 is emitted by the existing codebase as an infrastructure
    # / assessment-setup marker (no OWASP mapping — left intentionally
    # empty).
    "AC-00": [],
    "AC-01": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
    ],
    "AC-02": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM06", "coverage_type": "full"},
    ],
    "AC-03": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM06", "coverage_type": "full"},
    ],
    "AC-04": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM09", "coverage_type": "partial-app-layer"},
    ],
    "AC-05": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM03", "coverage_type": "partial-app-layer"},
    ],
    "AC-06": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
    ],
    "AC-07": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
    ],
    "AC-08": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
    ],
    "AC-09": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM06", "coverage_type": "full"},
    ],
    "AC-10": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM06", "coverage_type": "full"},
    ],
    "AC-11": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
    ],
    "AC-12": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
    ],
    "AC-13": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM06", "coverage_type": "full"},
    ],
}


def get_compliance_mappings(check_id: str) -> List[ComplianceMapping]:
    """
    Return the list of compliance mappings for a given check_id.

    Returns an empty list if the check_id is not in the table. This is
    deliberate: a missing entry should never crash the framework, and new
    checks can be safely added without tagging until we have time to update
    the table.
    """
    return list(CHECK_TO_COMPLIANCE_MAPPINGS.get(check_id, []))
