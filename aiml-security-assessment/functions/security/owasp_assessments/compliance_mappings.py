"""
Compliance framework mappings for the OWASP LLM assessments Lambda.

This module is the single source of truth for mapping each OW-XX check
emitted by the owasp_assessments Lambda to the compliance frameworks and
control IDs it supports.

Phase 2a introduced OW-01, OW-03, OW-08, OW-11, OW-14, OW-15, OW-16 inside
the existing Bedrock and AgentCore Lambdas (they ride on BR-05 / BR-07 /
AC-05). Phase 2b adds the remaining 11 OWASP checks — OW-02, OW-04, OW-05,
OW-06, OW-07, OW-09, OW-10, OW-12, OW-13, OW-17, OW-18 — plus the
detective leg of OW-15 (OW-15b) inside this new owasp_assessments module.

Deliberately permissive: a check with no mapping here gets an empty
mapping list on its findings — no crash, no schema drift.
"""

from __future__ import annotations

from typing import Dict, List, Literal, TypedDict

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

Framework = Literal["OWASP-LLM", "NIST-AI-RMF", "MITRE-ATLAS", "HIPAA", "FSI"]
CoverageType = Literal["full", "compensating", "partial-app-layer"]


class ComplianceMapping(TypedDict):
    framework: Framework
    framework_version: str
    control_id: str
    coverage_type: CoverageType


# ---------------------------------------------------------------------------
# Mapping table
# ---------------------------------------------------------------------------

OWASP_LLM_VERSION = "2025"

CHECK_TO_COMPLIANCE_MAPPINGS: Dict[str, List[ComplianceMapping]] = {
    # ---- Phase 2a checks (also tagged in Bedrock / AgentCore tables; ----
    # ---- duplicated here so the OWASP Lambda's own findings resolve) ---
    "OW-01": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM01", "coverage_type": "full"},
    ],
    "OW-03": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
    ],
    "OW-08": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM05", "coverage_type": "compensating"},
    ],
    "OW-11": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM07", "coverage_type": "partial-app-layer"},
    ],
    "OW-14": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM09", "coverage_type": "full"},
    ],
    "OW-15": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM10", "coverage_type": "partial-app-layer"},
    ],
    "OW-16": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM03", "coverage_type": "partial-app-layer"},
    ],

    # ---- Phase 2b checks (new in owasp_assessments module) -------------
    # OW-02: Knowledge Base data source trust (indirect prompt injection)
    "OW-02": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM01", "coverage_type": "partial-app-layer"},
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM03", "coverage_type": "partial-app-layer"},
    ],
    # OW-04: Invocation log retention & access
    "OW-04": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "partial-app-layer"},
    ],
    # OW-05: Imported/custom model provenance
    "OW-05": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM03", "coverage_type": "partial-app-layer"},
    ],
    # OW-06: JumpStart / Marketplace inventory
    "OW-06": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM03", "coverage_type": "partial-app-layer"},
    ],
    # OW-07: KB ingestion role scope
    "OW-07": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM04", "coverage_type": "partial-app-layer"},
    ],
    # OW-09: Agent action group wildcard scope
    "OW-09": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM06", "coverage_type": "full"},
    ],
    # OW-10: Human-in-the-loop / confirmation flags
    "OW-10": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM06", "coverage_type": "partial-app-layer"},
    ],
    # OW-12: Vector store network isolation
    "OW-12": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM08", "coverage_type": "full"},
    ],
    # OW-13: Multi-tenant KB isolation
    "OW-13": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM08", "coverage_type": "partial-app-layer"},
    ],
    # OW-17: KB retrieval resource policy
    "OW-17": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM02", "coverage_type": "full"},
    ],
    # OW-18: Multi-agent sub-agent inventory
    "OW-18": [
        {"framework": "OWASP-LLM", "framework_version": OWASP_LLM_VERSION,
         "control_id": "LLM06", "coverage_type": "partial-app-layer"},
    ],
}


def get_compliance_mappings(check_id: str) -> List[ComplianceMapping]:
    """Return the list of compliance mappings for a given check_id.

    Returns an empty list if the check_id is not in the table.
    """
    return list(CHECK_TO_COMPLIANCE_MAPPINGS.get(check_id, []))
