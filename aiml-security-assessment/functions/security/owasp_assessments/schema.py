from enum import Enum
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field, validator
import re

try:
    # Each service module keeps its own copy of compliance_mappings.py
    # (mirrors the existing per-module schema.py duplication pattern).
    from .compliance_mappings import (
        ComplianceMapping,  # noqa: F401 — re-exported
        get_compliance_mappings,
    )
except ImportError:
    # Fallback for flat-import test environments (e.g., running pytest from
    # the module directory rather than as a package).
    from compliance_mappings import (  # type: ignore
        get_compliance_mappings,
    )


class SeverityEnum(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class StatusEnum(str, Enum):
    FAILED = "Failed"
    PASSED = "Passed"
    NA = "N/A"


class Finding(BaseModel):
    """Represents a security finding with required fields and validations."""

    Check_ID: str = Field(
        ...,
        min_length=1,
        description="Unique check identifier (e.g., SM-01, BR-01, AC-01, OW-01).",
    )
    Finding: str = Field(..., min_length=1, description="The name/title of the finding")
    Finding_Details: str = Field(
        ..., min_length=1, description="Detailed description of the finding"
    )
    Resolution: str = Field(
        ..., min_length=0, description="Steps to resolve the finding"
    )
    Reference: str = Field(..., description="Documentation reference URL")
    Severity: SeverityEnum = Field(..., description="Severity level of the finding")
    Status: StatusEnum = Field(..., description="Current status of the finding")
    Compliance_Mappings: Optional[List[Dict[str, Any]]] = Field(
        default_factory=list,
        description=(
            "Compliance-framework mappings for this finding (e.g., OWASP LLM, "
            "NIST AI RMF, MITRE ATLAS, HIPAA). Populated automatically from "
            "compliance_mappings.CHECK_TO_COMPLIANCE_MAPPINGS based on Check_ID. "
            "Empty list if the check is not mapped."
        ),
    )

    @validator("Check_ID")
    def validate_check_id(cls, v):
        """Validate that Check_ID follows the pattern XX-NN (e.g., SM-01, BR-14, AC-05, OW-01)."""
        pattern = r"^[A-Z]{2,3}-\d{2}$"
        if not re.match(pattern, v):
            raise ValueError(
                "Check_ID must follow pattern XX-NN (e.g., SM-01, BR-14, AC-05, OW-01)"
            )
        return v

    @validator("Reference")
    def validate_reference_url(cls, v):
        """Validate that reference URL starts with https://"""
        if not str(v).startswith("https://"):
            raise ValueError("Reference URL must start with https://")
        return v

    @validator("Severity")
    def validate_severity(cls, v):
        """Validate that severity is one of the allowed values"""
        if v not in SeverityEnum.__members__.values():
            raise ValueError("Severity must be one of the allowed values")
        return v

    @validator("Status")
    def validate_status(cls, v):
        """Validate that status is one of the allowed values"""
        if v not in StatusEnum.__members__.values():
            raise ValueError("Status must be one of the allowed values")
        return v


def create_finding(
    check_id: str,
    finding_name: str,
    finding_details: str,
    resolution: str,
    reference: str,
    severity: SeverityEnum,
    status: StatusEnum,
    compliance_mappings: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Create a validated finding object.

    Compliance mappings are resolved automatically from the shared
    compliance_mappings.CHECK_TO_COMPLIANCE_MAPPINGS table keyed on
    check_id. Callers can override or extend via the optional
    `compliance_mappings` argument; when provided it replaces the
    auto-resolved value entirely.

    Args:
        check_id: Unique check identifier (e.g., SM-01, BR-01, AC-01, OW-01).
        finding_name: Name of the finding.
        finding_details: Detailed description.
        resolution: Steps to resolve.
        reference: Documentation URL.
        severity: Severity level.
        status: Current status.
        compliance_mappings: Optional explicit overrides. When None, the
            mappings are looked up from the central table via
            get_compliance_mappings(check_id).

    Returns:
        Dict[str, Any]: Validated finding as dictionary.

    Raises:
        ValidationError: If any field fails validation.
    """
    if compliance_mappings is None:
        # Auto-resolve from the central table. Returns [] when the check
        # has no mapping — intentional, see compliance_mappings.py header.
        compliance_mappings = get_compliance_mappings(check_id)

    finding = Finding(
        Check_ID=check_id,
        Finding=finding_name,
        Finding_Details=finding_details,
        Resolution=resolution,
        Reference=reference,
        Severity=severity,
        Status=status,
        Compliance_Mappings=compliance_mappings,
    )
    return dict(finding.model_dump())  # Convert to regular dictionary
