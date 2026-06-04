from enum import Enum
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field, validator

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
    """Represents a security finding with required fields and validations"""
    Finding: str = Field(..., min_length=1, description="The name/title of the finding")
    Finding_Details: str = Field(..., min_length=1, description="Detailed description of the finding")
    Resolution: str = Field(..., min_length=0, description="Steps to resolve the finding")
    Reference: str = Field(..., description="Documentation reference URL")
    Severity: SeverityEnum = Field(..., description="Severity level of the finding")
    Status: StatusEnum = Field(..., description="Current status of the finding")
    Compliance_Mappings: Optional[List[Dict[str, Any]]] = Field(
        default_factory=list,
        description=(
            "Compliance-framework mappings for this finding (e.g., OWASP LLM, "
            "NIST AI RMF, MITRE ATLAS, HIPAA). Backward-compatible: callers that "
            "do not populate this field get an empty list."
        ),
    )

    @validator('Reference')
    def validate_reference_url(cls, v):
        """Validate that reference URL starts with https://"""
        if not str(v).startswith('https://'):
            raise ValueError('Reference URL must start with https://')
        return v
    @validator('Severity')
    def validate_severity(cls, v):
        """Validate that severity is one of the allowed values"""
        if v not in SeverityEnum.__members__.values():
            raise ValueError('Severity must be one of the allowed values')
        return v
    @validator('Status')
    def validate_status(cls, v):
        """Validate that status is one of the allowed values"""
        if v not in StatusEnum.__members__.values():
            raise ValueError('Status must be one of the allowed values')
        return v

# Example usage:
def create_finding(
    finding_name: str,
    finding_details: str,
    resolution: str,
    reference: str,
    severity: SeverityEnum,
    status: StatusEnum,
    compliance_mappings: Optional[List[Dict[str, Any]]] = None,
) -> Finding:
    """
    Create a validated finding object

    Args:
        finding_name: Name of the finding
        finding_details: Detailed description
        resolution: Steps to resolve
        reference: Documentation URL
        severity: Severity level
        status: Current status
        compliance_mappings: Optional list of compliance-framework mappings.
            Defaults to empty list for backward compatibility.

    Returns:
        Finding: Validated finding object

    Raises:
        ValidationError: If any field fails validation
    """
    finding = Finding(
        Finding=finding_name,
        Finding_Details=finding_details,
        Resolution=resolution,
        Reference=reference,
        Severity=severity,
        Status=status,
        Compliance_Mappings=compliance_mappings or [],
    )
    return dict(finding.model_dump())  # Convert to regular dictionary
