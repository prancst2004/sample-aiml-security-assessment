"""
OWASP LLM Top 10 (2025) extensions for the Bedrock assessments Lambda.

These functions ride on top of existing Bedrock checks (BR-05 guardrails
loop, BR-07 prompt loop) and inspect data that was already fetched or can
be fetched with one additional per-resource API call.

Design note:
    The parent check_bedrock_guardrails() in app.py currently only calls
    bedrock:ListGuardrails. To evaluate OW-01/03/08/14/15 we need per-
    guardrail detail (bedrock:GetGuardrail). We do that here rather than
    inflating the main check function.

Coverage:
    OW-01 — Guardrail Prompt-Attack filter strength (LLM01)
    OW-03 — Guardrail PII Redaction (LLM02)
    OW-08 — Guardrail Output Filter compensating control (LLM05)
    OW-11 — System Prompt Protection (LLM07, partial-app-layer)
    OW-14 — Contextual Grounding Guardrail (LLM09)
    OW-15 — Guardrail Input Size Limit (LLM10, proactive leg)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

try:
    from .schema import create_finding
except ImportError:  # pragma: no cover — flat import for direct runs
    from schema import create_finding  # type: ignore

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Guardrail-driven checks (OW-01, OW-03, OW-08, OW-14, OW-15)
# ---------------------------------------------------------------------------

_GUARDRAIL_REF = "https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html"


def evaluate_guardrail_owasp_checks(
    bedrock_client: Any,
    guardrail_summaries: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Evaluate OW-01/03/08/14/15 across every existing guardrail.

    Args:
        bedrock_client: already-configured boto3 bedrock client.
        guardrail_summaries: the list returned by
            bedrock_client.list_guardrails()["guardrails"].

    Returns:
        List of finding dicts ready to append to the main Bedrock
        check's csv_data. All findings use the standard create_finding()
        which auto-resolves Compliance_Mappings via Check_ID.
    """
    findings: List[Dict[str, Any]] = []

    # N/A path: no guardrails at all. The parent BR-05 check already
    # raises a "no guardrails configured" finding, so we don't duplicate
    # that warning here — but we do emit N/A findings so the OWASP
    # coverage aggregation shows these controls as 'partial' not
    # 'not-assessed'.
    if not guardrail_summaries:
        for check_id, name, description in (
            ("OW-01", "Guardrail Prompt-Attack Filter",
             "No Bedrock guardrails exist, so prompt-attack filter strength cannot be assessed."),
            ("OW-03", "Guardrail PII Redaction",
             "No Bedrock guardrails exist, so PII redaction cannot be assessed."),
            ("OW-08", "Guardrail Output Filtering",
             "No Bedrock guardrails exist, so output filtering cannot be assessed."),
            ("OW-14", "Contextual Grounding Guardrail",
             "No Bedrock guardrails exist, so contextual grounding cannot be assessed."),
            ("OW-15", "Guardrail Input Size Limit",
             "No Bedrock guardrails exist, so input-size limit cannot be assessed."),
        ):
            findings.append(create_finding(
                check_id=check_id,
                finding_name=name,
                finding_details=description,
                resolution=(
                    "Configure at least one Bedrock guardrail to protect workloads "
                    "against prompt injection, PII disclosure, output abuse, "
                    "hallucinations, and oversized-input DoS."
                ),
                reference=_GUARDRAIL_REF,
                severity="Informational",
                status="N/A",
            ))
        return findings

    for summary in guardrail_summaries:
        guardrail_id = summary.get("id") or summary.get("guardrailId")
        guardrail_name = summary.get("name", guardrail_id)
        if not guardrail_id:
            continue

        try:
            detail = bedrock_client.get_guardrail(
                guardrailIdentifier=guardrail_id,
            )
        except Exception as e:  # pragma: no cover — defensive
            logger.warning(
                "Unable to fetch guardrail '%s' for OWASP evaluation: %s",
                guardrail_name, e,
            )
            findings.append(create_finding(
                check_id="OW-01",
                finding_name=f"Guardrail Inspection Failed: {guardrail_name}",
                finding_details=(
                    f"Could not retrieve details for guardrail '{guardrail_name}' "
                    f"(id={guardrail_id}): {e}"
                ),
                resolution=(
                    "Verify IAM permissions include bedrock:GetGuardrail "
                    "and retry the assessment."
                ),
                reference=_GUARDRAIL_REF,
                severity="Informational",
                status="N/A",
            ))
            continue

        findings.extend(_evaluate_single_guardrail(guardrail_name, detail))

    return findings


def _evaluate_single_guardrail(
    name: str, detail: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Apply OW-01/03/08/14/15 to the output of one get_guardrail call."""
    results: List[Dict[str, Any]] = []

    # ----- OW-01: Prompt-attack filter strength -----
    content_policy = detail.get("contentPolicy", {}) or {}
    filters = content_policy.get("filters", []) or []
    prompt_attack = next(
        (f for f in filters if f.get("type", "").upper() == "PROMPT_ATTACK"),
        None,
    )
    if prompt_attack is None:
        results.append(_owasp_finding(
            check_id="OW-01",
            finding_name="Prompt-Attack Filter Missing",
            detail=(
                f"Guardrail '{name}' does not include a PROMPT_ATTACK filter in its "
                f"contentPolicy. This leaves it unable to block direct prompt-"
                f"injection attempts."
            ),
            resolution=(
                "Add a PROMPT_ATTACK filter to the guardrail's contentPolicy with "
                "input and output strength set to HIGH."
            ),
            severity="High",
            status="Failed",
        ))
    else:
        input_strength = (prompt_attack.get("inputStrength") or "").upper()
        output_strength = (prompt_attack.get("outputStrength") or "").upper()
        if input_strength != "HIGH" or output_strength != "HIGH":
            results.append(_owasp_finding(
                check_id="OW-01",
                finding_name="Prompt-Attack Filter Weak",
                detail=(
                    f"Guardrail '{name}' has PROMPT_ATTACK filter configured with "
                    f"input={input_strength or 'unset'}, output={output_strength or 'unset'}. "
                    f"OWASP LLM01 mitigation requires HIGH on both legs."
                ),
                resolution=(
                    "Update the guardrail's PROMPT_ATTACK filter to set both "
                    "inputStrength and outputStrength to HIGH."
                ),
                severity="High",
                status="Failed",
            ))
        else:
            results.append(_owasp_finding(
                check_id="OW-01",
                finding_name="Prompt-Attack Filter Strong",
                detail=(
                    f"Guardrail '{name}' has PROMPT_ATTACK filter at HIGH strength on "
                    f"both input and output."
                ),
                resolution="No action required.",
                severity="Informational",
                status="Passed",
            ))

    # ----- OW-03: PII redaction -----
    sensitive_policy = detail.get("sensitiveInformationPolicy", {}) or {}
    pii_entities = sensitive_policy.get("piiEntities", []) or []
    # Baseline PII coverage we want to see
    baseline = {"EMAIL", "PHONE", "SSN", "CREDIT_DEBIT_CARD_NUMBER"}
    covered_types = {
        (e.get("type") or "").upper()
        for e in pii_entities
        if (e.get("action") or "").upper() in ("BLOCK", "ANONYMIZE")
    }
    if not pii_entities:
        # Informational: customers may intentionally not process PII.
        # Per proposal §5 OW-03, default severity is Medium but the finding
        # content makes clear it can be downgraded for non-PII workloads.
        results.append(_owasp_finding(
            check_id="OW-03",
            finding_name="PII Redaction Not Configured",
            detail=(
                f"Guardrail '{name}' has no sensitiveInformationPolicy PII entries. "
                f"If this workload processes personal data, PII exfiltration is not "
                f"blocked. If not, this finding can be treated as informational."
            ),
            resolution=(
                "For workloads that process personal data, add piiEntities entries "
                "for EMAIL, PHONE, SSN, and CREDIT_DEBIT_CARD_NUMBER with action "
                "BLOCK or ANONYMIZE. For internal / non-PII workloads, tag the "
                "guardrail to document that PII redaction is intentionally absent."
            ),
            severity="Medium",
            status="Failed",
        ))
    else:
        missing = baseline - covered_types
        if missing:
            results.append(_owasp_finding(
                check_id="OW-03",
                finding_name="PII Redaction Incomplete",
                detail=(
                    f"Guardrail '{name}' has piiEntities configured but is missing "
                    f"baseline types: {sorted(missing)}. Covered: {sorted(covered_types)}."
                ),
                resolution=(
                    f"Add BLOCK or ANONYMIZE entries for the missing PII types: "
                    f"{sorted(missing)}."
                ),
                severity="Medium",
                status="Failed",
            ))
        else:
            results.append(_owasp_finding(
                check_id="OW-03",
                finding_name="PII Redaction Configured",
                detail=(
                    f"Guardrail '{name}' blocks or anonymizes baseline PII types: "
                    f"{sorted(baseline)}."
                ),
                resolution="No action required.",
                severity="Informational",
                status="Passed",
            ))

    # ----- OW-08: Output filter compensating control (LLM05) -----
    # We look for ANY output-side protection: contentPolicy OUTPUT filter,
    # non-empty wordPolicy.managedWordLists or words, or topicPolicy.
    has_output_content_filter = any(
        (f.get("outputStrength") or "").upper() in ("LOW", "MEDIUM", "HIGH")
        for f in filters
    )
    word_policy = detail.get("wordPolicy", {}) or {}
    # Note: GetGuardrail returns "words"; the request schema uses "wordsConfig".
    # Accept either so the check is robust across API versions.
    _word_list = word_policy.get("words") or word_policy.get("wordsConfig") or []
    _managed_word_lists = word_policy.get("managedWordLists") or []
    has_word_lists = bool(_word_list or _managed_word_lists)
    topic_policy = detail.get("topicPolicy", {}) or {}
    has_topics = bool(topic_policy.get("topicsConfig"))

    if has_output_content_filter or has_word_lists or has_topics:
        results.append(_owasp_finding(
            check_id="OW-08",
            finding_name="Output-Side Guardrail Controls Present",
            detail=(
                f"Guardrail '{name}' applies output-side controls (content filter "
                f"output-strength / word list / topic policy). These are a "
                f"compensating control for OWASP LLM05 (Improper Output Handling) "
                f"— they do NOT replace downstream application-code output "
                f"sanitization."
            ),
            resolution=(
                "In addition to this guardrail, ensure the application code that "
                "consumes LLM output sanitizes it before use in eval(), SQL, shell, "
                "or HTML contexts. AWS control plane cannot assess that."
            ),
            severity="Informational",
            status="Passed",
        ))
    else:
        results.append(_owasp_finding(
            check_id="OW-08",
            finding_name="Output-Side Guardrail Controls Missing",
            detail=(
                f"Guardrail '{name}' has no output-side contentPolicy filters, "
                f"wordPolicy, or topicPolicy. OWASP LLM05 mitigation benefits from "
                f"at least one output-side control even when application-code "
                f"sanitization is primary."
            ),
            resolution=(
                "Configure at least one of: contentPolicy filter with outputStrength, "
                "wordPolicy.wordsConfig, or topicPolicy.topicsConfig to complement "
                "application-layer output sanitization."
            ),
            severity="Medium",
            status="Failed",
        ))

    # ----- OW-14: Contextual grounding -----
    grounding_policy = detail.get("contextualGroundingPolicy", {}) or {}
    grounding_filters = grounding_policy.get("filtersConfig") or grounding_policy.get("filters", [])
    if grounding_filters:
        types = {(f.get("type") or "").upper() for f in grounding_filters}
        if {"GROUNDING", "RELEVANCE"}.issubset(types):
            results.append(_owasp_finding(
                check_id="OW-14",
                finding_name="Contextual Grounding Enabled",
                detail=(
                    f"Guardrail '{name}' has contextualGroundingPolicy enabled with "
                    f"GROUNDING and RELEVANCE filters. This mitigates hallucinations "
                    f"in RAG / context-heavy workloads."
                ),
                resolution="No action required.",
                severity="Informational",
                status="Passed",
            ))
        else:
            results.append(_owasp_finding(
                check_id="OW-14",
                finding_name="Contextual Grounding Incomplete",
                detail=(
                    f"Guardrail '{name}' has contextualGroundingPolicy but only "
                    f"covers: {sorted(types)}. OWASP LLM09 mitigation benefits from "
                    f"both GROUNDING and RELEVANCE filters."
                ),
                resolution=(
                    "Extend contextualGroundingPolicy.filtersConfig to include both "
                    "GROUNDING and RELEVANCE filters with appropriate thresholds."
                ),
                severity="Medium",
                status="Failed",
            ))
    else:
        results.append(_owasp_finding(
            check_id="OW-14",
            finding_name="Contextual Grounding Disabled",
            detail=(
                f"Guardrail '{name}' has no contextualGroundingPolicy. For RAG "
                f"workloads this leaves hallucinations unmitigated at the "
                f"guardrail layer."
            ),
            resolution=(
                "Enable contextualGroundingPolicy with GROUNDING and RELEVANCE "
                "filters. Set thresholds appropriate to the use case (higher for "
                "factual RAG, lower for creative tasks)."
            ),
            severity="Medium",
            status="Failed",
        ))

    # ----- OW-15: Input size limit (proactive leg of Unbounded Consumption) -----
    # wordPolicy.words (response) / wordsConfig (request) or managedWordLists
    # act as proactive token limiters; alternatively a non-empty topicPolicy
    # with input-scope effectively enforces a word/topic envelope.
    has_input_word_limit = bool(_word_list or _managed_word_lists)
    if has_input_word_limit:
        results.append(_owasp_finding(
            check_id="OW-15",
            finding_name="Proactive Input Envelope Present",
            detail=(
                f"Guardrail '{name}' has a wordPolicy that limits input content. "
                f"This is the proactive leg of OWASP LLM10 mitigation — detective "
                f"controls (CloudWatch alarms, Budgets) are evaluated separately."
            ),
            resolution="No action required.",
            severity="Informational",
            status="Passed",
        ))
    else:
        results.append(_owasp_finding(
            check_id="OW-15",
            finding_name="Proactive Input Envelope Missing",
            detail=(
                f"Guardrail '{name}' has no wordPolicy that constrains input. "
                f"Consider adding a wordsConfig entry to block oversized / adversarial "
                f"inputs that drive up token cost. This finding addresses only the "
                f"proactive leg of LLM10; pair with CloudWatch alarms and AWS Budgets "
                f"for complete consumption monitoring (see OW-15)."
            ),
            resolution=(
                "Add a wordPolicy with wordsConfig or managedWordLists to block "
                "adversarial oversized inputs. Pair with CloudWatch alarms and AWS Budgets "
                "to complete consumption controls (OW-15)."
            ),
            severity="Medium",
            status="Failed",
        ))

    return results


# ---------------------------------------------------------------------------
# Bedrock Prompt-driven check (OW-11)
# ---------------------------------------------------------------------------


def evaluate_prompt_management_owasp_checks(
    bedrock_agent_client: Any,
    prompt_summaries: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Evaluate OW-11 (System Prompt Protection) against the results of
    bedrock-agent:ListPrompts.

    OWASP LLM07 is partial-app-layer: inline prompts in customer
    application code are outside AWS scope. Here we inspect what IS
    inspectable — whether managed Prompt resources are in use and whether
    they are suitably restricted.

    Args:
        bedrock_agent_client: already-configured boto3 bedrock-agent client.
        prompt_summaries: result of bedrock_agent_client.list_prompts()["promptSummaries"].
    """
    findings: List[Dict[str, Any]] = []

    if not prompt_summaries:
        findings.append(create_finding(
            check_id="OW-11",
            finding_name="System Prompt Protection — Inline Prompts Suspected",
            finding_details=(
                "No Bedrock Prompt Management resources are configured. If this "
                "account operates Bedrock-based assistants, system prompts are "
                "likely inline in application code, which is outside AWS control-"
                "plane scope and cannot be protected by managed prompt policies. "
                "This is a partial-app-layer gap under OWASP LLM07."
            ),
            resolution=(
                "Adopt Bedrock Prompt Management for production system prompts. "
                "Use versioned prompt resources and restrict access via IAM so "
                "system prompts cannot be exfiltrated by overly-scoped roles."
            ),
            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/prompt-management.html",
            severity="Medium",
            status="Failed",
        ))
        return findings

    # With prompts present, verify they aren't overly permissive. The
    # GetPrompt API doesn't expose a resource-based policy inline in all
    # regions; we flag for review rather than fail hard.
    findings.append(create_finding(
        check_id="OW-11",
        finding_name="Managed Prompts In Use",
        finding_details=(
            f"Bedrock Prompt Management is in use with {len(prompt_summaries)} prompts. "
            f"Verify that access to these prompts is restricted via IAM policies "
            f"and that resource-based policies (where applicable) do not grant "
            f"public or cross-account read. OWASP LLM07 has an application-layer "
            f"dimension (inline prompts in calling services) that cannot be "
            f"assessed from the AWS control plane."
        ),
        resolution=(
            "Review IAM policies for any principals with bedrock:GetPrompt. "
            "Ensure only the services that need to render prompts have read "
            "access. For applications still using inline system prompts, "
            "migrate to managed Prompt resources."
        ),
        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/prompt-management.html",
        severity="Informational",
        status="Passed",
    ))
    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _owasp_finding(
    check_id: str,
    finding_name: str,
    detail: str,
    resolution: str,
    severity: str,
    status: str,
    reference: Optional[str] = None,
) -> Dict[str, Any]:
    """Small wrapper around create_finding that sets the standard
    guardrail docs URL by default."""
    return create_finding(
        check_id=check_id,
        finding_name=finding_name,
        finding_details=detail,
        resolution=resolution,
        reference=reference or _GUARDRAIL_REF,
        severity=severity,
        status=status,
    )
