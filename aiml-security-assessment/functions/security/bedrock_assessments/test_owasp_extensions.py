"""
Tests for bedrock_owasp_extensions (Phase 2a).

Runs from inside bedrock_assessments/:
    python -m pytest test_bedrock_owasp_extensions.py -v
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from owasp_extensions import (
    evaluate_guardrail_owasp_checks,
    evaluate_prompt_management_owasp_checks,
)


# ---------------------------------------------------------------------------
# Fixtures: guardrail detail builders
# ---------------------------------------------------------------------------

def _guardrail(
    prompt_attack_input: str = "HIGH",
    prompt_attack_output: str = "HIGH",
    extra_filters=None,
    pii_entities=None,
    word_policy=None,
    topic_policy=None,
    grounding_filters=None,
):
    """Build a bedrock:GetGuardrail response payload."""
    filters = []
    if prompt_attack_input or prompt_attack_output:
        filters.append({
            "type": "PROMPT_ATTACK",
            "inputStrength": prompt_attack_input,
            "outputStrength": prompt_attack_output,
        })
    if extra_filters:
        filters.extend(extra_filters)
    return {
        "contentPolicy": {"filters": filters},
        "sensitiveInformationPolicy": {"piiEntities": pii_entities or []},
        "wordPolicy": word_policy or {},
        "topicPolicy": topic_policy or {},
        "contextualGroundingPolicy": {
            "filtersConfig": grounding_filters or []
        },
    }


def _mock_client(guardrail_map):
    """Return a MagicMock bedrock client whose get_guardrail reads from a dict."""
    client = MagicMock()
    client.get_guardrail.side_effect = lambda guardrailIdentifier: guardrail_map[
        guardrailIdentifier
    ]
    return client


def _by_check_id(findings, check_id):
    return [f for f in findings if f["Check_ID"] == check_id]


# ---------------------------------------------------------------------------
# OW-01 Prompt-Attack Filter
# ---------------------------------------------------------------------------

class TestPromptAttackFilter:
    def test_high_strength_passes(self):
        gr = _guardrail(prompt_attack_input="HIGH", prompt_attack_output="HIGH")
        client = _mock_client({"gr1": gr})
        out = evaluate_guardrail_owasp_checks(
            client, [{"id": "gr1", "name": "GR1"}]
        )
        ow01 = _by_check_id(out, "OW-01")
        assert len(ow01) == 1
        assert ow01[0]["Status"] == "Passed"
        assert "Strong" in ow01[0]["Finding"]

    def test_weak_strength_fails(self):
        gr = _guardrail(prompt_attack_input="LOW", prompt_attack_output="NONE")
        client = _mock_client({"gr1": gr})
        out = evaluate_guardrail_owasp_checks(
            client, [{"id": "gr1", "name": "GR1"}]
        )
        ow01 = _by_check_id(out, "OW-01")
        assert ow01[0]["Status"] == "Failed"
        assert ow01[0]["Severity"] == "High"
        assert "Weak" in ow01[0]["Finding"]

    def test_missing_filter_fails(self):
        gr = _guardrail(prompt_attack_input="", prompt_attack_output="")
        # Remove the synthesized filter
        gr["contentPolicy"]["filters"] = []
        client = _mock_client({"gr1": gr})
        out = evaluate_guardrail_owasp_checks(
            client, [{"id": "gr1", "name": "GR1"}]
        )
        ow01 = _by_check_id(out, "OW-01")
        assert ow01[0]["Status"] == "Failed"
        assert "Missing" in ow01[0]["Finding"]

    def test_no_guardrails_produces_na(self):
        out = evaluate_guardrail_owasp_checks(MagicMock(), [])
        ow01 = _by_check_id(out, "OW-01")
        assert len(ow01) == 1
        assert ow01[0]["Status"] == "N/A"

    def test_owasp_mapping_auto_attached(self):
        gr = _guardrail()
        client = _mock_client({"gr1": gr})
        out = evaluate_guardrail_owasp_checks(
            client, [{"id": "gr1", "name": "GR1"}]
        )
        ow01 = _by_check_id(out, "OW-01")[0]
        assert ow01["Compliance_Mappings"], "OW-01 should have OWASP mapping"
        mappings = ow01["Compliance_Mappings"]
        assert any(m["control_id"] == "LLM01" for m in mappings)


# ---------------------------------------------------------------------------
# OW-03 PII Redaction
# ---------------------------------------------------------------------------

class TestPiiRedaction:
    BASELINE = [
        {"type": "EMAIL", "action": "ANONYMIZE"},
        {"type": "PHONE", "action": "BLOCK"},
        {"type": "SSN", "action": "BLOCK"},
        {"type": "CREDIT_DEBIT_CARD_NUMBER", "action": "BLOCK"},
    ]

    def test_complete_baseline_passes(self):
        gr = _guardrail(pii_entities=self.BASELINE)
        client = _mock_client({"gr1": gr})
        out = evaluate_guardrail_owasp_checks(
            client, [{"id": "gr1", "name": "GR1"}]
        )
        ow03 = _by_check_id(out, "OW-03")
        assert ow03[0]["Status"] == "Passed"

    def test_partial_baseline_fails(self):
        gr = _guardrail(pii_entities=self.BASELINE[:2])  # only EMAIL, PHONE
        client = _mock_client({"gr1": gr})
        out = evaluate_guardrail_owasp_checks(
            client, [{"id": "gr1", "name": "GR1"}]
        )
        ow03 = _by_check_id(out, "OW-03")
        assert ow03[0]["Status"] == "Failed"
        assert "SSN" in ow03[0]["Finding_Details"]

    def test_empty_pii_policy_fails_with_non_pii_note(self):
        gr = _guardrail(pii_entities=[])
        client = _mock_client({"gr1": gr})
        out = evaluate_guardrail_owasp_checks(
            client, [{"id": "gr1", "name": "GR1"}]
        )
        ow03 = _by_check_id(out, "OW-03")[0]
        assert ow03["Status"] == "Failed"
        # Finding text acknowledges non-PII workload path
        assert "informational" in ow03["Finding_Details"].lower() or "non-pii" in ow03["Finding_Details"].lower()

    def test_non_block_action_not_counted(self):
        gr = _guardrail(pii_entities=[
            {"type": "EMAIL", "action": "NONE"},
            {"type": "PHONE", "action": "BLOCK"},
            {"type": "SSN", "action": "BLOCK"},
            {"type": "CREDIT_DEBIT_CARD_NUMBER", "action": "BLOCK"},
        ])
        client = _mock_client({"gr1": gr})
        out = evaluate_guardrail_owasp_checks(
            client, [{"id": "gr1", "name": "GR1"}]
        )
        ow03 = _by_check_id(out, "OW-03")[0]
        assert ow03["Status"] == "Failed"
        assert "EMAIL" in ow03["Finding_Details"]


# ---------------------------------------------------------------------------
# OW-08 Output filtering (LLM05 compensating control)
# ---------------------------------------------------------------------------

class TestOutputFilter:
    def test_content_output_filter_present_passes(self):
        gr = _guardrail(
            extra_filters=[{"type": "HATE", "outputStrength": "HIGH"}],
        )
        client = _mock_client({"gr1": gr})
        out = evaluate_guardrail_owasp_checks(
            client, [{"id": "gr1", "name": "GR1"}]
        )
        ow08 = _by_check_id(out, "OW-08")
        assert ow08[0]["Status"] == "Passed"
        assert "compensating control" in ow08[0]["Finding_Details"].lower()

    def test_word_list_passes(self):
        gr = _guardrail(word_policy={"wordsConfig": [{"text": "banned"}]})
        client = _mock_client({"gr1": gr})
        out = evaluate_guardrail_owasp_checks(
            client, [{"id": "gr1", "name": "GR1"}]
        )
        ow08 = _by_check_id(out, "OW-08")
        assert ow08[0]["Status"] == "Passed"

    def test_topic_policy_passes(self):
        gr = _guardrail(
            topic_policy={"topicsConfig": [{"name": "legal advice"}]}
        )
        client = _mock_client({"gr1": gr})
        out = evaluate_guardrail_owasp_checks(
            client, [{"id": "gr1", "name": "GR1"}]
        )
        ow08 = _by_check_id(out, "OW-08")
        assert ow08[0]["Status"] == "Passed"

    def test_none_of_the_controls_fails(self):
        gr = _guardrail()  # default has PROMPT_ATTACK which has no outputStrength set on other filters
        client = _mock_client({"gr1": gr})
        out = evaluate_guardrail_owasp_checks(
            client, [{"id": "gr1", "name": "GR1"}]
        )
        ow08 = _by_check_id(out, "OW-08")
        # PROMPT_ATTACK has outputStrength=HIGH in default, which counts as output filter
        # So let's build one that explicitly doesn't:
        gr2 = _guardrail(prompt_attack_input="HIGH", prompt_attack_output="")
        gr2["contentPolicy"]["filters"] = [
            {"type": "PROMPT_ATTACK", "inputStrength": "HIGH"}  # no outputStrength key
        ]
        client2 = _mock_client({"gr2": gr2})
        out2 = evaluate_guardrail_owasp_checks(
            client2, [{"id": "gr2", "name": "GR2"}]
        )
        ow08_2 = _by_check_id(out2, "OW-08")
        assert ow08_2[0]["Status"] == "Failed"


# ---------------------------------------------------------------------------
# OW-14 Contextual Grounding
# ---------------------------------------------------------------------------

class TestContextualGrounding:
    def test_both_filters_present_passes(self):
        gr = _guardrail(grounding_filters=[
            {"type": "GROUNDING", "threshold": 0.8},
            {"type": "RELEVANCE", "threshold": 0.7},
        ])
        client = _mock_client({"gr1": gr})
        out = evaluate_guardrail_owasp_checks(
            client, [{"id": "gr1", "name": "GR1"}]
        )
        ow14 = _by_check_id(out, "OW-14")
        assert ow14[0]["Status"] == "Passed"

    def test_missing_one_filter_fails(self):
        gr = _guardrail(grounding_filters=[
            {"type": "GROUNDING", "threshold": 0.8},
        ])
        client = _mock_client({"gr1": gr})
        out = evaluate_guardrail_owasp_checks(
            client, [{"id": "gr1", "name": "GR1"}]
        )
        ow14 = _by_check_id(out, "OW-14")
        assert ow14[0]["Status"] == "Failed"
        assert "RELEVANCE" in ow14[0]["Finding_Details"]

    def test_no_grounding_policy_fails(self):
        gr = _guardrail(grounding_filters=[])
        client = _mock_client({"gr1": gr})
        out = evaluate_guardrail_owasp_checks(
            client, [{"id": "gr1", "name": "GR1"}]
        )
        ow14 = _by_check_id(out, "OW-14")
        assert ow14[0]["Status"] == "Failed"


# ---------------------------------------------------------------------------
# OW-15 Input Size Limit
# ---------------------------------------------------------------------------

class TestInputSizeLimit:
    def test_word_list_present_passes(self):
        gr = _guardrail(word_policy={"wordsConfig": [{"text": "example"}]})
        client = _mock_client({"gr1": gr})
        out = evaluate_guardrail_owasp_checks(
            client, [{"id": "gr1", "name": "GR1"}]
        )
        ow15 = _by_check_id(out, "OW-15")
        assert ow15[0]["Status"] == "Passed"

    def test_managed_word_lists_passes(self):
        gr = _guardrail(
            word_policy={"managedWordLists": [{"type": "PROFANITY"}]}
        )
        client = _mock_client({"gr1": gr})
        out = evaluate_guardrail_owasp_checks(
            client, [{"id": "gr1", "name": "GR1"}]
        )
        ow15 = _by_check_id(out, "OW-15")
        assert ow15[0]["Status"] == "Passed"

    def test_empty_word_policy_fails(self):
        gr = _guardrail(word_policy={})
        client = _mock_client({"gr1": gr})
        out = evaluate_guardrail_owasp_checks(
            client, [{"id": "gr1", "name": "GR1"}]
        )
        ow15 = _by_check_id(out, "OW-15")
        assert ow15[0]["Status"] == "Failed"
        assert "proactive" in ow15[0]["Finding_Details"].lower()


# ---------------------------------------------------------------------------
# Multiple guardrails + resilience
# ---------------------------------------------------------------------------

class TestMultipleGuardrails:
    def test_produces_findings_per_guardrail(self):
        gr_good = _guardrail(
            pii_entities=TestPiiRedaction.BASELINE,
            grounding_filters=[
                {"type": "GROUNDING"}, {"type": "RELEVANCE"}
            ],
            word_policy={"wordsConfig": [{"text": "x"}]},
        )
        gr_bad = _guardrail(
            prompt_attack_input="LOW", prompt_attack_output="NONE",
            pii_entities=[],
        )
        client = _mock_client({"good": gr_good, "bad": gr_bad})
        out = evaluate_guardrail_owasp_checks(
            client,
            [{"id": "good", "name": "Good"}, {"id": "bad", "name": "Bad"}],
        )
        # 5 OWASP checks per guardrail × 2 guardrails = 10 findings
        assert len(out) == 10
        # Each finding names the guardrail
        names_in_details = [f["Finding_Details"] for f in out]
        assert any("Good" in d for d in names_in_details)
        assert any("Bad" in d for d in names_in_details)


# ---------------------------------------------------------------------------
# OW-11 Prompt Management (System Prompt Protection)
# ---------------------------------------------------------------------------

class TestPromptManagement:
    def test_no_prompts_emits_inline_warning(self):
        out = evaluate_prompt_management_owasp_checks(MagicMock(), [])
        assert len(out) == 1
        assert out[0]["Check_ID"] == "OW-11"
        assert out[0]["Status"] == "Failed"
        assert "inline" in out[0]["Finding_Details"].lower()

    def test_prompts_present_passes(self):
        out = evaluate_prompt_management_owasp_checks(
            MagicMock(),
            [{"name": "p1", "promptId": "1"}, {"name": "p2", "promptId": "2"}],
        )
        assert len(out) == 1
        assert out[0]["Status"] == "Passed"
        # Content still acknowledges the app-layer gap
        assert "application-layer" in out[0]["Finding_Details"].lower()

    def test_compliance_mapping_resolves_to_llm07(self):
        out = evaluate_prompt_management_owasp_checks(MagicMock(), [])
        mappings = out[0]["Compliance_Mappings"]
        assert any(m["control_id"] == "LLM07" for m in mappings)
        assert mappings[0]["coverage_type"] == "partial-app-layer"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
