"""
Unit tests for OWASP LLM checks (OW-02, OW-09, OW-15, OW-17).

Uses unittest.mock.MagicMock rather than moto so the tests run without
network or boto3-stubber complexity. Each check accepts injected clients
so this is straightforward.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from owasp_checks.llm02_kb_trust import evaluate_kb_source_trust
from owasp_checks.llm02_kb_retrieval import evaluate_kb_retrieval_policy
from owasp_checks.llm06_agent_agency import evaluate_action_group_wildcards
from owasp_checks.llm10_consumption import evaluate_detective_consumption_controls


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ce(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, "op")


def _kb_list_paginator(summaries):
    """Return a MagicMock that behaves like a boto3 paginator."""
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {"knowledgeBaseSummaries": summaries}
    ]
    return paginator


# ---------------------------------------------------------------------------
# OW-02 — KB source trust
# ---------------------------------------------------------------------------


class TestOw02KbSourceTrust:
    def test_no_kbs(self):
        ba = MagicMock()
        ba.get_paginator.return_value = _kb_list_paginator([])
        s3 = MagicMock()
        findings = evaluate_kb_source_trust(ba, s3)
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "OW-02"

    def test_private_bucket_passes(self):
        ba = MagicMock()
        ba.get_paginator.return_value = _kb_list_paginator([
            {"knowledgeBaseId": "kb-1", "name": "SupportKB"},
        ])
        ba.list_data_sources.return_value = {
            "dataSourceSummaries": [{"dataSourceId": "ds-1"}],
        }
        ba.get_data_source.return_value = {
            "dataSource": {
                "dataSourceConfiguration": {
                    "s3Configuration": {"bucketArn": "arn:aws:s3:::kb-private"}
                }
            }
        }
        s3 = MagicMock()
        s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        s3.get_bucket_policy_status.return_value = {
            "PolicyStatus": {"IsPublic": False}
        }

        findings = evaluate_kb_source_trust(ba, s3)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"
        assert "Private" in findings[0]["Finding"]

    def test_public_bucket_fails(self):
        ba = MagicMock()
        ba.get_paginator.return_value = _kb_list_paginator([
            {"knowledgeBaseId": "kb-1", "name": "SupportKB"},
        ])
        ba.list_data_sources.return_value = {
            "dataSourceSummaries": [{"dataSourceId": "ds-1"}],
        }
        ba.get_data_source.return_value = {
            "dataSource": {
                "dataSourceConfiguration": {
                    "s3Configuration": {"bucketArn": "arn:aws:s3:::kb-public"}
                }
            }
        }
        s3 = MagicMock()
        s3.get_public_access_block.side_effect = _ce("NoSuchPublicAccessBlockConfiguration")
        s3.get_bucket_policy_status.return_value = {
            "PolicyStatus": {"IsPublic": True}
        }

        findings = evaluate_kb_source_trust(ba, s3)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"
        assert "Publicly" in findings[0]["Finding"]

    def test_access_denied_emits_na(self):
        ba = MagicMock()
        ba.get_paginator.return_value = _kb_list_paginator([
            {"knowledgeBaseId": "kb-1", "name": "SupportKB"},
        ])
        ba.list_data_sources.return_value = {
            "dataSourceSummaries": [{"dataSourceId": "ds-1"}],
        }
        ba.get_data_source.return_value = {
            "dataSource": {
                "dataSourceConfiguration": {
                    "s3Configuration": {"bucketArn": "arn:aws:s3:::kb-cross-acct"}
                }
            }
        }
        s3 = MagicMock()
        s3.get_public_access_block.side_effect = _ce("AccessDenied")
        s3.get_bucket_policy_status.side_effect = _ce("AccessDenied")

        findings = evaluate_kb_source_trust(ba, s3)
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert "Undeterminable" in findings[0]["Finding"]

    def test_non_s3_source_emits_na(self):
        ba = MagicMock()
        ba.get_paginator.return_value = _kb_list_paginator([
            {"knowledgeBaseId": "kb-1", "name": "SupportKB"},
        ])
        ba.list_data_sources.return_value = {
            "dataSourceSummaries": [{"dataSourceId": "ds-1"}],
        }
        ba.get_data_source.return_value = {
            "dataSource": {
                "dataSourceConfiguration": {
                    "confluenceConfiguration": {"some": "thing"}
                }
            }
        }
        s3 = MagicMock()

        findings = evaluate_kb_source_trust(ba, s3)
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert "No S3 Sources" in findings[0]["Finding"]


# ---------------------------------------------------------------------------
# OW-17 — KB retrieval resource policy
# ---------------------------------------------------------------------------


class TestOw17KbRetrieval:
    def test_no_kbs(self):
        ba = MagicMock()
        ba.list_knowledge_bases.return_value = {"knowledgeBaseSummaries": []}
        findings = evaluate_kb_retrieval_policy(ba)
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"

    def test_missing_policy_fails(self):
        ba = MagicMock()
        ba.list_knowledge_bases.return_value = {
            "knowledgeBaseSummaries": [
                {"knowledgeBaseId": "kb-1", "name": "KB1"},
            ]
        }
        ba.get_knowledge_base.return_value = {
            "knowledgeBase": {"knowledgeBaseArn": "arn:aws:bedrock:us-east-1:1:kb/kb-1"}
        }
        ba.get_resource_policy.side_effect = _ce("ResourceNotFoundException")

        findings = evaluate_kb_retrieval_policy(ba)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"
        assert "Missing" in findings[0]["Finding"]

    def test_restrictive_policy_passes(self):
        ba = MagicMock()
        ba.list_knowledge_bases.return_value = {
            "knowledgeBaseSummaries": [
                {"knowledgeBaseId": "kb-1", "name": "KB1"},
            ]
        }
        ba.get_knowledge_base.return_value = {
            "knowledgeBase": {"knowledgeBaseArn": "arn:aws:bedrock:us-east-1:1:kb/kb-1"}
        }
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::1:role/RetrieverRole"},
                    "Action": "bedrock-agent:Retrieve",
                    "Resource": "*",
                }
            ],
        }
        ba.get_resource_policy.return_value = {"policy": json.dumps(policy)}

        findings = evaluate_kb_retrieval_policy(ba)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"

    def test_wildcard_principal_policy_fails(self):
        ba = MagicMock()
        ba.list_knowledge_bases.return_value = {
            "knowledgeBaseSummaries": [
                {"knowledgeBaseId": "kb-1", "name": "KB1"},
            ]
        }
        ba.get_knowledge_base.return_value = {
            "knowledgeBase": {"knowledgeBaseArn": "arn:aws:bedrock:us-east-1:1:kb/kb-1"}
        }
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "bedrock-agent:Retrieve",
                    "Resource": "*",
                }
            ],
        }
        ba.get_resource_policy.return_value = {"policy": json.dumps(policy)}

        findings = evaluate_kb_retrieval_policy(ba)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"
        assert "Permissive" in findings[0]["Finding"]

    def test_api_unavailable_emits_na(self):
        ba = MagicMock()
        ba.list_knowledge_bases.return_value = {
            "knowledgeBaseSummaries": [{"knowledgeBaseId": "kb-1", "name": "KB1"}]
        }
        ba.get_knowledge_base.return_value = {
            "knowledgeBase": {"knowledgeBaseArn": "arn:aws:bedrock:us-east-1:1:kb/kb-1"}
        }
        # AttributeError simulates boto3 versions where the API isn't present
        del ba.get_resource_policy
        ba.get_resource_policy = MagicMock(side_effect=AttributeError("no such op"))

        findings = evaluate_kb_retrieval_policy(ba)
        assert any(f["Status"] == "N/A" and "Unavailable" in f["Finding"] for f in findings)


# ---------------------------------------------------------------------------
# OW-09 — Agent action group wildcards
# ---------------------------------------------------------------------------


class TestOw09AgentWildcards:
    def test_no_agents(self):
        ba = MagicMock()
        ba.list_agents.return_value = {"agentSummaries": []}
        iam = MagicMock()
        lam = MagicMock()
        findings = evaluate_action_group_wildcards(ba, iam, lam)
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"

    def test_wildcard_role_fails(self):
        ba = MagicMock()
        ba.list_agents.return_value = {
            "agentSummaries": [{"agentId": "a-1", "agentName": "OrderBot"}]
        }
        ba.list_agent_action_groups.return_value = {
            "actionGroupSummaries": [
                {"actionGroupId": "ag-1", "actionGroupName": "PlaceOrder"}
            ]
        }
        ba.get_agent_action_group.return_value = {
            "agentActionGroup": {
                "actionGroupExecutor": {
                    "lambda": "arn:aws:lambda:us-east-1:1:function:PlaceOrderFn"
                }
            }
        }
        lam = MagicMock()
        lam.get_function.return_value = {
            "Configuration": {"Role": "arn:aws:iam::1:role/PlaceOrderRole"}
        }
        iam = MagicMock()
        iam.list_role_policies.return_value = {"PolicyNames": ["InlineWild"]}
        iam.get_role_policy.return_value = {
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:*",
                        "Resource": "*",
                    }
                ]
            }
        }

        findings = evaluate_action_group_wildcards(ba, iam, lam)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"

    def test_scoped_role_passes(self):
        ba = MagicMock()
        ba.list_agents.return_value = {
            "agentSummaries": [{"agentId": "a-1", "agentName": "OrderBot"}]
        }
        ba.list_agent_action_groups.return_value = {
            "actionGroupSummaries": [
                {"actionGroupId": "ag-1", "actionGroupName": "PlaceOrder"}
            ]
        }
        ba.get_agent_action_group.return_value = {
            "agentActionGroup": {
                "actionGroupExecutor": {
                    "lambda": "arn:aws:lambda:us-east-1:1:function:PlaceOrderFn"
                }
            }
        }
        lam = MagicMock()
        lam.get_function.return_value = {
            "Configuration": {"Role": "arn:aws:iam::1:role/PlaceOrderRole"}
        }
        iam = MagicMock()
        iam.list_role_policies.return_value = {"PolicyNames": ["InlineScoped"]}
        iam.get_role_policy.return_value = {
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": ["arn:aws:s3:::orders/*"],
                    }
                ]
            }
        }

        findings = evaluate_action_group_wildcards(ba, iam, lam)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"

    def test_policy_document_as_json_string(self):
        """IAM sometimes returns PolicyDocument as a JSON-encoded string."""
        ba = MagicMock()
        ba.list_agents.return_value = {
            "agentSummaries": [{"agentId": "a-1", "agentName": "Bot"}]
        }
        ba.list_agent_action_groups.return_value = {
            "actionGroupSummaries": [{"actionGroupId": "ag-1", "actionGroupName": "G"}]
        }
        ba.get_agent_action_group.return_value = {
            "agentActionGroup": {
                "actionGroupExecutor": {
                    "lambda": "arn:aws:lambda:us-east-1:1:function:Fn"
                }
            }
        }
        lam = MagicMock()
        lam.get_function.return_value = {
            "Configuration": {"Role": "arn:aws:iam::1:role/Role"}
        }
        iam = MagicMock()
        iam.list_role_policies.return_value = {"PolicyNames": ["P1"]}
        iam.get_role_policy.return_value = {
            "PolicyDocument": json.dumps({
                "Statement": [
                    {"Effect": "Allow", "Action": "*", "Resource": "*"}
                ]
            })
        }

        findings = evaluate_action_group_wildcards(ba, iam, lam)
        assert findings[0]["Status"] == "Failed"

    def test_no_lambda_executor_is_skipped(self):
        ba = MagicMock()
        ba.list_agents.return_value = {
            "agentSummaries": [{"agentId": "a-1", "agentName": "ChatBot"}]
        }
        ba.list_agent_action_groups.return_value = {
            "actionGroupSummaries": [
                {"actionGroupId": "ag-1", "actionGroupName": "ReturnOnly"}
            ]
        }
        ba.get_agent_action_group.return_value = {
            "agentActionGroup": {"actionGroupExecutor": {}}
        }
        iam = MagicMock()
        lam = MagicMock()

        findings = evaluate_action_group_wildcards(ba, iam, lam)
        # With no Lambda, we fall through to the "no action groups" N/A finding
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"


# ---------------------------------------------------------------------------
# OW-15b — Detective consumption controls
# ---------------------------------------------------------------------------


class TestOw15bConsumption:
    def test_alarm_present_passes(self):
        cw = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "MetricAlarms": [
                    {
                        "AlarmName": "BedrockInvocationSpike",
                        "Namespace": "AWS/Bedrock",
                        "MetricName": "InvocationCount",
                    }
                ]
            }
        ]
        cw.get_paginator.return_value = paginator
        budgets = MagicMock()
        budgets_paginator = MagicMock()
        budgets_paginator.paginate.return_value = [{"Budgets": []}]
        budgets.get_paginator.return_value = budgets_paginator

        findings = evaluate_detective_consumption_controls(cw, budgets)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Check_ID"] == "OW-15"

    def test_budget_present_passes(self):
        cw = MagicMock()
        empty_alarms = MagicMock()
        empty_alarms.paginate.return_value = [{"MetricAlarms": []}]
        cw.get_paginator.return_value = empty_alarms
        budgets = MagicMock()
        b_pg = MagicMock()
        b_pg.paginate.return_value = [
            {
                "Budgets": [
                    {
                        "BudgetName": "BedrockCostGuard",
                        "CostFilters": {"Service": ["Amazon Bedrock"]},
                    }
                ]
            }
        ]
        budgets.get_paginator.return_value = b_pg
        # Avoid STS round-trip in the test
        import os
        os.environ["AWS_ACCOUNT_ID"] = "111111111111"
        try:
            findings = evaluate_detective_consumption_controls(cw, budgets)
        finally:
            del os.environ["AWS_ACCOUNT_ID"]
        assert findings[0]["Status"] == "Passed"

    def test_nothing_present_fails(self):
        cw = MagicMock()
        empty_alarms = MagicMock()
        empty_alarms.paginate.return_value = [{"MetricAlarms": []}]
        cw.get_paginator.return_value = empty_alarms
        budgets = MagicMock()
        empty_budgets = MagicMock()
        empty_budgets.paginate.return_value = [{"Budgets": []}]
        budgets.get_paginator.return_value = empty_budgets
        import os
        os.environ["AWS_ACCOUNT_ID"] = "111111111111"
        try:
            findings = evaluate_detective_consumption_controls(cw, budgets)
        finally:
            del os.environ["AWS_ACCOUNT_ID"]
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"
        assert "Missing" in findings[0]["Finding"]

    def test_non_llm_alarm_does_not_count(self):
        cw = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "MetricAlarms": [
                    {
                        "AlarmName": "EC2CpuHigh",
                        "Namespace": "AWS/EC2",
                        "MetricName": "CPUUtilization",
                    }
                ]
            }
        ]
        cw.get_paginator.return_value = paginator
        budgets = MagicMock()
        empty_budgets = MagicMock()
        empty_budgets.paginate.return_value = [{"Budgets": []}]
        budgets.get_paginator.return_value = empty_budgets
        import os
        os.environ["AWS_ACCOUNT_ID"] = "111111111111"
        try:
            findings = evaluate_detective_consumption_controls(cw, budgets)
        finally:
            del os.environ["AWS_ACCOUNT_ID"]
        assert findings[0]["Status"] == "Failed"


# ---------------------------------------------------------------------------
# Sanity check: all OW-XX findings have resolved Compliance_Mappings
# ---------------------------------------------------------------------------


def test_exemplar_findings_carry_compliance_mappings():
    ba = MagicMock()
    ba.get_paginator.return_value = _kb_list_paginator([])
    s3 = MagicMock()
    for finding in evaluate_kb_source_trust(ba, s3):
        assert "Compliance_Mappings" in finding
        assert isinstance(finding["Compliance_Mappings"], list)
        # OW-02 is mapped to LLM01 + LLM03
        assert any(m["control_id"] in {"LLM01", "LLM03"} for m in finding["Compliance_Mappings"])
