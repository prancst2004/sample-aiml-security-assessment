"""
Unit tests for OWASP LLM checks (OW-04, OW-05, OW-06, OW-07,
OW-10, OW-12/13, OW-18).

Uses unittest.mock.MagicMock for boto3 clients, one pytest class per check.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from owasp_checks.llm02_log_retention import evaluate_invocation_log_retention
from owasp_checks.llm03_model_provenance import evaluate_model_provenance
from owasp_checks.llm03_jumpstart_inventory import evaluate_jumpstart_marketplace_inventory
from owasp_checks.llm04_kb_ingestion_role import evaluate_kb_ingestion_role
from owasp_checks.llm06_confirmation import evaluate_confirmation_flows
from owasp_checks.llm08_vector_isolation import evaluate_vector_store_isolation
from owasp_checks.llm06_sub_agent_inventory import evaluate_sub_agent_inventory


def _ce(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, "op")


# ---------------------------------------------------------------------------
# OW-04 Invocation Log Retention
# ---------------------------------------------------------------------------


class TestOw04LogRetention:
    def test_logging_disabled_fails(self):
        bedrock = MagicMock()
        bedrock.get_model_invocation_logging_configuration.side_effect = _ce("ValidationException")
        logs = MagicMock()
        s3 = MagicMock()
        findings = evaluate_invocation_log_retention(bedrock, logs, s3)
        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "OW-04"
        assert findings[0]["Status"] == "Failed"
        assert "Disabled" in findings[0]["Finding"]

    def test_cw_retention_ok_passes(self):
        bedrock = MagicMock()
        bedrock.get_model_invocation_logging_configuration.return_value = {
            "loggingConfig": {
                "cloudWatchConfig": {"logGroupName": "/aws/bedrock/invocations"},
            }
        }
        logs = MagicMock()
        logs.describe_log_groups.return_value = {
            "logGroups": [
                {"logGroupName": "/aws/bedrock/invocations", "retentionInDays": 90},
            ]
        }
        s3 = MagicMock()
        findings = evaluate_invocation_log_retention(bedrock, logs, s3)
        assert any(f["Status"] == "Passed" and "CloudWatch" in f["Finding"] for f in findings)

    def test_cw_retention_too_short_fails(self):
        bedrock = MagicMock()
        bedrock.get_model_invocation_logging_configuration.return_value = {
            "loggingConfig": {
                "cloudWatchConfig": {"logGroupName": "/aws/bedrock/invocations"},
            }
        }
        logs = MagicMock()
        logs.describe_log_groups.return_value = {
            "logGroups": [
                {"logGroupName": "/aws/bedrock/invocations", "retentionInDays": 7},
            ]
        }
        s3 = MagicMock()
        findings = evaluate_invocation_log_retention(bedrock, logs, s3)
        assert any(f["Status"] == "Failed" and "Insufficient" in f["Finding"] for f in findings)

    def test_s3_destination_public_fails(self):
        bedrock = MagicMock()
        bedrock.get_model_invocation_logging_configuration.return_value = {
            "loggingConfig": {
                "s3Config": {"bucketName": "bedrock-logs-public"},
            }
        }
        logs = MagicMock()
        s3 = MagicMock()
        s3.get_public_access_block.side_effect = _ce("NoSuchPublicAccessBlockConfiguration")
        s3.get_bucket_policy_status.return_value = {"PolicyStatus": {"IsPublic": False}}
        findings = evaluate_invocation_log_retention(bedrock, logs, s3)
        assert any(
            f["Status"] == "Failed" and f["Severity"] == "High"
            for f in findings
        )


# ---------------------------------------------------------------------------
# OW-05 Model Provenance
# ---------------------------------------------------------------------------


class TestOw05ModelProvenance:
    def test_no_custom_models_emits_na(self):
        bedrock = MagicMock()
        bedrock.list_custom_models.return_value = {"modelSummaries": []}
        s3 = MagicMock()
        sts = MagicMock()
        sts.get_caller_identity.return_value = {"Account": "111111111111"}
        findings = evaluate_model_provenance(bedrock, s3, sts)
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"

    def test_in_account_bucket_passes(self):
        bedrock = MagicMock()
        bedrock.list_custom_models.return_value = {
            "modelSummaries": [
                {"modelName": "support-qa-v1", "modelArn": "arn:aws:bedrock:us-east-1:1:custom-model/support-qa-v1"},
            ]
        }
        bedrock.get_custom_model.return_value = {
            "trainingDataConfig": {"s3Uri": "s3://my-training-bucket/data/"}
        }
        s3 = MagicMock()
        s3.get_bucket_acl.return_value = {"Owner": {"ID": "abc-canonical-id"}}
        sts = MagicMock()
        sts.get_caller_identity.return_value = {"Account": "111111111111"}
        findings = evaluate_model_provenance(bedrock, s3, sts)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"

    def test_cross_account_bucket_fails(self):
        bedrock = MagicMock()
        bedrock.list_custom_models.return_value = {
            "modelSummaries": [
                {"modelName": "third-party-model", "modelArn": "arn:aws:bedrock:us-east-1:1:custom-model/third-party-model"},
            ]
        }
        bedrock.get_custom_model.return_value = {
            "trainingDataConfig": {"s3Uri": "s3://vendor-bucket/weights/"}
        }
        s3 = MagicMock()
        s3.get_bucket_acl.side_effect = _ce("AccessDenied")
        sts = MagicMock()
        sts.get_caller_identity.return_value = {"Account": "111111111111"}
        findings = evaluate_model_provenance(bedrock, s3, sts)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"
        assert "Cross-Account" in findings[0]["Finding"]

    def test_untracked_provenance_fails(self):
        bedrock = MagicMock()
        bedrock.list_custom_models.return_value = {
            "modelSummaries": [
                {"modelName": "no-provenance", "modelArn": "arn:aws:bedrock:us-east-1:1:custom-model/no-provenance"},
            ]
        }
        bedrock.get_custom_model.return_value = {}
        s3 = MagicMock()
        sts = MagicMock()
        sts.get_caller_identity.return_value = {"Account": "111111111111"}
        findings = evaluate_model_provenance(bedrock, s3, sts)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"
        assert "Untracked" in findings[0]["Finding"]


# ---------------------------------------------------------------------------
# OW-06 JumpStart / Marketplace
# ---------------------------------------------------------------------------


class TestOw06JumpStartInventory:
    def test_no_model_packages_emits_na(self):
        sm = MagicMock()
        sm.list_model_packages.return_value = {"ModelPackageSummaryList": []}
        findings = evaluate_jumpstart_marketplace_inventory(sm)
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"

    def test_custom_only_emits_na(self):
        sm = MagicMock()
        sm.list_model_packages.return_value = {
            "ModelPackageSummaryList": [
                {
                    "ModelPackageName": "my-custom-v1",
                    "ModelPackageArn": "arn:aws:sagemaker:us-east-1:111:model-package/my-custom-v1",
                    "ModelPackageGroupName": "my-group",
                }
            ]
        }
        findings = evaluate_jumpstart_marketplace_inventory(sm)
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"

    def test_jumpstart_emits_passed_inventory(self):
        sm = MagicMock()
        sm.list_model_packages.return_value = {
            "ModelPackageSummaryList": [
                {
                    "ModelPackageName": "jumpstart-llama-7b",
                    "ModelPackageArn": "arn:aws:sagemaker:us-east-1:111:model-package/jumpstart-llama-7b",
                    "ModelPackageGroupName": "jumpstart-models",
                }
            ]
        }
        findings = evaluate_jumpstart_marketplace_inventory(sm)
        assert any("JumpStart" in f["Finding"] for f in findings)

    def test_marketplace_emits_passed_inventory(self):
        sm = MagicMock()
        sm.list_model_packages.return_value = {
            "ModelPackageSummaryList": [
                {
                    "ModelPackageName": "vendor-bert",
                    "ModelPackageArn": "arn:aws:sagemaker:us-east-1:aws:model-package/vendor-bert",
                    "ModelPackageGroupName": "vendor-group",
                }
            ]
        }
        findings = evaluate_jumpstart_marketplace_inventory(sm)
        assert any("Marketplace" in f["Finding"] for f in findings)


# ---------------------------------------------------------------------------
# OW-07 KB Ingestion Role Scope
# ---------------------------------------------------------------------------


class TestOw07KbIngestionRole:
    def test_no_kbs_emits_na(self):
        ba = MagicMock()
        ba.list_knowledge_bases.return_value = {"knowledgeBaseSummaries": []}
        iam = MagicMock()
        findings = evaluate_kb_ingestion_role(ba, iam)
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"

    def test_over_permissive_role_fails(self):
        ba = MagicMock()
        ba.list_knowledge_bases.return_value = {
            "knowledgeBaseSummaries": [{"knowledgeBaseId": "kb-1", "name": "KB1"}]
        }
        ba.get_knowledge_base.return_value = {
            "knowledgeBase": {"roleArn": "arn:aws:iam::1:role/KBIngestionRole"}
        }
        iam = MagicMock()
        iam.list_role_policies.return_value = {"PolicyNames": ["InlineWild"]}
        iam.get_role_policy.return_value = {
            "PolicyDocument": {
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
                ]
            }
        }
        findings = evaluate_kb_ingestion_role(ba, iam)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"

    def test_scoped_role_passes(self):
        ba = MagicMock()
        ba.list_knowledge_bases.return_value = {
            "knowledgeBaseSummaries": [{"knowledgeBaseId": "kb-1", "name": "KB1"}]
        }
        ba.get_knowledge_base.return_value = {
            "knowledgeBase": {"roleArn": "arn:aws:iam::1:role/KBIngestionRole"}
        }
        iam = MagicMock()
        iam.list_role_policies.return_value = {"PolicyNames": ["InlineScoped"]}
        iam.get_role_policy.return_value = {
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::kb-source/*",
                    }
                ]
            }
        }
        findings = evaluate_kb_ingestion_role(ba, iam)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"


# ---------------------------------------------------------------------------
# OW-10 Confirmation Flows
# ---------------------------------------------------------------------------


class TestOw10Confirmation:
    def test_no_agents_emits_na(self):
        ba = MagicMock()
        ba.list_agents.return_value = {"agentSummaries": []}
        findings = evaluate_confirmation_flows(ba)
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"

    def test_mixed_confirmation_emits_inventory(self):
        ba = MagicMock()
        ba.list_agents.return_value = {
            "agentSummaries": [{"agentId": "a-1", "agentName": "OrderBot"}]
        }
        ba.list_agent_action_groups.return_value = {
            "actionGroupSummaries": [
                {"actionGroupId": "ag-1", "actionGroupName": "PlaceOrder"},
                {"actionGroupId": "ag-2", "actionGroupName": "CheckStatus"},
            ]
        }

        def _get_ag(agentId, agentVersion, actionGroupId):
            if actionGroupId == "ag-1":
                return {"agentActionGroup": {"requireConfirmation": "ENABLED"}}
            return {"agentActionGroup": {"requireConfirmation": "DISABLED"}}

        ba.get_agent_action_group.side_effect = _get_ag
        findings = evaluate_confirmation_flows(ba)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"
        assert "1 require human confirmation" in findings[0]["Finding_Details"]
        assert "1 run without confirmation" in findings[0]["Finding_Details"]


# ---------------------------------------------------------------------------
# OW-12 / OW-13 Vector Store Isolation
# ---------------------------------------------------------------------------


class TestOw12And13VectorIsolation:
    def test_no_kbs_emits_two_nas(self):
        ba = MagicMock()
        ba.list_knowledge_bases.return_value = {"knowledgeBaseSummaries": []}
        findings = evaluate_vector_store_isolation(ba, MagicMock(), MagicMock())
        ids = {f["Check_ID"] for f in findings}
        assert ids == {"OW-12", "OW-13"}
        assert all(f["Status"] == "N/A" for f in findings)

    def test_aoss_private_passes(self):
        ba = MagicMock()
        ba.list_knowledge_bases.return_value = {
            "knowledgeBaseSummaries": [{"knowledgeBaseId": "kb-1", "name": "KB1"}]
        }
        ba.get_knowledge_base.return_value = {
            "knowledgeBase": {
                "storageConfiguration": {
                    "type": "OPENSEARCH_SERVERLESS",
                    "opensearchServerlessConfiguration": {
                        "collectionArn": "arn:aws:aoss:us-east-1:1:collection/col-private",
                    }
                }
            }
        }
        aoss = MagicMock()
        aoss.batch_get_collection.return_value = {
            "collectionDetails": [{"name": "col-private"}]
        }
        aoss.list_security_policies.return_value = {
            "securityPolicySummaries": [{"name": "p1"}]
        }
        aoss.get_security_policy.return_value = {
            "securityPolicyDetail": {
                "policy": json.dumps([
                    {
                        "Rules": [{"ResourceType": "collection", "Resource": ["collection/col-private"]}],
                        "AllowFromPublic": False,
                    }
                ])
            }
        }
        findings = evaluate_vector_store_isolation(ba, aoss, MagicMock())
        assert any(f["Check_ID"] == "OW-12" and f["Status"] == "Passed" for f in findings)
        assert any(f["Check_ID"] == "OW-13" and f["Status"] == "Passed" for f in findings)

    def test_aoss_public_fails(self):
        ba = MagicMock()
        ba.list_knowledge_bases.return_value = {
            "knowledgeBaseSummaries": [{"knowledgeBaseId": "kb-1", "name": "KB1"}]
        }
        ba.get_knowledge_base.return_value = {
            "knowledgeBase": {
                "storageConfiguration": {
                    "type": "OPENSEARCH_SERVERLESS",
                    "opensearchServerlessConfiguration": {
                        "collectionArn": "arn:aws:aoss:us-east-1:1:collection/col-public",
                    }
                }
            }
        }
        aoss = MagicMock()
        aoss.batch_get_collection.return_value = {
            "collectionDetails": [{"name": "col-public"}]
        }
        aoss.list_security_policies.return_value = {
            "securityPolicySummaries": [{"name": "p1"}]
        }
        aoss.get_security_policy.return_value = {
            "securityPolicyDetail": {
                "policy": json.dumps([
                    {
                        "Rules": [{"ResourceType": "collection", "Resource": ["collection/col-public"]}],
                        "AllowFromPublic": True,
                    }
                ])
            }
        }
        findings = evaluate_vector_store_isolation(ba, aoss, MagicMock())
        assert any(
            f["Check_ID"] == "OW-12" and f["Status"] == "Failed" and f["Severity"] == "High"
            for f in findings
        )

    def test_shared_collection_triggers_ow13_fail(self):
        ba = MagicMock()
        ba.list_knowledge_bases.return_value = {
            "knowledgeBaseSummaries": [
                {"knowledgeBaseId": "kb-1", "name": "TenantA"},
                {"knowledgeBaseId": "kb-2", "name": "TenantB"},
            ]
        }

        def _gkb(knowledgeBaseId):
            return {
                "knowledgeBase": {
                    "storageConfiguration": {
                        "type": "OPENSEARCH_SERVERLESS",
                        "opensearchServerlessConfiguration": {
                            "collectionArn": "arn:aws:aoss:us-east-1:1:collection/shared-col",
                        }
                    }
                }
            }
        ba.get_knowledge_base.side_effect = _gkb

        aoss = MagicMock()
        aoss.batch_get_collection.return_value = {
            "collectionDetails": [{"name": "shared-col"}]
        }
        aoss.list_security_policies.return_value = {"securityPolicySummaries": []}
        findings = evaluate_vector_store_isolation(ba, aoss, MagicMock())
        assert any(
            f["Check_ID"] == "OW-13" and f["Status"] == "Failed"
            and "Share a Vector Store" in f["Finding"]
            for f in findings
        )

    def test_external_vector_store_emits_na(self):
        ba = MagicMock()
        ba.list_knowledge_bases.return_value = {
            "knowledgeBaseSummaries": [{"knowledgeBaseId": "kb-1", "name": "PineconeKB"}]
        }
        ba.get_knowledge_base.return_value = {
            "knowledgeBase": {
                "storageConfiguration": {"type": "PINECONE"}
            }
        }
        findings = evaluate_vector_store_isolation(ba, MagicMock(), MagicMock())
        assert any(
            f["Check_ID"] == "OW-12" and f["Status"] == "N/A"
            and "External" in f["Finding"]
            for f in findings
        )


# ---------------------------------------------------------------------------
# OW-18 Sub-Agent Inventory
# ---------------------------------------------------------------------------


class TestOw18SubAgentInventory:
    def test_no_agents_emits_na(self):
        ba = MagicMock()
        ba.list_agents.return_value = {"agentSummaries": []}
        findings = evaluate_sub_agent_inventory(ba, MagicMock(), MagicMock())
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"

    def test_orchestrator_role_detected(self):
        ba = MagicMock()
        ba.list_agents.return_value = {
            "agentSummaries": [{"agentId": "a-1", "agentName": "OrchestratorBot"}]
        }
        ba.list_agent_action_groups.return_value = {
            "actionGroupSummaries": [
                {"actionGroupId": "ag-1", "actionGroupName": "CallSubAgent"}
            ]
        }
        ba.get_agent_action_group.return_value = {
            "agentActionGroup": {
                "actionGroupExecutor": {
                    "lambda": "arn:aws:lambda:us-east-1:1:function:CallSubAgentFn"
                }
            }
        }
        lam = MagicMock()
        lam.get_function.return_value = {
            "Configuration": {"Role": "arn:aws:iam::1:role/OrchestratorRole"}
        }
        iam = MagicMock()
        iam.list_role_policies.return_value = {"PolicyNames": ["InvokeSubAgent"]}
        iam.get_role_policy.return_value = {
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "bedrock-agent:InvokeAgent",
                        "Resource": "*",
                    }
                ]
            }
        }
        findings = evaluate_sub_agent_inventory(ba, iam, lam)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"
        assert "Orchestrator" in findings[0]["Finding"]

    def test_no_orchestrator_passes(self):
        ba = MagicMock()
        ba.list_agents.return_value = {
            "agentSummaries": [{"agentId": "a-1", "agentName": "SimpleBot"}]
        }
        ba.list_agent_action_groups.return_value = {
            "actionGroupSummaries": [
                {"actionGroupId": "ag-1", "actionGroupName": "SearchDocs"}
            ]
        }
        ba.get_agent_action_group.return_value = {
            "agentActionGroup": {
                "actionGroupExecutor": {
                    "lambda": "arn:aws:lambda:us-east-1:1:function:SearchDocsFn"
                }
            }
        }
        lam = MagicMock()
        lam.get_function.return_value = {
            "Configuration": {"Role": "arn:aws:iam::1:role/SearchDocsRole"}
        }
        iam = MagicMock()
        iam.list_role_policies.return_value = {"PolicyNames": ["Scoped"]}
        iam.get_role_policy.return_value = {
            "PolicyDocument": {
                "Statement": [
                    {"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": "arn:aws:dynamodb:us-east-1:1:table/docs"}
                ]
            }
        }
        findings = evaluate_sub_agent_inventory(ba, iam, lam)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"
