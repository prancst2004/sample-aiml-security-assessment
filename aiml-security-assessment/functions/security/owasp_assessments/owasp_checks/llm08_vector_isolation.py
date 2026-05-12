"""
OW-12: Vector Store Network Isolation.
OW-13: Multi-Tenant Knowledge Base Isolation.

OW-12: For each Bedrock Knowledge Base, resolve its vector store and
fail when the backing store exposes public network access.

    - OpenSearch Serverless: check the collection's network security
      policy for AllowFromPublic=true.
    - RDS / Aurora: check PubliclyAccessible on the cluster or
      instance.
    - Pinecone / Redis / MongoDB Atlas via Secrets Manager: we cannot
      reach into third-party endpoints from the control plane, so we
      emit an N/A finding noting the store is external.

OW-13: A per-account heuristic — when multiple KBs share the same
OpenSearch Serverless collection, warn that per-tenant filtering
becomes the customer's responsibility (OWASP LLM08). No-op when only
one KB points at a given collection.

Required IAM:
    bedrock-agent:ListKnowledgeBases
    bedrock-agent:GetKnowledgeBase
    aoss:BatchGetCollection
    aoss:ListSecurityPolicies
    aoss:GetSecurityPolicy
    rds:DescribeDBClusters
    rds:DescribeDBInstances
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

try:
    from ..schema import create_finding, SeverityEnum, StatusEnum
except ImportError:  # pragma: no cover
    from schema import create_finding, SeverityEnum, StatusEnum  # type: ignore

logger = logging.getLogger(__name__)

_REF = "https://docs.aws.amazon.com/bedrock/latest/userguide/knowledge-base-storage.html"


def _extract_storage(detail: Dict[str, Any]) -> Dict[str, Any]:
    kb = detail.get("knowledgeBase") or {}
    return kb.get("storageConfiguration") or {}


def _opensearch_serverless_public(
    aoss_client: Optional[Any], collection_arn: str,
) -> Dict[str, Any]:
    """Return {'public': bool, 'reason': str, 'checked': bool}."""
    if aoss_client is None:
        return {"public": False, "reason": "aoss client unavailable", "checked": False}

    # collection_arn: arn:aws:aoss:region:acct:collection/<collection-id>
    collection_id = collection_arn.split("/")[-1]
    try:
        batch = aoss_client.batch_get_collection(ids=[collection_id])
    except ClientError as e:
        logger.warning("aoss batch_get_collection failed: %s", e)
        return {"public": False, "reason": f"API error: {e}", "checked": False}
    except AttributeError:
        return {"public": False, "reason": "aoss API unavailable", "checked": False}

    details = batch.get("collectionDetails") or []
    if not details:
        return {"public": False, "reason": "collection not found", "checked": True}
    col_name = details[0].get("name", collection_id)

    # List network security policies that apply to this collection.
    try:
        policies_resp = aoss_client.list_security_policies(type="network")
        policies = policies_resp.get("securityPolicySummaries", [])
    except (ClientError, AttributeError) as e:
        logger.warning("aoss list_security_policies failed: %s", e)
        return {"public": False, "reason": f"cannot list policies: {e}", "checked": False}

    for pol in policies:
        pol_name = pol.get("name")
        try:
            full = aoss_client.get_security_policy(type="network", name=pol_name)
        except (ClientError, AttributeError):
            continue
        policy_doc = (full.get("securityPolicyDetail") or {}).get("policy") or ""
        try:
            doc = json.loads(policy_doc) if isinstance(policy_doc, str) else policy_doc
        except (json.JSONDecodeError, TypeError):
            continue

        # Policy is a list of rules; each rule has Rules[].ResourceType/Resource
        for rule in (doc if isinstance(doc, list) else [doc]):
            matches_this_collection = False
            for rt_rule in rule.get("Rules", []):
                if rt_rule.get("ResourceType") == "collection":
                    for resource in rt_rule.get("Resource", []):
                        # Resource patterns: "collection/<name>" or wildcards
                        if col_name in resource or resource.endswith("/*"):
                            matches_this_collection = True
            if matches_this_collection and rule.get("AllowFromPublic") is True:
                return {
                    "public": True,
                    "reason": f"network policy '{pol_name}' has AllowFromPublic=true",
                    "checked": True,
                }
    return {"public": False, "reason": "no public network policy found", "checked": True}


def _rds_cluster_public(
    rds_client: Optional[Any], cluster_arn: str,
) -> Dict[str, Any]:
    if rds_client is None:
        return {"public": False, "reason": "rds client unavailable", "checked": False}
    cluster_id = cluster_arn.split(":")[-1]
    try:
        resp = rds_client.describe_db_clusters(DBClusterIdentifier=cluster_id)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code == "DBClusterNotFoundFault":
            return {"public": False, "reason": "cluster not found", "checked": True}
        logger.warning("describe_db_clusters failed: %s", e)
        return {"public": False, "reason": f"API error: {e}", "checked": False}
    clusters = resp.get("DBClusters", [])
    if not clusters:
        return {"public": False, "reason": "cluster not found", "checked": True}
    cluster = clusters[0]
    # Aurora's public/private signal is at the instance layer
    for member in cluster.get("DBClusterMembers", []):
        instance_id = member.get("DBInstanceIdentifier")
        if not instance_id:
            continue
        try:
            inst_resp = rds_client.describe_db_instances(
                DBInstanceIdentifier=instance_id,
            )
        except ClientError:
            continue
        for inst in inst_resp.get("DBInstances", []):
            if inst.get("PubliclyAccessible"):
                return {
                    "public": True,
                    "reason": f"instance {instance_id} is PubliclyAccessible",
                    "checked": True,
                }
    return {"public": False, "reason": "all instances private", "checked": True}


def evaluate_vector_store_isolation(
    bedrock_agent_client: Any,
    aoss_client: Optional[Any],
    rds_client: Optional[Any],
) -> List[Dict[str, Any]]:
    """Emits OW-12 (network isolation) and OW-13 (multi-tenant)."""
    findings: List[Dict[str, Any]] = []

    try:
        resp = bedrock_agent_client.list_knowledge_bases()
        summaries = resp.get("knowledgeBaseSummaries", [])
    except ClientError as e:
        logger.warning("list_knowledge_bases failed: %s", e)
        summaries = []

    if not summaries:
        for check_id, name in (
            ("OW-12", "Vector Store Network Isolation"),
            ("OW-13", "Multi-Tenant KB Isolation"),
        ):
            findings.append(create_finding(
                check_id=check_id,
                finding_name=f"{name} — No KBs",
                finding_details=(
                    "No Bedrock Knowledge Bases found; OW-12 / OW-13 not "
                    "applicable."
                ),
                resolution="No action required.",
                reference=_REF,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            ))
        return findings

    # collection_arn -> list of kb names (for OW-13)
    collection_to_kbs: Dict[str, List[str]] = defaultdict(list)

    for kb_summary in summaries:
        kb_id = kb_summary.get("knowledgeBaseId")
        kb_name = kb_summary.get("name", kb_id)
        if not kb_id:
            continue

        try:
            detail = bedrock_agent_client.get_knowledge_base(knowledgeBaseId=kb_id)
        except ClientError as e:
            logger.warning("get_knowledge_base failed for %s: %s", kb_id, e)
            continue

        storage = _extract_storage(detail)
        storage_type = storage.get("type", "").upper()

        if storage_type == "OPENSEARCH_SERVERLESS":
            cfg = storage.get("opensearchServerlessConfiguration") or {}
            collection_arn = cfg.get("collectionArn", "")
            if collection_arn:
                collection_to_kbs[collection_arn].append(kb_name)
            result = _opensearch_serverless_public(aoss_client, collection_arn)
        elif storage_type in ("RDS", "AURORA"):
            cfg = storage.get("rdsConfiguration") or {}
            cluster_arn = cfg.get("resourceArn", "")
            result = _rds_cluster_public(rds_client, cluster_arn)
        else:
            # Pinecone / Redis / MongoDB Atlas — third-party, out of scope
            findings.append(create_finding(
                check_id="OW-12",
                finding_name=f"Vector Store External: {kb_name}",
                finding_details=(
                    f"KB '{kb_name}' uses vector store type '{storage_type or 'unknown'}' "
                    f"which is not an AWS-managed store. Network isolation "
                    f"must be verified at the third-party provider's "
                    f"console and cannot be assessed from AWS."
                ),
                resolution=(
                    "Verify that the external vector store (Pinecone, "
                    "Redis, MongoDB Atlas, etc.) is configured to only "
                    "accept connections from authorized VPCs / IPs."
                ),
                reference=_REF,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            ))
            continue

        if not result["checked"]:
            findings.append(create_finding(
                check_id="OW-12",
                finding_name=f"Vector Store Isolation Undeterminable: {kb_name}",
                finding_details=(
                    f"KB '{kb_name}' ({storage_type}) — could not verify "
                    f"network access: {result['reason']}."
                ),
                resolution=(
                    "Grant the assessment role the vector-store read "
                    "permissions (aoss:BatchGetCollection, aoss:GetSecurityPolicy, "
                    "rds:DescribeDBClusters, rds:DescribeDBInstances) and "
                    "retry."
                ),
                reference=_REF,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            ))
        elif result["public"]:
            findings.append(create_finding(
                check_id="OW-12",
                finding_name=f"Vector Store Publicly Accessible: {kb_name}",
                finding_details=(
                    f"KB '{kb_name}' ({storage_type}) is publicly accessible: "
                    f"{result['reason']}. Vector embeddings can be queried "
                    f"or poisoned from the internet (OWASP LLM08)."
                ),
                resolution=(
                    "Tighten the network configuration so the vector store "
                    "is only reachable from authorized VPCs (OpenSearch "
                    "Serverless: remove AllowFromPublic from the network "
                    "policy; Aurora: set PubliclyAccessible=false and "
                    "place the cluster in private subnets)."
                ),
                reference=_REF,
                severity=SeverityEnum.HIGH,
                status=StatusEnum.FAILED,
            ))
        else:
            findings.append(create_finding(
                check_id="OW-12",
                finding_name=f"Vector Store Private: {kb_name}",
                finding_details=(
                    f"KB '{kb_name}' ({storage_type}) — {result['reason']}."
                ),
                resolution="No action required.",
                reference=_REF,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.PASSED,
            ))

    # OW-13 heuristic
    shared = {arn: kbs for arn, kbs in collection_to_kbs.items() if len(kbs) > 1}
    if shared:
        for arn, kbs in shared.items():
            findings.append(create_finding(
                check_id="OW-13",
                finding_name="Multiple KBs Share a Vector Store Collection",
                finding_details=(
                    f"Knowledge Bases {kbs} all point to OpenSearch "
                    f"Serverless collection '{arn.split('/')[-1]}'. If this "
                    f"collection serves multiple tenants, per-tenant "
                    f"filtering becomes the application's responsibility "
                    f"(OWASP LLM08 multi-tenant isolation)."
                ),
                resolution=(
                    "Either split tenants into separate collections, or "
                    "ensure every retrieval includes a tenant-filter in "
                    "the metadata filter expression and that the KB role "
                    "policy scopes access per tenant."
                ),
                reference=_REF,
                severity=SeverityEnum.MEDIUM,
                status=StatusEnum.FAILED,
            ))
    else:
        findings.append(create_finding(
            check_id="OW-13",
            finding_name="KB Collections Not Shared",
            finding_details=(
                f"Each of the {len(summaries)} KB(s) uses its own vector "
                f"store collection — no multi-tenant sharing detected."
            ),
            resolution="No action required.",
            reference=_REF,
            severity=SeverityEnum.INFORMATIONAL,
            status=StatusEnum.PASSED,
        ))

    return findings
