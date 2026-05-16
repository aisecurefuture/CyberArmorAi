"""Cloud-inventory A-BOM collector.

Phase 4 part 2. Walks a tenant's cloud accounts and emits CycloneDX
1.6 components for every resource — EC2, EKS, S3, RDS, Lambda,
DynamoDB, etc. Same identity_key dedup + provenance trail as the
other collectors.

AWS first; GCP + Azure land in the next slice. For AWS we use the
Resource Groups Tagging API (``get-resources``) because it gives us
broad cross-service coverage from a single API call with one
permission (``tag:GetResources``). Untagged resources are catchable
via per-service APIs — that's a follow-up for service-specific
visibility.

Components emit as ``source_kind=cloud_resource`` with
``source_id = aws:<account>:<region>`` so the Components view filter
lights up and the Loaded-vs-Installed overlay can pick up "the same
container we saw in JFrog is also running in this EKS cluster" once
phase-2 RASP starts reporting workload-side libraries.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("cyberarmor.control_plane.cloud_collector")

# Per-sync cap so a 50k-resource account can't drain the handler.
CLOUD_API_BUDGET = 1000


# ── AWS Resource Groups Tagging API client ────────────────────────────


class AWSError(Exception):
    pass


# Mapping from AWS service prefix → CycloneDX component.type. Anything
# not in this table defaults to ``platform``. The taxonomy follows the
# design doc §2: hardware-ish things land as ``device``, opaque
# managed services as ``platform``, data stores as ``data``, ML
# artifacts as ``machine-learning-model``.
_AWS_SERVICE_TYPE = {
    "ec2":            "device",       # actual instances + interfaces
    "ecs":            "container",
    "eks":            "platform",
    "lambda":         "application",
    "s3":             "data",
    "rds":            "data",
    "dynamodb":       "data",
    "redshift":       "data",
    "elasticache":    "data",
    "kinesis":        "data",
    "sqs":            "platform",
    "sns":            "platform",
    "iam":            "platform",
    "kms":            "cryptographic-asset",
    "secretsmanager": "cryptographic-asset",
    "sagemaker":      "machine-learning-model",
    "bedrock":        "machine-learning-model",
    "apigateway":     "platform",
    "apigatewayv2":   "platform",
    "cloudfront":     "platform",
    "route53":        "platform",
    "elb":            "platform",
    "elasticloadbalancing": "platform",
    "elasticbeanstalk":     "platform",
    "stepfunctions":  "platform",
    "ecr":            "container",
    "vpc":            "device",
    "logs":           "data",
}

_ARN_RE = re.compile(
    r"^arn:(?P<partition>[^:]+):(?P<service>[^:]+):(?P<region>[^:]*):(?P<account>[^:]*):(?P<resource>.+)$"
)


def _parse_arn(arn: str) -> Optional[Dict[str, str]]:
    m = _ARN_RE.match(arn or "")
    if not m:
        return None
    return m.groupdict()


def _resource_label(service: str, resource_segment: str) -> Tuple[str, str]:
    """Split the ARN resource segment into (resource_type, resource_id).

    AWS ARNs come in two shapes:
      ``arn:aws:s3:::bucket-name``  → resource_segment="bucket-name"
      ``arn:aws:lambda:us-east-1:123:function:my-fn`` → "function:my-fn"
      ``arn:aws:ec2:us-east-1:123:instance/i-abc123``  → "instance/i-abc123"

    We try slash first, then colon, then fall back to the bare value
    with the service as the type so the BOM still shows something
    meaningful.
    """
    if "/" in resource_segment:
        rtype, _, rid = resource_segment.partition("/")
        return rtype, rid
    if ":" in resource_segment:
        rtype, _, rid = resource_segment.partition(":")
        return rtype, rid
    return service, resource_segment


def sync_aws_account(
    access_key: str,
    secret_key: str,
    region: str,
    *,
    session_token: Optional[str] = None,
    account_id_hint: Optional[str] = None,
    resource_types: Optional[List[str]] = None,
) -> Tuple[str, List[Dict[str, Any]]]:
    """Sync one AWS account+region pair. Returns the standard
    ``(source_id, components)`` tuple. ``account_id_hint`` is optional
    — when unset we resolve it from STS get-caller-identity (one call)
    so the source_id is stable.

    Permissions required on the IAM role / user:
      - ``tag:GetResources`` (Resource Groups Tagging API)
      - ``sts:GetCallerIdentity`` (for account_id resolution)
    """
    try:
        import boto3
        from botocore.exceptions import ClientError, BotoCoreError
    except ImportError as exc:
        raise AWSError(f"boto3 not available: {exc}") from exc

    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=region,
    )

    # Account ID for the source_id label. Cheap one-call lookup.
    account = account_id_hint or "unknown"
    if not account_id_hint:
        try:
            sts = session.client("sts")
            account = str(sts.get_caller_identity().get("Account") or "unknown")
        except (ClientError, BotoCoreError) as exc:
            logger.warning("sts get-caller-identity failed: %s", exc)
            # Still proceed — we'll stamp "unknown" and the operator can
            # spot the gap in the inspector.

    source_id = f"aws:{account}:{region}"
    tagging = session.client("resourcegroupstaggingapi")

    components: List[Dict[str, Any]] = []
    pagination_token = ""
    iterations = 0
    while iterations < 50:
        kwargs: Dict[str, Any] = {
            "PaginationToken": pagination_token,
            "ResourcesPerPage": 100,
        }
        if resource_types:
            kwargs["ResourceTypeFilters"] = resource_types
        try:
            resp = tagging.get_resources(**kwargs)
        except (ClientError, BotoCoreError) as exc:
            raise AWSError(f"resourcegroupstaggingapi get-resources failed: {exc}") from exc
        rows = resp.get("ResourceTagMappingList") or []
        for entry in rows:
            arn = str(entry.get("ResourceARN") or "")
            parsed = _parse_arn(arn)
            if not parsed:
                continue
            service = parsed["service"]
            cyclonedx_type = _AWS_SERVICE_TYPE.get(service, "platform")
            rtype, rid = _resource_label(service, parsed["resource"])
            tags = entry.get("Tags") or []
            name_tag = next((t.get("Value") for t in tags if isinstance(t, dict) and t.get("Key") in ("Name", "name")), None)
            display_name = name_tag or rid or rtype
            component: Dict[str, Any] = {
                "type": cyclonedx_type,
                "name": f"{service}:{rtype}/{display_name}",
                "version": "",  # cloud resources don't have semver — version stays empty
                "purl": f"pkg:aws/{service}/{rtype}/{display_name}",
                "manufacturer": "Amazon Web Services",
                "properties": [
                    {"name": "cyberarmor:provider", "value": "aws"},
                    {"name": "cyberarmor:account_id", "value": account},
                    {"name": "cyberarmor:region", "value": region},
                    {"name": "cyberarmor:service", "value": service},
                    {"name": "cyberarmor:resource_type", "value": rtype},
                    {"name": "cyberarmor:resource_arn", "value": arn},
                ],
                "__path": arn,
            }
            # Surface up to 8 tags as properties so the inspector
            # panel shows the operator-relevant metadata. AWS hard-caps
            # at 50 tags per resource; 8 is plenty for the demo.
            for t in tags[:8]:
                if isinstance(t, dict) and t.get("Key"):
                    component["properties"].append({
                        "name": f"cyberarmor:tag:{t['Key']}",
                        "value": str(t.get("Value") or ""),
                    })
            components.append(component)
            if len(components) >= CLOUD_API_BUDGET:
                break
        if len(components) >= CLOUD_API_BUDGET:
            logger.warning("aws sync %s/%s hit budget %d — truncating",
                           account, region, CLOUD_API_BUDGET)
            break
        pagination_token = resp.get("PaginationToken") or ""
        if not pagination_token:
            break
        iterations += 1

    logger.info("aws sync %s region=%s → resources=%d",
                source_id, region, len(components))
    return source_id, components


# ── GCP Cloud Asset Inventory client ──────────────────────────────────


class GCPError(Exception):
    pass


# GCP asset.assetType → CycloneDX component.type. Same taxonomy as AWS
# — compute → device, storage → data, IAM → platform, models →
# machine-learning-model.
_GCP_ASSET_TYPE = {
    "compute.googleapis.com/Instance":            "device",
    "compute.googleapis.com/Network":             "device",
    "compute.googleapis.com/Subnetwork":          "device",
    "compute.googleapis.com/Disk":                "device",
    "compute.googleapis.com/Firewall":            "platform",
    "container.googleapis.com/Cluster":           "platform",
    "cloudfunctions.googleapis.com/CloudFunction": "application",
    "run.googleapis.com/Service":                 "application",
    "appengine.googleapis.com/Service":           "application",
    "storage.googleapis.com/Bucket":              "data",
    "bigquery.googleapis.com/Dataset":            "data",
    "bigquery.googleapis.com/Table":              "data",
    "sqladmin.googleapis.com/Instance":           "data",
    "spanner.googleapis.com/Instance":            "data",
    "spanner.googleapis.com/Database":            "data",
    "pubsub.googleapis.com/Topic":                "platform",
    "pubsub.googleapis.com/Subscription":         "platform",
    "iam.googleapis.com/ServiceAccount":          "platform",
    "cloudkms.googleapis.com/CryptoKey":          "cryptographic-asset",
    "secretmanager.googleapis.com/Secret":        "cryptographic-asset",
    "aiplatform.googleapis.com/Model":            "machine-learning-model",
    "aiplatform.googleapis.com/Endpoint":         "machine-learning-model",
    "artifactregistry.googleapis.com/Repository": "container",
}


def sync_gcp_project(service_account_json: str, project: str) -> Tuple[str, List[Dict[str, Any]]]:
    """Sync one GCP project. ``service_account_json`` is the literal
    contents of a SA key file (pasted by the operator). Uses Cloud Asset
    Inventory's search_all_resources for broad coverage.

    Required permission: ``cloudasset.assets.searchAllResources`` on the
    project (covered by ``roles/cloudasset.viewer``).
    """
    try:
        import json as _json
        from google.cloud import asset_v1
        from google.oauth2 import service_account
    except ImportError as exc:
        raise GCPError(f"google-cloud-asset not available: {exc}") from exc

    try:
        sa_info = _json.loads(service_account_json) if isinstance(service_account_json, str) else service_account_json
    except (ValueError, TypeError) as exc:
        raise GCPError(f"service account JSON parse failed: {exc}") from exc

    try:
        credentials = service_account.Credentials.from_service_account_info(sa_info)
    except Exception as exc:  # noqa: BLE001 — google libs raise miscellaneous types
        raise GCPError(f"GCP credentials rejected: {exc}") from exc

    client = asset_v1.AssetServiceClient(credentials=credentials)
    scope = f"projects/{project}"
    source_id = f"gcp:{project}"
    components: List[Dict[str, Any]] = []

    try:
        # search_all_resources is paginated; library hides this with an
        # iterator that yields up to read_mask-shaped objects.
        results = client.search_all_resources(
            request={"scope": scope, "page_size": 500},
        )
        for asset in results:
            asset_type = str(asset.asset_type or "")
            name = str(asset.name or "")
            display = str(asset.display_name or "") or name.split("/")[-1]
            location = str(asset.location or "")
            cyclonedx_type = _GCP_ASSET_TYPE.get(asset_type, "platform")
            short_service = asset_type.split(".")[0] if asset_type else "gcp"
            short_type = asset_type.split("/")[-1] if "/" in asset_type else asset_type
            component: Dict[str, Any] = {
                "type": cyclonedx_type,
                "name": f"{short_service}:{short_type}/{display}",
                "version": "",
                "purl": f"pkg:gcp/{short_service}/{short_type}/{display}",
                "manufacturer": "Google Cloud",
                "properties": [
                    {"name": "cyberarmor:provider", "value": "gcp"},
                    {"name": "cyberarmor:project", "value": project},
                    {"name": "cyberarmor:region", "value": location},
                    {"name": "cyberarmor:asset_type", "value": asset_type},
                    {"name": "cyberarmor:resource_name", "value": name},
                ],
                "__path": name,
            }
            labels = getattr(asset, "labels", None)
            # asset.labels is a mapping field on the proto; pull up to 8.
            if labels:
                for i, (k, v) in enumerate(labels.items()):
                    if i >= 8:
                        break
                    component["properties"].append({
                        "name": f"cyberarmor:label:{k}",
                        "value": str(v),
                    })
            components.append(component)
            if len(components) >= CLOUD_API_BUDGET:
                logger.warning("gcp sync %s hit budget %d — truncating",
                               project, CLOUD_API_BUDGET)
                break
    except Exception as exc:  # noqa: BLE001 — protobuf / grpc error spectrum
        raise GCPError(f"gcp search_all_resources failed for {project}: {exc}") from exc

    logger.info("gcp sync %s → resources=%d", project, len(components))
    return source_id, components


# ── Azure Resource Graph client ───────────────────────────────────────


class AzureCloudError(Exception):
    pass


# Azure ARM resource type (lowercased) → CycloneDX component.type.
_AZURE_TYPE = {
    "microsoft.compute/virtualmachines":         "device",
    "microsoft.compute/disks":                   "device",
    "microsoft.network/virtualnetworks":         "device",
    "microsoft.network/networkinterfaces":       "device",
    "microsoft.network/loadbalancers":           "platform",
    "microsoft.network/publicipaddresses":       "platform",
    "microsoft.containerservice/managedclusters": "platform",
    "microsoft.containerregistry/registries":    "container",
    "microsoft.web/sites":                       "application",
    "microsoft.web/serverfarms":                 "platform",
    "microsoft.storage/storageaccounts":         "data",
    "microsoft.sql/servers":                     "data",
    "microsoft.sql/servers/databases":           "data",
    "microsoft.documentdb/databaseaccounts":     "data",
    "microsoft.cache/redis":                     "data",
    "microsoft.servicebus/namespaces":           "platform",
    "microsoft.eventhub/namespaces":             "platform",
    "microsoft.keyvault/vaults":                 "cryptographic-asset",
    "microsoft.cognitiveservices/accounts":      "machine-learning-model",
    "microsoft.machinelearningservices/workspaces": "machine-learning-model",
    "microsoft.functions/sites":                 "application",
}


def sync_azure_subscription(
    tenant_id: str, client_id: str, client_secret: str, subscription_id: str,
) -> Tuple[str, List[Dict[str, Any]]]:
    """Sync one Azure subscription via Resource Graph. Uses a service
    principal — operator supplies tenant_id (their AAD tenant, NOT
    CyberArmor tenant) + client_id + client_secret.

    Required: ``Reader`` role on the subscription (or a more granular
    ``Resource Graph Reader`` if the AAD admin prefers). Resource Graph
    is read-only by design so escalation risk is minimal.
    """
    try:
        from azure.identity import ClientSecretCredential
        from azure.mgmt.resourcegraph import ResourceGraphClient
        from azure.mgmt.resourcegraph.models import QueryRequest
    except ImportError as exc:
        raise AzureCloudError(f"azure SDK not available: {exc}") from exc

    try:
        credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
        client = ResourceGraphClient(credential)
    except Exception as exc:  # noqa: BLE001
        raise AzureCloudError(f"azure credential init failed: {exc}") from exc

    source_id = f"azure:{subscription_id}"
    components: List[Dict[str, Any]] = []

    query = (
        "Resources | "
        "project id, type, name, location, kind, tags, subscriptionId, resourceGroup"
    )

    # Resource Graph paginates via ``skip`` / ``top``. 1000 per page is
    # the API ceiling.
    skip = 0
    while skip < CLOUD_API_BUDGET:
        try:
            req = QueryRequest(
                subscriptions=[subscription_id],
                query=query,
                options={"top": 1000, "skip": skip},
            )
            resp = client.resources(req)
        except Exception as exc:  # noqa: BLE001
            raise AzureCloudError(f"azure resource graph query failed: {exc}") from exc
        data = resp.data or []
        # When ResourceGraph returns ``objectArray``, data is already a list
        # of dicts. When it returns ``table`` (older clients), columns + rows
        # need stitching. Handle both shapes.
        rows: List[Dict[str, Any]] = []
        if isinstance(data, list):
            rows = data
        elif isinstance(data, dict) and "columns" in data and "rows" in data:
            cols = [c.get("name") for c in data.get("columns") or []]
            for row in data.get("rows") or []:
                rows.append(dict(zip(cols, row)))
        if not rows:
            break

        for entry in rows:
            if not isinstance(entry, dict):
                continue
            arm_type = str(entry.get("type") or "").lower()
            cyclonedx_type = _AZURE_TYPE.get(arm_type, "platform")
            name = str(entry.get("name") or "")
            short_type = arm_type.split("/")[-1] if "/" in arm_type else arm_type
            short_service = arm_type.split("/")[0].replace("microsoft.", "") if "." in arm_type else "azure"
            arm_id = str(entry.get("id") or "")
            location = str(entry.get("location") or "")
            tags = entry.get("tags") or {}
            component: Dict[str, Any] = {
                "type": cyclonedx_type,
                "name": f"{short_service}:{short_type}/{name}",
                "version": "",
                "purl": f"pkg:azure/{short_service}/{short_type}/{name}",
                "manufacturer": "Microsoft Azure",
                "properties": [
                    {"name": "cyberarmor:provider", "value": "azure"},
                    {"name": "cyberarmor:subscription_id", "value": subscription_id},
                    {"name": "cyberarmor:region", "value": location},
                    {"name": "cyberarmor:resource_type", "value": arm_type},
                    {"name": "cyberarmor:resource_id", "value": arm_id},
                    {"name": "cyberarmor:resource_group", "value": str(entry.get("resourceGroup") or "")},
                ],
                "__path": arm_id,
            }
            if isinstance(tags, dict):
                for i, (k, v) in enumerate(tags.items()):
                    if i >= 8:
                        break
                    component["properties"].append({
                        "name": f"cyberarmor:tag:{k}",
                        "value": str(v),
                    })
            components.append(component)
            if len(components) >= CLOUD_API_BUDGET:
                break

        if len(rows) < 1000 or len(components) >= CLOUD_API_BUDGET:
            break
        skip += 1000

    logger.info("azure sync %s → resources=%d", subscription_id, len(components))
    return source_id, components


# ── Dispatch ──────────────────────────────────────────────────────────


def sync_cloud_source(
    provider: str,
    creds: Dict[str, Any],
    regions: List[str],
) -> List[Tuple[str, List[Dict[str, Any]]]]:
    """Top-level dispatch.

    Credential bag per provider:
      aws    → {access_key_id, secret_access_key, session_token?}
                regions list is AWS region codes (us-east-1, …)
      gcp    → {service_account_json}
                ``regions`` is interpreted as a list of project IDs.
      azure  → {tenant_id, client_id, client_secret}
                ``regions`` is interpreted as a list of subscription IDs.
    """
    if provider not in ("aws", "gcp", "azure"):
        raise ValueError(f"unsupported cloud provider: {provider}")
    if not regions:
        raise ValueError("at least one region / project / subscription required")

    out: List[Tuple[str, List[Dict[str, Any]]]] = []
    if provider == "aws":
        access_key = str(creds.get("access_key_id") or "")
        secret_key = str(creds.get("secret_access_key") or "")
        session_token = creds.get("session_token") or None
        if not access_key or not secret_key:
            raise ValueError("aws access_key_id and secret_access_key required")
        for region in regions:
            region = region.strip()
            if not region:
                continue
            try:
                source_id, components = sync_aws_account(
                    access_key, secret_key, region, session_token=session_token,
                )
            except AWSError as exc:
                logger.warning("aws sync region=%s failed: %s", region, exc)
                continue
            out.append((source_id, components))
        return out

    if provider == "gcp":
        sa_json = str(creds.get("service_account_json") or "")
        if not sa_json:
            raise ValueError("gcp service_account_json required")
        for project in regions:
            project = project.strip()
            if not project:
                continue
            try:
                source_id, components = sync_gcp_project(sa_json, project)
            except GCPError as exc:
                logger.warning("gcp sync project=%s failed: %s", project, exc)
                continue
            out.append((source_id, components))
        return out

    # azure
    az_tenant = str(creds.get("azure_tenant_id") or "")
    az_client = str(creds.get("azure_client_id") or "")
    az_secret = str(creds.get("azure_client_secret") or "")
    if not (az_tenant and az_client and az_secret):
        raise ValueError("azure tenant_id, client_id and client_secret required")
    for subscription_id in regions:
        subscription_id = subscription_id.strip()
        if not subscription_id:
            continue
        try:
            source_id, components = sync_azure_subscription(
                az_tenant, az_client, az_secret, subscription_id,
            )
        except AzureCloudError as exc:
            logger.warning("azure sync subscription=%s failed: %s", subscription_id, exc)
            continue
        out.append((source_id, components))
    return out
