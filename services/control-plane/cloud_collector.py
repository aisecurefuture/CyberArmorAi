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


def sync_cloud_source(
    provider: str,
    creds: Dict[str, Any],
    regions: List[str],
) -> List[Tuple[str, List[Dict[str, Any]]]]:
    """Top-level dispatch. ``provider`` selects the cloud; ``creds``
    carries the auth bag (access_key / secret_key / session_token for
    AWS); ``regions`` is the list to fan out over."""
    if provider != "aws":
        raise ValueError(f"unsupported cloud provider: {provider}")
    access_key = str(creds.get("access_key_id") or "")
    secret_key = str(creds.get("secret_access_key") or "")
    session_token = creds.get("session_token") or None
    if not access_key or not secret_key:
        raise ValueError("aws access_key_id and secret_access_key required")
    if not regions:
        raise ValueError("at least one region required")

    out: List[Tuple[str, List[Dict[str, Any]]]] = []
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
