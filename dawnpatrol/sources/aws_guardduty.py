"""AWS GuardDuty findings, from the GuardDuty API.

GuardDuty is AWS's own detector over CloudTrail, VPC flow logs and DNS logs,
so its findings are already conclusions; this source collects every
non-archived finding *updated* inside the run window (a finding that keeps
recurring is updated, not re-created, so its new activity still shows up).

Settings (see docs/aws-setup.md for enabling GuardDuty and credentials):

* ``DAWNPATROL_SOURCE_AWS_GUARDDUTY_REGIONS`` (required; enables the source):
  comma-separated regions with a detector. A listed region with no detector
  is reported as a collection error - GuardDuty is regional, and a region
  without it is a blind spot, not a quiet day.
* credentials: see ``_aws.py``

Each finding becomes one ``EventKind.IDS`` event with ``action=gd_finding``,
``program`` = the finding type (``Recon:EC2/PortProbeUnprotectedPort``),
``severity`` = LOW/MEDIUM/HIGH/CRITICAL from GuardDuty's numeric score,
``src_ip`` = the remote address involved, ``dst_ip``/``dst_port`` = the local
resource's private address and port, ``user`` = the IAM user/principal for
credential findings, ``device`` = ``<account>/<region>``, ``domain`` = the
domain for DNS findings. Sample findings (from ``create-sample-findings``)
are kept, marked ``raw.sample``, so the pipeline can be tested end to end.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from ..context import RunContext
from ..models import CollectionResult, Event, EventKind, Probe, Window
from . import _aws
from .base import Source

log = logging.getLogger(__name__)

ENV = "DAWNPATROL_SOURCE_AWS_GUARDDUTY_"
_BATCH = 50   # get_findings accepts at most 50 ids


def severity_label(score: float) -> str:
    """GuardDuty's published bands: 1-3.9 low, 4-6.9 medium, 7-8.9 high, 9+ critical."""
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


class AwsGuardDutySource(Source):
    name = "aws_guardduty"
    kinds = frozenset({EventKind.IDS})
    requires_env = frozenset({f"{ENV}REGIONS"})
    min_expected_records = 0

    def collect(self, window: Window, ctx: RunContext) -> CollectionResult:
        result = CollectionResult(source=self.name, window=window, requested_window=window)
        criteria = {"Criterion": {
            "updatedAt": {"GreaterThanOrEqual": int(window.start.timestamp() * 1000),
                          "LessThan": int(window.end.timestamp() * 1000)},
            "service.archived": {"Equals": ["false"]},
        }}
        for region in _aws.regions(f"{ENV}REGIONS"):
            try:
                gd = _aws.session(region).client("guardduty")
                detectors = gd.list_detectors().get("DetectorIds") or []
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"{region}: {_aws.error_text(exc)}")
                result.complete = False
                continue
            if not detectors:
                result.errors.append(f"{region}: GuardDuty has no detector in this region")
                result.complete = False
                continue
            for detector in detectors:
                try:
                    ids: list[str] = []
                    for page in gd.get_paginator("list_findings").paginate(
                            DetectorId=detector, FindingCriteria=criteria):
                        ids += page.get("FindingIds") or []
                        result.pages += 1
                    for i in range(0, len(ids), _BATCH):
                        found = gd.get_findings(DetectorId=detector,
                                                FindingIds=ids[i:i + _BATCH])
                        for finding in found.get("Findings") or []:
                            event = self.normalize(finding)
                            if event is not None:
                                result.events.append(event)
                except Exception as exc:  # noqa: BLE001
                    result.errors.append(f"{region} detector {detector}: "
                                         f"{_aws.error_text(exc)}")
                    result.complete = False
        result.reported_total = len(result.events)
        return result

    def normalize(self, f: dict[str, Any]) -> Event | None:
        try:
            ts = _ts(f.get("UpdatedAt") or f["CreatedAt"])
        except (KeyError, ValueError):
            return None
        svc = f.get("Service") or {}
        action = svc.get("Action") or {}
        resource = f.get("Resource") or {}
        score = float(f.get("Severity") or 0)
        sample = bool((svc.get("AdditionalInfo") or {}).get("Sample")) or \
            str(f.get("Title", "")).startswith("[SAMPLE]")

        remote = None
        local_port = None
        domain = None
        for key in ("NetworkConnectionAction", "AwsApiCallAction", "DnsRequestAction",
                    "KubernetesApiCallAction", "RdsLoginAttemptAction"):
            part = action.get(key) or {}
            remote = remote or ((part.get("RemoteIpDetails") or {}).get("IpAddressV4"))
            local_port = local_port or (part.get("LocalPortDetails") or {}).get("Port")
            domain = domain or part.get("Domain")
        probes = (action.get("PortProbeAction") or {}).get("PortProbeDetails") or []
        if probes:
            remote = remote or (probes[0].get("RemoteIpDetails") or {}).get("IpAddressV4")
            local_port = local_port or (probes[0].get("LocalPortDetails") or {}).get("Port")
        instance = resource.get("InstanceDetails") or {}
        nics = instance.get("NetworkInterfaces") or []
        local_ip = nics[0].get("PrivateIpAddress") if nics else None
        key = resource.get("AccessKeyDetails") or {}
        account = f.get("AccountId") or ""
        region = f.get("Region") or ""
        ftype = f.get("Type") or "unknown"
        return Event(
            ts=ts, source=self.name, kind=EventKind.IDS,
            dedup_key=Event.make_dedup_key(self.name, f.get("Id"), f.get("UpdatedAt")),
            action="gd_finding", program=ftype[:128], severity=severity_label(score),
            message=(f.get("Title") or ftype)[:1000],
            user=(key.get("UserName") or key.get("PrincipalId") or None),
            device=f"{account}/{region}"[:255],
            domain=domain, dst_port=local_port,
            raw={
                "finding_id": f.get("Id"), "type": ftype, "score": score,
                "sample": sample, "count": svc.get("Count"),
                "resource_type": resource.get("ResourceType"),
                "instance_id": instance.get("InstanceId"),
                "access_key_id": key.get("AccessKeyId"),
                "description": (f.get("Description") or "")[:600],
                "first_seen": svc.get("EventFirstSeen"), "last_seen": svc.get("EventLastSeen"),
                "account": account, "region": region,
            },
            **self.assign_zones(src_ip=remote, dst_ip=local_ip),
        )

    def self_test(self, ctx: RunContext) -> list[Probe]:
        probes: list[Probe] = []
        for region in _aws.regions(f"{ENV}REGIONS"):
            try:
                gd = _aws.session(region).client("guardduty")
                detectors = gd.list_detectors().get("DetectorIds") or []
                states = [gd.get_detector(DetectorId=d).get("Status") for d in detectors]
                probes.append(Probe(
                    name=f"detector-{region}", request="guardduty:ListDetectors",
                    ok=bool(detectors) and all(s == "ENABLED" for s in states),
                    records=len(detectors),
                    detail=f"detectors {detectors} status {states}" if detectors
                    else "no detector in this region"))
            except Exception as exc:  # noqa: BLE001
                probes.append(Probe(name=f"detector-{region}", request="guardduty:ListDetectors",
                                    ok=False, detail=_aws.error_text(exc)))
        return probes


def _ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
