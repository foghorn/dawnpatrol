"""AWS CloudTrail, read from the S3 bucket a trail delivers to.

Reading the bucket rather than the ``LookupEvents`` API is deliberate: it is
complete (LookupEvents covers management events only and is throttled to two
requests a second), it works for organization trails spanning many accounts,
and it costs only S3 list/get requests.

Layout read (single-account and organization trails):

    s3://<bucket>/<prefix>/AWSLogs/[<org-id>/]<account>/CloudTrail/<region>/YYYY/MM/DD/*.json.gz

Settings (see docs/aws-setup.md for creating the trail and credentials):

* ``DAWNPATROL_SOURCE_AWS_CLOUDTRAIL_BUCKET`` (required; enables the source)
* ``..._CLOUDTRAIL_PREFIX``: the trail's S3 key prefix, if it has one
* ``..._CLOUDTRAIL_ACCOUNTS`` / ``..._CLOUDTRAIL_REGIONS``: restrict to these
  account IDs / regions; default is everything found in the bucket
* ``..._CLOUDTRAIL_MAX_EVENTS``: safety cap per run (default 200000); hitting it
  marks the collection incomplete rather than silently truncating
* ``..._CLOUDTRAIL_TRAIL``: trail name or ARN; when set, each run also checks
  the trail is still logging, so a stopped trail is a health failure
* credentials: see ``_aws.py``

Mapping to the common Event model (``analyzers/cloud_activity.py`` reads it):

* ``program``  ``<service>:<eventName>``, e.g. ``iam:CreateAccessKey``
* ``action``   ``ok`` / ``denied`` / ``error``; console sign-ins are
  ``EventKind.AUTH`` with ``aws_login_ok`` / ``aws_login_fail``
* ``user``     the principal ARN (the role ARN for assumed-role sessions)
* ``device``   ``<account>/<region>``
* ``src_ip``   the caller's address when it is an IP (AWS services call from
  names like ``s3.amazonaws.com``, kept in ``raw.source``)
* ``severity`` ``read`` or ``write``; ``block_reason`` the error code
* ``raw``      region, user agent, MFA, error message, and the resources the
  call named (``targets``: secret IDs, bucket names, users, roles...)

Calls AWS services make on their own behalf (userIdentity type
``AWSService``) are dropped and counted: they are the bulk of a quiet
account's trail and say nothing about who is acting in it.
"""

from __future__ import annotations

import gzip
import ipaddress
import json
import logging
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from ..context import RunContext
from ..models import CollectionResult, Event, EventKind, Probe, Window
from ..secrets import read_env, read_int, read_list
from . import _aws
from .base import Source

log = logging.getLogger(__name__)

ENV = "DAWNPATROL_SOURCE_AWS_CLOUDTRAIL_"
#: Request parameters that name the resource a call touched.
_TARGET_KEYS = ("secretId", "name", "names", "bucketName", "userName", "roleName",
                "groupName", "policyArn", "trailName", "detectorId", "functionName",
                "instanceId", "instancesSet", "keyId", "path", "stackName", "stackSetName",
                "hostedZoneId", "id", "environmentName", "instanceName", "providerName",
                "url")
_FILE_TS = re.compile(r"_(\d{8}T\d{4})Z_")
#: A delivery file can hold events up to ~15 min older than its name.
_SLACK = timedelta(hours=1)
_LOGIN_EVENTS = {"ConsoleLogin"}


class AwsCloudTrailSource(Source):
    name = "aws_cloudtrail"
    kinds = frozenset({EventKind.AUTH, EventKind.OTHER})
    requires_env = frozenset({f"{ENV}BUCKET"})
    min_expected_records = 0

    def collect(self, window: Window, ctx: RunContext) -> CollectionResult:
        result = CollectionResult(source=self.name, window=window, requested_window=window)
        bucket = read_env(f"{ENV}BUCKET", "")
        prefix = _prefix(read_env(f"{ENV}PREFIX", ""))
        cap = read_int(f"{ENV}MAX_EVENTS", 200_000)
        try:
            sess = _aws.session()
            s3 = sess.client("s3")
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"AWS session failed: {_aws.error_text(exc)}")
            return result

        self._check_trail(sess, result)

        try:
            roots = self._region_roots(s3, bucket, prefix)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"listing s3://{bucket}/{prefix}AWSLogs/ failed: "
                                 f"{_aws.error_text(exc)}")
            return result
        if not roots:
            result.errors.append(f"no CloudTrail logs under s3://{bucket}/{prefix}AWSLogs/ "
                                 f"(wrong bucket/prefix, or the trail has never delivered)")
            return result

        days = _days(window.start - _SLACK, window.end + _SLACK)
        service_calls = 0
        seen: set[str] = set()
        for root in roots:
            for day in days:
                try:
                    keys = _list_keys(s3, bucket, f"{root}{day}/")
                except Exception as exc:  # noqa: BLE001
                    result.errors.append(f"listing {root}{day}/ failed: {_aws.error_text(exc)}")
                    result.complete = False
                    continue
                for key in keys:
                    stamp = _file_time(key)
                    if stamp and not (window.start - _SLACK <= stamp <= window.end + _SLACK):
                        continue
                    try:
                        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
                        records = json.loads(gzip.decompress(body)).get("Records") or []
                    except Exception as exc:  # noqa: BLE001
                        result.errors.append(f"reading {key} failed: {_aws.error_text(exc)}")
                        result.complete = False
                        continue
                    result.pages += 1
                    for rec in records:
                        event = self.normalize(rec)
                        if event is None:
                            service_calls += 1
                            continue
                        if not (window.start <= event.ts < window.end):
                            continue
                        if event.dedup_key in seen:
                            continue
                        seen.add(event.dedup_key)
                        result.events.append(event)
                        if len(result.events) >= cap:
                            result.complete = False
                            result.errors.append(
                                f"stopped at the {cap}-event cap ({ENV}MAX_EVENTS); "
                                f"the rest of the window was not read")
                            return self._finish(result, service_calls, roots)
        return self._finish(result, service_calls, roots)

    def _finish(self, result: CollectionResult, service_calls: int,
                roots: list[str]) -> CollectionResult:
        result.reported_total = len(result.events)
        result.notes.append(f"read {len(roots)} account/region log folder(s), "
                            f"{result.pages} delivery file(s)")
        if service_calls:
            result.notes.append(f"{service_calls} call(s) made by AWS services on their own "
                                f"behalf (userIdentity AWSService) were not kept")
        return result

    # ----- normalization ---------------------------------------------------- #

    def normalize(self, rec: dict[str, Any]) -> Event | None:
        uid = rec.get("userIdentity") or {}
        utype = uid.get("type") or ""
        if utype == "AWSService":
            return None
        try:
            ts = datetime.fromisoformat(str(rec["eventTime"]).replace("Z", "+00:00"))
        except (KeyError, ValueError):
            return None
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)

        service = (rec.get("eventSource") or "").split(".", 1)[0] or "unknown"
        name = rec.get("eventName") or "unknown"
        account = rec.get("recipientAccountId") or uid.get("accountId") or ""
        region = rec.get("awsRegion") or ""
        source_addr = rec.get("sourceIPAddress") or ""
        src_ip = source_addr if _is_ip(source_addr) else None
        error = rec.get("errorCode") or ""
        issuer = ((uid.get("sessionContext") or {}).get("sessionIssuer") or {})
        principal = (issuer.get("arn") if utype == "AssumedRole" and issuer.get("arn")
                     else uid.get("arn")) or f"{utype}:{uid.get('principalId', '')}"
        if utype == "Root":
            principal = f"arn:aws:iam::{account}:root"

        kind = EventKind.OTHER
        if name in _LOGIN_EVENTS:
            kind = EventKind.AUTH
            outcome = ((rec.get("responseElements") or {}).get("ConsoleLogin") or "")
            action = "aws_login_ok" if outcome == "Success" and not error else "aws_login_fail"
        elif not error:
            action = "ok"
        elif re.search(r"AccessDenied|Unauthorized|Forbidden|NotAuthorized", error, re.I):
            action = "denied"
        else:
            action = "error"

        extra = rec.get("additionalEventData") or {}
        attrs = ((uid.get("sessionContext") or {}).get("attributes") or {})
        mfa = extra.get("MFAUsed") or attrs.get("mfaAuthenticated")
        read_only = rec.get("readOnly")
        targets = _targets(rec.get("requestParameters"))
        user_agent = (rec.get("userAgent") or "")[:300]
        program = f"{service}:{name}"[:128]
        short = principal.rsplit("/", 1)[-1] if "/" in principal else principal
        message = f"{program} by {short} from {source_addr or 'unknown'}"
        if error:
            message += f" ({error})"
        return Event(
            ts=ts, source=self.name, kind=kind,
            dedup_key=Event.make_dedup_key(self.name, rec.get("eventID") or
                                           f"{ts.isoformat()}|{program}|{principal}"),
            action=action, program=program, user=principal[:255],
            device=f"{account}/{region}"[:255],
            severity=None if read_only is None else ("read" if read_only else "write"),
            block_reason=error[:64] or None,
            message=message[:1000],
            raw={
                "region": region, "account": account, "source": source_addr,
                "caller_account": uid.get("accountId"),
                "event_source": rec.get("eventSource"), "event_name": name,
                "principal_type": utype, "principal_arn": uid.get("arn"),
                "access_key_id": uid.get("accessKeyId"), "user_agent": user_agent,
                "error_code": error or None,
                "error_message": (rec.get("errorMessage") or "")[:300] or None,
                "read_only": read_only, "mfa": mfa, "targets": targets,
                "from_console": bool(rec.get("sessionCredentialFromConsole")),
                "event_type": rec.get("eventType"),
                # Capped copy of the request, so a watched name is found wherever
                # in the call it appears (a DNS change batch, a role path...).
                "request": _request_text(rec.get("requestParameters")),
            },
            **self.assign_zones(src_ip=src_ip),
        )

    # ----- S3 layout -------------------------------------------------------- #

    def _region_roots(self, s3: Any, bucket: str, prefix: str) -> list[str]:
        """``.../<account>/CloudTrail/<region>/`` folders to read."""
        want_accounts = set(read_list(f"{ENV}ACCOUNTS"))
        want_regions = set(read_list(f"{ENV}REGIONS"))
        account_dirs: list[str] = []
        for top in _list_dirs(s3, bucket, f"{prefix}AWSLogs/"):
            label = top.rstrip("/").rsplit("/", 1)[-1]
            if label.startswith("o-"):                       # organization trail
                account_dirs += _list_dirs(s3, bucket, top)
            else:
                account_dirs.append(top)
        roots = []
        for acct in account_dirs:
            account = acct.rstrip("/").rsplit("/", 1)[-1]
            if want_accounts and account not in want_accounts:
                continue
            for reg in _list_dirs(s3, bucket, f"{acct}CloudTrail/"):
                region = reg.rstrip("/").rsplit("/", 1)[-1]
                if want_regions and region not in want_regions:
                    continue
                roots.append(reg)
        return roots

    def _check_trail(self, sess: Any, result: CollectionResult) -> None:
        trail = read_env(f"{ENV}TRAIL", "")
        if not trail:
            return
        try:
            status = sess.client("cloudtrail").get_trail_status(Name=trail)
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"trail status check failed: {_aws.error_text(exc)}")
            return
        if not status.get("IsLogging"):
            result.errors.append(f"trail {trail} is NOT logging (stopped at "
                                 f"{status.get('StopLoggingTime', 'unknown time')})")
        if status.get("LatestDeliveryError"):
            result.errors.append(f"trail {trail} delivery error: "
                                 f"{status['LatestDeliveryError']}")

    # ----- probes ----------------------------------------------------------- #

    def self_test(self, ctx: RunContext) -> list[Probe]:
        bucket = read_env(f"{ENV}BUCKET", "")
        prefix = _prefix(read_env(f"{ENV}PREFIX", ""))
        try:
            sess = _aws.session()
            ident = sess.client("sts").get_caller_identity()
        except Exception as exc:  # noqa: BLE001
            return [Probe(name="credentials", request="sts:GetCallerIdentity", ok=False,
                          detail=_aws.error_text(exc))]
        probes = [Probe(name="credentials", request="sts:GetCallerIdentity", ok=True,
                        detail=f"acting as {ident.get('Arn')}")]
        try:
            roots = self._region_roots(sess.client("s3"), bucket, prefix)
            probes.append(Probe(name="bucket", request=f"s3:ListBucket {bucket}", ok=bool(roots),
                                records=len(roots),
                                detail=f"{len(roots)} account/region log folder(s)"))
        except Exception as exc:  # noqa: BLE001
            probes.append(Probe(name="bucket", request=f"s3:ListBucket {bucket}", ok=False,
                                detail=_aws.error_text(exc)))
        if read_env(f"{ENV}TRAIL", ""):
            result = CollectionResult(source=self.name)
            self._check_trail(sess, result)
            probes.append(Probe(name="trail-logging", request="cloudtrail:GetTrailStatus",
                                ok=not result.errors,
                                detail="; ".join(result.errors + result.notes) or "logging"))
        return probes


# ----- helpers ------------------------------------------------------------- #

def _prefix(raw: str) -> str:
    raw = raw.strip("/")
    return f"{raw}/" if raw else ""


def _days(start: datetime, end: datetime) -> list[str]:
    day, out = start.date(), []
    while day <= end.date():
        out.append(day.strftime("%Y/%m/%d"))
        day += timedelta(days=1)
    return out


def _list_dirs(s3: Any, bucket: str, prefix: str) -> list[str]:
    out: list[str] = []
    for page in s3.get_paginator("list_objects_v2").paginate(
            Bucket=bucket, Prefix=prefix, Delimiter="/"):
        out += [p["Prefix"] for p in page.get("CommonPrefixes") or []]
    return out


def _list_keys(s3: Any, bucket: str, prefix: str) -> list[str]:
    out: list[str] = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        out += [o["Key"] for o in page.get("Contents") or [] if o["Key"].endswith(".json.gz")]
    return out


def _file_time(key: str) -> datetime | None:
    m = _FILE_TS.search(key.rsplit("/", 1)[-1])
    if not m:
        return None
    return datetime.strptime(m.group(1), "%Y%m%dT%H%M").replace(tzinfo=UTC)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _request_text(params: Any) -> str | None:
    if not params:
        return None
    text = json.dumps(params, separators=(",", ":"), default=str)
    return text if len(text) <= 2000 else text[:1997] + "..."


def _targets(params: Any) -> list[str]:
    """Resource names a call's request parameters point at (capped)."""
    if not isinstance(params, dict):
        return []
    out: list[str] = []
    for key in _TARGET_KEYS:
        value = params.get(key)
        if isinstance(value, str):
            out.append(value)
        elif isinstance(value, list):
            out += [v for v in value if isinstance(v, str)]
        elif isinstance(value, dict) and key == "instancesSet":
            out += [i.get("instanceId") for i in value.get("items") or []
                    if isinstance(i, dict) and i.get("instanceId")]
    return [t[:200] for t in out[:20]]
