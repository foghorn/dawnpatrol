"""AWS account posture: a daily snapshot of the account's security settings,
reported as changes.

CloudTrail shows what was *done*; this shows how things *are*. Once a day
(``..._POSTURE_INTERVAL_HOURS``, default 20) it reads:

* the IAM credential report: users, console passwords, MFA, access keys with
  their age and last use, and the root user's MFA and keys;
* the account password policy and account-level S3 Block Public Access;
* every bucket's versioning, Object Lock, public-access block and whether
  its policy makes it public;
* every trail's logging state and the GuardDuty detectors;
* Route 53 records, CloudFront distributions and Elastic Beanstalk
  environments, to find DNS names and CDN origins pointing at cloud
  resources that no longer exist here (takeover risk).

It compares the snapshot with the previous one (kept in the data folder as
``aws-posture.json``) and emits one ``EventKind.OTHER`` event per result:

* ``action=critical``: a state that is dangerous every day it lasts (root
  access keys, root without MFA, a trail not logging, a detector missing),
  repeated each snapshot;
* ``action=issue``: a weakness (password without MFA, stale or old keys,
  public bucket, unversioned backup bucket, dangling DNS), reported once when
  it first appears. The first snapshot reports everything it finds once, at
  LOW, as the starting inventory;
* ``action=change``: something differs from the previous snapshot;
* ``action=resolved``: an earlier issue is gone.

``program`` is ``posture:<area>``, ``severity`` the suggested level
(INFO/LOW/MEDIUM/HIGH), ``message`` the sentence a person reads, ``raw`` the
subject and before/after values. ``analyzers/cloud_activity.py`` turns them
into signals.

Settings: ``DAWNPATROL_SOURCE_AWS_POSTURE=true`` enables it (credentials as
for the other AWS sources, see ``_aws.py``); ``..._POSTURE_REGIONS`` lists the
regions for GuardDuty and Elastic Beanstalk (default: the GuardDuty and
expected regions); ``..._POSTURE_KEY_MAX_AGE_DAYS`` (default 90) and
``..._POSTURE_STALE_DAYS`` (default 90). The read-only permissions it needs
are in docs/aws-setup.md. A dry run reads and reports but doesn't save the
snapshot, so the next real run still sees the changes.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ..context import RunContext
from ..models import CollectionResult, Event, EventKind, Probe, Window
from ..secrets import read_bool, read_env, read_int, read_list
from . import _aws
from .base import Source

log = logging.getLogger(__name__)

ENV = "DAWNPATROL_SOURCE_AWS_POSTURE"
STATE_NAME = "aws-posture.json"
#: DNS record types whose change can redirect mail, delegate the zone, or
#: change who may send as the domain.
SENSITIVE_RECORD_TYPES = {"MX", "NS", "TXT", "SOA", "CAA"}


class AwsPostureSource(Source):
    name = "aws_posture"
    kinds = frozenset({EventKind.OTHER})
    requires_env = frozenset({ENV})
    min_expected_records = 0
    activity_driven = True

    # ----- collect ---------------------------------------------------------- #

    def collect(self, window: Window, ctx: RunContext) -> CollectionResult:
        result = CollectionResult(source=self.name, window=window, requested_window=window)
        if not read_bool(ENV, False):
            result.notes.append(f"{ENV} is not true; posture snapshot skipped")
            return result
        path = _state_path(ctx)
        previous = _load(path)
        now = datetime.now(UTC)
        interval = timedelta(hours=read_int(f"{ENV}_INTERVAL_HOURS", 20))
        if previous and now - _taken(previous) < interval:
            age = (now - _taken(previous)).total_seconds() / 3600
            result.notes.append(f"posture snapshot taken {age:.1f} h ago; the next one is "
                                f"due after {interval.total_seconds() / 3600:.0f} h")
            return result
        try:
            sess = _aws.session()
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"AWS session failed: {_aws.error_text(exc)}")
            return result

        snap = self.snapshot(sess, result, self._regions())
        for item in assess(snap, previous, self._backup_buckets(),
                           key_max_age=read_int(f"{ENV}_KEY_MAX_AGE_DAYS", 90),
                           stale_days=read_int(f"{ENV}_STALE_DAYS", 90), now=now):
            result.events.append(self._event(item, snap, now))
        result.reported_total = len(result.events)
        result.notes.append("first posture snapshot: existing state reported once as the "
                            "starting inventory" if not previous else
                            f"compared with the snapshot of {previous.get('taken_at')}")
        if result.errors:
            # Keep whatever sections did read, and the old copy of the rest, so a
            # passing permission error doesn't make every item look new tomorrow.
            for key, value in (previous or {}).items():
                if snap.get(key) is None and value is not None:
                    snap[key] = value
        if ctx is not None and getattr(ctx, "dry_run", False):
            result.notes.append("dry run: snapshot not saved")
        else:
            _save(path, snap)
        return result

    def _regions(self) -> list[str]:
        regions = read_list(f"{ENV}_REGIONS")
        if regions:
            return regions
        found = read_list("DAWNPATROL_SOURCE_AWS_GUARDDUTY_REGIONS") + \
            read_list("DAWNPATROL_SOURCE_AWS_EXPECTED_REGIONS")
        for acct in getattr(self.profile, "cloud_accounts", None) or []:
            found += acct.expected_regions
        return sorted(set(found)) or [_aws.default_region()]

    def _backup_buckets(self) -> set[str]:
        return {b for acct in getattr(self.profile, "cloud_accounts", None) or []
                for b in acct.backup_buckets}

    def _event(self, item: dict[str, Any], snap: dict[str, Any], now: datetime) -> Event:
        account = snap.get("account") or ""
        subject = str(item.get("subject") or "")
        return Event(
            ts=now, source=self.name, kind=EventKind.OTHER,
            dedup_key=Event.make_dedup_key(self.name, snap.get("taken_at"), item["area"],
                                           item["action"], subject, item["message"]),
            action=item["action"], program=f"posture:{item['area']}"[:128],
            severity=item["level"], message=item["message"][:1000],
            user=(item.get("user") or None), device=f"{account}/global"[:255],
            domain=(item.get("domain") or None),
            raw={"area": item["area"], "subject": subject, "before": item.get("before"),
                 "after": item.get("after"), "account": account,
                 "first_snapshot": bool(item.get("first")), "detail": item.get("detail")},
        )

    # ----- snapshot --------------------------------------------------------- #

    def snapshot(self, sess: Any, result: CollectionResult,
                 regions: list[str]) -> dict[str, Any]:
        snap: dict[str, Any] = {"taken_at": datetime.now(UTC).isoformat()}

        def section(name: str, fn: Any) -> None:
            try:
                snap[name] = fn()
                result.pages += 1
            except Exception as exc:  # noqa: BLE001
                snap[name] = None
                result.errors.append(f"{name}: {_aws.error_text(exc)}")
                result.complete = False

        section("iam", lambda: _iam(sess.client("iam")))
        snap["account"] = ((snap.get("iam") or {}).get("account")
                           or read_env("DAWNPATROL_SOURCE_AWS_ACCOUNT_ID", "") or "")
        section("password_policy", lambda: _password_policy(sess.client("iam")))
        if snap["account"]:
            section("s3_account_bpa",
                    lambda: _account_bpa(sess.client("s3control"), snap["account"]))
        section("buckets", lambda: _buckets(sess.client("s3")))
        section("trails", lambda: _trails(sess.client("cloudtrail")))
        section("guardduty", lambda: _guardduty(sess, regions))
        section("dns", lambda: _dns(sess.client("route53")))
        section("cloudfront", lambda: _cloudfront(sess.client("cloudfront")))
        section("beanstalk", lambda: _beanstalk(sess, regions))
        snap["regions"] = regions
        return snap

    # ----- probes ----------------------------------------------------------- #

    def self_test(self, ctx: RunContext) -> list[Probe]:
        try:
            sess = _aws.session()
        except Exception as exc:  # noqa: BLE001
            return [Probe(name="posture-credentials", request="session", ok=False,
                          detail=_aws.error_text(exc))]
        checks = [
            ("posture-iam", "iam:GetAccountPasswordPolicy",
             lambda: _password_policy(sess.client("iam"))),
            ("posture-s3", "s3:ListAllMyBuckets",
             lambda: sess.client("s3").list_buckets()),
            ("posture-route53", "route53:ListHostedZones",
             lambda: sess.client("route53").list_hosted_zones()),
            ("posture-cloudfront", "cloudfront:ListDistributions",
             lambda: sess.client("cloudfront").list_distributions()),
        ]
        probes = []
        for name, request, fn in checks:
            try:
                fn()
                probes.append(Probe(name=name, request=request, ok=True, detail="allowed"))
            except Exception as exc:  # noqa: BLE001
                probes.append(Probe(name=name, request=request, ok=False,
                                    detail=_aws.error_text(exc)))
        return probes


# --------------------------------------------------------------------------- #
# Readers (each returns plain JSON-able data)
# --------------------------------------------------------------------------- #

def _code(exc: Exception) -> str:
    return str((getattr(exc, "response", None) or {}).get("Error", {}).get("Code", ""))


def _iam(iam: Any, wait_seconds: int = 60) -> dict[str, Any]:
    deadline = time.monotonic() + wait_seconds
    while iam.generate_credential_report().get("State") != "COMPLETE":
        if time.monotonic() > deadline:
            raise TimeoutError("credential report still generating")
        time.sleep(2)
    content = iam.get_credential_report()["Content"]
    if isinstance(content, bytes):
        content = content.decode("utf-8")
    return parse_credential_report(content)


def parse_credential_report(text: str) -> dict[str, Any]:
    def val(v: str | None) -> str | None:
        return None if v in (None, "", "N/A", "no_information", "not_supported") else v

    users: dict[str, Any] = {}
    root: dict[str, Any] = {}
    account = ""
    for row in csv.DictReader(io.StringIO(text)):
        keys = {}
        for n in ("1", "2"):
            if row.get(f"access_key_{n}_active") == "true" or val(
                    row.get(f"access_key_{n}_last_rotated")):
                keys[f"key{n}"] = {
                    "active": row.get(f"access_key_{n}_active") == "true",
                    "rotated": val(row.get(f"access_key_{n}_last_rotated")),
                    "last_used": val(row.get(f"access_key_{n}_last_used_date")),
                }
        entry = {
            "arn": row.get("arn"),
            "created": val(row.get("user_creation_time")),
            "password": row.get("password_enabled") == "true",
            "password_last_used": val(row.get("password_last_used")),
            "mfa": row.get("mfa_active") == "true",
            "keys": keys,
        }
        if row.get("user") == "<root_account>":
            root = entry
            account = str(row.get("arn") or "").split(":")[4] if row.get("arn") else ""
        else:
            users[row.get("user") or "?"] = entry
    return {"account": account, "root": root, "users": users}


def _password_policy(iam: Any) -> dict[str, Any]:
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except Exception as exc:
        if _code(exc) == "NoSuchEntity":
            return {}
        raise
    return {k: v for k, v in policy.items() if isinstance(v, (bool, int, str))}


def _account_bpa(s3control: Any, account: str) -> dict[str, Any]:
    try:
        return dict(s3control.get_public_access_block(AccountId=account)
                    ["PublicAccessBlockConfiguration"])
    except Exception as exc:
        if _code(exc) == "NoSuchPublicAccessBlockConfiguration":
            return {}
        raise


def _buckets(s3: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for b in s3.list_buckets().get("Buckets") or []:
        name = b["Name"]
        info: dict[str, Any] = {}
        try:
            v = s3.get_bucket_versioning(Bucket=name)
            info["versioning"] = v.get("Status") or "Off"
        except Exception as exc:  # noqa: BLE001
            info["versioning"] = f"unknown ({_code(exc) or 'error'})"
        try:
            info["bpa"] = dict(s3.get_public_access_block(Bucket=name)
                               ["PublicAccessBlockConfiguration"])
        except Exception as exc:  # noqa: BLE001
            info["bpa"] = {} if _code(exc) == "NoSuchPublicAccessBlockConfiguration" \
                else f"unknown ({_code(exc) or 'error'})"
        try:
            info["public"] = bool(s3.get_bucket_policy_status(Bucket=name)
                                  ["PolicyStatus"].get("IsPublic"))
        except Exception as exc:  # noqa: BLE001
            info["public"] = False if _code(exc) == "NoSuchBucketPolicy" else None
        try:
            cfg = s3.get_object_lock_configuration(Bucket=name)["ObjectLockConfiguration"]
            info["object_lock"] = cfg.get("ObjectLockEnabled") == "Enabled"
        except Exception:  # noqa: BLE001
            info["object_lock"] = False
        out[name] = info
    return out


def _trails(ct: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for t in ct.describe_trails(includeShadowTrails=False).get("trailList") or []:
        status = ct.get_trail_status(Name=t.get("TrailARN") or t["Name"])
        out[t["Name"]] = {"logging": bool(status.get("IsLogging")),
                          "multi_region": bool(t.get("IsMultiRegionTrail")),
                          "bucket": t.get("S3BucketName")}
    return out


def _guardduty(sess: Any, regions: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for region in regions:
        gd = sess.client("guardduty", region_name=region)
        ids = gd.list_detectors().get("DetectorIds") or []
        out[region] = {"detectors": len(ids),
                       "enabled": bool(ids) and all(
                           gd.get_detector(DetectorId=d).get("Status") == "ENABLED"
                           for d in ids)}
    return out


def _dns(r53: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for page in r53.get_paginator("list_hosted_zones").paginate():
        for zone in page.get("HostedZones") or []:
            records: dict[str, list[str]] = {}
            for rpage in r53.get_paginator("list_resource_record_sets").paginate(
                    HostedZoneId=zone["Id"]):
                for rr in rpage.get("ResourceRecordSets") or []:
                    key = f"{rr['Name'].rstrip('.').lower()} {rr['Type']}"
                    if rr.get("SetIdentifier"):
                        key += f" [{rr['SetIdentifier']}]"
                    values = [v["Value"] for v in rr.get("ResourceRecords") or []]
                    if rr.get("AliasTarget"):
                        values.append("ALIAS " + rr["AliasTarget"]["DNSName"].rstrip(".").lower())
                    records[key] = sorted(values)
            out[zone["Name"].rstrip(".").lower()] = records
    return out


def _cloudfront(cf: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for page in cf.get_paginator("list_distributions").paginate():
        for d in (page.get("DistributionList") or {}).get("Items") or []:
            out[d["Id"]] = {
                "domain": d.get("DomainName"),
                "enabled": bool(d.get("Enabled")),
                "aliases": sorted((d.get("Aliases") or {}).get("Items") or []),
                "origins": sorted(o.get("DomainName", "")
                                  for o in (d.get("Origins") or {}).get("Items") or []),
            }
    return out


def _beanstalk(sess: Any, regions: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for region in regions:
        eb = sess.client("elasticbeanstalk", region_name=region)
        for env in eb.describe_environments(IncludeDeleted=False).get("Environments") or []:
            out[f"{region}/{env['EnvironmentName']}"] = {
                "cname": (env.get("CNAME") or "").lower(), "status": env.get("Status"),
            }
    return out


# --------------------------------------------------------------------------- #
# Assessment: snapshot (+ previous) -> reportable items
# --------------------------------------------------------------------------- #

def assess(snap: dict[str, Any], prev: dict[str, Any] | None, backup_buckets: set[str],
           *, key_max_age: int = 90, stale_days: int = 90,
           now: datetime | None = None) -> list[dict[str, Any]]:
    now = now or datetime.now(UTC)
    items: list[dict[str, Any]] = []
    first = prev is None

    def add(action: str, area: str, level: str, message: str, **kw: Any) -> None:
        items.append({"action": action, "area": area, "level": level,
                      "message": message, "first": first, **kw})

    # Critical states: every snapshot.
    iam = snap.get("iam") or {}
    root = iam.get("root") or {}
    if root:
        active_root_keys = [k for k, v in (root.get("keys") or {}).items() if v.get("active")]
        if active_root_keys:
            add("critical", "root", "HIGH",
                f"The root user has {len(active_root_keys)} active access key(s)",
                subject="root")
        if not root.get("mfa"):
            add("critical", "root", "HIGH", "The root user has no MFA", subject="root")
    for name, t in (snap.get("trails") or {}).items():
        if not t.get("logging"):
            add("critical", "trail", "HIGH", f"Trail {name} is not logging", subject=name)
    for region, g in (snap.get("guardduty") or {}).items():
        if not g.get("detectors"):
            add("critical", "guardduty", "HIGH", f"GuardDuty has no detector in {region}",
                subject=region)
        elif not g.get("enabled"):
            add("critical", "guardduty", "HIGH", f"GuardDuty is disabled in {region}",
                subject=region)

    # Issues: reported when they first appear (all of them on the first snapshot).
    current = _issues(snap, backup_buckets, key_max_age, stale_days, now)
    before = {} if first else {
        iid: i for iid, i in
        _issues(prev or {}, backup_buckets, key_max_age, stale_days, now).items()
        if _section_present(prev, i["section"])}
    for issue_id, issue in current.items():
        if issue_id in before:
            continue
        if not first and not _section_present(prev, issue["section"]):
            continue      # the area wasn't readable last time: not a new issue
        add("issue", issue["area"], "LOW" if first else issue["level"], issue["message"],
            subject=issue["subject"], user=issue.get("user"), domain=issue.get("domain"),
            detail=issue.get("detail"))
    for issue_id, issue in before.items():
        if issue_id not in current and _section_present(snap, issue["section"]):
            add("resolved", issue["area"], "INFO", f"Resolved: {issue['message']}",
                subject=issue["subject"])

    if not first:
        for change in _changes(prev or {}, snap, backup_buckets):
            add("change", change.pop("area"), change.pop("level"), change.pop("message"),
                **change)
    return items


def _section_present(snap: dict[str, Any] | None, section: str) -> bool:
    return bool(snap) and snap.get(section) is not None


def _days_since(stamp: str | None, now: datetime) -> float | None:
    if not stamp:
        return None
    try:
        dt = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return (now - dt).total_seconds() / 86400


def _issues(snap: dict[str, Any], backup_buckets: set[str], key_max_age: int,
            stale_days: int, now: datetime) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}

    def issue(iid: str, section: str, area: str, level: str, message: str,
              subject: str, **kw: Any) -> None:
        out[iid] = {"id": iid, "section": section, "area": area, "level": level,
                    "message": message, "subject": subject, **kw}

    for user, u in ((snap.get("iam") or {}).get("users") or {}).items():
        arn = u.get("arn")
        if u.get("password") and not u.get("mfa"):
            issue(f"nomfa:{user}", "iam", "iam_user", "MEDIUM",
                  f"IAM user {user} has a console password and no MFA", user, user=arn)
        if u.get("password"):
            idle = _days_since(u.get("password_last_used") or u.get("created"), now)
            if idle is not None and idle >= stale_days:
                issue(f"idlepw:{user}", "iam", "iam_user", "LOW",
                      f"IAM user {user}'s console password has not been used for "
                      f"{int(idle)} days", user, user=arn)
        for slot, k in (u.get("keys") or {}).items():
            if not k.get("active"):
                continue
            age = _days_since(k.get("rotated"), now)
            if age is not None and age >= key_max_age:
                issue(f"oldkey:{user}:{slot}", "iam", "access_key", "LOW",
                      f"IAM user {user}'s access key {slot[-1]} is {int(age)} days old",
                      f"{user}#{slot}", user=arn)
            idle = _days_since(k.get("last_used") or k.get("rotated"), now)
            if idle is not None and idle >= stale_days:
                issue(f"idlekey:{user}:{slot}", "iam", "access_key", "LOW",
                      f"IAM user {user}'s access key {slot[-1]} is active but unused for "
                      f"{int(idle)} days", f"{user}#{slot}", user=arn)

    if snap.get("password_policy") == {}:
        issue("nopolicy", "password_policy", "password_policy", "LOW",
              "The account has no IAM password policy", "password_policy")
    bpa = snap.get("s3_account_bpa")
    if bpa is not None and not (isinstance(bpa, dict) and bpa and all(bpa.values())):
        issue("acctbpa", "s3_account_bpa", "s3_account", "LOW",
              "Account-level S3 Block Public Access is not fully on", "s3_account_bpa")

    buckets = snap.get("buckets") or {}
    for name, b in buckets.items():
        if b.get("public"):
            issue(f"public:{name}", "buckets", "s3_bucket", "MEDIUM",
                  f"Bucket {name} is public through its bucket policy", name)
        if name in backup_buckets and b.get("versioning") != "Enabled":
            issue(f"unversioned:{name}", "buckets", "s3_bucket", "MEDIUM",
                  f"Backup bucket {name} has versioning {b.get('versioning')}: deleted or "
                  f"overwritten backups can't be recovered", name)
    for name in sorted(backup_buckets):
        if snap.get("buckets") is not None and name not in buckets:
            issue(f"missingbackup:{name}", "buckets", "s3_bucket", "HIGH",
                  f"Backup bucket {name} does not exist", name)

    for iid, item in _dangling(snap).items():
        issue(iid, item.pop("section"), item.pop("area"), "HIGH", item.pop("message"),
              item.pop("subject"), **item)
    return out


def _dangling(snap: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """DNS names and CloudFront origins pointing at cloud resources that aren't
    in this account: someone who creates that bucket or environment serves
    content (or receives traffic) under the owner's name."""
    out: dict[str, dict[str, Any]] = {}
    buckets = snap.get("buckets")
    envs = snap.get("beanstalk")
    regions = set(snap.get("regions") or [])
    cnames = {e.get("cname") for e in (envs or {}).values()}

    def bucket_of(target: str, record: str) -> str | None:
        t = target.lower().rstrip(".")
        if not t.endswith(".amazonaws.com"):
            return None
        if t.startswith(("s3-website", "s3.", "s3-")):
            # A Route 53 alias to a website endpoint names no bucket: S3 serves
            # the bucket called exactly like the record.
            return record or None
        if ".s3" in t:
            return t.split(".s3", 1)[0] or None
        return None

    if buckets is not None:
        for dist_id, d in (snap.get("cloudfront") or {}).items():
            for origin in d.get("origins") or []:
                b = bucket_of(origin, "")
                if b and b not in buckets:
                    label = ", ".join(d.get("aliases") or []) or d.get("domain")
                    out[f"dangling-origin:{dist_id}:{b}"] = {
                        "section": "cloudfront", "area": "dangling", "subject": dist_id,
                        "domain": (d.get("aliases") or [None])[0],
                        "message": f"CloudFront {dist_id} ({label}) serves from bucket {b}, "
                                   f"which doesn't exist in this account (takeover risk)"}
    for records in (snap.get("dns") or {}).values():
        for key, values in records.items():
            name, rtype = key.split(" ", 2)[:2]
            if rtype not in ("CNAME", "A", "AAAA"):
                continue
            for v in values:
                target = v.removeprefix("ALIAS ").lower().rstrip(".")
                b = bucket_of(target, name)
                if b and buckets is not None and b not in buckets:
                    out[f"dangling-dns:{key}"] = {
                        "section": "dns", "area": "dangling", "subject": key, "domain": name,
                        "message": f"{name} points at S3 bucket {b}, which doesn't exist in "
                                   f"this account (takeover risk)"}
                if target.endswith(".elasticbeanstalk.com") and envs is not None:
                    parts = target.split(".")
                    region = parts[-3] if len(parts) >= 4 else ""
                    if region in regions and target not in cnames:
                        out[f"dangling-dns:{key}"] = {
                            "section": "dns", "area": "dangling", "subject": key,
                            "domain": name,
                            "message": f"{name} points at Elastic Beanstalk name {target}, "
                                       f"which no environment here owns (takeover risk)"}
    return out


def _changes(old: dict[str, Any], new: dict[str, Any],
             backup_buckets: set[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    def ch(area: str, level: str, message: str, subject: str, before: Any = None,
           after: Any = None, **kw: Any) -> None:
        out.append({"area": area, "level": level, "message": message, "subject": subject,
                    "before": before, "after": after, **kw})

    if old.get("iam") is not None and new.get("iam") is not None:
        ou, nu = old["iam"].get("users") or {}, new["iam"].get("users") or {}
        for user in sorted(set(nu) - set(ou)):
            ch("iam_user", "MEDIUM", f"New IAM user {user}", user, user=nu[user].get("arn"))
        for user in sorted(set(ou) - set(nu)):
            ch("iam_user", "LOW", f"IAM user {user} was deleted", user)
        for user in sorted(set(ou) & set(nu)):
            a, b = ou[user], nu[user]
            arn = b.get("arn")
            if a.get("mfa") and not b.get("mfa"):
                ch("iam_user", "MEDIUM", f"MFA was removed from IAM user {user}", user,
                   True, False, user=arn)
            if not a.get("password") and b.get("password"):
                ch("iam_user", "MEDIUM", f"IAM user {user} was given a console password",
                   user, False, True, user=arn)
            ka, kb = a.get("keys") or {}, b.get("keys") or {}
            for slot in sorted(set(ka) | set(kb)):
                x, y = ka.get(slot) or {}, kb.get(slot) or {}
                n = slot[-1]
                if y.get("rotated") and y.get("rotated") != x.get("rotated"):
                    ch("access_key", "MEDIUM", f"IAM user {user} has a new access key "
                       f"(slot {n}, created {y['rotated'][:10]})", f"{user}#{slot}",
                       x.get("rotated"), y.get("rotated"), user=arn)
                elif x.get("active") is False and y.get("active"):
                    ch("access_key", "MEDIUM", f"IAM user {user}'s access key {n} was "
                       f"reactivated", f"{user}#{slot}", False, True, user=arn)
                elif x.get("active") and y and not y.get("active"):
                    ch("access_key", "INFO", f"IAM user {user}'s access key {n} was "
                       f"deactivated", f"{user}#{slot}", True, False, user=arn)
                elif x and not y:
                    ch("access_key", "LOW", f"IAM user {user}'s access key {n} was deleted",
                       f"{user}#{slot}", user=arn)
        ra, rb = old["iam"].get("root") or {}, new["iam"].get("root") or {}
        if (ra.get("password_last_used") != rb.get("password_last_used")
                and rb.get("password_last_used")):
            ch("root", "MEDIUM", f"The root user signed in "
               f"(last sign-in {rb['password_last_used'][:16]})", "root",
               ra.get("password_last_used"), rb.get("password_last_used"))

    if old.get("password_policy") is not None and new.get("password_policy") is not None \
            and old["password_policy"] != new["password_policy"]:
        weaker = not new["password_policy"] or (
            new["password_policy"].get("MinimumPasswordLength", 0)
            < old["password_policy"].get("MinimumPasswordLength", 0))
        ch("password_policy", "MEDIUM" if weaker else "LOW",
           "The IAM password policy was " + ("removed or weakened" if weaker else "changed"),
           "password_policy", old["password_policy"], new["password_policy"])

    oa, na = old.get("s3_account_bpa"), new.get("s3_account_bpa")
    if isinstance(oa, dict) and isinstance(na, dict) and oa != na:
        loosened = sorted(k for k, v in oa.items() if v and not na.get(k))
        ch("s3_account", "MEDIUM" if loosened else "LOW",
           "Account-level S3 Block Public Access was "
           + (f"loosened ({', '.join(loosened)} off)" if loosened else "changed"),
           "s3_account_bpa", oa, na)

    ob, nb = old.get("buckets"), new.get("buckets")
    if ob is not None and nb is not None:
        for name in sorted(set(nb) - set(ob)):
            ch("s3_bucket", "LOW", f"New bucket {name}", name)
        for name in sorted(set(ob) - set(nb)):
            ch("s3_bucket", "HIGH" if name in backup_buckets else "MEDIUM",
               f"Bucket {name} was deleted", name)
        for name in sorted(set(ob) & set(nb)):
            x, y = ob[name], nb[name]
            backup = name in backup_buckets
            if x.get("versioning") != y.get("versioning"):
                off = x.get("versioning") == "Enabled"
                ch("s3_bucket", ("HIGH" if backup else "MEDIUM") if off else "LOW",
                   f"Bucket {name} versioning changed from {x.get('versioning')} to "
                   f"{y.get('versioning')}", name, x.get("versioning"), y.get("versioning"))
            if x.get("object_lock") and not y.get("object_lock"):
                ch("s3_bucket", "HIGH" if backup else "MEDIUM",
                   f"Bucket {name} no longer has Object Lock", name, True, False)
            if not x.get("public") and y.get("public"):
                ch("s3_bucket", "HIGH", f"Bucket {name} became public", name, False, True)
            if isinstance(x.get("bpa"), dict) and isinstance(y.get("bpa"), dict) \
                    and x["bpa"] != y["bpa"]:
                loosened = sorted(k for k, v in x["bpa"].items() if v and not y["bpa"].get(k))
                ch("s3_bucket", "MEDIUM" if loosened else "LOW",
                   f"Bucket {name}'s public-access block was "
                   + (f"loosened ({', '.join(loosened)} off)" if loosened else "changed"),
                   name, x["bpa"], y["bpa"])

    ot, nt = old.get("trails"), new.get("trails")
    if ot is not None and nt is not None:
        for name in sorted(set(nt) - set(ot)):
            ch("trail", "LOW", f"New trail {name}", name)
        for name in sorted(set(ot) - set(nt)):
            ch("trail", "HIGH", f"Trail {name} was deleted", name)

    og, ng = old.get("guardduty"), new.get("guardduty")
    if og is not None and ng is not None:
        for region in sorted(set(ng) & set(og)):
            if not og[region].get("detectors") and ng[region].get("detectors"):
                ch("guardduty", "LOW", f"GuardDuty detector created in {region}", region)

    od, nd = old.get("dns"), new.get("dns")
    if od is not None and nd is not None:
        for zone in sorted(set(nd) - set(od)):
            ch("dns", "MEDIUM", f"New hosted zone {zone}", zone, domain=zone)
        for zone in sorted(set(od) - set(nd)):
            ch("dns", "MEDIUM", f"Hosted zone {zone} was deleted", zone, domain=zone)
        for zone in sorted(set(od) & set(nd)):
            x, y = od[zone], nd[zone]
            for key in sorted(set(x) | set(y)):
                if x.get(key) == y.get(key):
                    continue
                name, rtype = key.split(" ", 2)[:2]
                sensitive = rtype in SENSITIVE_RECORD_TYPES or name == zone
                verb = "added" if key not in x else "deleted" if key not in y else "changed"
                ch("dns", "MEDIUM" if sensitive else "LOW", f"DNS record {key} {verb}",
                   key, x.get(key), y.get(key), domain=name)

    oc, nc = old.get("cloudfront"), new.get("cloudfront")
    if oc is not None and nc is not None:
        for dist in sorted(set(nc) - set(oc)):
            ch("cloudfront", "MEDIUM", f"New CloudFront distribution {dist} "
               f"({', '.join(nc[dist].get('aliases') or []) or nc[dist].get('domain')})",
               dist, None, nc[dist])
        for dist in sorted(set(oc) - set(nc)):
            ch("cloudfront", "LOW", f"CloudFront distribution {dist} was deleted", dist,
               oc[dist], None)
        for dist in sorted(set(oc) & set(nc)):
            x, y = oc[dist], nc[dist]
            for field_name in ("origins", "aliases"):
                if x.get(field_name) != y.get(field_name):
                    ch("cloudfront", "MEDIUM", f"CloudFront {dist} {field_name} changed",
                       dist, x.get(field_name), y.get(field_name))
            if x.get("enabled") != y.get("enabled"):
                ch("cloudfront", "LOW", f"CloudFront {dist} was "
                   f"{'enabled' if y.get('enabled') else 'disabled'}", dist)

    oe, ne = old.get("beanstalk"), new.get("beanstalk")
    if oe is not None and ne is not None:
        for env in sorted(set(ne) - set(oe)):
            ch("beanstalk", "MEDIUM", f"New Elastic Beanstalk environment {env}", env)
        for env in sorted(set(oe) - set(ne)):
            ch("beanstalk", "LOW", f"Elastic Beanstalk environment {env} is gone", env)
    return out


# --------------------------------------------------------------------------- #
# State file
# --------------------------------------------------------------------------- #

def _state_path(ctx: RunContext | None) -> Path:
    settings = getattr(ctx, "settings", None)
    base = getattr(settings, "data_dir", None) or read_env("DAWNPATROL_DATA_DIR", "./data")
    return Path(base or "./data") / STATE_NAME


def _load(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) and data.get("taken_at") else None
    except (OSError, ValueError):
        return None


def _save(path: Path, snap: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(snap, default=str), encoding="utf-8")
        tmp.replace(path)
    except OSError as exc:
        log.warning("aws_posture: could not save %s: %s", path, exc)


def _taken(snap: dict[str, Any]) -> datetime:
    try:
        return datetime.fromisoformat(snap["taken_at"])
    except (KeyError, ValueError, TypeError):
        return datetime.min.replace(tzinfo=UTC)
