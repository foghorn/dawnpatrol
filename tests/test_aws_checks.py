"""The second set of AWS checks: stolen-key reconnaissance, key networks,
abuse-prone services, backup protection (S3 data events), and the posture
snapshot source."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from dawnpatrol.analyzers.baseline import Baseline
from dawnpatrol.analyzers.cloud_activity import CloudActivityAnalyzer, _closest
from dawnpatrol.models import EntityType, EventKind, Severity
from dawnpatrol.profile import Profile
from dawnpatrol.query import EventQuery
from dawnpatrol.sources import aws_posture as posture
from dawnpatrol.sources.aws_cloudtrail import AwsCloudTrailSource
from dawnpatrol.sources.aws_posture import AwsPostureSource, assess, parse_credential_report
from dawnpatrol.store import entity_pairs_from_events

from .test_aws import ACCT, _analyze, _by_tax, ct

BACKUP = f"arn:aws:iam::{ACCT}:user/backup"
ALICE = f"arn:aws:iam::{ACCT}:user/alice"

PROFILE = f"""
site: {{name: t}}
cloud_accounts:
  - account_id: "{ACCT}"
    expected_regions: [us-east-1]
    backup_buckets: [backups]
    services_in_use: [ses]
    principals:
      - match: user/backup
        allowed_services: [s3]
        allowed_buckets: [backups]
"""


@pytest.fixture
def acct_profile(tmp_path):
    path = tmp_path / "p.yml"
    path.write_text(PROFILE, encoding="utf-8")
    return Profile.load(path)


def keyed(rec, key="AKIAEXAMPLEKEY000001"):
    rec["userIdentity"]["accessKeyId"] = key
    return rec


def s3(name, minutes=0, arn=BACKUP, **kw):
    return ct(name, source="s3.amazonaws.com", arn=arn, minutes=minutes, **kw)


# --------------------------------------------------------------------------- #
# 1. reconnaissance
# --------------------------------------------------------------------------- #

def _recon_burst(arn, start=0, key="AKIAEXAMPLEKEY000001"):
    calls = [("GetCallerIdentity", "sts.amazonaws.com"), ("ListBuckets", "s3.amazonaws.com"),
             ("ListUsers", "iam.amazonaws.com"), ("GetAccountSummary", "iam.amazonaws.com"),
             ("DescribeInstances", "ec2.amazonaws.com"),
             ("ListSecrets", "secretsmanager.amazonaws.com")]
    return [keyed(ct(name, source=src, arn=arn, read_only=True, minutes=start + i), key)
            for i, (name, src) in enumerate(calls)]


def test_identity_check_then_reads_across_services_is_reconnaissance(
        store, profile, window):
    tax = _by_tax(_analyze(store, profile, window, _recon_burst(ALICE)))
    (sig,) = tax["cloud.key_reconnaissance"]
    assert sig.severity_hint == Severity.MEDIUM
    assert sig.evidence["services"] == ["ec2", "iam", "s3", "secretsmanager"]
    assert sig.evidence["long_term_key"] is True


def test_reconnaissance_by_a_single_purpose_key_is_high(store, acct_profile, window):
    tax = _by_tax(_analyze(store, acct_profile, window, _recon_burst(BACKUP)))
    assert tax["cloud.key_reconnaissance"][0].severity_hint == Severity.HIGH


def test_reads_long_after_the_identity_check_are_not_reconnaissance(store, profile, window):
    burst = _recon_burst(ALICE)
    late = [burst[0]] + [keyed(ct(r["eventName"], source=r["eventSource"], arn=ALICE,
                                  read_only=True, minutes=30 + i))
                         for i, r in enumerate(burst[1:])]
    assert "cloud.key_reconnaissance" not in _by_tax(_analyze(store, profile, window, late))


def test_dawnpatrols_own_calls_are_not_reconnaissance(store, profile, window, monkeypatch):
    key = "AKIADAWNPATROL000001"
    monkeypatch.setenv("DAWNPATROL_SOURCE_AWS_ACCESS_KEY_ID", key)
    arn = f"arn:aws:iam::{ACCT}:user/dawnpatrol"
    calls = [("GetCallerIdentity", "sts"), ("GetTrailStatus", "cloudtrail"),
             ("ListDetectors", "guardduty"), ("GetDetector", "guardduty"),
             ("GetCredentialReport", "iam"), ("ListHostedZones", "route53"),
             ("ListDistributions", "cloudfront")]
    recs = [keyed(ct(n, source=f"{s}.amazonaws.com", arn=arn, read_only=True, minutes=i), key)
            for i, (n, s) in enumerate(calls)]
    assert "cloud.key_reconnaissance" not in _by_tax(_analyze(store, profile, window, recs))
    # ...but the same key exploring elsewhere still counts
    store2_recs = recs + [keyed(ct(n, source=f"{s}.amazonaws.com", arn=arn, read_only=True,
                                   minutes=10 + i, params={"n": i}), key)
                          for i, (n, s) in enumerate([("ListUsers", "iam"),
                                                      ("ListRoles", "iam"),
                                                      ("DescribeInstances", "ec2"),
                                                      ("ListSecrets", "secretsmanager"),
                                                      ("ListFunctions", "lambda")])]
    store.delete_run("aws", force=True)
    assert "cloud.key_reconnaissance" in _by_tax(_analyze(store, profile, window, store2_recs))


# --------------------------------------------------------------------------- #
# 2. long-term key from a new network
# --------------------------------------------------------------------------- #

def test_key_networks_are_recorded_for_long_term_keys_only(profile):
    src = AwsCloudTrailSource()
    src.configure(profile)
    events = [src.normalize(keyed(s3("ListBuckets", ip="8.8.8.8"))),
              src.normalize(keyed(s3("ListBuckets", ip="8.8.4.4", minutes=1),
                                  key="ASIATEMPORARY0000001")),
              src.normalize(keyed(s3("ListBuckets", ip="10.0.0.5", minutes=2)))]
    pairs = {(t, v) for t, v, _ in entity_pairs_from_events(events)}
    keyed_pairs = {v for t, v in pairs if t == EntityType.KEY_NETWORK}
    assert keyed_pairs == {"AKIAEXAMPLEKEY000001|8.8.8.8"}


def test_closest_prefix():
    assert _closest("8.8.8.200", ["8.8.8.8", "1.1.1.1"]) == (24, "8.8.8.8")
    assert _closest("8.8.200.1", ["8.8.8.8"])[0] == 16
    assert _closest("2001:db8::1", ["8.8.8.8"]) == (0, None)


def test_new_networks_are_rated_by_distance(store, profile, window):
    past = datetime.now(UTC) - timedelta(days=3)
    store.observe_entities([(EntityType.KEY_NETWORK, "AKIAEXAMPLEKEY000001|8.8.8.8", 5),
                            (EntityType.KEY_NETWORK, "AKIAOTHERKEY00000001|8.8.8.8", 5)],
                           past)
    recs = [keyed(s3("ListBuckets", ip="8.8.8.8")),             # known
            keyed(s3("ListBuckets", ip="8.8.8.77", minutes=1)),  # same /24: ignored
            keyed(s3("ListBuckets", ip="8.8.200.1", minutes=2)),  # same /16: LOW
            keyed(s3("ListBuckets", ip="8.8.8.8", minutes=3), key="AKIAOTHERKEY00000001"),
            keyed(s3("ListBuckets", ip="8.8.9.1", minutes=4), key="AKIAOTHERKEY00000001"),
            keyed(s3("ListBuckets", ip="1.1.1.1", minutes=5), key="AKIAOTHERKEY00000001")]
    sigs = {s.evidence["access_key"]: s for s in
            _by_tax(_analyze(store, profile, window, recs))["cloud.key_new_network"]}
    low = sigs["AKIAEXAMPLEKEY000001"]
    assert low.severity_hint == Severity.LOW
    assert [d["address"] for d in low.evidence["new_networks"]] == ["8.8.200.1"]
    medium = sigs["AKIAOTHERKEY00000001"]
    assert medium.severity_hint == Severity.MEDIUM
    assert {d["address"] for d in medium.evidence["new_networks"]} == {"8.8.9.1", "1.1.1.1"}


def test_key_networks_are_silent_until_there_is_history(store, profile, window):
    recs = [keyed(s3("ListBuckets", ip="1.1.1.1"))]
    assert "cloud.key_new_network" not in _by_tax(_analyze(store, profile, window, recs))


def test_a_key_with_no_history_is_reported_low(store, profile, window):
    store.observe_entities([(EntityType.KEY_NETWORK, "AKIAOTHERKEY00000001|8.8.8.8", 1)],
                           datetime.now(UTC) - timedelta(days=3))
    recs = [keyed(s3("ListBuckets", ip="1.1.1.1"))]
    (sig,) = _by_tax(_analyze(store, profile, window, recs))["cloud.key_new_network"]
    assert sig.severity_hint == Severity.LOW and "first time" in sig.title


# --------------------------------------------------------------------------- #
# 3. abuse-prone services
# --------------------------------------------------------------------------- #

def test_abuse_prone_services(store, acct_profile, window):
    recs = [
        ct("GetModelInvocationLoggingConfiguration", source="bedrock.amazonaws.com",
           arn=ALICE, read_only=True),
        ct("InvokeModel", source="bedrock.amazonaws.com", arn=ALICE, minutes=1),
        ct("RequestServiceQuotaIncrease", source="servicequotas.amazonaws.com", arn=ALICE,
           minutes=2, error="AccessDenied"),
        ct("Publish", source="sns.amazonaws.com", arn=ALICE, minutes=3,
           params={"topicArn": "arn:aws:sns:us-east-1:1:alerts"}),
        ct("Publish", source="sns.amazonaws.com", arn=ALICE, minutes=4,
           params={"phoneNumber": "+15550100"}),
        ct("GetSendQuota", source="ses.amazonaws.com", arn=ALICE, minutes=5),  # in use
    ]
    sigs = {s.evidence["service"]: s for s in
            _by_tax(_analyze(store, acct_profile, window, recs))["cloud.abuse_service"]}
    assert set(sigs) == {"bedrock", "servicequotas", "sns"}
    assert sigs["bedrock"].severity_hint == Severity.HIGH
    assert sigs["bedrock"].evidence["checked_logging"] is True
    assert sigs["servicequotas"].severity_hint == Severity.MEDIUM   # denied
    assert sigs["sns"].evidence["events"] == 1                      # the SMS only


# --------------------------------------------------------------------------- #
# 4. backups (S3 data events)
# --------------------------------------------------------------------------- #

def test_mass_delete_ransomware_and_backup_retention(store, acct_profile, window):
    deletes = [s3("DeleteObject", minutes=i % 100, params={"bucketName": "backups",
                                                          "key": f"f{i}"})
               for i in range(120)]
    sse_c = s3("PutObject", minutes=5, params={"bucketName": "backups", "key": "x"},
               additionalEventData={"SSEApplied": "SSE_C"})
    suspend = s3("PutBucketVersioning", arn=ALICE, minutes=6, params={
        "bucketName": "backups", "VersioningConfiguration": {"Status": "Suspended"}})
    enable = s3("PutBucketVersioning", arn=ALICE, minutes=7, params={
        "bucketName": "other", "VersioningConfiguration": {"Status": "Enabled"}})
    result = _analyze(store, acct_profile, window, deletes + [sse_c, suspend, enable])
    tax = _by_tax(result)
    (mass,) = tax["cloud.mass_delete"]
    assert mass.severity_hint == Severity.MEDIUM and mass.evidence["deleted"] == 120
    (enc,) = tax["cloud.ransomware_encryption"]
    assert enc.severity_hint == Severity.HIGH and enc.evidence["buckets"] == ["backups"]
    (ret,) = tax["cloud.backup_retention_change"]
    assert ret.severity_hint == Severity.HIGH and ret.evidence["buckets"] == ["backups"]
    metrics = {m.key: m.value for m in result.metrics}
    assert metrics["aws.s3.object_deletes"] == 120 and metrics["aws.s3.object_writes"] == 1


def test_sse_c_is_read_from_request_headers_too(profile):
    src = AwsCloudTrailSource()
    src.configure(profile)
    ev = src.normalize(s3("PutObject", params={
        "bucketName": "b", "key": "k", "x-amz-server-side-encryption-customer-algorithm": "AES256"}))
    assert ev.raw["sse"] == "SSE_C" and ev.raw["object_key"] == "k"


# --------------------------------------------------------------------------- #
# 5. posture snapshot
# --------------------------------------------------------------------------- #

REPORT = """user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
<root_account>,arn:aws:iam::111122223333:root,2019-08-06T00:00:00+00:00,not_supported,2026-09-20T00:00:00+00:00,not_supported,not_supported,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A
lisa,arn:aws:iam::111122223333:user/lisa,2019-08-06T00:00:00+00:00,true,no_information,2019-08-06T00:00:00+00:00,N/A,false,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A
backup,arn:aws:iam::111122223333:user/backup,2024-01-31T00:00:00+00:00,false,N/A,N/A,N/A,false,true,2024-01-31T00:00:00+00:00,2026-11-20T00:00:00+00:00,us-east-1,s3,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A
"""

NOW = datetime(2026, 11, 21, tzinfo=UTC)


def _snap(**over):
    snap = {
        "taken_at": NOW.isoformat(), "account": ACCT, "regions": ["us-east-1", "us-east-2"],
        "iam": parse_credential_report(REPORT), "password_policy": {},
        "s3_account_bpa": {},
        "buckets": {"backups": {"versioning": "Off", "bpa": {}, "public": False,
                                "object_lock": False},
                    "site": {"versioning": "Enabled", "bpa": {}, "public": True,
                             "object_lock": False}},
        "trails": {"main": {"logging": True}},
        "guardduty": {"us-east-1": {"detectors": 1, "enabled": True}},
        "dns": {"example.org": {"example.org MX": ["10 mx.example.net"],
                                "app.example.org CNAME": ["app-prod.us-east-2.elasticbeanstalk.com"],
                                "www.example.org CNAME": ["live.us-east-2.elasticbeanstalk.com"]}},
        "cloudfront": {"E1": {"domain": "d1.cloudfront.net", "enabled": True,
                              "aliases": ["files.example.org"],
                              "origins": ["files.example.org.s3.amazonaws.com"]},
                       "E2": {"domain": "d2.cloudfront.net", "enabled": True,
                              "aliases": [], "origins": ["site.s3.amazonaws.com"]}},
        "beanstalk": {"us-east-2/live": {"cname": "live.us-east-2.elasticbeanstalk.com"}},
    }
    snap.update(over)
    return snap


def test_credential_report_parsing():
    rep = parse_credential_report(REPORT)
    assert rep["account"] == ACCT
    assert rep["root"]["mfa"] is True and rep["root"]["keys"] == {}
    assert rep["users"]["lisa"]["password"] is True and rep["users"]["lisa"]["mfa"] is False
    assert rep["users"]["backup"]["keys"]["key1"]["active"] is True


def test_first_snapshot_is_an_inventory_at_low(acct_profile):
    items = assess(_snap(), None, {"backups"}, now=NOW)
    issues = {i["message"]: i for i in items if i["action"] == "issue"}
    assert all(i["level"] == "LOW" and i["first"] for i in issues.values())
    text = " | ".join(issues)
    assert "lisa has a console password and no MFA" in text
    assert "backup's access key 1 is" in text and "days old" in text
    assert "no IAM password policy" in text and "Block Public Access" in text
    assert "Bucket site is public" in text and "Backup bucket backups has versioning Off" in text
    assert "app.example.org points at Elastic Beanstalk" in text
    assert "www.example.org" not in text                     # its environment exists
    assert "CloudFront E1 (files.example.org) serves from bucket files.example.org" in text
    assert not any(i["action"] == "critical" for i in items)


def test_critical_states_repeat_every_snapshot():
    snap = _snap(trails={"main": {"logging": False}},
                 guardduty={"us-east-2": {"detectors": 0, "enabled": False}})
    snap["iam"]["root"]["keys"] = {"key1": {"active": True, "rotated": "2020-01-01"}}
    crit = [i["message"] for i in assess(snap, snap, set(), now=NOW)
            if i["action"] == "critical"]
    assert crit == ["The root user has 1 active access key(s)", "Trail main is not logging",
                    "GuardDuty has no detector in us-east-2"]


def test_changes_since_the_last_snapshot():
    old = _snap()
    new = json.loads(json.dumps(old))
    new["iam"]["users"]["mallory"] = {"arn": "arn:aws:iam::1:user/mallory", "password": True,
                                      "mfa": False, "keys": {}}
    new["iam"]["users"]["backup"]["keys"]["key2"] = {"active": True, "rotated": "2026-11-20T00:00:00+00:00",
                                                     "last_used": None}
    new["buckets"]["backups"]["versioning"] = "Enabled"
    new["buckets"]["site"]["public"] = False
    new["dns"]["example.org"]["example.org MX"] = ["10 evil.example.net"]
    new["dns"]["example.org"]["blog.example.org CNAME"] = ["host.example.net"]
    del new["cloudfront"]["E1"]
    items = assess(new, old, {"backups"}, now=NOW)
    changes = {i["message"]: i["level"] for i in items if i["action"] == "change"}
    assert changes["New IAM user mallory"] == "MEDIUM"
    assert changes["IAM user backup has a new access key (slot 2, created 2026-11-20)"] == "MEDIUM"
    assert changes["DNS record example.org MX changed"] == "MEDIUM"
    assert changes["DNS record blog.example.org CNAME added"] == "LOW"
    assert changes["Bucket backups versioning changed from Off to Enabled"] == "LOW"
    assert changes["CloudFront distribution E1 was deleted"] == "LOW"
    issues = [i for i in items if i["action"] == "issue"]
    assert [i["message"] for i in issues] == [
        "IAM user mallory has a console password and no MFA"]
    assert issues[0]["level"] == "MEDIUM"
    resolved = {i["message"] for i in items if i["action"] == "resolved"}
    assert any("Backup bucket backups" in m for m in resolved)
    assert any("Bucket site is public" in m for m in resolved)
    assert any("CloudFront E1" in m for m in resolved)


def test_backup_versioning_turned_off_is_high():
    old = _snap()
    old["buckets"]["backups"]["versioning"] = "Enabled"
    new = json.loads(json.dumps(old))
    new["buckets"]["backups"]["versioning"] = "Suspended"
    changes = [i for i in assess(new, old, {"backups"}, now=NOW) if i["action"] == "change"]
    assert [(c["message"], c["level"]) for c in changes] == [
        ("Bucket backups versioning changed from Enabled to Suspended", "HIGH")]


def test_an_unreadable_section_is_not_diffed():
    old = _snap()
    new = _snap(dns=None)
    items = assess(new, old, {"backups"}, now=NOW)
    assert not [i for i in items if i["area"] == "dns" or "Elastic Beanstalk" in i["message"]
                and i["action"] == "resolved"]


class FakePostureSession:
    def __init__(self):
        self.calls = []

    def client(self, name, region_name=None):
        self.calls.append(name)
        return FakeApi(name)


class FakeApi:
    def __init__(self, name):
        self.name = name

    def generate_credential_report(self):
        return {"State": "COMPLETE"}

    def get_credential_report(self):
        return {"Content": REPORT.encode()}

    def get_account_password_policy(self):
        err = Exception("none")
        err.response = {"Error": {"Code": "NoSuchEntity"}}
        raise err

    def get_public_access_block(self, **kw):
        return {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True}}

    def list_buckets(self):
        return {"Buckets": [{"Name": "backups"}]}

    def get_bucket_versioning(self, Bucket):  # noqa: N803
        return {"Status": "Enabled"}

    def get_bucket_policy_status(self, Bucket):  # noqa: N803
        return {"PolicyStatus": {"IsPublic": False}}

    def get_object_lock_configuration(self, Bucket):  # noqa: N803
        return {"ObjectLockConfiguration": {}}

    def describe_trails(self, **kw):
        return {"trailList": [{"Name": "main", "TrailARN": "arn:t"}]}

    def get_trail_status(self, Name):  # noqa: N803
        return {"IsLogging": True}

    def list_detectors(self):
        return {"DetectorIds": ["d"]}

    def get_detector(self, DetectorId):  # noqa: N803
        return {"Status": "ENABLED"}

    def get_paginator(self, name):
        return self

    def paginate(self, **kw):
        yield {}

    def describe_environments(self, **kw):
        return {"Environments": []}


def _posture_ctx(tmp_path, window, dry_run=False):
    from types import SimpleNamespace
    return SimpleNamespace(window=window, dry_run=dry_run,
                           settings=SimpleNamespace(data_dir=tmp_path))


def test_posture_collect_saves_and_waits_for_the_interval(
        monkeypatch, tmp_path, profile, window):
    monkeypatch.setenv("DAWNPATROL_SOURCE_AWS_POSTURE", "true")
    monkeypatch.setenv("DAWNPATROL_SOURCE_AWS_POSTURE_REGIONS", "us-east-1")
    monkeypatch.setattr(posture._aws, "session", lambda region=None: FakePostureSession())
    src = AwsPostureSource()
    src.configure(profile)

    dry = src.collect(window, _posture_ctx(tmp_path, window, dry_run=True))
    assert dry.events and not (tmp_path / "aws-posture.json").exists()

    first = src.collect(window, _posture_ctx(tmp_path, window))
    assert not first.errors, first.errors
    assert all(e.kind == EventKind.OTHER and e.program.startswith("posture:")
               for e in first.events)
    assert (tmp_path / "aws-posture.json").exists()

    again = src.collect(window, _posture_ctx(tmp_path, window))
    assert again.events == [] and "next one is due" in again.notes[0]


def test_posture_events_become_signals(store, profile, window):
    src = AwsPostureSource()
    src.configure(profile)
    old = _snap()
    new = json.loads(json.dumps(old))
    new["trails"]["main"]["logging"] = False
    new["iam"]["users"]["mallory"] = {"arn": f"arn:aws:iam::{ACCT}:user/mallory",
                                      "password": False, "mfa": False, "keys": {}}
    when = window.end - timedelta(minutes=5)
    events = [src._event(i, new, when) for i in assess(new, old, set(), now=NOW)]
    store.start_run("po", 1, window.start, window)
    store.insert_events("po", events)
    result = CloudActivityAnalyzer().run(EventQuery(store, "po"), profile,
                                         Baseline(store, "po"))
    tax = _by_tax(result)
    (crit,) = tax["cloud.posture_critical"]
    assert crit.severity_hint == Severity.HIGH and "not logging" in crit.title
    (change,) = tax["cloud.posture_change"]
    assert change.title == "AWS posture: New IAM user mallory"
    assert change.severity_hint == Severity.MEDIUM
