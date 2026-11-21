"""AWS sources (CloudTrail from S3, GuardDuty from its API) and the
cloud_activity analyzer, against fake boto3 clients - no AWS account, no
network, no boto3 install needed."""

from __future__ import annotations

import gzip
import io
import json
from datetime import UTC, datetime, timedelta

import pytest

from dawnpatrol.analyzers.baseline import Baseline
from dawnpatrol.analyzers.cloud_activity import CloudActivityAnalyzer
from dawnpatrol.models import EventKind, Metric, Severity
from dawnpatrol.query import EventQuery
from dawnpatrol.sources import _aws
from dawnpatrol.sources.aws_cloudtrail import AwsCloudTrailSource
from dawnpatrol.sources.aws_guardduty import AwsGuardDutySource, severity_label

ACCT = "111122223333"
T0 = datetime(2026, 6, 1, 10, 0, tzinfo=UTC)


def ct(name, *, source="iam.amazonaws.com", user="IAMUser", arn=None, ip="198.51.100.20",
       error=None, read_only=False, params=None, minutes=0, region="us-east-1", **extra):
    uid = {"type": user, "accountId": ACCT,
           "arn": arn or f"arn:aws:iam::{ACCT}:user/alice", "principalId": "AID1"}
    if user == "Root":
        uid["arn"] = f"arn:aws:iam::{ACCT}:root"
    rec = {"eventTime": (T0 + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "eventSource": source, "eventName": name, "awsRegion": region,
           "sourceIPAddress": ip, "userAgent": "aws-cli/2.15", "userIdentity": uid,
           "recipientAccountId": ACCT, "readOnly": read_only,
           "eventID": f"{name}-{minutes}-{arn}-{error}-{json.dumps(params, sort_keys=True)}",
           "requestParameters": params}
    if error:
        rec["errorCode"] = error
    rec.update(extra)
    return rec


# --------------------------------------------------------------------------- #
# CloudTrail normalization
# --------------------------------------------------------------------------- #

@pytest.fixture
def cloudtrail(profile):
    src = AwsCloudTrailSource()
    src.configure(profile)
    return src


def test_api_call_maps_to_the_common_event_shape(cloudtrail):
    ev = cloudtrail.normalize(ct("CreateAccessKey", params={"userName": "bob"}))
    assert ev.kind == EventKind.OTHER and ev.action == "ok"
    assert ev.program == "iam:CreateAccessKey"
    assert ev.user == f"arn:aws:iam::{ACCT}:user/alice"
    assert ev.device == f"{ACCT}/us-east-1" and ev.severity == "write"
    assert ev.src_ip == "198.51.100.20" and ev.src_zone == "external"
    assert ev.raw["targets"] == ["bob"] and ev.raw["user_agent"] == "aws-cli/2.15"


def test_denials_errors_service_callers_and_roles(cloudtrail):
    denied = cloudtrail.normalize(ct("ListUsers", error="AccessDenied", read_only=True))
    assert denied.action == "denied" and denied.block_reason == "AccessDenied"
    assert denied.severity == "read"
    other = cloudtrail.normalize(ct("CreateUser", error="EntityAlreadyExists"))
    assert other.action == "error"
    assert cloudtrail.normalize(ct("Decrypt", user="AWSService")) is None
    by_service = cloudtrail.normalize(ct("PutObject", ip="s3.amazonaws.com"))
    assert by_service.src_ip is None and by_service.raw["source"] == "s3.amazonaws.com"
    role = cloudtrail.normalize(ct("GetSecretValue", user="AssumedRole",
                                   arn=f"arn:aws:sts::{ACCT}:assumed-role/ci/run-1",
                                   userIdentity=None))
    assert role is not None


def test_assumed_role_sessions_are_attributed_to_the_role(cloudtrail):
    rec = ct("ListBuckets", user="AssumedRole", arn=f"arn:aws:sts::{ACCT}:assumed-role/ci/s1")
    rec["userIdentity"]["sessionContext"] = {
        "sessionIssuer": {"arn": f"arn:aws:iam::{ACCT}:role/ci"},
        "attributes": {"mfaAuthenticated": "false"}}
    ev = cloudtrail.normalize(rec)
    assert ev.user == f"arn:aws:iam::{ACCT}:role/ci"
    assert ev.raw["mfa"] == "false"


def test_console_login_is_an_auth_event(cloudtrail):
    ok = cloudtrail.normalize(ct("ConsoleLogin", source="signin.amazonaws.com", user="Root",
                                 responseElements={"ConsoleLogin": "Success"},
                                 additionalEventData={"MFAUsed": "No"}))
    assert ok.kind == EventKind.AUTH and ok.action == "aws_login_ok"
    assert ok.user == f"arn:aws:iam::{ACCT}:root" and ok.raw["mfa"] == "No"
    bad = cloudtrail.normalize(ct("ConsoleLogin", source="signin.amazonaws.com",
                                  responseElements={"ConsoleLogin": "Failure"}))
    assert bad.action == "aws_login_fail"


# --------------------------------------------------------------------------- #
# CloudTrail collection from S3
# --------------------------------------------------------------------------- #

class FakeS3:
    def __init__(self, objects: dict[str, bytes]):
        self.objects = objects

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return self

    def paginate(self, Bucket, Prefix, Delimiter=None):  # noqa: N803 - boto3 names
        keys = sorted(k for k in self.objects if k.startswith(Prefix))
        if Delimiter:
            dirs = sorted({Prefix + k[len(Prefix):].split("/", 1)[0] + "/"
                           for k in keys if "/" in k[len(Prefix):]})
            yield {"CommonPrefixes": [{"Prefix": d} for d in dirs]}
        else:
            yield {"Contents": [{"Key": k} for k in keys]}

    def get_object(self, Bucket, Key):  # noqa: N803
        return {"Body": io.BytesIO(self.objects[Key])}


class FakeCloudTrailApi:
    def __init__(self, logging=True):
        self.logging = logging

    def get_trail_status(self, Name):  # noqa: N803
        return {"IsLogging": self.logging, "StopLoggingTime": "2026-06-01T09:00:00Z"}


class FakeSession:
    def __init__(self, **clients):
        self.clients = clients

    def client(self, name):
        return self.clients[name]


def _gz(records):
    return gzip.compress(json.dumps({"Records": records}).encode())


def test_collect_reads_org_trail_layout_and_keeps_only_the_window(
        monkeypatch, cloudtrail, window):
    base = f"logs/AWSLogs/o-abc123/{ACCT}/CloudTrail/us-east-1/"
    inside = ct("CreateUser", minutes=0)
    inside["eventTime"] = (window.end - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    outside = ct("DeleteUser", minutes=1)
    outside["eventTime"] = (window.start - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    day = (window.end - timedelta(hours=2)).strftime("%Y/%m/%d")
    stamp = (window.end - timedelta(hours=2)).strftime("%Y%m%dT%H%M")
    s3 = FakeS3({
        f"{base}{day}/{ACCT}_CloudTrail_us-east-1_{stamp}Z_aaa.json.gz":
            _gz([inside, outside, ct("Decrypt", user="AWSService")]),
        f"{base}{day}/digest.txt": b"ignored",
    })
    monkeypatch.setenv("DAWNPATROL_SOURCE_AWS_CLOUDTRAIL_BUCKET", "trail-bucket")
    monkeypatch.setenv("DAWNPATROL_SOURCE_AWS_CLOUDTRAIL_PREFIX", "/logs/")
    monkeypatch.setenv("DAWNPATROL_SOURCE_AWS_CLOUDTRAIL_TRAIL", "main")
    monkeypatch.setattr(_aws, "session", lambda region=None: FakeSession(
        s3=s3, cloudtrail=FakeCloudTrailApi(logging=False)))
    result = cloudtrail.collect(window, ctx=None)
    assert [e.program for e in result.events] == ["iam:CreateUser"]
    assert any("AWSService" in n for n in result.notes)
    assert any("NOT logging" in e for e in result.errors)


def test_collect_reports_an_empty_bucket_as_an_error(monkeypatch, cloudtrail, window):
    monkeypatch.setenv("DAWNPATROL_SOURCE_AWS_CLOUDTRAIL_BUCKET", "trail-bucket")
    monkeypatch.setattr(_aws, "session", lambda region=None: FakeSession(s3=FakeS3({})))
    result = cloudtrail.collect(window, ctx=None)
    assert result.events == [] and "no CloudTrail logs" in result.errors[0]


# --------------------------------------------------------------------------- #
# GuardDuty
# --------------------------------------------------------------------------- #

def finding(ftype="Recon:EC2/PortProbeUnprotectedPort", score=5.0, sample=False,
            updated="2026-06-01T11:00:00Z"):
    return {
        "Id": f"f-{ftype}-{score}", "Type": ftype, "Severity": score,
        "Title": ("[SAMPLE] " if sample else "") + f"{ftype} on i-123",
        "Description": "Unprotected port 22 is being probed.",
        "AccountId": ACCT, "Region": "us-east-1",
        "CreatedAt": "2026-06-01T10:00:00Z", "UpdatedAt": updated,
        "Resource": {"ResourceType": "Instance", "InstanceDetails": {
            "InstanceId": "i-123",
            "NetworkInterfaces": [{"PrivateIpAddress": "172.31.5.9"}]}},
        "Service": {"Count": 4, "AdditionalInfo": {"Sample": sample}, "Action": {
            "PortProbeAction": {"PortProbeDetails": [{
                "LocalPortDetails": {"Port": 22},
                "RemoteIpDetails": {"IpAddressV4": "203.0.113.7"}}]}}},
    }


class FakeGuardDuty:
    def __init__(self, findings, detectors=("det1",)):
        self.findings = {f["Id"]: f for f in findings}
        self.detectors = list(detectors)
        self.criteria = None

    def list_detectors(self):
        return {"DetectorIds": self.detectors}

    def get_detector(self, DetectorId):  # noqa: N803
        return {"Status": "ENABLED"}

    def get_paginator(self, name):
        assert name == "list_findings"
        return self

    def paginate(self, DetectorId, FindingCriteria):  # noqa: N803
        self.criteria = FindingCriteria
        yield {"FindingIds": list(self.findings)}

    def get_findings(self, DetectorId, FindingIds):  # noqa: N803
        return {"Findings": [self.findings[i] for i in FindingIds]}


def test_severity_bands():
    assert [severity_label(s) for s in (2, 4, 6.9, 7, 8.9, 9.5)] == \
        ["LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL"]


def test_guardduty_collects_findings_and_flags_regions_without_a_detector(
        monkeypatch, profile, window):
    gd_east = FakeGuardDuty([finding(), finding("Backdoor:EC2/C&CActivity.B", 8.0)])
    gd_west = FakeGuardDuty([], detectors=())
    monkeypatch.setenv("DAWNPATROL_SOURCE_AWS_GUARDDUTY_REGIONS", "us-east-1,us-west-2")
    monkeypatch.setattr(_aws, "session", lambda region=None: FakeSession(
        guardduty=gd_east if region == "us-east-1" else gd_west))
    src = AwsGuardDutySource()
    src.configure(profile)
    result = src.collect(window, ctx=None)
    assert {e.program for e in result.events} == {"Recon:EC2/PortProbeUnprotectedPort",
                                                  "Backdoor:EC2/C&CActivity.B"}
    probe = next(e for e in result.events if e.program.startswith("Recon"))
    assert probe.kind == EventKind.IDS and probe.action == "gd_finding"
    assert probe.src_ip == "203.0.113.7" and probe.dst_ip == "172.31.5.9"
    assert probe.dst_port == 22 and probe.severity == "MEDIUM"
    assert gd_east.criteria["Criterion"]["service.archived"] == {"Equals": ["false"]}
    assert any("us-west-2" in e and "no detector" in e for e in result.errors)


# --------------------------------------------------------------------------- #
# The analyzer
# --------------------------------------------------------------------------- #

def _analyze(store, profile, window, records=(), findings=()):
    src = AwsCloudTrailSource()
    src.configure(profile)
    gd = AwsGuardDutySource()
    gd.configure(profile)
    events = [src.normalize(r) for r in records]
    events = [e for e in events if e is not None]
    events += [gd.normalize(f) for f in findings]
    assert all(window.start <= e.ts < window.end for e in events)
    store.start_run("aws", 1, window.start, window)
    store.insert_events("aws", events)
    return CloudActivityAnalyzer().run(EventQuery(store, "aws"), profile, Baseline(store, "aws"))


def _by_tax(result):
    out = {}
    for s in result.signals:
        out.setdefault(s.taxonomy, []).append(s)
    return out


def test_root_tampering_and_iam_changes(store, profile, window):
    result = _analyze(store, profile, window, records=[
        ct("ConsoleLogin", source="signin.amazonaws.com", user="Root",
           responseElements={"ConsoleLogin": "Success"}, additionalEventData={"MFAUsed": "No"}),
        ct("StopLogging", source="cloudtrail.amazonaws.com", minutes=1),
        ct("DeleteDetector", source="guardduty.amazonaws.com", error="AccessDenied", minutes=2),
        ct("CreateAccessKey", params={"userName": "bob"}, minutes=3),
        ct("AttachUserPolicy", params={"userName": "bob"}, minutes=4),
    ])
    tax = _by_tax(result)
    assert tax["cloud.root_usage"][0].severity_hint == Severity.HIGH
    assert tax["cloud.console_login_no_mfa"][0].severity_hint == Severity.MEDIUM
    sev = {s.evidence["apis"][0]: s.severity_hint for s in tax["cloud.logging_tampering"]}
    assert sev == {"cloudtrail:StopLogging": Severity.HIGH,
                   "guardduty:DeleteDetector": Severity.MEDIUM}
    (iam,) = tax["cloud.iam_persistence"]
    assert iam.evidence["apis"] == ["iam:AttachUserPolicy", "iam:CreateAccessKey"]
    metrics = {m.key: m.value for m in result.metrics}
    assert metrics["aws.ct.events"] == 5 and metrics["aws.ct.denied"] == 1


def test_sso_console_login_is_not_called_mfa_less(store, profile, window):
    rec = ct("ConsoleLogin", source="signin.amazonaws.com", user="AssumedRole",
             arn=f"arn:aws:sts::{ACCT}:assumed-role/AWSReservedSSO_Admin/alice",
             responseElements={"ConsoleLogin": "Success"}, additionalEventData={"MFAUsed": "No"})
    assert "cloud.console_login_no_mfa" not in _by_tax(_analyze(store, profile, window, [rec]))


def test_probing_and_sweeps(store, profile, window):
    denied = [ct(f"List{i}", source="ec2.amazonaws.com", error="UnauthorizedOperation",
                 read_only=True, minutes=i) for i in range(12)]
    secrets = [ct("GetSecretValue", source="secretsmanager.amazonaws.com", read_only=True,
                  params={"secretId": f"prod/db{i}"}, minutes=20 + i) for i in range(10)]
    few = [ct("GetSecretValue", source="secretsmanager.amazonaws.com", read_only=True,
              arn=f"arn:aws:iam::{ACCT}:user/app", params={"secretId": "prod/app"},
              minutes=40 + i) for i in range(30)]
    tax = _by_tax(_analyze(store, profile, window, denied + secrets + few))
    (probe,) = tax["cloud.permission_probing"]
    assert probe.evidence["events"] == 12 and len(probe.evidence["denied_apis"]) == 12
    (sweep,) = tax["cloud.secrets_sweep"]       # alice: 10 distinct; app: 30 reads of 1
    assert sweep.severity_hint == Severity.HIGH and len(sweep.evidence["distinct"]) == 10


def test_unexpected_region_ignores_global_services(store, profile, window, monkeypatch):
    monkeypatch.setenv("DAWNPATROL_SOURCE_AWS_EXPECTED_REGIONS", "us-east-1,us-west-2")
    tax = _by_tax(_analyze(store, profile, window, [
        ct("RunInstances", source="ec2.amazonaws.com", region="ap-southeast-3"),
        ct("CreateUser", region="eu-central-1"),     # iam is global: ignored
        ct("RunInstances", source="ec2.amazonaws.com", region="us-west-2", minutes=1),
    ]))
    (sig,) = tax["cloud.unexpected_region"]
    assert sig.evidence["region"] == "ap-southeast-3"


def test_guardduty_findings_keep_their_severity_and_samples_are_info(store, profile, window):
    tax = _by_tax(_analyze(store, profile, window, findings=[
        finding("Backdoor:EC2/C&CActivity.B", 8.0),
        finding("Recon:EC2/Portscan", 2.0, sample=True),
    ]))
    by_type = {s.evidence["finding_type"]: s for s in tax["cloud.guardduty_finding"]}
    assert by_type["Backdoor:EC2/C&CActivity.B"].severity_hint == Severity.HIGH
    assert by_type["Recon:EC2/Portscan"].severity_hint == Severity.INFO
    assert by_type["Recon:EC2/Portscan"].evidence["sample"] is True


def test_source_credentials_are_registered_for_leak_scanning(monkeypatch):
    from dawnpatrol.config import Settings
    monkeypatch.setenv("DAWNPATROL_SOURCE_AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG")
    monkeypatch.setenv("DAWNPATROL_SOURCE_PIHOLE_PASSWORD", "hunter2hunter2")
    settings = Settings.from_env()
    assert settings.secrets.scan("leak wJalrXUtnFEMI/K7MDENG here")
    assert settings.secrets.scan("pw hunter2hunter2")


def test_cloud_metrics_always_reach_the_report_tables(window):
    from dawnpatrol.models import Report
    report = Report(run_id="r", generated_at=window.end, window=window,
                    metrics=[Metric(key=f"m{i}", value=i, section="perimeter")
                             for i in range(60)]
                    + [Metric(key="aws.ct.events", value=5, section="cloud")])
    keys = [m.key for m in report.table_metrics(40)]
    assert len(keys) == 41 and keys[-1] == "aws.ct.events"


# --------------------------------------------------------------------------- #
# Generic change groups and the profile's cloud_accounts rules
# --------------------------------------------------------------------------- #

def test_storage_compute_dns_and_cross_account_changes(store, profile, window):
    vendor = ct("AssumeRole", source="sts.amazonaws.com", user="AWSAccount", minutes=9,
                arn=None, read_only=True)
    vendor["userIdentity"] = {"type": "AWSAccount", "accountId": "999988887777",
                              "principalId": "AIDAVENDOR:rolemaster"}
    tax = _by_tax(_analyze(store, profile, window, [
        ct("PutBucketPolicy", source="s3.amazonaws.com", params={"bucketName": "backups"}),
        ct("DeletePublicAccessBlock", source="s3.amazonaws.com", minutes=1,
           params={"bucketName": "backups"}, error="AccessDenied"),
        ct("RunInstances", source="ec2.amazonaws.com", minutes=2),
        ct("ChangeResourceRecordSets", source="route53.amazonaws.com", minutes=3,
           params={"hostedZoneId": "Z1", "changeBatch": {"changes": [
               {"action": "UPSERT", "resourceRecordSet": {"name": "files.example.org"}}]}}),
        vendor,
    ]))
    (storage,) = tax["cloud.storage_change"]
    assert storage.severity_hint == Severity.MEDIUM and storage.evidence["succeeded"] == 1
    assert "backups" in storage.evidence["targets"]
    assert tax["cloud.compute_launch"][0].severity_hint == Severity.MEDIUM
    (dns,) = tax["cloud.dns_edge_change"]
    assert "files.example.org" in dns.evidence["requests"][0]
    (xacct,) = tax["cloud.cross_account"]
    assert xacct.evidence["caller_account"] == "999988887777"
    assert xacct.severity_hint == Severity.LOW


ACCOUNT_PROFILE = f"""
site: {{name: t}}
cloud_accounts:
  - account_id: "{ACCT}"
    name: personal
    expected_regions: [us-east-1, us-east-2]
    blocked_accounts: ["999988887777"]
    principals:
      - {{match: user/old-contractor, dormant: true, notes: "left in 2019"}}
      - {{match: user/alice, long_term_keys: false}}
      - match: user/backup
        allowed_services: [s3]
        allowed_buckets: [site-content, backups]
    watched_resources:
      - {{match: files.example.org, severity: HIGH, note: dangling CloudFront name}}
"""


@pytest.fixture
def account_profile(tmp_path):
    from dawnpatrol.profile import Profile
    path = tmp_path / "p.yml"
    path.write_text(ACCOUNT_PROFILE, encoding="utf-8")
    return Profile.load(path)


def test_cloud_accounts_load_and_reach_the_model(account_profile):
    (acct,) = account_profile.cloud_accounts
    assert acct.expected_regions == ["us-east-1", "us-east-2"]
    assert [p.match for p in acct.principals] == ["user/old-contractor", "user/alice", "user/backup"]
    text = account_profile.as_context()
    assert f"CLOUD ACCOUNT aws {ACCT} (personal)" in text
    assert "principal user/old-contractor [dormant: any activity is suspicious]" in text
    assert "services: s3 only; buckets: site-content, backups only" in text
    assert "watched resource files.example.org (HIGH): dangling CloudFront name" in text


def test_cloud_accounts_reject_bad_entries(tmp_path):
    from dawnpatrol.errors import ConfigError
    from dawnpatrol.profile import Profile
    path = tmp_path / "p.yml"
    path.write_text("cloud_accounts:\n  - name: no id\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        Profile.load(path)


def test_account_rules_fire_at_high(store, account_profile, window):
    alice_key = ct("ListBuckets", source="s3.amazonaws.com", read_only=True, minutes=1)
    alice_key["userIdentity"]["accessKeyId"] = "AKIAEXAMPLE000000001"
    alice_console = ct("ListBuckets", source="s3.amazonaws.com", read_only=True, minutes=2)
    alice_console["userIdentity"]["accessKeyId"] = "ASIAEXAMPLE000000002"
    backup = f"arn:aws:iam::{ACCT}:user/backup"
    blocked = ct("GetRole", read_only=True, minutes=8,
                 params={"roleName": "Worker"}, arn=f"arn:aws:iam::{ACCT}:user/alice")
    blocked["requestParameters"] = {"roleArn": "arn:aws:iam::999988887777:role/rolemaster"}
    tax = _by_tax(_analyze(store, account_profile, window, [
        ct("ConsoleLogin", source="signin.amazonaws.com", arn=f"arn:aws:iam::{ACCT}:user/old-contractor",
           responseElements={"ConsoleLogin": "Success"}),
        alice_key, alice_console,
        ct("PutObject", source="s3.amazonaws.com", arn=backup, minutes=3,
           params={"bucketName": "backups", "key": "a.tar"}),
        ct("GetCallerIdentity", source="sts.amazonaws.com", arn=backup, read_only=True,
           minutes=4),
        ct("GetObject", source="s3.amazonaws.com", arn=backup, read_only=True, minutes=5,
           params={"bucketName": "payroll"}),
        ct("CreateBucket", source="s3.amazonaws.com", minutes=6,
           params={"bucketName": "files.example.org"}),
        ct("RunInstances", source="ec2.amazonaws.com", region="ap-south-1", minutes=7),
        blocked,
    ]))
    assert tax["cloud.dormant_principal"][0].severity_hint == Severity.HIGH
    (key,) = tax["cloud.unexpected_access_key"]
    assert key.evidence["access_keys"] == ["AKIAEXAMPLE000000001"]
    scope = {s.id: s for s in tax["cloud.principal_out_of_scope"]}
    assert scope["aws.out_of_scope_service.user/backup"].evidence["apis"] == \
        ["sts:GetCallerIdentity"]
    assert scope["aws.out_of_scope_bucket.user/backup"].evidence["buckets"] == ["payroll"]
    assert tax["cloud.watched_resource"][0].evidence["watched"] == "files.example.org"
    assert tax["cloud.blocked_account"][0].severity_hint == Severity.HIGH
    # expected_regions came from the profile, no env var needed
    assert tax["cloud.unexpected_region"][0].evidence["region"] == "ap-south-1"
