"""AWS account activity: CloudTrail behaviour checks, GuardDuty findings and
the posture snapshot.

Reads events from ``sources/aws_cloudtrail.py``, ``sources/aws_guardduty.py``
and ``sources/aws_posture.py``
(see their docstrings for the field mapping). Every check is a pattern that
shows up in real cloud intrusions and is cheap to tell apart from routine
administration:

* root account activity
* console sign-ins without MFA, and bursts of failed sign-ins
* attempts to stop or blind logging and detection (CloudTrail, GuardDuty,
  AWS Config, VPC flow logs) - HIGH when they succeed
* IAM changes that create or widen access (users, keys, identity providers,
  policies, trust, reactivated keys)
* bucket access/retention changes (policy, ACL, public-access block,
  versioning, lifecycle, deletion), compute launches, DNS/CDN changes, and
  calls by another account's identity
* the profile's ``cloud_accounts`` rules, at HIGH: dormant principals,
  long-term-key use by console-only principals, principals outside their
  allowed services or buckets, blocked accounts, and watched resource names
* permission probing: one principal denied across many different APIs
* sweeps: one principal reading many secrets, enumerating IAM, or touching
  many buckets - the agentic "try everything" shape published for ARTEX and
  its forks (thresholds 10 secrets / 10 IAM read APIs / 15 buckets)
* write activity in a region outside the expected regions (the profile's
  ``cloud_accounts[].expected_regions`` or ``DAWNPATROL_SOURCE_AWS_EXPECTED_REGIONS``)
* stolen-key reconnaissance: one key calling ``sts:GetCallerIdentity`` and then
  5+ read APIs across 2+ services within 15 minutes (HIGH for a key the
  profile limits to certain services)
* a long-term key (AKIA...) calling from a new network, against every address
  it has used before: same /24 ignored, same /16 LOW, further MEDIUM
* abuse-prone services: Bedrock (LLMjacking), SES, SMS, quota increases -
  HIGH when a call succeeded, unless the profile lists the service as in use
* backups (needs S3 data events): mass object deletion, objects written
  with a customer-supplied key (SSE-C ransomware), and retention changes on
  the profile's ``backup_buckets`` (HIGH)
* GuardDuty findings, one signal per finding type at GuardDuty's severity
* the daily posture snapshot (``sources/aws_posture.py``): critical states,
  new weaknesses, and configuration changes

Thresholds are module constants. Anything legitimate that trips one (a CI role
that rotates keys, an auditor's read-only sweep) belongs in the profile's
known_quirks or a suppression, not in a raised threshold.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from datetime import timedelta
from typing import Any

from ..models import AnalyzerResult, Entity, EntityType, EventKind, Metric, Severity, Signal
from ..profile import Profile
from ..query import EventQuery
from ..secrets import read_env, read_int, read_list
from .base import Analyzer
from .baseline import Baseline

CT = "aws_cloudtrail"
GD = "aws_guardduty"
PO = "aws_posture"

TAMPERING = [
    "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
    "cloudtrail:PutEventSelectors", "cloudtrail:PutInsightSelectors",
    "guardduty:DeleteDetector", "guardduty:UpdateDetector", "guardduty:CreateFilter",
    "guardduty:UpdateFilter", "guardduty:DisassociateFromAdministratorAccount",
    "guardduty:DisassociateFromMasterAccount", "guardduty:DeletePublishingDestination",
    "guardduty:StopMonitoringMembers", "config:StopConfigurationRecorder",
    "config:DeleteConfigurationRecorder", "config:DeleteDeliveryChannel",
    "ec2:DeleteFlowLogs", "logs:DeleteLogGroup", "kms:ScheduleKeyDeletion", "kms:DisableKey",
]
IAM_CHANGES = [
    "iam:CreateUser", "iam:CreateAccessKey", "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile", "iam:AttachUserPolicy", "iam:AttachRolePolicy",
    "iam:AttachGroupPolicy", "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:PutGroupPolicy",
    "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:AddUserToGroup",
    "iam:UpdateAssumeRolePolicy", "iam:CreateRole", "iam:DeactivateMFADevice",
    "iam:DeleteVirtualMFADevice", "iam:CreateServiceSpecificCredential",
    "sts:GetFederationToken", "iam:UpdateAccessKey", "iam:CreateSAMLProvider",
    "iam:UpdateSAMLProvider", "iam:CreateOpenIDConnectProvider",
    "iam:AddClientIDToOpenIDConnectProvider", "iam:DeleteAccountPasswordPolicy",
    "kms:PutKeyPolicy",
]
#: Changes to who can read or keep bucket data.
STORAGE_CHANGES = [
    "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutBucketAcl",
    "s3:PutBucketPublicAccessBlock", "s3:DeleteBucketPublicAccessBlock",
    "s3:PutAccountPublicAccessBlock", "s3:DeleteAccountPublicAccessBlock",
    "s3:PutBucketVersioning", "s3:PutBucketLifecycle", "s3:DeleteBucketLifecycle",
    "s3:PutBucketReplication", "s3:DeleteBucket", "s3:PutBucketObjectLockConfiguration",
]
#: Anything that starts something running (crypto-mining is the classic payoff).
COMPUTE_PREFIXES = [
    "ec2:RunInstances", "ec2:RequestSpotInstances", "ec2:RequestSpotFleet",
    "ec2:CreateFleet", "lambda:CreateFunction", "lambda:UpdateFunctionCode",
    "elasticbeanstalk:CreateEnvironment", "lightsail:CreateInstances",
    "lightsail:CreateContainerService", "ecs:RunTask", "ecs:CreateService",
    "eks:CreateCluster", "eks:CreateNodegroup", "batch:SubmitJob",
    "sagemaker:CreateNotebookInstance", "sagemaker:CreateTrainingJob",
    "autoscaling:CreateAutoScalingGroup",
]
#: DNS and CDN changes can redirect mail or web traffic.
DNS_EDGE_PREFIXES = [
    "route53:ChangeResourceRecordSets", "route53:CreateHostedZone",
    "route53:DeleteHostedZone", "route53:AssociateVPCWithHostedZone",
    "route53domains:", "cloudfront:CreateDistribution", "cloudfront:UpdateDistribution",
    "cloudfront:DeleteDistribution",
]
SECRET_READS = ["secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue",
                "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"]
BUCKET_PREFIXES = ["s3:GetBucket", "s3:ListObjects", "s3:GetObject", "s3:HeadBucket"]
IAM_READ_PREFIXES = ["iam:List", "iam:Get"]
#: Global services log in us-east-1 whatever region the caller is in.
GLOBAL_SERVICES = {"iam", "sts", "signin", "organizations", "cloudfront", "route53",
                   "support", "health", "account", "billing", "ce", "budgets"}

#: How stolen keys are turned into money, by service. Any use in an account
#: that doesn't use the service is worth a look; ``services_in_use`` in the
#: profile exempts one the owner really uses.
ABUSE_PROGRAMS: dict[str, tuple[str, list[str]]] = {
    "bedrock": ("AI model use (LLMjacking)", ["bedrock:", "bedrock-runtime:",
                                               "bedrock-agent:"]),
    "ses": ("email sending", ["ses:", "email:"]),
    "sns": ("SMS sending", ["sns:SetSMSAttributes", "sns:GetSMSAttributes",
                            "sns:CreateSMSSandboxPhoneNumber", "sns:VerifySMSSandboxPhoneNumber",
                            "sns:GetSMSSandboxAccountStatus", "sns:Publish"]),
    "sms-voice": ("SMS sending", ["sms-voice:", "pinpoint-sms-voice:"]),
    "servicequotas": ("service quota increase", ["servicequotas:RequestServiceQuotaIncrease"]),
}
#: What DawnPatrol itself calls with its own key (sources and probes). Those
#: calls are left out of the reconnaissance and sweep checks; anything else
#: signed with its key still counts.
OWN_FOOTPRINT = (
    "sts:GetCallerIdentity", "cloudtrail:GetTrailStatus", "cloudtrail:DescribeTrails",
    "guardduty:ListDetectors", "guardduty:GetDetector", "guardduty:ListFindings",
    "guardduty:GetFindings", "iam:GenerateCredentialReport", "iam:GetCredentialReport",
    "iam:GetAccountPasswordPolicy", "s3:ListBuckets", "s3:ListObjects",
    "s3:GetBucketVersioning", "s3:GetBucketPublicAccessBlock", "s3:GetBucketPolicyStatus",
    "s3:GetObjectLockConfiguration", "s3:GetBucketObjectLockConfiguration",
    "s3:GetAccountPublicAccessBlock", "route53:ListHostedZones",
    "route53:ListResourceRecordSets", "cloudfront:ListDistributions",
    "elasticbeanstalk:DescribeEnvironments",
)
#: Bucket changes that make backups deletable or expire them.
BACKUP_RETENTION = ["s3:PutBucketVersioning", "s3:PutBucketLifecycle",
                    "s3:PutBucketLifecycleConfiguration", "s3:DeleteBucket",
                    "s3:PutBucketObjectLockConfiguration", "s3:DeleteBucketReplication",
                    "s3:PutBucketReplication"]
OBJECT_DELETES = ["s3:DeleteObject", "s3:DeleteObjects"]
OBJECT_WRITES = ["s3:PutObject", "s3:CopyObject", "s3:CreateMultipartUpload"]

RECON_WINDOW = timedelta(minutes=15)
RECON_MIN_APIS = 5
RECON_MIN_SERVICES = 2
MASS_DELETE_MIN = 100

SECRETS_SWEEP_MIN = 10
IAM_ENUM_MIN = 10
BUCKET_SWEEP_MIN = 15
DENIED_MIN_CALLS = 10
DENIED_MIN_APIS = 5
LOGIN_FAIL_MIN = 5
_LIST = 10


class CloudActivityAnalyzer(Analyzer):
    name = "cloud_activity"
    requires_kinds = frozenset({EventKind.AUTH, EventKind.OTHER, EventKind.IDS})
    requires_sources = frozenset({CT, GD, PO})
    order = 65

    def run(self, q: EventQuery, profile: Profile, baseline: Baseline) -> AnalyzerResult:
        r = AnalyzerResult(analyzer=self.name)
        ct_total = q.count(source=CT)
        if ct_total:
            r.metrics += [
                Metric(key="aws.ct.events", value=ct_total, section="cloud",
                       label="CloudTrail events"),
                Metric(key="aws.ct.writes", value=q.count(source=CT, severity="write"),
                       section="cloud", label="CloudTrail write events"),
                Metric(key="aws.ct.denied", value=q.count(source=CT, action="denied"),
                       section="cloud", label="CloudTrail access-denied calls"),
                Metric(key="aws.ct.principals", value=q.distinct_count("user", source=CT),
                       section="cloud", label="Distinct AWS principals"),
            ]
            self._root(q, r)
            self._console_logins(q, r)
            self._tampering(q, r)
            self._changes(q, r, IAM_CHANGES, None, "iam_change", "IAM access changes",
                          "cloud.iam_persistence",
                          "New users, keys, identity providers, policies or trust are how "
                          "access is kept after a break-in. Match each change to a known "
                          "admin task; one nobody planned is the finding.")
            self._changes(q, r, STORAGE_CHANGES, None, "storage_change",
                          "bucket access or retention changes", "cloud.storage_change",
                          "Bucket policies, ACLs and public-access blocks decide who can "
                          "read the data; versioning and lifecycle decide whether it "
                          "survives deletion. Confirm each change was intended.")
            self._changes(q, r, None, COMPUTE_PREFIXES, "compute_launch", "compute launched",
                          "cloud.compute_launch",
                          "Something was started. In an account that normally runs "
                          "little, unplanned compute is the usual payoff of stolen "
                          "credentials (crypto-mining). Check what, where, and by whom.")
            self._changes(q, r, None, DNS_EDGE_PREFIXES, "dns_edge_change",
                          "DNS or CDN changes", "cloud.dns_edge_change",
                          "DNS and CDN changes can redirect mail or web traffic, or claim a "
                          "dangling name. Check the exact records changed (evidence.requests).",
                          requests=True)
            self._cross_account(q, r)
            self._denied(q, r)
            self._sweeps(q, r)
            self._regions(q, r, profile)
            self._account_rules(q, r, profile)
            self._recon(q, r, profile)
            self._key_networks(q, r, baseline)
            self._abuse(q, r, profile)
            self._backups(q, r, profile)
        if q.count(source=GD):
            self._guardduty(q, r)
        if q.count(source=PO):
            self._posture(q, r)
        return r

    # ----- CloudTrail ------------------------------------------------------- #

    def _root(self, q: EventQuery, r: AnalyzerResult) -> None:
        rows = q.detail_rows(source=CT, user_suffix=":root")
        if not rows:
            return
        by_account: dict[str, list[dict]] = defaultdict(list)
        for row in rows:
            by_account[row["raw"].get("account") or "?"].append(row)
        for account, items in by_account.items():
            r.signals.append(self._signal(
                f"aws.root_activity.{account}", "AWS root account used",
                "cloud.root_usage", Severity.HIGH, 0.8, items,
                hint=("The root user should be used for almost nothing day to day. Confirm "
                      "the owner did this, from where, and that root has MFA; a root "
                      "access key or root activity from an unfamiliar address is a likely "
                      "compromise."),
                extra={"account": account}))

    def _console_logins(self, q: EventQuery, r: AnalyzerResult) -> None:
        rows = q.detail_rows(source=CT, kind=EventKind.AUTH)
        no_mfa = defaultdict(list)
        failed = defaultdict(list)
        for row in rows:
            # Federated/SSO sign-ins (AssumedRole) record MFAUsed=No even when
            # the identity provider enforced MFA, so only IAM users and root count.
            if (row["action"] == "aws_login_ok"
                    and row["raw"].get("principal_type") in ("IAMUser", "Root")
                    and str(row["raw"].get("mfa")).lower() in ("no", "false")):
                no_mfa[row["user"]].append(row)
            elif row["action"] == "aws_login_fail":
                failed[row["src_ip"] or row["user"]].append(row)
        for user, items in no_mfa.items():
            r.signals.append(self._signal(
                f"aws.console_login_no_mfa.{user}", "AWS console sign-in without MFA",
                "cloud.console_login_no_mfa", Severity.MEDIUM, 0.7, items,
                hint="A password alone protects this identity. Enable MFA, and confirm the "
                     "sign-in addresses are the owner's."))
        for who, items in failed.items():
            if len(items) < LOGIN_FAIL_MIN:
                continue
            r.signals.append(self._signal(
                f"aws.console_login_failures.{who}",
                f"{len(items)} failed AWS console sign-ins",
                "cloud.console_login_failures", Severity.MEDIUM, 0.6, items,
                hint="Repeated failures from one address or against one user: check for "
                     "a later success from the same source."))

    def _tampering(self, q: EventQuery, r: AnalyzerResult) -> None:
        rows = q.detail_rows(source=CT, programs=TAMPERING)
        grouped = defaultdict(list)
        for row in rows:
            grouped[(row["program"], row["user"])].append(row)
        for (program, user), items in grouped.items():
            succeeded = any(i["action"] == "ok" for i in items)
            r.signals.append(self._signal(
                f"aws.defense_evasion.{program}.{user}",
                f"{program} {'succeeded' if succeeded else 'attempted (denied/failed)'}",
                "cloud.logging_tampering", Severity.HIGH if succeeded else Severity.MEDIUM,
                0.75, items,
                hint=("Stopping or changing logging and detection is what an intruder does "
                      "first. Confirm it was a planned change by this principal; if not, "
                      "re-enable it and treat the principal as compromised. A GuardDuty "
                      "filter (CreateFilter) can silently auto-archive findings.")))

    def _changes(self, q: EventQuery, r: AnalyzerResult, programs: list[str] | None,
                 prefixes: list[str] | None, label: str, title: str, taxonomy: str,
                 hint: str, requests: bool = False) -> None:
        """One signal per principal for a group of change APIs: MEDIUM when any
        call succeeded, LOW when every attempt was denied or failed."""
        rows = q.detail_rows(source=CT, programs=programs, program_prefixes=prefixes)
        grouped = defaultdict(list)
        for row in rows:
            grouped[row["user"]].append(row)
        for user, items in grouped.items():
            succeeded = [i for i in items if i["action"] == "ok"]
            apis = sorted({i["program"] for i in items})
            names = ", ".join(a.split(":", 1)[1] for a in apis[:4])
            extra: dict[str, Any] = {"succeeded": len(succeeded),
                                     "targets": sorted({t for i in items
                                                        for t in i["raw"].get("targets") or []})[:20]}
            if requests:
                extra["requests"] = [i["raw"].get("request") for i in items[:5]]
            r.signals.append(self._signal(
                f"aws.{label}.{user}",
                f"{_short(user)}: {title} ({names})" if succeeded
                else f"{_short(user)}: {title} attempted, all denied ({names})",
                taxonomy, Severity.MEDIUM if succeeded else Severity.LOW, 0.6, items,
                hint=hint, extra=extra))

    def _cross_account(self, q: EventQuery, r: AnalyzerResult) -> None:
        """Calls made by another AWS account's identity (role assumption by a
        vendor, a partner, or someone holding a trust you forgot about)."""
        rows = q.detail_rows(source=CT, raw_contains='"principal_type": "AWSAccount"')
        grouped = defaultdict(list)
        for row in rows:
            caller = row["raw"].get("caller_account") or "?"
            if caller != row["raw"].get("account"):
                grouped[caller].append(row)
        for caller, items in grouped.items():
            r.signals.append(self._signal(
                f"aws.cross_account.{caller}", f"Account {caller} acted in this account",
                "cloud.cross_account", Severity.LOW, 0.6, items,
                hint="Another AWS account used a trust into this one. Expected for a "
                     "vendor you still use; anything else means a role trust should be "
                     "removed. Check the profile's cloud_accounts notes.",
                extra={"caller_account": caller}))

    def _denied(self, q: EventQuery, r: AnalyzerResult) -> None:
        rows = q.detail_rows(source=CT, action="denied")
        grouped = defaultdict(list)
        for row in rows:
            grouped[row["user"]].append(row)
        for user, items in grouped.items():
            apis = {i["program"] for i in items}
            if len(items) < DENIED_MIN_CALLS or len(apis) < DENIED_MIN_APIS:
                continue
            r.signals.append(self._signal(
                f"aws.permission_probing.{user}",
                f"{_short(user)} denied {len(items)} times across {len(apis)} APIs",
                "cloud.permission_probing", Severity.MEDIUM, 0.6, items,
                hint="Many different denied APIs from one identity is someone (or an "
                     "automated agent) finding out what stolen credentials can do. A "
                     "misconfigured tool repeats the same one or two APIs instead.",
                extra={"denied_apis": sorted(apis)[:20]}))

    def _sweeps(self, q: EventQuery, r: AnalyzerResult) -> None:
        checks = [
            ("secrets", q.detail_rows(source=CT, programs=SECRET_READS), SECRETS_SWEEP_MIN,
             Severity.HIGH, "cloud.secrets_sweep", "read {n} distinct secrets/parameters",
             lambda row: row["raw"].get("targets") or []),
            ("iam_enum", q.detail_rows(source=CT, program_prefixes=IAM_READ_PREFIXES),
             IAM_ENUM_MIN, Severity.MEDIUM, "cloud.iam_enumeration",
             "called {n} distinct IAM read APIs", lambda row: [row["program"]]),
            ("buckets", q.detail_rows(source=CT, program_prefixes=BUCKET_PREFIXES),
             BUCKET_SWEEP_MIN, Severity.MEDIUM, "cloud.bucket_sweep",
             "touched {n} distinct S3 buckets",
             lambda row: [t for t in row["raw"].get("targets") or [] if "/" not in t]),
        ]
        for label, rows, minimum, sev, taxonomy, title, key in checks:
            per_user: dict[str, set[str]] = defaultdict(set)
            items_by_user = defaultdict(list)
            for row in rows:
                if row["action"] != "ok" or _is_own(row):
                    continue
                per_user[row["user"]].update(key(row))
                items_by_user[row["user"]].append(row)
            for user, distinct in per_user.items():
                if len(distinct) < minimum:
                    continue
                items = items_by_user[user]
                console = all(i["raw"].get("from_console") for i in items)
                severity = Severity.LOW if console and sev < Severity.HIGH else sev
                r.signals.append(self._signal(
                    f"aws.{label}_sweep.{user}",
                    f"{_short(user)} {title.format(n=len(distinct))}", taxonomy,
                    severity, 0.6, items,
                    hint=("One identity reading many secrets, IAM objects or buckets in a "
                          "day is the automated sweep pattern published for agentic attack "
                          "tools (ARTEX and forks). Check whether this principal normally "
                          "does this (a backup or audit role) and where it called from. "
                          "Activity entirely from the AWS console is usually a person "
                          "browsing, so it is rated lower."),
                    extra={"distinct": sorted(distinct)[:20], "all_from_console": console}))

    def _regions(self, q: EventQuery, r: AnalyzerResult, profile: Profile) -> None:
        expected = set(read_list("DAWNPATROL_SOURCE_AWS_EXPECTED_REGIONS"))
        for acct in profile.cloud_accounts:
            expected.update(acct.expected_regions)
        if not expected:
            return
        rows = q.detail_rows(source=CT, severity="write", limit=50000)
        grouped = defaultdict(list)
        for row in rows:
            region = row["raw"].get("region") or ""
            service = (row["program"] or "").split(":", 1)[0]
            if region and region not in expected and service not in GLOBAL_SERVICES:
                grouped[region].append(row)
        for region, items in grouped.items():
            r.signals.append(self._signal(
                f"aws.unexpected_region.{region}",
                f"{len(items)} write call(s) in unused region {region}",
                "cloud.unexpected_region", Severity.MEDIUM, 0.65, items,
                hint="Resources launched where nobody looks (often EC2 for crypto-mining) "
                     "are a classic sign of stolen credentials. Check what was created.",
                extra={"region": region, "expected_regions": sorted(expected)}))

    # ----- the profile's per-account expectations -------------------------- #

    def _account_rules(self, q: EventQuery, r: AnalyzerResult, profile: Profile) -> None:
        for acct in profile.cloud_accounts:
            if acct.provider != "aws":
                continue
            mine = f"{acct.account_id}/"
            for pr in acct.principals:
                rows = [x for x in q.detail_rows(source=CT, user_suffix=pr.match)
                        if (x["device"] or "").startswith(mine)]
                if not rows:
                    continue
                if pr.dormant:
                    r.signals.append(self._signal(
                        f"aws.dormant_principal.{pr.match}",
                        f"Dormant identity {pr.match} was used", "cloud.dormant_principal",
                        Severity.HIGH, 0.85, rows,
                        hint=f"The profile marks this identity dormant: {pr.notes or 'no use expected'}. "
                             "Any activity means someone has its credentials."))
                if not pr.long_term_keys:
                    keyed = [x for x in rows
                             if str(x["raw"].get("access_key_id") or "").startswith("AKIA")]
                    if keyed:
                        r.signals.append(self._signal(
                            f"aws.long_term_key_use.{pr.match}",
                            f"{pr.match} called AWS with a long-term access key",
                            "cloud.unexpected_access_key", Severity.HIGH, 0.8, keyed,
                            hint="The profile says this identity never uses long-term "
                                 "access keys. A call signed with one (AKIA...) means a key "
                                 "exists and is being used: find and disable it.",
                            extra={"access_keys": sorted({x["raw"]["access_key_id"]
                                                          for x in keyed})}))
                if pr.allowed_services:
                    outside = [x for x in rows if (x["program"] or "").split(":", 1)[0]
                               not in pr.allowed_services]
                    if outside:
                        r.signals.append(self._signal(
                            f"aws.out_of_scope_service.{pr.match}",
                            f"{pr.match} called services outside its scope",
                            "cloud.principal_out_of_scope", Severity.HIGH, 0.8, outside,
                            hint=f"The profile limits this identity to "
                                 f"{', '.join(pr.allowed_services)}. Calls elsewhere (an "
                                 f"identity check, IAM listing) are what someone does after "
                                 f"stealing its keys.",
                            extra={"allowed_services": pr.allowed_services}))
                if pr.allowed_buckets:
                    stray = [x for x in rows if (x["program"] or "").startswith("s3:")
                             and any(t not in pr.allowed_buckets and "/" not in t
                                     for t in x["raw"].get("targets") or [])]
                    if stray:
                        r.signals.append(self._signal(
                            f"aws.out_of_scope_bucket.{pr.match}",
                            f"{pr.match} touched buckets outside its scope",
                            "cloud.principal_out_of_scope", Severity.HIGH, 0.8, stray,
                            hint=f"The profile limits this identity to "
                                 f"{', '.join(pr.allowed_buckets)}.",
                            extra={"allowed_buckets": pr.allowed_buckets,
                                   "buckets": sorted({t for x in stray
                                                      for t in x["raw"].get("targets") or []
                                                      if t not in pr.allowed_buckets})[:20]}))
            for blocked in acct.blocked_accounts:
                rows = [x for x in q.detail_rows(source=CT, raw_contains=blocked)
                        if (x["device"] or "").startswith(mine)]
                if rows:
                    r.signals.append(self._signal(
                        f"aws.blocked_account.{blocked}",
                        f"Account {blocked} appeared in this account's activity",
                        "cloud.blocked_account", Severity.HIGH, 0.85, rows,
                        hint="The profile says this account must never appear here (for "
                             "example a vendor that was removed). Find which trust or "
                             "resource still references it.",
                        extra={"blocked_account": blocked}))
            for wr in acct.watched_resources:
                rows = [x for x in q.detail_rows(source=CT, raw_contains=wr.match)
                        if (x["device"] or "").startswith(mine)]
                if rows:
                    r.signals.append(self._signal(
                        f"aws.watched_resource.{wr.match}",
                        f"Watched resource {wr.match} was touched",
                        "cloud.watched_resource", Severity.parse(wr.severity), 0.8, rows,
                        hint=f"The profile watches this name: {wr.note or 'any use is notable'}.",
                        extra={"watched": wr.match,
                               "requests": [x["raw"].get("request") for x in rows[:5]]}))

    # ----- stolen-key patterns ---------------------------------------------- #

    def _recon(self, q: EventQuery, r: AnalyzerResult, profile: Profile) -> None:
        """``sts:GetCallerIdentity`` followed within minutes by reads across
        several services, from one access key: the first thing anyone does
        with a key they've just found, before changing anything."""
        anchors = [a for a in q.detail_rows(source=CT, programs=["sts:GetCallerIdentity"])
                   if a["raw"].get("access_key_id")]
        by_key: dict[str, list[dict]] = defaultdict(list)
        for a in anchors:
            by_key[a["raw"]["access_key_id"]].append(a)
        for key, starts in by_key.items():
            user = starts[0]["user"]
            rows = [x for x in q.detail_rows(source=CT, user=user, limit=50000)
                    if x["raw"].get("access_key_id") == key
                    and x["program"] != "sts:GetCallerIdentity"
                    and x["raw"].get("event_category") != "Data"
                    and (x["raw"].get("read_only") or x["action"] == "denied")
                    and not _is_own(x)]
            best: list[dict] = []
            for start in starts:
                follow = [x for x in rows
                          if start["ts"] <= x["ts"] <= start["ts"] + RECON_WINDOW]
                if len({x["program"] for x in follow}) > len({x["program"] for x in best}):
                    best = [start, *follow]
            apis = {x["program"] for x in best[1:]}
            services = {a.split(":", 1)[0] for a in apis}
            if len(apis) < RECON_MIN_APIS or len(services) < RECON_MIN_SERVICES:
                continue
            rule = _principal_rule(profile, user)
            console = all(x["raw"].get("from_console") for x in best)
            severity = (Severity.LOW if console
                        else Severity.HIGH if rule and rule.allowed_services
                        else Severity.MEDIUM)
            denied = sum(1 for x in best if x["action"] == "denied")
            r.signals.append(self._signal(
                f"aws.key_recon.{key}",
                f"{_short(user)}: identity check then {len(apis)} read APIs across "
                f"{len(services)} services within {int(RECON_WINDOW.total_seconds() // 60)} min",
                "cloud.key_reconnaissance", severity, 0.7, best,
                hint=("Asking AWS 'who am I' and then listing what the key can reach is the "
                      "first thing done with a stolen key. Confirm the owner was exploring "
                      "by hand; otherwise disable the key. A single-purpose key (the profile "
                      "limits its services) has no reason to do this at all."),
                extra={"access_key": key, "services": sorted(services),
                       "read_apis": sorted(apis)[:20], "denied_calls": denied,
                       "long_term_key": key.startswith("AKIA"), "all_from_console": console}))

    def _key_networks(self, q: EventQuery, r: AnalyzerResult, baseline: Baseline) -> None:
        """A long-term key calling from a network it has never used.

        Compared with every address the key has used before: the same /24 is
        the same network (ignored), the same /16 the same provider's nearby
        range (LOW), anything further away MEDIUM. IPv6: /48 and /32.
        Silent until the key-network history exists, so the first run seeds it.
        """
        if not baseline.has_history(EntityType.KEY_NETWORK):
            return
        rows = q.detail_rows(source=CT, raw_contains='"access_key_id": "AKIA', limit=100000)
        by_key: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
        for row in rows:
            ip = row.get("src_ip")
            if ip and _is_global(ip):
                by_key[row["raw"]["access_key_id"]][ip].append(row)
        for key, per_ip in by_key.items():
            prior = [v.split("|", 1)[1] for v in
                     baseline.known_with_prefix(EntityType.KEY_NETWORK, f"{key}|")]
            fresh = [ip for ip in per_ip if ip not in prior]
            if not fresh:
                continue
            items = sorted((x for ip in fresh for x in per_ip[ip]), key=lambda x: x["ts"])
            user = items[0]["user"]
            if not prior:
                r.signals.append(self._signal(
                    f"aws.key_new_network.{key}",
                    f"{_short(user)}: long-term key {_key_tail(key)} used for the first time "
                    f"since monitoring began", "cloud.key_new_network", Severity.LOW, 0.5,
                    items,
                    hint="No earlier use of this access key is on record. Expected for a "
                         "newly created or rarely used key; check it was created on purpose.",
                    extra={"access_key": key, "new_addresses": fresh[:_LIST]}))
                continue
            worst = Severity.INFO
            detail = []
            for ip in fresh:
                bits, nearest = _closest(ip, prior)
                sev = _distance_severity(ip, bits)
                if sev is None:
                    continue
                worst = max(worst, sev)
                detail.append({"address": ip, "nearest_known": nearest,
                               "shared_prefix_bits": bits, "calls": len(per_ip[ip])})
            if not detail:
                continue
            noted = {d["address"] for d in detail}
            r.signals.append(self._signal(
                f"aws.key_new_network.{key}",
                f"{_short(user)}: long-term key {_key_tail(key)} used from "
                f"{len(detail)} new network(s)", "cloud.key_new_network", worst, 0.65,
                [x for x in items if x["src_ip"] in noted],
                hint=("A long-lived access key normally calls from the same place (a NAS, "
                      "a server, home). A new /16 is often the same provider renumbering "
                      "(LOW); a completely different network is where a leaked key gets "
                      "used. Check the address's owner and what the key did from there."),
                extra={"access_key": key, "new_networks": detail[:_LIST],
                       "known_addresses": len(prior)}))

    def _abuse(self, q: EventQuery, r: AnalyzerResult, profile: Profile) -> None:
        in_use = {s for acct in profile.cloud_accounts for s in acct.services_in_use}
        for service, (label, prefixes) in ABUSE_PROGRAMS.items():
            if service in in_use:
                continue
            rows = q.detail_rows(source=CT, program_prefixes=prefixes)
            if service == "sns":
                # Publishing to a topic is ordinary; to a phone number it's SMS.
                rows = [x for x in rows if x["program"] != "sns:Publish"
                        or "phoneNumber" in (x["raw"].get("request") or "")]
            grouped = defaultdict(list)
            for row in rows:
                if not _is_own(row):
                    grouped[row["user"]].append(row)
            for user, items in grouped.items():
                ok = [i for i in items if i["action"] == "ok"]
                console = all(i["raw"].get("from_console") for i in items)
                severity = Severity.HIGH if ok and not console else Severity.MEDIUM
                apis = sorted({i["program"] for i in items})
                r.signals.append(self._signal(
                    f"aws.abuse_service.{service}.{user}",
                    f"{_short(user)}: {label} ({', '.join(a.split(':', 1)[1] for a in apis[:4])})"
                    + ("" if ok else ", all denied"),
                    "cloud.abuse_service", severity, 0.75, items,
                    hint=("Stolen AWS keys are mostly used for money: running AI models on "
                          "the victim's bill (attackers first check model-invocation "
                          "logging is off), sending spam or SMS, or raising quotas to mine "
                          "crypto. This account doesn't use the service, so confirm the "
                          "owner did this; a denied attempt still means someone tried. "
                          "Console-only activity is usually a person browsing."),
                    extra={"service": service, "succeeded": len(ok),
                           "checked_logging": any("InvocationLoggingConfiguration" in a
                                                  for a in apis),
                           "all_from_console": console}))

    def _backups(self, q: EventQuery, r: AnalyzerResult, profile: Profile) -> None:
        """Object deletion and ransomware-style encryption (S3 data events), and
        retention changes on the profile's backup buckets."""
        deletes = q.detail_rows(source=CT, programs=OBJECT_DELETES, limit=100000)
        writes = q.detail_rows(source=CT, programs=OBJECT_WRITES, raw_contains="SSE_C")
        if deletes or q.count(source=CT, program=OBJECT_WRITES):
            r.metrics += [
                Metric(key="aws.s3.object_writes", value=q.count(source=CT, program=OBJECT_WRITES),
                       section="cloud", label="S3 object writes (data events)"),
                Metric(key="aws.s3.object_deletes", value=len(deletes), section="cloud",
                       label="S3 object deletes (data events)"),
            ]
        minimum = read_int("DAWNPATROL_SOURCE_AWS_MASS_DELETE_MIN", MASS_DELETE_MIN)
        grouped = defaultdict(list)
        for row in deletes:
            if row["action"] == "ok":
                bucket = next(iter(row["raw"].get("targets") or []), "?")
                grouped[(row["user"], bucket)].append(row)
        for (user, bucket), items in grouped.items():
            if len(items) < minimum:
                continue
            r.signals.append(self._signal(
                f"aws.mass_delete.{bucket}.{user}",
                f"{_short(user)} deleted {len(items)} objects from {bucket}",
                "cloud.mass_delete", Severity.HIGH if len(items) >= 10 * minimum
                else Severity.MEDIUM, 0.7, items,
                hint=("Bulk deletion from a bucket is how backups are destroyed before (or "
                      "instead of) ransom. A sync tool pruning old files deletes too: "
                      "compare with this principal's normal runs and its user agent."),
                extra={"bucket": bucket, "deleted": len(items),
                       "sample_keys": [i["raw"].get("object_key") for i in items[:10]]}))
        sse_c = defaultdict(list)
        for row in writes:
            if row["raw"].get("sse") == "SSE_C":
                sse_c[row["user"]].append(row)
        for user, items in sse_c.items():
            buckets = sorted({t for i in items for t in i["raw"].get("targets") or []})
            r.signals.append(self._signal(
                f"aws.sse_c_writes.{user}",
                f"{_short(user)} wrote {len(items)} objects encrypted with its own key (SSE-C)",
                "cloud.ransomware_encryption", Severity.HIGH, 0.85, items,
                hint=("Objects written with a customer-supplied key can only be read with "
                      "that key, which AWS doesn't keep. Re-encrypting a bucket's files "
                      "this way is a published S3 ransomware technique (Codefinger, 2025). "
                      "Disable the key now and check the bucket's versions."),
                extra={"buckets": buckets[:_LIST],
                       "sample_keys": [i["raw"].get("object_key") for i in items[:10]]}))

        backups = {b for acct in profile.cloud_accounts for b in acct.backup_buckets}
        if not backups:
            return
        rows = [x for x in q.detail_rows(source=CT, programs=BACKUP_RETENTION)
                if x["action"] == "ok" and set(x["raw"].get("targets") or []) & backups
                and (x["program"] != "s3:PutBucketVersioning"
                     or "Suspended" in (x["raw"].get("request") or ""))]
        grouped = defaultdict(list)
        for row in rows:
            grouped[row["user"]].append(row)
        for user, items in grouped.items():
            r.signals.append(self._signal(
                f"aws.backup_retention.{user}",
                f"{_short(user)} weakened backup protection "
                f"({', '.join(sorted({i['program'].split(':', 1)[1] for i in items}))})",
                "cloud.backup_retention_change", Severity.HIGH, 0.8, items,
                hint=("Suspending versioning, adding expiry rules, removing Object Lock or "
                      "replication, or deleting a backup bucket makes the backups "
                      "destroyable - the step before deleting them. Confirm the owner "
                      "made this change (evidence.requests)."),
                extra={"buckets": sorted({t for i in items
                                          for t in i["raw"].get("targets") or []} & backups),
                       "requests": [i["raw"].get("request") for i in items[:5]]}))

    # ----- posture snapshot -------------------------------------------------- #

    def _posture(self, q: EventQuery, r: AnalyzerResult) -> None:
        rows = q.detail_rows(source=PO)
        r.metrics.append(Metric(key="aws.posture.items", value=len(rows), section="cloud",
                                label="Posture snapshot items"))
        grouped = defaultdict(list)
        for row in rows:
            if row["action"] == "critical":
                grouped[(row["action"], row["program"], row["raw"].get("subject"))].append(row)
            else:
                grouped[(row["action"], row["program"], None)].append(row)
        hints = {
            "critical": "A state that is dangerous for as long as it lasts; reported on "
                        "every snapshot until fixed.",
            "issue": "A weakness found in the account's configuration. On the first "
                     "snapshot every existing one is listed once, at LOW, as the starting "
                     "inventory; after that only new ones appear.",
            "change": "The account's configuration differs from the previous daily "
                      "snapshot. Match each change to something the owner did; "
                      "evidence.changes has before and after.",
            "resolved": "An earlier posture issue is no longer present.",
        }
        for (action, program, subject), items in grouped.items():
            area = program.split(":", 1)[1]
            worst = max(Severity.parse(i["severity"] or "INFO") for i in items)
            first = any(i["raw"].get("first_snapshot") for i in items)
            title = (items[0]["message"] if len(items) == 1
                     else f"{len(items)} {area.replace('_', ' ')} posture {action}s")
            if action == "issue" and first:
                title = f"Starting inventory: {title}"
            r.signals.append(self._signal(
                f"aws.posture.{action}.{area}" + (f".{subject}" if subject else ""),
                f"AWS posture: {title}", f"cloud.posture_{action}", worst,
                0.8 if action in ("critical", "change") else 0.6, items,
                hint=hints.get(action, ""),
                extra={"items": [i["message"] for i in items[:20]],
                       "changes": [{"subject": i["raw"].get("subject"),
                                    "before": i["raw"].get("before"),
                                    "after": i["raw"].get("after")}
                                   for i in items[:10] if action == "change"]}))

    # ----- GuardDuty -------------------------------------------------------- #

    def _guardduty(self, q: EventQuery, r: AnalyzerResult) -> None:
        rows = q.detail_rows(source=GD, kind=EventKind.IDS)
        r.metrics.append(Metric(key="aws.gd.findings", value=len(rows), section="cloud",
                                label="GuardDuty findings updated"))
        grouped = defaultdict(list)
        for row in rows:
            grouped[row["program"]].append(row)
        for ftype, items in grouped.items():
            sample = all(i["raw"].get("sample") for i in items)
            worst = max(Severity.parse(i["severity"] or "LOW") for i in items)
            severity = Severity.INFO if sample else worst
            top = max(items, key=lambda i: i["raw"].get("score") or 0)
            title = f"GuardDuty: {top['message']}"
            if sample:
                title = f"GuardDuty sample finding: {ftype}"
            r.signals.append(self._signal(
                f"aws.guardduty.{ftype}", title[:200], "cloud.guardduty_finding",
                severity, 0.85 if not sample else 0.3, items,
                hint=("GuardDuty's own detection; its description is in evidence. "
                      "Sample findings exist only to test the pipeline." if sample else
                      "GuardDuty's own detection, rated with its severity; its "
                      "description is in evidence. Confirm against the resource and the "
                      "remote address before acting."),
                extra={"finding_type": ftype, "max_score": top["raw"].get("score"),
                       "description": top["raw"].get("description"),
                       "resources": sorted({i["raw"].get("instance_id") or
                                            i["raw"].get("access_key_id") or
                                            i["raw"].get("resource_type") or "?"
                                            for i in items})[:_LIST],
                       "sample": sample}))

    # ----- shared ----------------------------------------------------------- #

    def _signal(self, sid: str, title: str, taxonomy: str, severity: Severity,
                confidence: float, items: list[dict[str, Any]], *, hint: str,
                extra: dict[str, Any] | None = None) -> Signal:
        users = sorted({i["user"] for i in items if i.get("user")})
        ips = sorted({i["src_ip"] for i in items if i.get("src_ip")})
        evidence: dict[str, Any] = {
            "events": len(items),
            "apis": sorted({i["program"] for i in items if i.get("program")})[:_LIST],
            "principals": users[:_LIST],
            "source_ips": ips[:_LIST],
            "accounts_regions": sorted({i["device"] for i in items if i.get("device")})[:_LIST],
            "user_agents": sorted({(i["raw"].get("user_agent") or "")[:120]
                                   for i in items if i["raw"].get("user_agent")})[:5],
            "error_codes": sorted({i["raw"].get("error_code") for i in items
                                   if i["raw"].get("error_code")})[:_LIST],
            "first_seen": items[0]["ts"].strftime("%Y-%m-%d %H:%M UTC"),
            "last_seen": items[-1]["ts"].strftime("%Y-%m-%d %H:%M UTC"),
            **(extra or {}),
        }
        entities = [Entity(EntityType.USER, u, "principal") for u in users[:_LIST]]
        entities += [Entity(EntityType.IP, ip, "source") for ip in ips[:_LIST]]
        return Signal(id=sid[:255], analyzer=self.name, title=title[:200], taxonomy=taxonomy,
                      severity_hint=severity, confidence=confidence, entities=entities,
                      evidence=evidence, narrative_hint=hint)


def _short(arn: str) -> str:
    return arn.rsplit("/", 1)[-1] if "/" in arn else arn.rsplit(":", 1)[-1]


def _key_tail(key: str) -> str:
    return f"...{key[-4:]}"


def _is_global(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _closest(ip: str, known: list[str]) -> tuple[int, str | None]:
    """Longest prefix (bits) ``ip`` shares with any known address of its family."""
    addr = ipaddress.ip_address(ip)
    best, nearest = 0, None
    for other in known:
        try:
            o = ipaddress.ip_address(other)
        except ValueError:
            continue
        if o.version != addr.version:
            continue
        diff = int(addr) ^ int(o)
        bits = addr.max_prefixlen - diff.bit_length()
        if nearest is None or bits > best:
            best, nearest = bits, other
    return best, nearest


def _distance_severity(ip: str, shared_bits: int) -> Severity | None:
    """IPv4: same /24 None (ignore), same /16 LOW, else MEDIUM. IPv6: /48, /32."""
    v6 = ":" in ip
    if shared_bits >= (48 if v6 else 24):
        return None
    if shared_bits >= (32 if v6 else 16):
        return Severity.LOW
    return Severity.MEDIUM


def _own_key() -> str:
    return read_env("DAWNPATROL_SOURCE_AWS_ACCESS_KEY_ID", "") or ""


def _is_own(row: dict[str, Any]) -> bool:
    """A call DawnPatrol itself makes, with its own key."""
    own = _own_key()
    return bool(own) and row["raw"].get("access_key_id") == own and \
        any((row.get("program") or "").startswith(p) for p in OWN_FOOTPRINT)


def _principal_rule(profile: Profile, user: str | None) -> Any:
    for acct in profile.cloud_accounts:
        for pr in acct.principals:
            if user and user.endswith(pr.match):
                return pr
    return None
