"""AWS account activity: CloudTrail behaviour checks and GuardDuty findings.

Reads events from ``sources/aws_cloudtrail.py`` and ``sources/aws_guardduty.py``
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
* GuardDuty findings, one signal per finding type at GuardDuty's severity

Thresholds are module constants. Anything legitimate that trips one (a CI role
that rotates keys, an auditor's read-only sweep) belongs in the profile's
known_quirks or a suppression, not in a raised threshold.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..models import AnalyzerResult, Entity, EntityType, EventKind, Metric, Severity, Signal
from ..profile import Profile
from ..query import EventQuery
from ..secrets import read_list
from .base import Analyzer
from .baseline import Baseline

CT = "aws_cloudtrail"
GD = "aws_guardduty"

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
    requires_sources = frozenset({CT, GD})
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
        if q.count(source=GD):
            self._guardduty(q, r)
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
                if row["action"] != "ok":
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
