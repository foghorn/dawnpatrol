# Setting up AWS for DawnPatrol (CloudTrail, GuardDuty and posture)

DawnPatrol reads two things from an AWS account:

- **CloudTrail**: a record of every API call made in the account (who did what,
  from where, and whether it was allowed). DawnPatrol reads it from the S3 bucket
  a trail delivers to, and the `cloud_activity` analyzer looks for root use,
  sign-ins without MFA, logging being switched off, new keys and policies,
  permission probing, secret/IAM/bucket sweeps, and activity in regions you
  don't use.
- **GuardDuty**: AWS's own threat detection. DawnPatrol collects its findings
  through the API and reports each finding type at GuardDuty's severity.
- **Posture** (optional): once a day, DawnPatrol reads the account's security
  settings and reports what changed. That covers IAM users, keys and MFA, the
  password policy, buckets, trails, detectors, DNS and CloudFront.

This guide builds everything with the AWS CLI:

1. a private, encrypted S3 bucket for CloudTrail logs;
2. a multi-region trail writing to it;
3. GuardDuty in each region you use;
4. a dedicated, read-only IAM identity for DawnPatrol;
5. the DawnPatrol settings, and a test.

Each step can be run again safely or skipped if you already have the piece:
an existing trail and bucket work as they are, so jump to step 4 and point
DawnPatrol at them.

## 0. Before you start

You need AWS CLI v2, signed in as an administrator of the account (`aws sts
get-caller-identity` should print your admin identity). Set these once in the
shell you'll run the steps from:

```bash
export AWS_REGION=us-east-1                    # your main region
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export TRAIL=dawnpatrol-trail
export BUCKET=cloudtrail-logs-${ACCOUNT_ID}    # S3 names are global; this keeps it unique
export REGIONS="us-east-1 us-west-2"           # every region you run anything in
```

**Costs to expect.** These are the drivers; check current figures on the AWS
pricing pages for CloudTrail, GuardDuty and S3.

- One trail's copy of *management* events is free. Data events (S3 object
  calls, Lambda invokes) are charged per event; step 2a logs only writes and
  deletes on the backup buckets, so the cost follows how much your backups
  upload.
- S3 storage for a small account's trail is cents per month. The lifecycle rule
  in step 1 caps how long logs are kept.
- GuardDuty is charged by the volume of logs it analyzes, after a 30-day free
  trial per region. `aws guardduty get-usage-statistics` (step 3) shows the
  running cost.
- DawnPatrol's own reads (S3 list/get, a few GuardDuty API calls) cost a
  fraction of a cent per day.

## 1. A bucket for CloudTrail logs

Create the bucket. `us-east-1` must not be given a location constraint; every
other region must:

```bash
if [ "$AWS_REGION" = "us-east-1" ]; then
  aws s3api create-bucket --bucket "$BUCKET" --region "$AWS_REGION"
else
  aws s3api create-bucket --bucket "$BUCKET" --region "$AWS_REGION" \
    --create-bucket-configuration LocationConstraint="$AWS_REGION"
fi
```

Make it private and encrypted, and expire logs after a year (adjust `Days` to
how far back you want to be able to look):

```bash
aws s3api put-public-access-block --bucket "$BUCKET" \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

aws s3api put-bucket-encryption --bucket "$BUCKET" \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

aws s3api put-bucket-lifecycle-configuration --bucket "$BUCKET" \
  --lifecycle-configuration \
  '{"Rules":[{"ID":"expire-cloudtrail","Status":"Enabled","Filter":{"Prefix":"AWSLogs/"},"Expiration":{"Days":365}}]}'
```

Allow CloudTrail, and only this trail, to write into it:

```bash
cat > cloudtrail-bucket-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::${BUCKET}",
      "Condition": {"StringEquals": {
        "aws:SourceArn": "arn:aws:cloudtrail:${AWS_REGION}:${ACCOUNT_ID}:trail/${TRAIL}"}}
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::${BUCKET}/AWSLogs/${ACCOUNT_ID}/*",
      "Condition": {"StringEquals": {
        "s3:x-amz-acl": "bucket-owner-full-control",
        "aws:SourceArn": "arn:aws:cloudtrail:${AWS_REGION}:${ACCOUNT_ID}:trail/${TRAIL}"}}
    }
  ]
}
EOF
aws s3api put-bucket-policy --bucket "$BUCKET" --policy file://cloudtrail-bucket-policy.json
```

## 2. A multi-region trail

One trail covering every region, including global services like IAM and
sign-in (which log in `us-east-1`), with log-file integrity validation:

```bash
aws cloudtrail create-trail --name "$TRAIL" --s3-bucket-name "$BUCKET" \
  --is-multi-region-trail --include-global-service-events \
  --enable-log-file-validation --region "$AWS_REGION"

aws cloudtrail start-logging --name "$TRAIL" --region "$AWS_REGION"
```

A new trail records read and write management events by default, which is
what DawnPatrol's checks need. Confirm:

```bash
aws cloudtrail get-event-selectors --trail-name "$TRAIL" --region "$AWS_REGION"
aws cloudtrail get-trail-status --name "$TRAIL" --region "$AWS_REGION" \
  --query '{logging:IsLogging,lastDelivery:LatestDeliveryTime,error:LatestDeliveryError}'
```

The first log files land in the bucket within about 15 minutes:

```bash
aws s3 ls "s3://${BUCKET}/AWSLogs/${ACCOUNT_ID}/CloudTrail/" --recursive | head
```

### 2a. S3 data events on backup buckets (recommended)

Management events don't include object reads, writes or deletes, so a backup
bucket can be emptied or re-encrypted without a trace. Data events fix that.
They're charged per event, so log only writes and deletes, and only on the
buckets that matter:

```bash
aws cloudtrail put-event-selectors --trail-name "$TRAIL" --region "$AWS_REGION" \
  --advanced-event-selectors '[
 {"Name":"Management events",
  "FieldSelectors":[{"Field":"eventCategory","Equals":["Management"]}]},
 {"Name":"Backup bucket writes and deletes",
  "FieldSelectors":[
   {"Field":"eventCategory","Equals":["Data"]},
   {"Field":"resources.type","Equals":["AWS::S3::Object"]},
   {"Field":"eventName","Equals":[
     "PutObject","CopyObject","CreateMultipartUpload",
     "DeleteObject","DeleteObjects","PutObjectAcl",
     "PutObjectRetention","PutObjectLegalHold"]},
   {"Field":"resources.ARN","StartsWith":[
     "arn:aws:s3:::example-backups/"]}]}
]'
```

List each bucket as `arn:aws:s3:::<bucket>/`; the trailing slash keeps
`backups/` from also matching `backups-old/`. `UploadPart` is left out
because a large upload makes thousands of them; `CreateMultipartUpload`
carries the same encryption headers. Name the same buckets in the profile's
`backup_buckets`. With this on, DawnPatrol reports:

- mass deletion by one identity, at 100 or more objects
  (`DAWNPATROL_SOURCE_AWS_MASS_DELETE_MIN`);
- objects written with a customer-supplied key (SSE-C), the ransomware
  technique of re-encrypting your files with the attacker's key;
- versioning suspended, expiry rules added, or Object Lock, replication or the
  bucket itself removed on a backup bucket.

Running `put-event-selectors` is itself reported, as a logging change. Record it
in the profile's notes as yours.

The real protection is versioning, so a deleted or overwritten object can be
recovered. DawnPatrol then reports anyone turning it off:

```bash
aws s3api put-bucket-versioning --bucket example-backups \
  --versioning-configuration Status=Enabled
```

Expire old versions so they don't pile up. First check that the bucket has no
lifecycle rules (`aws s3api get-bucket-lifecycle-configuration --bucket
example-backups`), because the command below replaces them:

```bash
aws s3api put-bucket-lifecycle-configuration --bucket example-backups \
  --lifecycle-configuration '{"Rules":[{"ID":"expire-old-versions",
 "Status":"Enabled","Filter":{},
 "NoncurrentVersionExpiration":{"NoncurrentDays":30}}]}'
```

## 3. GuardDuty in each region

GuardDuty is regional: a region without a detector is a blind spot, and
DawnPatrol reports it as one. Enable it everywhere you run anything:

```bash
for r in $REGIONS; do
  existing=$(aws guardduty list-detectors --region "$r" --query 'DetectorIds[0]' --output text)
  if [ "$existing" = "None" ]; then
    aws guardduty create-detector --enable \
      --finding-publishing-frequency FIFTEEN_MINUTES --region "$r"
  else
    echo "$r: detector $existing already exists"
  fi
done
```

Check it, and see the running cost estimate:

```bash
for r in $REGIONS; do
  d=$(aws guardduty list-detectors --region "$r" --query 'DetectorIds[0]' --output text)
  aws guardduty get-detector --detector-id "$d" --region "$r" --query Status --output text
  aws guardduty get-usage-statistics --detector-id "$d" --region "$r" \
    --usage-statistic-type SUM_BY_DATA_SOURCE \
    --usage-criteria '{"DataSources":["CLOUD_TRAIL","FLOW_LOGS","DNS_LOGS"]}'
done
```

## 4. A read-only identity for DawnPatrol

DawnPatrol needs to list and read the trail's log files, check the trail is
still logging, and read GuardDuty findings. Nothing else, and no write access
anywhere:

```bash
cat > dawnpatrol-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid": "ListTrailBucket", "Effect": "Allow",
     "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::${BUCKET}"},
    {"Sid": "ReadTrailLogs", "Effect": "Allow",
     "Action": "s3:GetObject", "Resource": "arn:aws:s3:::${BUCKET}/AWSLogs/*"},
    {"Sid": "TrailHealth", "Effect": "Allow",
     "Action": ["cloudtrail:GetTrailStatus", "cloudtrail:DescribeTrails"],
     "Resource": "*"},
    {"Sid": "GuardDutyRead", "Effect": "Allow",
     "Action": ["guardduty:ListDetectors", "guardduty:GetDetector",
                "guardduty:ListFindings", "guardduty:GetFindings"],
     "Resource": "*"},
    {"Sid": "PostureRead", "Effect": "Allow",
     "Action": ["iam:GenerateCredentialReport", "iam:GetCredentialReport",
                "iam:GetAccountPasswordPolicy", "s3:ListAllMyBuckets",
                "s3:GetBucketVersioning", "s3:GetBucketPublicAccessBlock",
                "s3:GetBucketPolicyStatus", "s3:GetBucketObjectLockConfiguration",
                "s3:GetAccountPublicAccessBlock", "route53:ListHostedZones",
                "route53:ListResourceRecordSets", "cloudfront:ListDistributions",
                "elasticbeanstalk:DescribeEnvironments"],
     "Resource": "*"}
  ]
}
EOF
aws iam create-policy --policy-name DawnPatrolReadOnly \
  --policy-document file://dawnpatrol-policy.json
```

`PostureRead` is only needed for the posture snapshot (step 5); leave it out
if you don't turn that on. All of it is read-only: the credential report lists
users and when their passwords and keys were last used, never the secrets
themselves.

**Adding posture to an existing policy.** A managed policy can't be edited in
place. Save the full document above (with `PostureRead`) as a new default
version. AWS keeps up to five versions; delete an old one with
`aws iam delete-policy-version` if it complains:

```bash
aws iam create-policy-version --set-as-default \
  --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/DawnPatrolReadOnly" \
  --policy-document file://dawnpatrol-policy.json
```

That change is itself reported as an IAM change; record it in the profile's
notes as yours.

If the trail writes under a key prefix, change the `ReadTrailLogs` resource to
`arn:aws:s3:::${BUCKET}/<prefix>/AWSLogs/*`. If the bucket uses SSE-KMS rather
than the default encryption from step 1, also allow `kms:Decrypt` on that key.

**Option A: an IAM user with an access key.** This is the simple choice when
DawnPatrol runs outside AWS, as on a home server:

```bash
aws iam create-user --user-name dawnpatrol
aws iam attach-user-policy --user-name dawnpatrol \
  --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/DawnPatrolReadOnly"
aws iam create-access-key --user-name dawnpatrol \
  --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text
```

The secret is shown only once; it goes straight into DawnPatrol's `.env` in
step 5. Rotate it like any long-lived key: create a second key, switch
DawnPatrol to it, then delete the first with `aws iam delete-access-key`.

**Option B: a role.** Use a role when DawnPatrol runs on EC2/ECS (attach the
policy to the instance or task role and set no credentials at all), or when one
DawnPatrol identity reads a different account. For the cross-account case,
create the role in the monitored account, trusting the identity DawnPatrol runs
as:

```bash
cat > dawnpatrol-trust.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::<DAWNPATROL_ACCOUNT_ID>:user/dawnpatrol"},
    "Action": "sts:AssumeRole",
    "Condition": {"StringEquals": {"sts:ExternalId": "<a-random-string>"}}
  }]
}
EOF
aws iam create-role --role-name DawnPatrolReadOnly \
  --assume-role-policy-document file://dawnpatrol-trust.json
aws iam attach-role-policy --role-name DawnPatrolReadOnly \
  --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/DawnPatrolReadOnly"
```

Then set `DAWNPATROL_SOURCE_AWS_ROLE_ARN` and `..._EXTERNAL_ID` in step 5. The
identity DawnPatrol starts as also needs `sts:AssumeRole` on that role ARN.

## 5. Configure DawnPatrol

In `.env` (never commit this file):

```bash
# Credentials (option A). Leave both unset to use the default AWS chain
# (instance/task role, AWS_PROFILE, ~/.aws mounted into the container).
DAWNPATROL_SOURCE_AWS_ACCESS_KEY_ID=AKIA...
DAWNPATROL_SOURCE_AWS_SECRET_ACCESS_KEY=...
DAWNPATROL_SOURCE_AWS_REGION=us-east-1
# Option B, on top of either:
#DAWNPATROL_SOURCE_AWS_ROLE_ARN=arn:aws:iam::111122223333:role/DawnPatrolReadOnly
#DAWNPATROL_SOURCE_AWS_EXTERNAL_ID=<a-random-string>

# CloudTrail: setting the bucket switches the aws_cloudtrail source on.
DAWNPATROL_SOURCE_AWS_CLOUDTRAIL_BUCKET=cloudtrail-logs-111122223333
#DAWNPATROL_SOURCE_AWS_CLOUDTRAIL_PREFIX=          # only if the trail uses one
DAWNPATROL_SOURCE_AWS_CLOUDTRAIL_TRAIL=dawnpatrol-trail   # alerts if logging stops

# GuardDuty: setting the regions switches the aws_guardduty source on.
DAWNPATROL_SOURCE_AWS_GUARDDUTY_REGIONS=us-east-1,us-west-2

# Write activity anywhere else is reported (global services excepted).
DAWNPATROL_SOURCE_AWS_EXPECTED_REGIONS=us-east-1,us-west-2

# Daily posture snapshot (needs PostureRead from step 4).
DAWNPATROL_SOURCE_AWS_POSTURE=true
#DAWNPATROL_SOURCE_AWS_POSTURE_INTERVAL_HOURS=20
```

The posture snapshot is kept in the data folder (`aws-posture.json`). The first
one lists every weakness it finds once, at LOW, as a starting inventory. From
then on you see:
- critical states every day until they're fixed: root access keys, root
  without MFA, a trail not logging, a detector missing;
- new weaknesses once, at their own level;
- every change since the previous day.

DNS names and CloudFront origins that point at an S3 bucket or Elastic
Beanstalk name that doesn't exist in the account are reported as dangling, at
HIGH, because whoever creates that name serves content under your domain.

Then describe the account in `profile.yml` with a `cloud_accounts` entry (a
commented example is in `config/profile.example.yml`; the fields are in
`docs/components/profile.md`). Its `notes` and per-principal notes tell the model
what is normal, so routine activity ("the `ci-deploy` role rotates its keys every
pipeline run") isn't reported as suspicious. Its rules turn what should *never*
happen into HIGH signals:

- `dormant: true` for identities nobody should use;
- `long_term_keys: false` for people who only use the console;
- `allowed_services` / `allowed_buckets` for single-purpose keys;
- `blocked_accounts` for vendors you've removed;
- `watched_resources` for names an attacker would target, such as dangling DNS
  names and orphaned secrets;
- `backup_buckets` for buckets holding backups (retention changes are HIGH);
- `services_in_use` for any of `bedrock`, `ses`, `sns`, `sms-voice` or
  `servicequotas` you really use. Calls to the others are reported, because
  they're how stolen keys are cashed in.

Long-term access keys need no setting. Each one's source addresses are recorded,
and a call from a new network is reported: the same /24 as before is ignored,
the same /16 is LOW, and anything further away is MEDIUM.

Set `expected_regions` there too.

## 6. Test it

Restart the container so it picks up the settings, then:

```bash
docker exec dawnpatrol dawnpatrol list-plugins   # aws_cloudtrail, aws_guardduty, aws_posture, cloud_activity: ENABLED
docker exec dawnpatrol dawnpatrol probe          # credentials, bucket, trail-logging, detector-<region>, posture-*
```

To see a GuardDuty finding travel the whole pipeline, create a sample one.
DawnPatrol reports sample findings at INFO so they never raise the report's
status:

```bash
d=$(aws guardduty list-detectors --region "$AWS_REGION" --query 'DetectorIds[0]' --output text)
aws guardduty create-sample-findings --detector-id "$d" --region "$AWS_REGION" \
  --finding-types "Recon:EC2/PortProbeUnprotectedPort"

docker exec dawnpatrol dawnpatrol run --dry-run --print
```

The report gains a **Cloud** block in its statistics (CloudTrail events, write
events, access-denied calls, principals, GuardDuty findings), and any CloudTrail
or GuardDuty finding appears with the rest. Archive the sample afterwards:

```bash
recent=$(aws guardduty list-findings --detector-id "$d" --region "$AWS_REGION" \
  --max-items 50 --query FindingIds --output text)
samples=$(aws guardduty get-findings --detector-id "$d" --region "$AWS_REGION" \
  --finding-ids $recent \
  --query 'Findings[?Service.AdditionalInfo.Sample==`true`].Id' --output text)
[ -n "$samples" ] && aws guardduty archive-findings --detector-id "$d" \
  --region "$AWS_REGION" --finding-ids $samples
```

This checks the 50 most recent findings, which covers a sample you just
created.

## Several accounts (AWS Organizations)

For an organization, use one **organization trail** in the management account
(`create-trail ... --is-organization-trail`). It writes every member account's
logs to one bucket under `AWSLogs/<org-id>/<account-id>/`, which DawnPatrol
reads as is; `DAWNPATROL_SOURCE_AWS_CLOUDTRAIL_ACCOUNTS` narrows it to chosen
accounts. The bucket policy's `AWSCloudTrailWrite` statement then needs the
organization path too (`arn:aws:s3:::${BUCKET}/AWSLogs/<org-id>/*`), as AWS's
organization-trail documentation shows. For GuardDuty, designate a delegated administrator account
(`aws guardduty enable-organization-admin-account`) so all members' findings
are visible from it, and point DawnPatrol's credentials (or role) at that
account.

## Undoing it

```bash
aws cloudtrail stop-logging --name "$TRAIL" --region "$AWS_REGION"
aws cloudtrail delete-trail --name "$TRAIL" --region "$AWS_REGION"
for r in $REGIONS; do
  d=$(aws guardduty list-detectors --region "$r" --query 'DetectorIds[0]' --output text)
  [ "$d" != "None" ] && aws guardduty delete-detector --detector-id "$d" --region "$r"
done
for k in $(aws iam list-access-keys --user-name dawnpatrol \
             --query 'AccessKeyMetadata[].AccessKeyId' --output text); do
  aws iam delete-access-key --user-name dawnpatrol --access-key-id "$k"
done
aws iam detach-user-policy --user-name dawnpatrol \
  --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/DawnPatrolReadOnly"
aws iam delete-user --user-name dawnpatrol
aws iam delete-policy --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/DawnPatrolReadOnly"
# The bucket keeps the logs until you empty and delete it:
#   aws s3 rm "s3://${BUCKET}" --recursive && aws s3api delete-bucket --bucket "$BUCKET"
```

Stopping the trail is exactly what the `cloud.logging_tampering` check
watches for, so expect the next DawnPatrol run to report it.
