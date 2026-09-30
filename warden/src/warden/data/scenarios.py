"""Scenario library: the 20 incidents in datasets/v1.

Three tiers, deliberately unbalanced toward the ones that hurt:

  easy  (9)  malicious, single-principal, signal is contiguous
  noisy (7)  benign, but shaped like an attack. Only the principal's BASELINE
             distinguishes them. An agent that never calls describe_principal()
             should fail every one of these — that is the point.
  hard  (4)  malicious, multi-hop. Signal is split across principals, sessions
             or days, and each carries distractors that look better than the
             real evidence.

Every builder returns signal events only. Background noise is layered on by
generator.py, which also assigns the final event ordering.
"""

from __future__ import annotations

from dataclasses import dataclass, field


def starts_at(hour: int, minute: int):
    """Pin a scenario's t0 time-of-day (UTC). Only for scenarios whose alert text or answer key
    makes a claim about the clock, e.g. "inside the 02:00-05:00 backup window"; everything else
    keeps its staggered random start."""
    def deco(fn):
        fn.start_utc = (hour, minute)
        return fn
    return deco

# --- the cast ----------------------------------------------------------------
# Shared across all incidents so describe_principal() is a stable global lookup.
CAST = {
    "alice.chen": dict(
        principal_id="AIDA00000000000000001", principal_type="IAMUser", is_service=False,
        department="Data Engineering", created_days_ago=980,
        home_regions=["us-east-1", "us-west-2"],
        typical_events=["GetObject", "ListBucket", "PutObject", "StartQueryExecution", "ConsoleLogin"],
        typical_hours_utc=[13, 23], known_asns=["AS7922 Comcast", "AS14618 Amazon"],
        notes="Owns the analytics-lake pipelines. Routinely reads s3://acme-analytics-lake.",
    ),
    "bob.martins": dict(
        principal_id="AIDA00000000000000002", principal_type="IAMUser", is_service=False,
        department="Platform Engineering", created_days_ago=1420,
        home_regions=["us-east-1"],
        typical_events=["DescribeInstances", "GetObject", "ConsoleLogin", "AssumeRole"],
        typical_hours_utc=[12, 22], known_asns=["AS7922 Comcast"],
        notes="Platform on-call. Assumes svc-ci-deploy during releases.",
    ),
    "priya.rao": dict(
        principal_id="AIDA00000000000000003", principal_type="IAMUser", is_service=False,
        department="Security", created_days_ago=610,
        home_regions=["us-east-1", "eu-west-1"],
        typical_events=["LookupEvents", "DescribeTrails", "GetBucketPolicy", "ConsoleLogin"],
        typical_hours_utc=[8, 18], known_asns=["AS3320 DTAG", "AS7922 Comcast"],
        notes="Detection engineer. Read-only across the estate by design.",
    ),
    "dana.okafor": dict(
        principal_id="AIDA00000000000000004", principal_type="IAMUser", is_service=False,
        department="Finance", created_days_ago=240,
        home_regions=["us-east-1"],
        typical_events=["GetObject", "ConsoleLogin", "GetCostAndUsage"],
        typical_hours_utc=[13, 22], known_asns=["AS701 Verizon"],
        notes="Reads s3://acme-finance-reports only. No infrastructure access.",
    ),
    "marcus.webb": dict(
        principal_id="AIDA00000000000000005", principal_type="IAMUser", is_service=False,
        department="Data Engineering", created_days_ago=95,
        home_regions=["us-east-1"],
        typical_events=["GetObject", "ListBucket", "ConsoleLogin"],
        typical_hours_utc=[13, 23], known_asns=["AS7922 Comcast"],
        notes="Joined 3 months ago. Scoped to s3://acme-analytics-lake/project-atlas/ only.",
    ),
    "admin-breakglass": dict(
        principal_id="AIDA00000000000000006", principal_type="IAMUser", is_service=False,
        department="Security", created_days_ago=1600,
        home_regions=["us-east-1"],
        typical_events=["ConsoleLogin"], typical_hours_utc=[0, 23], known_asns=[],
        notes="Break-glass account. Any use is expected to be paged and ticketed. Last used 214 days ago.",
    ),
    "svc-ci-deploy": dict(
        principal_id="AROA00000000000000001", principal_type="AssumedRole", is_service=True,
        department="Platform Engineering", created_days_ago=1500,
        home_regions=["us-east-1", "us-west-2", "eu-west-1"],
        typical_events=["RunInstances", "TerminateInstances", "PutObject", "CreateStack", "UpdateFunctionCode"],
        typical_hours_utc=[0, 23], known_asns=["AS14618 Amazon"],
        notes="CI/CD deploy role. Bursty by design: release windows launch 20-60 instances in minutes.",
    ),
    "svc-backup": dict(
        principal_id="AROA00000000000000002", principal_type="AssumedRole", is_service=True,
        department="Platform Engineering", created_days_ago=1500,
        home_regions=["us-east-1", "us-west-2"],
        typical_events=["CreateSnapshot", "DescribeVolumes", "DeleteSnapshot", "CopySnapshot"],
        typical_hours_utc=[2, 5], known_asns=["AS14618 Amazon"],
        notes="Nightly backup role. Snapshots 02:00-05:00 UTC. Never shares snapshots externally.",
    ),
    "svc-secrets-rotator": dict(
        principal_id="AROA00000000000000003", principal_type="AssumedRole", is_service=True,
        department="Security", created_days_ago=800,
        home_regions=["us-east-1"],
        typical_events=["GetSecretValue", "PutSecretValue", "UpdateSecretVersionStage", "ListSecrets"],
        typical_hours_utc=[6, 7], known_asns=["AS14618 Amazon"],
        notes="Rotates all secrets on the 1st of each month, 06:00-07:00 UTC, in one pass.",
    ),
    "svc-lambda-invoice": dict(
        principal_id="AROA00000000000000004", principal_type="AssumedRole", is_service=True,
        department="Finance", created_days_ago=430,
        home_regions=["us-east-1"],
        typical_events=["GetObject", "PutObject", "SendEmail"],
        typical_hours_utc=[0, 23], known_asns=["AS14618 Amazon"],
        notes="Invoice-rendering Lambda. Reads finance reports, writes PDFs. No secrets access.",
    ),
}

BUCKETS = [
    "acme-analytics-lake", "acme-finance-reports", "acme-app-assets",
    "acme-terraform-state", "acme-customer-exports", "acme-logs-archive",
]


@dataclass
class ScenarioResult:
    events: list
    rule_id: str
    rule_name: str
    severity_reported: str
    summary: str
    primary_principal: str
    seed_event_ids: list
    gt: dict = field(default_factory=dict)


# --- malicious: easy tier ----------------------------------------------------

def credential_exfil_role_chain(ctx) -> ScenarioResult:
    """Compromised user assumes a role and bulk-copies a bucket out."""
    hostile = ctx.hostile_ip("AS49505 Selectel")
    e = []
    e.append(ctx.ev(4, "ConsoleLogin", "signin.amazonaws.com", "alice.chen", ip=hostile,
                    asn="AS49505 Selectel", response={"ConsoleLogin": "Success", "MFAUsed": "No"},
                    read_only=False))
    sess = ctx.session()
    e.append(ctx.ev(9, "AssumeRole", "sts.amazonaws.com", "alice.chen", ip=hostile,
                    asn="AS49505 Selectel", session=sess,
                    params={"roleArn": "arn:aws:iam::%s:role/analytics-readall" % ctx.account_id},
                    read_only=False))
    e.append(ctx.ev(11, "ListBuckets", "s3.amazonaws.com", "alice.chen", ip=hostile,
                    asn="AS49505 Selectel", session=sess))
    for i in range(6):
        e.append(ctx.ev(13 + i, "GetObject", "s3.amazonaws.com", "alice.chen", ip=hostile,
                        asn="AS49505 Selectel", session=sess,
                        params={"bucketName": "acme-customer-exports",
                                "key": "2026/q3/customers-part-%02d.parquet" % i},
                        resources=["arn:aws:s3:::acme-customer-exports"]))
    e.append(ctx.ev(21, "PutObject", "s3.amazonaws.com", "alice.chen", ip=hostile,
                    asn="AS49505 Selectel", session=sess, read_only=False,
                    params={"bucketName": "dropzone-9f2a-public", "key": "acme.tar.gz"},
                    resources=["arn:aws:s3:::dropzone-9f2a-public"]))
    return ScenarioResult(
        events=e, rule_id="R-1042", rule_name="Console login from unrecognised ASN without MFA",
        severity_reported="high", primary_principal="alice.chen", seed_event_ids=[e[0].event_id],
        summary="IAM user alice.chen authenticated to the console from AS49505 (Selectel, RU) without MFA, "
                "then assumed analytics-readall.",
        gt=dict(verdict="true_positive", severity="critical", recommended_action="contain",
                mitre_techniques=["T1078.004", "T1537", "T1530"],
                required_evidence_event_ids=[e[0].event_id, e[1].event_id, e[-1].event_id],
                distractor_event_ids=[e[2].event_id],
                required_tool_calls=["search_logs", "describe_principal", "submit_verdict"],
                principals_involved=["alice.chen"],
                resources_involved=["acme-customer-exports", "dropzone-9f2a-public"],
                min_steps=4, max_reasonable_steps=12,
                rationale="Login from an ASN outside alice.chen's baseline, MFA absent, followed by role "
                          "assumption and a write to an account-external bucket. The PutObject to "
                          "dropzone-9f2a-public is the exfiltration and must be cited; ListBuckets alone "
                          "is reconnaissance and is not sufficient evidence."))


def persistence_new_access_key(ctx) -> ScenarioResult:
    hostile = ctx.hostile_ip("AS204957 Alviva")
    e = []
    e.append(ctx.ev(2, "ConsoleLogin", "signin.amazonaws.com", "bob.martins", ip=hostile,
                    asn="AS204957 Alviva", read_only=False,
                    response={"ConsoleLogin": "Success", "MFAUsed": "Yes"}))
    e.append(ctx.ev(8, "CreateAccessKey", "iam.amazonaws.com", "bob.martins", ip=hostile,
                    asn="AS204957 Alviva", read_only=False,
                    params={"userName": "dana.okafor"},
                    response={"accessKeyId": "AKIA9Z2QEXAMPLE01"}))
    e.append(ctx.ev(10, "AttachUserPolicy", "iam.amazonaws.com", "bob.martins", ip=hostile,
                    asn="AS204957 Alviva", read_only=False,
                    params={"userName": "dana.okafor",
                            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}))
    e.append(ctx.ev(26, "GetCallerIdentity", "sts.amazonaws.com", "dana.okafor",
                    ip=ctx.hostile_ip("AS204957 Alviva"), asn="AS204957 Alviva"))
    return ScenarioResult(
        events=e, rule_id="R-2201", rule_name="IAM privilege escalation: AdministratorAccess attached",
        severity_reported="high", primary_principal="bob.martins", seed_event_ids=[e[2].event_id],
        summary="bob.martins attached AdministratorAccess to dana.okafor and minted a new access key for that user.",
        gt=dict(verdict="true_positive", severity="critical", recommended_action="contain",
                mitre_techniques=["T1098.001", "T1078.004"],
                required_evidence_event_ids=[e[1].event_id, e[2].event_id],
                distractor_event_ids=[e[0].event_id],
                required_tool_calls=["search_logs", "describe_principal", "submit_verdict"],
                principals_involved=["bob.martins", "dana.okafor"], resources_involved=["dana.okafor"],
                min_steps=4, max_reasonable_steps=12,
                rationale="A platform engineer minting credentials for a finance user and granting admin is "
                          "cross-department privilege escalation with a persistence mechanism attached. The "
                          "successful MFA login is a distractor: MFA succeeded, so the login alone looks clean."))


def crypto_mining_ec2(ctx) -> ScenarioResult:
    e = []
    sess = ctx.session()
    for i, region in enumerate(["ap-south-1", "sa-east-1", "ap-south-1"]):
        e.append(ctx.ev(6 + i * 3, "RunInstances", "ec2.amazonaws.com", "svc-ci-deploy",
                        region=region, session=sess, read_only=False,
                        params={"instanceType": "p4d.24xlarge", "count": 8,
                                "imageId": "ami-0bd2c8f1e3a77c9de"}))
    e.append(ctx.ev(18, "CreateSecurityGroup", "ec2.amazonaws.com", "svc-ci-deploy",
                    region="ap-south-1", session=sess, read_only=False,
                    params={"groupName": "sg-open-3333", "ingress": "0.0.0.0/0:3333"}))
    return ScenarioResult(
        events=e, rule_id="R-3310", rule_name="GPU instance burst in non-home region",
        severity_reported="medium", primary_principal="svc-ci-deploy", seed_event_ids=[e[0].event_id],
        summary="svc-ci-deploy launched 24 p4d.24xlarge instances across ap-south-1 and sa-east-1.",
        gt=dict(verdict="true_positive", severity="high", recommended_action="contain",
                mitre_techniques=["T1496", "T1078.004"],
                required_evidence_event_ids=[e[0].event_id, e[3].event_id],
                distractor_event_ids=[e[1].event_id],
                required_tool_calls=["search_logs", "describe_principal", "submit_verdict"],
                principals_involved=["svc-ci-deploy"], resources_involved=["ap-south-1", "sa-east-1"],
                min_steps=4, max_reasonable_steps=12,
                rationale="svc-ci-deploy bursts by design, so instance count alone is not the signal. Two "
                          "things fall outside its baseline: the regions (ap-south-1 and sa-east-1 are not "
                          "home regions) and a security group opening port 3333 to the world, which is a "
                          "mining-pool port and never part of a deploy."))


def s3_public_exposure(ctx) -> ScenarioResult:
    e = []
    e.append(ctx.ev(5, "PutBucketPolicy", "s3.amazonaws.com", "marcus.webb", read_only=False,
                    params={"bucketName": "acme-customer-exports",
                            "policy": '{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}'},
                    resources=["arn:aws:s3:::acme-customer-exports"]))
    e.append(ctx.ev(7, "DeletePublicAccessBlock", "s3.amazonaws.com", "marcus.webb", read_only=False,
                    params={"bucketName": "acme-customer-exports"},
                    resources=["arn:aws:s3:::acme-customer-exports"]))
    for i in range(4):
        e.append(ctx.ev(31 + i * 2, "GetObject", "s3.amazonaws.com", "anonymous",
                        ip=ctx.hostile_ip("AS4134 Chinanet"), asn="AS4134 Chinanet",
                        params={"bucketName": "acme-customer-exports", "key": "2026/q3/customers-part-%02d.parquet" % i},
                        resources=["arn:aws:s3:::acme-customer-exports"]))
    return ScenarioResult(
        events=e, rule_id="R-1188", rule_name="S3 public access block removed",
        severity_reported="high", primary_principal="marcus.webb", seed_event_ids=[e[1].event_id],
        summary="marcus.webb removed the public access block and applied a wildcard read policy to "
                "acme-customer-exports.",
        gt=dict(verdict="true_positive", severity="critical", recommended_action="contain",
                mitre_techniques=["T1530", "T1580"],
                required_evidence_event_ids=[e[0].event_id, e[1].event_id, e[2].event_id],
                distractor_event_ids=[],
                required_tool_calls=["search_logs", "describe_principal", "submit_verdict"],
                principals_involved=["marcus.webb"], resources_involved=["acme-customer-exports"],
                min_steps=4, max_reasonable_steps=12,
                rationale="Exposure plus confirmed anonymous reads from an external ASN. Severity is driven "
                          "by the anonymous GetObject events: without them this is a misconfiguration, with "
                          "them it is a live data breach. marcus.webb is scoped to project-atlas only and "
                          "has no business touching customer-exports."))


def defense_evasion_cloudtrail(ctx) -> ScenarioResult:
    hostile = ctx.hostile_ip("AS9009 M247")
    e = []
    e.append(ctx.ev(3, "StopLogging", "cloudtrail.amazonaws.com", "admin-breakglass", ip=hostile,
                    asn="AS9009 M247", read_only=False,
                    params={"name": "acme-org-trail"}))
    e.append(ctx.ev(4, "DeleteTrail", "cloudtrail.amazonaws.com", "admin-breakglass", ip=hostile,
                    asn="AS9009 M247", read_only=False, params={"name": "acme-org-trail-secondary"}))
    e.append(ctx.ev(6, "PutEventSelectors", "cloudtrail.amazonaws.com", "admin-breakglass", ip=hostile,
                    asn="AS9009 M247", read_only=False,
                    params={"name": "acme-org-trail", "eventSelectors": "ReadWriteType=ReadOnly"}))
    return ScenarioResult(
        events=e, rule_id="R-4001", rule_name="CloudTrail logging disabled",
        severity_reported="critical", primary_principal="admin-breakglass", seed_event_ids=[e[0].event_id],
        summary="admin-breakglass stopped acme-org-trail, deleted the secondary trail and narrowed event "
                "selectors to read-only.",
        gt=dict(verdict="true_positive", severity="critical", recommended_action="contain",
                mitre_techniques=["T1562.008"],
                required_evidence_event_ids=[e[0].event_id, e[1].event_id, e[2].event_id],
                distractor_event_ids=[],
                required_tool_calls=["search_logs", "describe_principal", "submit_verdict"],
                principals_involved=["admin-breakglass"], resources_involved=["acme-org-trail"],
                min_steps=3, max_reasonable_steps=10,
                rationale="Break-glass credentials unused for 214 days, used from an unrecognised ASN, to "
                          "blind the audit trail across two trails and then narrow selectors so future "
                          "writes go unrecorded. All three actions are required evidence: any one alone "
                          "could be maintenance."))


def secrets_enumeration(ctx) -> ScenarioResult:
    e = []
    sess = ctx.session()
    e.append(ctx.ev(2, "ListSecrets", "secretsmanager.amazonaws.com", "svc-lambda-invoice", session=sess))
    names = ["prod/db/master", "prod/stripe/api", "prod/okta/saml", "prod/github/deploy",
             "prod/datadog/api", "prod/twilio/auth", "prod/aws/root-alt"]
    for i, n in enumerate(names):
        e.append(ctx.ev(3 + i, "GetSecretValue", "secretsmanager.amazonaws.com", "svc-lambda-invoice",
                        session=sess, params={"secretId": n},
                        resources=["arn:aws:secretsmanager:us-east-1:%s:secret:%s" % (ctx.account_id, n)]))
    return ScenarioResult(
        events=e, rule_id="R-2604", rule_name="Bulk secret retrieval by non-rotation principal",
        severity_reported="high", primary_principal="svc-lambda-invoice", seed_event_ids=[e[1].event_id],
        summary="svc-lambda-invoice enumerated and read 7 production secrets in under 10 minutes.",
        gt=dict(verdict="true_positive", severity="critical", recommended_action="contain",
                mitre_techniques=["T1555.006", "T1526"],
                required_evidence_event_ids=[e[0].event_id, e[1].event_id, e[-1].event_id],
                distractor_event_ids=[],
                required_tool_calls=["search_logs", "describe_principal", "submit_verdict"],
                principals_involved=["svc-lambda-invoice"], resources_involved=names,
                min_steps=4, max_reasonable_steps=12,
                rationale="The invoice Lambda's baseline is GetObject/PutObject/SendEmail with no secrets "
                          "access at all. Reading prod/aws/root-alt and prod/github/deploy is lateral-movement "
                          "preparation. Compare against svc-secrets-rotator, whose baseline does include this "
                          "pattern — the same events from that principal on the 1st would be benign."))


def snapshot_share_external(ctx) -> ScenarioResult:
    e = []
    e.append(ctx.ev(5, "CreateSnapshot", "ec2.amazonaws.com", "marcus.webb", read_only=False,
                    params={"volumeId": "vol-0a91c2f3d4e5b6708", "description": "tmp"}))
    e.append(ctx.ev(12, "ModifySnapshotAttribute", "ec2.amazonaws.com", "marcus.webb", read_only=False,
                    params={"snapshotId": "snap-07d1e9a2b3c4f5061", "attribute": "createVolumePermission",
                            "userIds": ["609284471033"]}))
    return ScenarioResult(
        events=e, rule_id="R-3402", rule_name="EBS snapshot shared with external account",
        severity_reported="high", primary_principal="marcus.webb", seed_event_ids=[e[1].event_id],
        summary="marcus.webb shared snapshot snap-07d1e9a2 with AWS account 609284471033, which is outside "
                "the organisation.",
        gt=dict(verdict="true_positive", severity="high", recommended_action="contain",
                mitre_techniques=["T1537"],
                required_evidence_event_ids=[e[0].event_id, e[1].event_id],
                distractor_event_ids=[],
                required_tool_calls=["search_logs", "describe_principal", "submit_verdict"],
                principals_involved=["marcus.webb"], resources_involved=["snap-07d1e9a2b3c4f5061"],
                min_steps=3, max_reasonable_steps=10,
                rationale="Snapshot creation is normal for svc-backup but not for a scoped data engineer, "
                          "and sharing to an account outside the org is exfiltration regardless of who does "
                          "it. Both events are required: the share without the create loses provenance."))


def console_bruteforce_success(ctx) -> ScenarioResult:
    hostile = ctx.hostile_ip("AS14061 DigitalOcean")
    e = []
    for i in range(11):
        e.append(ctx.ev(1 + i, "ConsoleLogin", "signin.amazonaws.com", "dana.okafor", ip=hostile,
                        asn="AS14061 DigitalOcean", read_only=False, error="Failed authentication",
                        response={"ConsoleLogin": "Failure"}))
    e.append(ctx.ev(13, "ConsoleLogin", "signin.amazonaws.com", "dana.okafor", ip=hostile,
                    asn="AS14061 DigitalOcean", read_only=False,
                    response={"ConsoleLogin": "Success", "MFAUsed": "No"}))
    e.append(ctx.ev(16, "GetObject", "s3.amazonaws.com", "dana.okafor", ip=hostile,
                    asn="AS14061 DigitalOcean",
                    params={"bucketName": "acme-finance-reports", "key": "2026/payroll-q3.xlsx"},
                    resources=["arn:aws:s3:::acme-finance-reports"]))
    return ScenarioResult(
        events=e, rule_id="R-1001", rule_name="Repeated console authentication failures followed by success",
        severity_reported="high", primary_principal="dana.okafor", seed_event_ids=[e[11].event_id],
        summary="11 failed console logins for dana.okafor from AS14061, then a successful login without MFA.",
        gt=dict(verdict="true_positive", severity="high", recommended_action="contain",
                mitre_techniques=["T1110", "T1078.004"],
                required_evidence_event_ids=[e[11].event_id, e[12].event_id],
                distractor_event_ids=[e[0].event_id],
                required_tool_calls=["search_logs", "describe_principal", "submit_verdict"],
                principals_involved=["dana.okafor"], resources_involved=["acme-finance-reports"],
                min_steps=4, max_reasonable_steps=12,
                rationale="The failures alone are noise; the successful no-MFA login from the same hostile "
                          "ASN and the immediate payroll access are the evidence. Citing only a failed "
                          "attempt is the classic wrong answer here."))


def credential_exfil_via_ci_role(ctx) -> ScenarioResult:
    hostile = ctx.hostile_ip("AS200651 Flokinet")
    e = []
    sess = ctx.session()
    e.append(ctx.ev(3, "AssumeRole", "sts.amazonaws.com", "svc-ci-deploy", ip=hostile,
                    asn="AS200651 Flokinet", session=sess, read_only=False,
                    params={"roleArn": "arn:aws:iam::%s:role/ci-deploy" % ctx.account_id,
                            "roleSessionName": "gh-actions-7741"}))
    e.append(ctx.ev(6, "GetObject", "s3.amazonaws.com", "svc-ci-deploy", ip=hostile,
                    asn="AS200651 Flokinet", session=sess,
                    params={"bucketName": "acme-terraform-state", "key": "prod/terraform.tfstate"},
                    resources=["arn:aws:s3:::acme-terraform-state"]))
    e.append(ctx.ev(9, "GetSecretValue", "secretsmanager.amazonaws.com", "svc-ci-deploy", ip=hostile,
                    asn="AS200651 Flokinet", session=sess, params={"secretId": "prod/db/master"}))
    e.append(ctx.ev(14, "PutObject", "s3.amazonaws.com", "svc-ci-deploy", ip=hostile,
                    asn="AS200651 Flokinet", session=sess, read_only=False,
                    params={"bucketName": "tfstate-mirror-b71c", "key": "prod.tfstate"},
                    resources=["arn:aws:s3:::tfstate-mirror-b71c"]))
    return ScenarioResult(
        events=e, rule_id="R-1055", rule_name="Service role assumed from non-AWS ASN",
        severity_reported="high", primary_principal="svc-ci-deploy", seed_event_ids=[e[0].event_id],
        summary="ci-deploy was assumed from AS200651 rather than AWS infrastructure, then read Terraform "
                "state and a production secret.",
        gt=dict(verdict="true_positive", severity="critical", recommended_action="contain",
                mitre_techniques=["T1078.004", "T1552.001", "T1537"],
                required_evidence_event_ids=[e[0].event_id, e[2].event_id, e[3].event_id],
                distractor_event_ids=[e[1].event_id],
                required_tool_calls=["search_logs", "describe_principal", "submit_verdict"],
                principals_involved=["svc-ci-deploy"],
                resources_involved=["acme-terraform-state", "tfstate-mirror-b71c", "prod/db/master"],
                min_steps=4, max_reasonable_steps=12,
                rationale="svc-ci-deploy's only known ASN is AS14618 (Amazon). A CI role driven from a "
                          "bulletproof host is stolen. Reading tfstate is arguably in-baseline and is the "
                          "distractor; the secret read and the write to an external mirror bucket are not."))


# --- benign but attack-shaped: noisy tier ------------------------------------

def benign_ci_deploy_burst(ctx) -> ScenarioResult:
    e = []
    sess = ctx.session()
    for i in range(5):
        e.append(ctx.ev(2 + i, "RunInstances", "ec2.amazonaws.com", "svc-ci-deploy",
                        region="us-west-2", session=sess, read_only=False,
                        params={"instanceType": "c6i.4xlarge", "count": 9,
                                "tags": {"deploy": "release-2026.09.1"}}))
    e.append(ctx.ev(40, "TerminateInstances", "ec2.amazonaws.com", "svc-ci-deploy", region="us-west-2",
                    session=sess, read_only=False, params={"count": 45}))
    return ScenarioResult(
        events=e, rule_id="R-3310", rule_name="Instance burst detected",
        severity_reported="medium", primary_principal="svc-ci-deploy", seed_event_ids=[e[0].event_id],
        summary="svc-ci-deploy launched 45 instances in us-west-2 within 6 minutes.",
        gt=dict(verdict="false_positive", severity="informational", recommended_action="close_benign",
                mitre_techniques=[],
                required_evidence_event_ids=[e[0].event_id, e[5].event_id],
                distractor_event_ids=[e[1].event_id],
                required_tool_calls=["search_logs", "describe_principal", "submit_verdict"],
                principals_involved=["svc-ci-deploy"], resources_involved=["us-west-2"],
                min_steps=3, max_reasonable_steps=10,
                rationale="Every attribute is inside svc-ci-deploy's baseline: home region, AWS ASN, general "
                          "purpose instance type, release tag, and a clean teardown 34 minutes later. The "
                          "teardown is what settles it — miners do not terminate their own fleet."))


def benign_travel_login(ctx) -> ScenarioResult:
    e = []
    e.append(ctx.ev(3, "ConsoleLogin", "signin.amazonaws.com", "priya.rao",
                    ip=ctx.hostile_ip("AS3320 DTAG"), asn="AS3320 DTAG", region="eu-west-1",
                    read_only=False, response={"ConsoleLogin": "Success", "MFAUsed": "Yes"}))
    for i in range(3):
        e.append(ctx.ev(8 + i * 4, "LookupEvents", "cloudtrail.amazonaws.com", "priya.rao",
                        asn="AS3320 DTAG", region="eu-west-1",
                        params={"lookupAttributes": "EventName=ConsoleLogin"}))
    return ScenarioResult(
        events=e, rule_id="R-1043", rule_name="Console login from new geography",
        severity_reported="medium", primary_principal="priya.rao", seed_event_ids=[e[0].event_id],
        summary="priya.rao authenticated from Germany (AS3320), 6,400 km from her last login 9 hours earlier.",
        gt=dict(verdict="false_positive", severity="informational", recommended_action="close_benign",
                mitre_techniques=[],
                required_evidence_event_ids=[e[0].event_id],
                distractor_event_ids=[e[1].event_id],
                required_tool_calls=["describe_principal", "submit_verdict"],
                principals_involved=["priya.rao"], resources_involved=[],
                min_steps=2, max_reasonable_steps=8,
                rationale="AS3320 and eu-west-1 are both in priya.rao's baseline, MFA succeeded, and the "
                          "subsequent activity is read-only CloudTrail lookups — her documented job. "
                          "Impossible-travel rules fire on distance, not on baseline, which is why this "
                          "reaches a human at all."))


@starts_at(3, 11)  # first snapshot lands at 03:12, matching the alert summary
def benign_backup_snapshots(ctx) -> ScenarioResult:
    e = []
    for i in range(9):
        e.append(ctx.ev(1 + i * 2, "CreateSnapshot", "ec2.amazonaws.com", "svc-backup", read_only=False,
                        params={"volumeId": "vol-0%015x" % (0xa1b2c3 + i), "description": "nightly-2026-09-03"}))
    e.append(ctx.ev(22, "DeleteSnapshot", "ec2.amazonaws.com", "svc-backup", read_only=False,
                    params={"snapshotId": "snap-0%015x" % 0x99aa11, "reason": "retention-30d"}))
    return ScenarioResult(
        events=e, rule_id="R-3401", rule_name="Bulk snapshot creation",
        severity_reported="medium", primary_principal="svc-backup", seed_event_ids=[e[0].event_id],
        summary="svc-backup created 9 EBS snapshots in 18 minutes at 03:12 UTC.",
        gt=dict(verdict="false_positive", severity="informational", recommended_action="close_benign",
                mitre_techniques=[],
                required_evidence_event_ids=[e[0].event_id, e[9].event_id],
                distractor_event_ids=[],
                required_tool_calls=["describe_principal", "submit_verdict"],
                principals_involved=["svc-backup"], resources_involved=[],
                min_steps=2, max_reasonable_steps=8,
                rationale="Inside the 02:00-05:00 UTC backup window, home region, AWS ASN, retention-tagged, "
                          "and no ModifySnapshotAttribute anywhere in the window. Absence of a sharing event "
                          "is itself evidence and should be stated."))


@starts_at(6, 12)  # first GetSecretValue (the seed) lands at 06:14, matching the summary
def benign_secrets_rotation(ctx) -> ScenarioResult:
    e = []
    sess = ctx.session()
    e.append(ctx.ev(1, "ListSecrets", "secretsmanager.amazonaws.com", "svc-secrets-rotator", session=sess))
    for i, n in enumerate(["prod/db/master", "prod/stripe/api", "prod/okta/saml", "prod/github/deploy"]):
        e.append(ctx.ev(2 + i * 2, "GetSecretValue", "secretsmanager.amazonaws.com",
                        "svc-secrets-rotator", session=sess, params={"secretId": n}))
        e.append(ctx.ev(3 + i * 2, "PutSecretValue", "secretsmanager.amazonaws.com",
                        "svc-secrets-rotator", session=sess, read_only=False,
                        params={"secretId": n, "versionStages": ["AWSPENDING"]}))
    return ScenarioResult(
        events=e, rule_id="R-2604", rule_name="Bulk secret retrieval",
        severity_reported="high", primary_principal="svc-secrets-rotator", seed_event_ids=[e[1].event_id],
        summary="svc-secrets-rotator read 4 production secrets in sequence at 06:14 UTC.",
        gt=dict(verdict="false_positive", severity="informational", recommended_action="close_benign",
                mitre_techniques=[],
                required_evidence_event_ids=[e[2].event_id],
                distractor_event_ids=[e[1].event_id],
                required_tool_calls=["describe_principal", "submit_verdict"],
                principals_involved=["svc-secrets-rotator"], resources_involved=[],
                min_steps=2, max_reasonable_steps=8,
                rationale="Each GetSecretValue is immediately followed by a PutSecretValue staging AWSPENDING "
                          "— the read-then-write pattern is rotation, not theft. Same rule as the malicious "
                          "secrets-enumeration incident; only the principal baseline and the paired writes "
                          "separate them."))


def benign_analyst_bulk_read(ctx) -> ScenarioResult:
    e = []
    sess = ctx.session()
    for i in range(14):
        e.append(ctx.ev(2 + i, "GetObject", "s3.amazonaws.com", "alice.chen", session=sess,
                        params={"bucketName": "acme-analytics-lake",
                                "key": "warehouse/events/dt=2026-09-0%d/part-000%02d.parquet" % (i % 3 + 1, i)},
                        resources=["arn:aws:s3:::acme-analytics-lake"]))
    return ScenarioResult(
        events=e, rule_id="R-1502", rule_name="High-volume object retrieval",
        severity_reported="medium", primary_principal="alice.chen", seed_event_ids=[e[0].event_id],
        summary="alice.chen retrieved 14 objects (2.1 GB) from acme-analytics-lake in 15 minutes.",
        gt=dict(verdict="false_positive", severity="informational", recommended_action="close_benign",
                mitre_techniques=[],
                required_evidence_event_ids=[e[0].event_id],
                distractor_event_ids=[],
                required_tool_calls=["describe_principal", "submit_verdict"],
                principals_involved=["alice.chen"], resources_involved=["acme-analytics-lake"],
                min_steps=2, max_reasonable_steps=8,
                rationale="alice.chen owns the analytics-lake pipelines; reading warehouse partitions is her "
                          "documented function, from a known ASN, in a home region, with no write to any "
                          "external destination anywhere in the window."))


def benign_iac_policy_update(ctx) -> ScenarioResult:
    e = []
    sess = ctx.session()
    e.append(ctx.ev(4, "GetObject", "s3.amazonaws.com", "svc-ci-deploy", session=sess,
                    params={"bucketName": "acme-terraform-state", "key": "prod/terraform.tfstate"}))
    e.append(ctx.ev(6, "PutBucketPolicy", "s3.amazonaws.com", "svc-ci-deploy", session=sess, read_only=False,
                    params={"bucketName": "acme-app-assets",
                            "policy": '{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:role/cdn-origin"},'
                                      '"Action":"s3:GetObject"}' % ctx.account_id},
                    resources=["arn:aws:s3:::acme-app-assets"]))
    e.append(ctx.ev(7, "PutBucketVersioning", "s3.amazonaws.com", "svc-ci-deploy", session=sess,
                    read_only=False, params={"bucketName": "acme-app-assets", "status": "Enabled"}))
    return ScenarioResult(
        events=e, rule_id="R-1187", rule_name="S3 bucket policy modified",
        severity_reported="medium", primary_principal="svc-ci-deploy", seed_event_ids=[e[1].event_id],
        summary="svc-ci-deploy replaced the bucket policy on acme-app-assets.",
        gt=dict(verdict="false_positive", severity="informational", recommended_action="close_benign",
                mitre_techniques=[],
                required_evidence_event_ids=[e[1].event_id],
                distractor_event_ids=[e[0].event_id],
                required_tool_calls=["search_logs", "get_events", "submit_verdict"],
                principals_involved=["svc-ci-deploy"], resources_involved=["acme-app-assets"],
                min_steps=3, max_reasonable_steps=10,
                rationale="The policy grants a named in-account role, not a wildcard principal, and no "
                          "DeletePublicAccessBlock accompanies it. Reading the policy body rather than "
                          "matching on the event name is the whole task here."))


def benign_failed_logins_typo(ctx) -> ScenarioResult:
    e = []
    for i in range(6):
        e.append(ctx.ev(2 + i, "ConsoleLogin", "signin.amazonaws.com", "bob.martins",
                        read_only=False, error="Failed authentication",
                        response={"ConsoleLogin": "Failure"}))
    e.append(ctx.ev(11, "ConsoleLogin", "signin.amazonaws.com", "bob.martins", read_only=False,
                    response={"ConsoleLogin": "Success", "MFAUsed": "Yes"}))
    return ScenarioResult(
        events=e, rule_id="R-1001", rule_name="Repeated console authentication failures followed by success",
        severity_reported="high", primary_principal="bob.martins", seed_event_ids=[e[6].event_id],
        summary="6 failed console logins for bob.martins, then a successful login.",
        gt=dict(verdict="false_positive", severity="low", recommended_action="close_benign",
                mitre_techniques=[],
                required_evidence_event_ids=[e[6].event_id],
                distractor_event_ids=[e[0].event_id],
                required_tool_calls=["search_logs", "describe_principal", "submit_verdict"],
                principals_involved=["bob.martins"], resources_involved=[],
                min_steps=3, max_reasonable_steps=10,
                rationale="All seven attempts come from bob.martins's own known ASN and home region, the "
                          "success used MFA, and no privileged action follows. Same rule as the dana.okafor "
                          "brute-force incident; the source ASN is the only discriminator."))


def benign_lambda_invoice_run(ctx) -> ScenarioResult:
    e = []
    sess = ctx.session()
    for i in range(8):
        e.append(ctx.ev(1 + i, "GetObject", "s3.amazonaws.com", "svc-lambda-invoice", session=sess,
                        params={"bucketName": "acme-finance-reports", "key": "2026/09/invoice-src-%03d.json" % i}))
    for i in range(3):
        e.append(ctx.ev(10 + i, "PutObject", "s3.amazonaws.com", "svc-lambda-invoice", session=sess,
                        read_only=False,
                        params={"bucketName": "acme-finance-reports", "key": "2026/09/rendered/inv-%03d.pdf" % i}))
    return ScenarioResult(
        events=e, rule_id="R-1502", rule_name="High-volume object retrieval",
        severity_reported="low", primary_principal="svc-lambda-invoice", seed_event_ids=[e[0].event_id],
        summary="svc-lambda-invoice read 8 objects and wrote 3 to acme-finance-reports.",
        gt=dict(verdict="false_positive", severity="informational", recommended_action="close_benign",
                mitre_techniques=[],
                required_evidence_event_ids=[e[0].event_id, e[8].event_id],
                distractor_event_ids=[],
                required_tool_calls=["describe_principal", "submit_verdict"],
                principals_involved=["svc-lambda-invoice"], resources_involved=["acme-finance-reports"],
                min_steps=2, max_reasonable_steps=8,
                rationale="Read-then-write inside a single bucket that is the principal's documented scope. "
                          "The write destination is the discriminator: same bucket, not an external one."))


# --- malicious, multi-hop: hard tier -----------------------------------------

def low_and_slow_exfil(ctx) -> ScenarioResult:
    """Signal spread over 4 days and interleaved with the principal's real work."""
    e = []
    for day in range(4):
        base = day * 1440
        for i in range(3):
            e.append(ctx.ev(base + 200 + i * 7, "GetObject", "s3.amazonaws.com", "alice.chen",
                            params={"bucketName": "acme-analytics-lake",
                                    "key": "warehouse/events/dt=2026-09-0%d/part-000%02d.parquet" % (day + 1, i)},
                            resources=["arn:aws:s3:::acme-analytics-lake"]))
        e.append(ctx.ev(base + 690, "GetObject", "s3.amazonaws.com", "alice.chen",
                        ip=ctx.hostile_ip("AS51396 Pfcloud"), asn="AS51396 Pfcloud",
                        params={"bucketName": "acme-customer-exports",
                                "key": "2026/q3/customers-part-%02d.parquet" % day},
                        resources=["arn:aws:s3:::acme-customer-exports"]))
    return ScenarioResult(
        events=e, rule_id="R-1503", rule_name="Access to customer-exports outside owning team",
        severity_reported="low", primary_principal="alice.chen", seed_event_ids=[e[3].event_id],
        summary="alice.chen read one object from acme-customer-exports. Volume below alerting threshold.",
        gt=dict(verdict="true_positive", severity="high", recommended_action="escalate",
                mitre_techniques=["T1530", "T1537"],
                required_evidence_event_ids=[e[3].event_id, e[7].event_id, e[11].event_id, e[15].event_id],
                distractor_event_ids=[e[0].event_id, e[4].event_id],
                required_tool_calls=["search_logs", "describe_principal", "submit_verdict"],
                principals_involved=["alice.chen"], resources_involved=["acme-customer-exports"],
                min_steps=6, max_reasonable_steps=18,
                rationale="Each day in isolation is one object below threshold. Only the four-day pattern "
                          "reveals it, and only the source ASN separates the exfiltration reads (AS51396, "
                          "unknown) from her legitimate analytics-lake reads on the same days (AS7922, known). "
                          "All four hostile-ASN reads are required evidence; citing one is insufficient."))


def insider_scope_violation(ctx) -> ScenarioResult:
    e = []
    sess = ctx.session()
    for i in range(4):
        e.append(ctx.ev(3 + i, "GetObject", "s3.amazonaws.com", "marcus.webb", session=sess,
                        params={"bucketName": "acme-analytics-lake",
                                "key": "project-atlas/models/v%d.pkl" % i}))
    e.append(ctx.ev(19, "ListBucket", "s3.amazonaws.com", "marcus.webb", session=sess,
                    params={"bucketName": "acme-analytics-lake", "prefix": "project-helios/"}))
    for i in range(5):
        e.append(ctx.ev(21 + i * 2, "GetObject", "s3.amazonaws.com", "marcus.webb", session=sess,
                        params={"bucketName": "acme-analytics-lake",
                                "key": "project-helios/roadmap/pricing-model-2027.xlsx" if i == 0
                                else "project-helios/data/segment-%02d.csv" % i}))
    e.append(ctx.ev(44, "PutObject", "s3.amazonaws.com", "marcus.webb", session=sess, read_only=False,
                    params={"bucketName": "acme-app-assets", "key": "tmp/mw/bundle.zip"}))
    return ScenarioResult(
        events=e, rule_id="R-1502", rule_name="High-volume object retrieval",
        severity_reported="medium", primary_principal="marcus.webb", seed_event_ids=[e[0].event_id],
        summary="marcus.webb retrieved 9 objects from acme-analytics-lake in 45 minutes.",
        gt=dict(verdict="true_positive", severity="medium", recommended_action="escalate",
                mitre_techniques=["T1530", "T1580"],
                required_evidence_event_ids=[e[4].event_id, e[5].event_id, e[10].event_id],
                distractor_event_ids=[e[0].event_id, e[1].event_id],
                required_tool_calls=["search_logs", "describe_principal", "submit_verdict"],
                principals_involved=["marcus.webb"], resources_involved=["acme-analytics-lake"],
                min_steps=6, max_reasonable_steps=16,
                rationale="Same bucket, same ASN, same principal — nothing here trips a boundary rule. The "
                          "violation is the PREFIX: marcus.webb is scoped to project-atlas, and the "
                          "project-helios list-then-read plus the staging write to app-assets is scoped "
                          "data collection. The project-atlas reads are legitimate and are the distractors. "
                          "This requires reading the baseline notes, not just the region and ASN."))


def lambda_supply_chain(ctx) -> ScenarioResult:
    e = []
    e.append(ctx.ev(2, "UpdateFunctionCode", "lambda.amazonaws.com", "svc-ci-deploy", read_only=False,
                    params={"functionName": "invoice-renderer", "sha256": "8f31c0a9d2e4b7615c0d3f9a2b8e4177"}))
    e.append(ctx.ev(4, "UpdateFunctionConfiguration", "lambda.amazonaws.com", "svc-ci-deploy",
                    read_only=False,
                    params={"functionName": "invoice-renderer", "role":
                            "arn:aws:iam::%s:role/analytics-readall" % ctx.account_id}))
    sess = ctx.session()
    e.append(ctx.ev(31, "GetSecretValue", "secretsmanager.amazonaws.com", "svc-lambda-invoice",
                    session=sess, params={"secretId": "prod/db/master"}))
    e.append(ctx.ev(34, "GetObject", "s3.amazonaws.com", "svc-lambda-invoice", session=sess,
                    params={"bucketName": "acme-customer-exports", "key": "2026/q3/customers-part-00.parquet"},
                    resources=["arn:aws:s3:::acme-customer-exports"]))
    e.append(ctx.ev(37, "PutObject", "s3.amazonaws.com", "svc-lambda-invoice", session=sess,
                    read_only=False,
                    params={"bucketName": "acme-logs-archive", "key": "debug/rnd-4471.bin"},
                    resources=["arn:aws:s3:::acme-logs-archive"]))
    return ScenarioResult(
        events=e, rule_id="R-2604", rule_name="Bulk secret retrieval by non-rotation principal",
        severity_reported="high", primary_principal="svc-lambda-invoice", seed_event_ids=[e[2].event_id],
        summary="svc-lambda-invoice read prod/db/master, which is outside its documented permissions.",
        gt=dict(verdict="true_positive", severity="critical", recommended_action="contain",
                mitre_techniques=["T1648", "T1555.006", "T1530"],
                required_evidence_event_ids=[e[0].event_id, e[1].event_id, e[2].event_id, e[3].event_id],
                distractor_event_ids=[e[4].event_id],
                required_tool_calls=["search_logs", "describe_principal", "submit_verdict"],
                principals_involved=["svc-lambda-invoice", "svc-ci-deploy"],
                resources_involved=["invoice-renderer", "prod/db/master", "acme-customer-exports"],
                min_steps=7, max_reasonable_steps=20,
                rationale="The alert fires on the Lambda, but the Lambda is the victim. Root cause is 29 "
                          "minutes earlier and under a DIFFERENT principal: svc-ci-deploy pushed new code "
                          "and swapped the execution role to analytics-readall. An agent that investigates "
                          "only the alerting principal will conclude 'misconfigured Lambda' and miss the "
                          "code push entirely. Both principals must appear in the evidence."))


def dormant_key_reactivation(ctx) -> ScenarioResult:
    e = []
    sess = ctx.session()
    e.append(ctx.ev(1, "GetCallerIdentity", "sts.amazonaws.com", "admin-breakglass",
                    ip=ctx.hostile_ip("AS62240 Clouvider"), asn="AS62240 Clouvider", session=sess))
    e.append(ctx.ev(5, "ListUsers", "iam.amazonaws.com", "admin-breakglass",
                    ip=ctx.hostile_ip("AS62240 Clouvider"), asn="AS62240 Clouvider", session=sess))
    e.append(ctx.ev(8, "ListAttachedUserPolicies", "iam.amazonaws.com", "admin-breakglass",
                    ip=ctx.hostile_ip("AS62240 Clouvider"), asn="AS62240 Clouvider", session=sess))
    e.append(ctx.ev(23, "CreateUser", "iam.amazonaws.com", "admin-breakglass",
                    ip=ctx.hostile_ip("AS62240 Clouvider"), asn="AS62240 Clouvider", session=sess,
                    read_only=False, params={"userName": "svc-metrics-agent"}))
    e.append(ctx.ev(25, "AttachUserPolicy", "iam.amazonaws.com", "admin-breakglass",
                    ip=ctx.hostile_ip("AS62240 Clouvider"), asn="AS62240 Clouvider", session=sess,
                    read_only=False, params={"userName": "svc-metrics-agent",
                                             "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}))
    e.append(ctx.ev(27, "CreateAccessKey", "iam.amazonaws.com", "admin-breakglass",
                    ip=ctx.hostile_ip("AS62240 Clouvider"), asn="AS62240 Clouvider", session=sess,
                    read_only=False, params={"userName": "svc-metrics-agent"}))
    return ScenarioResult(
        events=e, rule_id="R-2101", rule_name="IAM user created",
        severity_reported="low", primary_principal="admin-breakglass", seed_event_ids=[e[3].event_id],
        summary="A new IAM user svc-metrics-agent was created by admin-breakglass.",
        gt=dict(verdict="true_positive", severity="critical", recommended_action="contain",
                mitre_techniques=["T1078.004", "T1098.001", "T1136.003", "T1580"],
                required_evidence_event_ids=[e[0].event_id, e[3].event_id, e[4].event_id, e[5].event_id],
                distractor_event_ids=[e[1].event_id, e[2].event_id],
                required_tool_calls=["search_logs", "describe_principal", "submit_verdict"],
                principals_involved=["admin-breakglass"], resources_involved=["svc-metrics-agent"],
                min_steps=6, max_reasonable_steps=18,
                rationale="A low-severity 'IAM user created' alert hiding a full account takeover. The "
                          "escalation comes entirely from context the alert does not carry: break-glass "
                          "credentials dormant 214 days, an unrecognised ASN, 22 minutes of IAM "
                          "reconnaissance, then a service-account-shaped user with AdministratorAccess and "
                          "programmatic keys. The recon events are distractors — the persistence chain is "
                          "the evidence."))


# --- registry ----------------------------------------------------------------
# (builder, tier). Order here is the order incidents are numbered.
# benign_lambda_invoice_run is defined above but held out of v1 — spare capacity
# for when you widen the benign tier in week 4.
REGISTRY = [
    (credential_exfil_role_chain, "easy"),
    (benign_ci_deploy_burst, "noisy"),
    (persistence_new_access_key, "easy"),
    (benign_travel_login, "noisy"),
    (crypto_mining_ec2, "easy"),
    (benign_backup_snapshots, "noisy"),
    (s3_public_exposure, "easy"),
    (benign_secrets_rotation, "noisy"),
    (defense_evasion_cloudtrail, "easy"),
    (benign_analyst_bulk_read, "noisy"),
    (secrets_enumeration, "easy"),
    (benign_iac_policy_update, "noisy"),
    (snapshot_share_external, "easy"),
    (benign_failed_logins_typo, "noisy"),
    (console_bruteforce_success, "easy"),
    (credential_exfil_via_ci_role, "easy"),
    (low_and_slow_exfil, "hard"),
    (insider_scope_violation, "hard"),
    (lambda_supply_chain, "hard"),
    (dormant_key_reactivation, "hard"),
]
