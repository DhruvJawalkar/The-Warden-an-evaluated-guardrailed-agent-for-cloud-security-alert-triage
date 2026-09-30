"""Deterministic generator for the week-2 enrichment tables (threat intel, asset inventory, trust).

    python -m warden.data.enrichment --out datasets/enrichment_v1 --seed 20260930

Kept OUT of datasets/v1 on purpose: v1 is the tagged week-1 baseline, and these tables change what
an agent can learn. They are an experimental variable (`--toolset full`), not part of the baseline.

Rules this file follows:
  * It never opens any incident file or answer key. Every row below is what a real feed or
    inventory would plausibly say about the principals, buckets and ASNs that exist in the world
    model, written without reference to which incident is an attack.
  * The feed has NOISE on purpose: a routine source with abuse reports, an attacker-adjacent network
    the feed has never heard of, an ambiguous VPN exit. A feed that separates good from bad cleanly
    is an answer key, and an eval built on it measures lookup, not judgement.
"""

from __future__ import annotations

import argparse
import json
import os
import random
from datetime import date, timedelta

ENRICHMENT_VERSION = "1.0.0"
FEED_DATE = date(2026, 9, 1)

# asn, name, class, reputation, categories, typical abuse reports / 90d, confidence, note
# reputation: clean | neutral | mixed | poor. Absent ASNs are simply not listed.
_ASNS = [
    (14618, "Amazon", "cloud_provider", "neutral", ["cloud_provider", "scanning_source"], 180, "high",
     "Very large legitimate customer base; also rented by attackers. Origin alone is weak evidence."),
    (7922, "Comcast", "residential_isp", "clean", ["residential"], 12, "high",
     "Consumer broadband. Low-volume reports are mostly compromised home devices."),
    (3320, "DTAG", "residential_isp", "clean", ["residential"], 9, "high", "Consumer broadband, DE."),
    (701, "Verizon", "residential_isp", "clean", ["residential", "mobile"], 14, "high",
     "Consumer and mobile carrier."),
    (14061, "DigitalOcean", "cloud_hosting", "mixed", ["cloud_hosting", "scanning_source", "brute_force_source"],
     340, "medium", "Popular developer cloud. Many legitimate customers; frequent source of scanning."),
    (49505, "Selectel", "hosting", "poor", ["hosting", "brute_force_source", "credential_stuffing"], 420,
     "medium", "Hosting provider with a long abuse history."),
    (62240, "Clouvider", "hosting", "mixed", ["hosting"], 95, "low", "Hosting provider, mixed customer base."),
    (4134, "Chinanet", "national_carrier", "mixed", ["carrier", "scanning_source"], 260, "low",
     "National carrier: huge population of ordinary users and a large abusive tail."),
    (200651, "Flokinet", "hosting", "poor", ["hosting", "offshore_hosting"], 210, "medium",
     "Offshore hosting with lax abuse handling."),
    (9009, "M247", "vpn_infrastructure", "mixed", ["vpn_exit", "anonymizer"], 130, "low",
     "Commercial VPN exit infrastructure: used by privacy-conscious staff and by attackers alike."),
]
# Deliberately absent from the feed: AS204957 (Alviva), AS51396 (Pfcloud). "Not found" must never be
# read as "safe", and the tool says so.

_ASSETS = {
    "acme-analytics-lake": dict(
        type="s3_bucket", owner_team="Data Engineering", data_classification="internal",
        environment="prod", public_access_block=True,
        grants=[{"principal": "alice.chen", "access": "read/write"},
                {"principal": "marcus.webb", "access": "read", "scope": "project-atlas/ prefix only"},
                {"principal": "priya.rao", "access": "read"}],
        notes="Analytics pipelines write here; heavy reads by the owning team are routine."),
    "acme-customer-exports": dict(
        type="s3_bucket", owner_team="Customer Data Platform", data_classification="restricted (customer PII)",
        environment="prod", public_access_block=True,
        grants=[{"principal": "cdp-exporter", "access": "read/write"},
                {"principal": "priya.rao", "access": "read", "scope": "audit"}],
        notes="Customer data exports. Access outside the owning team requires a recorded grant."),
    "acme-finance-reports": dict(
        type="s3_bucket", owner_team="Finance", data_classification="confidential",
        environment="prod", public_access_block=True,
        grants=[{"principal": "dana.okafor", "access": "read"},
                {"principal": "svc-lambda-invoice", "access": "read/write"}],
        notes="Monthly finance reports and rendered invoices."),
    "acme-app-assets": dict(
        type="s3_bucket", owner_team="Platform Engineering", data_classification="public",
        environment="prod", public_access_block=False,
        grants=[{"principal": "svc-ci-deploy", "access": "read/write"}],
        notes="Static site assets, intended to be publicly readable. Bucket policy is managed by the deploy pipeline."),
    "acme-terraform-state": dict(
        type="s3_bucket", owner_team="Platform Engineering", data_classification="confidential",
        environment="prod", public_access_block=True,
        grants=[{"principal": "svc-ci-deploy", "access": "read/write"}],
        notes="Terraform state; may embed credentials and resource identifiers."),
    "acme-logs-archive": dict(
        type="s3_bucket", owner_team="Security", data_classification="internal",
        environment="prod", public_access_block=True,
        grants=[{"principal": "priya.rao", "access": "read"}], notes="Archived audit logs."),
    "dropzone-9f2a-public": dict(
        type="s3_bucket", owner_team=None, data_classification="unclassified",
        environment="unknown", public_access_block=False, grants=[],
        notes="No owner tag and no provisioning record."),
    "tfstate-mirror-b71c": dict(
        type="s3_bucket", owner_team=None, data_classification="unclassified",
        environment="unknown", public_access_block=True, grants=[],
        notes="No owner tag and no provisioning record."),
}
for _name, _owner, _cls in [
    ("prod/db/master", "Platform Engineering", "critical"), ("prod/stripe/api", "Finance", "critical"),
    ("prod/okta/saml", "Security", "critical"), ("prod/github/deploy", "Platform Engineering", "high"),
    ("prod/datadog/api", "Platform Engineering", "medium"), ("prod/twilio/auth", "Platform Engineering", "medium"),
    ("prod/aws/root-alt", "Security", "critical"),
]:
    _ASSETS[_name] = dict(
        type="secret", owner_team=_owner, data_classification=_cls, environment="prod",
        public_access_block=None,
        grants=[{"principal": "svc-secrets-rotator", "access": "read", "scope": "scheduled rotation"}],
        notes="Application secret. Only the rotation service and the owning application should read it.")

_TRUST = {
    "svc-ci-deploy": dict(assumable_by=["bob.martins", "ci-pipeline-runner"],
                          notes="Deploy role. Humans assume it during release windows; the pipeline runner assumes it from AWS infrastructure."),
    "svc-backup": dict(assumable_by=["backup-scheduler"], notes="Assumed by the backup scheduler from AWS infrastructure."),
    "svc-secrets-rotator": dict(assumable_by=["rotation-scheduler"], notes="Assumed by the rotation scheduler from AWS infrastructure."),
    "svc-lambda-invoice": dict(assumable_by=["lambda.amazonaws.com"], notes="Lambda execution role for the invoice function."),
}


def build_threat_intel(seed: int) -> dict:
    rng = random.Random(seed)
    entries = {}
    for asn, name, klass, rep, cats, base, conf, note in _ASNS:
        reports = max(0, int(base * rng.uniform(0.8, 1.25)))
        last = FEED_DATE - timedelta(days=rng.randint(1, 40))
        entries["AS%d" % asn] = {
            "asn": "AS%d" % asn, "name": name, "network_class": klass, "reputation": rep,
            "categories": cats, "abuse_reports_90d": reports, "last_reported": last.isoformat(),
            "confidence": conf, "note": note,
        }
    return {"feed": "warden-synthetic-feed", "feed_date": FEED_DATE.isoformat(),
            "version": ENRICHMENT_VERSION, "entries": entries}


def build_assets() -> dict:
    return {"version": ENRICHMENT_VERSION, "assets": _ASSETS, "trust": _TRUST}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="datasets/enrichment_v1")
    ap.add_argument("--seed", type=int, default=20260930)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    for fname, obj in (("threat_intel.json", build_threat_intel(args.seed)),
                       ("assets.json", build_assets())):
        with open(os.path.join(args.out, fname), "w", encoding="utf-8", newline="\n") as fh:
            json.dump(obj, fh, indent=2, sort_keys=True)
            fh.write("\n")
    print("wrote %s" % args.out)


if __name__ == "__main__":
    main()
