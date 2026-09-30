"""Deterministic synthetic CloudTrail generator for Warden.

Stdlib only, seeded, reproducible: same seed in, byte-identical dataset out.
That property is not a nicety — week 4 diffs eval runs across code changes, and
a dataset that drifts underneath you makes every regression unfalsifiable.

Layout produced:

    datasets/v1/
      manifest.json          seed, counts, versions, tier distribution
      principals.json        behavioural baselines (agent-visible)
      incidents.jsonl        one Incident per line, ground truth INCLUDED
      alerts/<id>.json       the agent's entry point (no ground truth)
      logs/<id>.jsonl        signal + background events, chronological

The agent is only ever handed alerts/ and logs/ and principals.json.
incidents.jsonl is the answer key and must stay out of the tool plane.

Usage:
    python -m warden.data.generator --out datasets/v1 --seed 20260903 --count 20
"""

from __future__ import annotations

import argparse
import json
import os
import random
import zlib
from datetime import datetime, timedelta, timezone

from warden.data.schema import (
    SCHEMA_VERSION, Alert, Event, GroundTruth, Incident, PrincipalProfile, write_jsonl,
)
from warden.data.scenarios import BUCKETS, CAST, REGISTRY

GENERATOR_VERSION = "1.0.0"
ACCOUNT_ID = "418209773165"

USER_AGENTS = [
    "aws-cli/2.15.30 Python/3.11.8 Linux/6.5.0 exec-env/AWS_ECS_FARGATE",
    "Boto3/1.34.51 md/Botocore#1.34.51 ua/2.0 os/linux md/arch#x86_64",
    "console.amazonaws.com",
    "terraform-provider-aws/5.44.0 (+https://www.terraform.io)",
    "aws-sdk-go/1.51.6 (go1.22.1; linux; amd64)",
]

BACKGROUND_EVENTS = [
    ("DescribeInstances", "ec2.amazonaws.com", True),
    ("ListBucket", "s3.amazonaws.com", True),
    ("GetObject", "s3.amazonaws.com", True),
    ("DescribeVolumes", "ec2.amazonaws.com", True),
    ("GetCallerIdentity", "sts.amazonaws.com", True),
    ("DescribeSecurityGroups", "ec2.amazonaws.com", True),
    ("ListTables", "dynamodb.amazonaws.com", True),
    ("GetParameter", "ssm.amazonaws.com", True),
    ("DescribeLogGroups", "logs.amazonaws.com", True),
    ("PutObject", "s3.amazonaws.com", False),
    ("HeadObject", "s3.amazonaws.com", True),
    ("AssumeRole", "sts.amazonaws.com", False),
]


class GenContext:
    """Mints events for one incident. Handed to each scenario builder."""

    def __init__(self, rng: random.Random, incident_id: str, t0: datetime):
        self.rng = rng
        self.incident_id = incident_id
        self.t0 = t0
        self.account_id = ACCOUNT_ID
        self._seq = 0
        self._session_seq = 0

    # -- helpers available to scenario builders --
    def session(self) -> str:
        self._session_seq += 1
        return "%s-sess-%d" % (self.incident_id.lower(), self._session_seq)

    def hostile_ip(self, asn: str) -> str:
        # zlib.crc32, not hash(): str hashing is salted per process unless
        # PYTHONHASHSEED is pinned, which would silently break determinism.
        h = zlib.crc32((asn + self.incident_id).encode("utf-8")) % 200
        return "%d.%d.%d.%d" % (45 + h % 150, self.rng.randint(1, 254),
                                self.rng.randint(1, 254), self.rng.randint(2, 253))

    def normal_ip(self, principal: str) -> str:
        prof = CAST.get(principal)
        if prof and prof["is_service"]:
            return "10.%d.%d.%d" % (self.rng.randint(0, 40), self.rng.randint(0, 255),
                                    self.rng.randint(2, 253))
        return "73.%d.%d.%d" % (self.rng.randint(0, 255), self.rng.randint(0, 255),
                                self.rng.randint(2, 253))

    def ev(self, minute, event_name, event_source, principal, *, region=None, ip=None,
           asn=None, params=None, response=None, error=None, resources=None,
           read_only=True, ua=None, session=None) -> Event:
        self._seq += 1
        prof = CAST.get(principal)
        if region is None:
            region = prof["home_regions"][0] if prof else "us-east-1"
        if asn is None:
            asn = (prof["known_asns"][0] if prof and prof["known_asns"] else "AS14618 Amazon")
        if ip is None:
            ip = self.normal_ip(principal)
        return Event(
            event_id="evt-%s-%04d" % (self.incident_id, self._seq),
            event_time=(self.t0 + timedelta(minutes=minute)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            event_source=event_source,
            event_name=event_name,
            aws_region=region,
            source_ip=ip,
            source_asn=asn,
            user_agent=ua or self.rng.choice(USER_AGENTS),
            principal_id=prof["principal_id"] if prof else "ANONYMOUS",
            principal_type=prof["principal_type"] if prof else "Anonymous",
            principal_name=principal,
            account_id=self.account_id,
            session_id=session,
            request_parameters=params or {},
            response_elements=response,
            error_code=error,
            resources=resources or [],
            read_only=read_only,
        )


def _background(ctx: GenContext, count: int, window_minutes: int, exclude: str) -> list:
    """Routine estate activity. Never touches the scenario's signal principal."""
    others = [k for k in CAST if k != exclude]
    out = []
    for _ in range(count):
        who = ctx.rng.choice(others)
        prof = CAST[who]
        name, source, ro = ctx.rng.choice(BACKGROUND_EVENTS)
        if name not in prof["typical_events"] and ctx.rng.random() < 0.55:
            name, source, ro = ctx.rng.choice(
                [(n, s, r) for n, s, r in BACKGROUND_EVENTS if n in prof["typical_events"]]
                or BACKGROUND_EVENTS
            )
        params = {}
        if source == "s3.amazonaws.com":
            params = {"bucketName": ctx.rng.choice(BUCKETS),
                      "key": "warehouse/part-%05d.parquet" % ctx.rng.randint(0, 99999)}
        out.append(ctx.ev(
            ctx.rng.randint(0, window_minutes), name, source, who,
            region=ctx.rng.choice(prof["home_regions"]), params=params, read_only=ro,
        ))
    return out


def build_incident(index: int, builder, tier: str, seed: int) -> tuple:
    incident_id = "WRD-%04d" % (index + 1)
    rng = random.Random(seed * 1000 + index)
    # Stagger incidents across a fortnight so timestamps are not all identical.
    t0 = datetime(2026, 8, 24, 0, 0, 0, tzinfo=timezone.utc) + timedelta(
        days=index % 14, hours=rng.randint(0, 23), minutes=rng.randint(0, 59)
    )
    ctx = GenContext(rng, incident_id, t0.replace(tzinfo=None))
    result = builder(ctx)

    signal = result.events
    # Hard-tier signal is spread across days, so its noise window must cover the
    # same span or the background would cluster in front of the evidence.
    window = 1440 * 5 if tier == "hard" else 240
    noise_count = rng.randint(180, 420) if tier != "hard" else rng.randint(420, 700)
    noise = _background(ctx, noise_count, window, result.primary_principal)

    events = sorted(signal + noise, key=lambda e: (e.event_time, e.event_id))

    alert = Alert(
        alert_id="ALT-%04d" % (index + 1),
        incident_id=incident_id,
        detected_at=(t0 + timedelta(minutes=45)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        rule_id=result.rule_id,
        rule_name=result.rule_name,
        severity_reported=result.severity_reported,
        summary=result.summary,
        primary_principal=result.primary_principal,
        account_id=ACCOUNT_ID,
        region=signal[0].aws_region,
        seed_event_ids=result.seed_event_ids,
    )
    gt = GroundTruth(scenario=builder.__name__, tier=tier, **result.gt)
    incident = Incident(
        incident_id=incident_id, tier=tier, scenario=builder.__name__, alert=alert,
        ground_truth=gt, log_path="logs/%s.jsonl" % incident_id,
        event_count=len(events), signal_event_count=len(signal),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        generator_version=GENERATOR_VERSION, seed=seed,
    )
    return incident, events


def generate(out_dir: str, seed: int, count: int) -> dict:
    os.makedirs(os.path.join(out_dir, "logs"), exist_ok=True)
    os.makedirs(os.path.join(out_dir, "alerts"), exist_ok=True)

    incidents, tier_counts, total_events = [], {}, 0
    for i, (builder, tier) in enumerate(REGISTRY[:count]):
        incident, events = build_incident(i, builder, tier, seed)
        write_jsonl(os.path.join(out_dir, "logs", "%s.jsonl" % incident.incident_id),
                    [e.to_json() for e in events])
        with open(os.path.join(out_dir, "alerts", "%s.json" % incident.incident_id),
                  "w", encoding="utf-8") as fh:
            json.dump(incident.alert.to_json(), fh, indent=2)
        incidents.append(incident)
        tier_counts[tier] = tier_counts.get(tier, 0) + 1
        total_events += incident.event_count

    write_jsonl(os.path.join(out_dir, "incidents.jsonl"), [i.to_json() for i in incidents])

    profiles = {name: PrincipalProfile(name=name, **spec).to_json() for name, spec in CAST.items()}
    with open(os.path.join(out_dir, "principals.json"), "w", encoding="utf-8") as fh:
        json.dump(profiles, fh, indent=2)

    verdicts = {}
    for inc in incidents:
        verdicts[inc.ground_truth.verdict] = verdicts.get(inc.ground_truth.verdict, 0) + 1

    manifest = {
        "dataset_version": "v1",
        "schema_version": SCHEMA_VERSION,
        "generator_version": GENERATOR_VERSION,
        "seed": seed,
        "incident_count": len(incidents),
        "total_events": total_events,
        "tier_distribution": tier_counts,
        "verdict_distribution": verdicts,
        "account_id": ACCOUNT_ID,
        "principal_count": len(profiles),
        "note": "Regenerate with: make gen. Deterministic for a fixed seed.",
    }
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    return manifest


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate the Warden golden dataset.")
    ap.add_argument("--out", default="datasets/v1")
    ap.add_argument("--seed", type=int, default=20260903)
    ap.add_argument("--count", type=int, default=20)
    args = ap.parse_args()
    manifest = generate(args.out, args.seed, args.count)
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
