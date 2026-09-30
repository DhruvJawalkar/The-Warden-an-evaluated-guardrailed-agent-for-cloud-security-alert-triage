# RB-SEC-001: Bulk secret retrieval

## Purpose

Applies when many secrets are listed or read in a short time. Secrets stores hold database passwords and API keys, so a sweep hands an attacker every downstream system at once. Some services read secrets in bulk as their job, which makes the identity of the reader the key fact.

## Investigation steps

Check whether the principal is documented as a secrets consumer, and whether the specific secrets read fall inside its allowed scope. A rotation service reads many secrets on a schedule; an application role should read only its own. Look at sequence: list-then-read of everything is enumeration. Note any secret outside the principal's documented permissions, since a single such read is enough to matter.

## Benign explanations

Scheduled rotation jobs, deployment steps that fetch their own configuration, and disaster-recovery tests. Reads arrive at the scheduled time from the service's normal network and touch a predictable list.

## Containment

Rotate every secret that was read, starting with the most privileged, and revoke the principal's credentials. Rotation is a write action and needs approval. Rotate before concluding the investigation, since the secrets have to be treated as exposed.

## Evidence to capture

The list and read events, the count and names of secrets touched, and the principal's documented scope for comparison.
