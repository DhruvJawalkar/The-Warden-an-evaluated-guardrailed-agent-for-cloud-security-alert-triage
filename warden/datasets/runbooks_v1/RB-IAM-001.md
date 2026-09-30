# RB-IAM-001: Privilege escalation through policy attachment

## Purpose

Applies when a principal attaches a broad managed policy, adds an inline policy with wildcard actions, or creates credentials for another identity. Escalation is how a foothold with narrow rights becomes control of the account. The alerting principal may be the victim of a hijacked session rather than the author of the change.

## Investigation steps

Identify who made the change and to whom it applied. Check whether the actor normally performs identity administration; most engineers never do. Look at the session that made the change: where it came from and how it was established. Then follow the beneficiary: did the newly empowered identity use the new rights, and from where? Search all write events by the actor across the window, not only the alerting call.

## Benign explanations

Planned access changes by an identity team, with a ticket reference and business-hours timing. An onboarding sequence where a new employee is granted a role appropriate to their team. Break-glass use that is announced and time-boxed.

## Containment

Detach the added policy, deactivate any freshly minted access key, and revoke the actor's active sessions. Each of these is a write action requiring analyst approval. Preserve the original policy document before detaching it.

## Evidence to capture

The attach or put-policy event, the key-creation event if any, and the first action taken with the new rights. The change event alone shows intent; the follow-on use shows impact.
