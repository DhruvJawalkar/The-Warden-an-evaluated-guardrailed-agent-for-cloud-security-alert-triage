# RB-LOG-001: Audit logging disabled or narrowed

## Purpose

Applies when a trail is stopped, deleted or its event selectors are reduced. Turning off the record of what you do is a defence-evasion step and typically precedes something else. Any such change deserves immediate attention because the evidence window is closing while you read.

## Investigation steps

Establish the exact scope of the change: stopped, deleted, or narrowed to read-only events. Determine the gap: when logging stopped and whether it has resumed. Identify who made the change and from which session. Then look at what else that principal did just before and after; actions taken inside the blind spot may only be visible through other sources such as service-specific logs.

## Benign explanations

Planned trail reconfiguration during an organisation-wide logging migration, announced in advance and performed by the platform team. Even then, the trail should be re-enabled promptly.

## Containment

Re-enable logging first, since every minute off is lost evidence. Then revoke the actor's sessions. Both need approval, but this is the one action worth escalating with urgency rather than waiting in the queue.

## Evidence to capture

The stop, delete or selector-change events with parameters, the exact start and end of the logging gap, and everything the actor did adjacent to it.
