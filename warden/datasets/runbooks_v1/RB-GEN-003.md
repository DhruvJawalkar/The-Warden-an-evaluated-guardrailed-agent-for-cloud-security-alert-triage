# RB-GEN-003: Containment actions and approval

## Purpose

Describes which response actions exist, which need a human to approve, and what order to take them in. The investigating agent recommends; a person decides on anything that changes the environment. Containment that breaks production is an incident of its own.

## Investigation steps

Before recommending containment, confirm the blast radius: what the identity can reach, what depends on it, and whether it serves production traffic. A service role behind a live workload needs a different plan from a personal user account. Prefer reversible steps such as disabling a key or revoking sessions over deletion, and take a snapshot of state before changing it.

## Benign explanations

If the evidence supports a benign explanation, the correct action is to close with the reason recorded, not to contain as a precaution. Precautionary containment of a routine automation role is a common cause of outages.

## Containment

Order of preference: revoke sessions, disable credentials, restrict policy, isolate resources, delete. Every write action is gated on approval from the on-call analyst, with the action, the target and the supporting events stated in the request. Emergency actions such as re-enabling audit logging may be flagged for expedited approval but are not exempt.

## Evidence to capture

The approval request, who approved, the action taken and its result, and the state before the change so it can be undone.
