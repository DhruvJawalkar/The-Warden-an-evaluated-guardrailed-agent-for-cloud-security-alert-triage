# RB-IAM-002: New identity created outside provisioning

## Purpose

Applies when a new IAM user or role appears, particularly a user with programmatic keys and no human owner. Attackers create identities to keep access after the original credential is rotated. The creation is only the start; what the new identity is allowed to do decides the severity.

## Investigation steps

Find who created the identity and by what path. Compare against the provisioning pipeline: legitimate identities are normally created by automation with tags and a naming convention. Check the new identity's attached policies, whether a key was created within minutes, and whether the key has been used and from which network. A creator that acts rarely, and outside its normal hours, deserves a look at its own session.

## Benign explanations

A service onboarding through the approved pipeline, an engineer working from a ticket, or a migration that recreates users. These leave tags, a conventional name and a low-privilege policy.

## Containment

Disable the new identity's keys, remove attached policies, and hold the identity for review instead of deleting it so that its history remains queryable. Approval is required before any of these changes.

## Evidence to capture

The creation event, the policy attachment, the key creation, and the first use of the key. Note the naming and tagging so the reviewer can judge whether it followed convention.
