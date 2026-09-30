# RB-CONSOLE-001: Console sign-in from an unfamiliar network or location

## Purpose

Applies when a human IAM user signs in to the management console from a network provider or country not seen in their history, especially when MFA was not part of the sign-in. Console access by a person is the most common way stolen passwords become cloud access, so the first question is whether the person and the sign-in agree.

## Investigation steps

Pull the principal's baseline first: home regions, usual provider networks, working hours. Compare the sign-in on each dimension separately, because a plausible country can still come from a hosting provider. Check whether MFA was used, then look at what the session did in the first ten minutes: role assumption, listing of buckets, reading of data stores. Sessions that go straight to enumeration and role switching behave like an intruder rather than a traveller.

## Benign explanations

Business travel, a change of ISP, a corporate VPN exit node in another country, or a user working from a new office. A benign sign-in usually shows normal working hours, MFA satisfied, and activity limited to the tools the person routinely uses. Residential and mobile carriers are far more likely to be benign than commodity hosting providers.

## Containment

If the sign-in has no MFA and the follow-on activity is enumeration or role switching, treat the credentials as compromised: revoke active sessions, disable the console password, and rotate access keys. These are write actions and need analyst approval before they are executed.

## Evidence to capture

The sign-in event with source network and MFA field, the first role assumption after it, and any data-read events in the same session. For a benign verdict, capture the prior sign-in that establishes the person's usual pattern.
