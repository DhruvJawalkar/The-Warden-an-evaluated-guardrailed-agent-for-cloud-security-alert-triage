# RB-CONSOLE-002: Repeated authentication failures followed by success

## Purpose

Applies when a burst of failed console sign-ins for one user is followed by a successful one. The pattern is consistent with password guessing or credential stuffing that eventually landed, but also with a person who forgot a password. The decision turns on the source of the failures and what happens after the success.

## Investigation steps

Count the failures and read their spacing: machine-paced attempts arrive at near-regular intervals, human attempts are ragged. Note the source network of the failures and of the success, and whether they match. Check for MFA on the successful sign-in. Then read forward from the success: a password reset flow or normal work is reassuring, immediate role assumption or access-key creation is not.

## Benign explanations

A small number of failures from the user's usual network, followed by a success from the same network with MFA satisfied, is ordinary forgetfulness or a password manager desync. Failures clustered right after a scheduled password rotation are also common.

## Containment

When failures came from hosting infrastructure and the success skipped MFA, force a password reset, revoke sessions, and review keys created since the success. Lockout policy changes are outside the analyst's remit and go to the identity team.

## Evidence to capture

The failed-attempt sequence with timestamps and source networks, the successful sign-in, and its MFA field. For a benign call, capture the matching network in earlier history.
