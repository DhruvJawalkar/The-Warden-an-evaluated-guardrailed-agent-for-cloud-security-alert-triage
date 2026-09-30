# RB-STS-001: Service role used from outside the provider network

## Purpose

Applies when a role that belongs to automation is assumed from an address that is not the provider's own infrastructure. Service roles are supposed to be assumed by services running inside the cloud. An outside caller means the credentials left the environment, often through a leaked file or a compromised pipeline.

## Investigation steps

Check the network of origin against the role's known networks. Identify how the credentials could have been obtained: a repository, a build log, a state file. Follow the session: automation assumed from outside usually goes for secrets, infrastructure state and storage. Compare what it reads with what the role reads in normal operation, which is typically narrow and repetitive.

## Benign explanations

A developer running a pipeline locally through a documented process, or a partner integration with an allow-listed external address. These are rare enough that each should have a named owner.

## Containment

Revoke the role's active sessions and rotate any credentials it could reach. Tighten the trust policy to require the expected source. Approval is required. Also hunt for the leak that let the credentials out.

## Evidence to capture

The role assumption with source address, what the session read afterwards, and the baseline showing the role's normal networks.
