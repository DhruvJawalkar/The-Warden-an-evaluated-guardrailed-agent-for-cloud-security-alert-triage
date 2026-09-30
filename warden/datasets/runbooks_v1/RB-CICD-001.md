# RB-CICD-001: Pipeline compromise and supply-chain changes

## Purpose

Applies when a deployment principal pushes code or swaps a role's configuration shortly before another workload behaves oddly. The workload that alerts may be innocent: an attacker who controls the pipeline can change what a function runs or what it is allowed to do, and the anomaly appears downstream, later.

## Investigation steps

When the alerting principal's own activity looks driven by something else, ask what changed. Search for code updates, layer changes, role reassignments and environment edits made to that workload in the hours before the alert. Identify the actor of that change and investigate them too. Compare the timeline: a role swap minutes before unexpected secret reads is causal until shown otherwise.

## Benign explanations

Routine releases: a deploy from the pipeline, tied to a merge, during the release window, with the role unchanged. A new permission added intentionally alongside new code.

## Containment

Roll back the function to the last known-good version, restore the previous execution role, and rotate credentials the changed workload could read. Also review what else the deploying principal touched. All are write actions that need approval.

## Evidence to capture

The change event on the workload, the actor who made it, and the downstream anomalous events. The pair is what shows cause; either alone is ambiguous.
