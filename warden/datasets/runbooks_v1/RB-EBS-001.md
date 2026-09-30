# RB-EBS-001: Disk snapshot creation and sharing

## Purpose

Applies when volume snapshots are created in bulk or shared with another AWS account. Sharing a snapshot moves a full copy of a disk, including any secrets on it, to a place you do not control. Creation alone is usually backup activity; sharing outside the organisation is the event that matters.

## Investigation steps

Separate the two behaviours. For bulk creation, compare with the backup principal's schedule and volume count. For sharing, identify the destination account and check it against the organisation's list of member and partner accounts. An unknown destination is a finding regardless of who did it. Look at the sharing principal's other activity, since exfiltration tends to arrive in a chain of small steps.

## Benign explanations

Nightly backup jobs create many snapshots at a fixed hour and share none. Sharing with a known disaster-recovery or vendor account under a signed agreement is expected and documented.

## Containment

Remove the external sharing permission and delete the copy in the destination if the organisation controls it. These are write actions requiring approval. Determine what data the disk held to size the exposure.

## Evidence to capture

The share event with the destination account identifier, the snapshot and its source volume, and the creating principal's history.
