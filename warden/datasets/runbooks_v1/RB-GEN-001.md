# RB-GEN-001: Baseline-first triage method

## Purpose

A general method for any alert. Activity is anomalous only relative to the identity that performed it. The same event is routine for one principal and alarming for another, so establish the baseline before forming a view.

## Investigation steps

Start with who: is the principal a person or a service, which team owns it, and what does it usually do. Then compare each dimension of the alert against the baseline independently: region, source network, action, targeted resource, hour of day, scope. One mismatch is a finding even when the rest looks normal. Widen the search to writes by the same principal across the whole window. If the activity seems enabled by a change, look for who made it.

## Benign explanations

Do not accept "this looks normal" without a positive reason. Legitimate activity leaves affirmative traces: an owner, a schedule, a ticket, a known network. Absence of anomalies is weaker evidence than a matching record of intent.

## Escalation

Escalate when the baseline disagrees on any dimension and you cannot find an affirmative explanation. Escalating a real event late costs more than escalating an ordinary one early, but a queue full of guesses trains analysts to ignore it, so tie each escalation to specific events.

## Evidence to capture

The baseline used, the events that deviate from it, and the events showing legitimacy where the call is benign.
