# Synthetic dataset data dictionary

All records are synthetic demo data. No real customer or personal data is used. IDs are stable for a given generator seed.

- `entities.json`: entity records with `id`, `type`, `label`, `scenario_id`, `ground_truth_label`, and safe `metadata`.
- `events.json`: timestamped activity records with `id`, `event_type`, `timestamp`, `source_id`, `target_id`, `scenario_id`, `ground_truth_label`, and event-specific `details`.
- `relationships.json`: graph edges with `id`, `source`, `target`, `type`, `timestamp`, `evidence_id`, and `scenario_id`. `evidence_id` links an edge to the source event.
- `scenarios.json`: scenario descriptions and ground-truth labels for evaluation and demo selection.
- `summary.json`: generated counts by entity type, event type, scenario, and event ground-truth label.

## Labels and leakage prevention

`ground_truth_label` is for evaluation/demo annotation only. Detection features must not use this label as an input. `BENIGN` means benign in this synthetic scenario, `PLANTED_SUSPICIOUS` identifies a deliberately constructed demo pattern, and `AMBIGUOUS` requires context and human review. These are not claims about real-world prevalence or actual criminality.

## Scenario coverage

- `SCN-01`: ordinary legitimate activity
- `SCN-02`: benign shared public/campus IP
- `SCN-03`: shared device and hosting IP with rapid high-value activity
- `SCN-04`: multiple accounts sending to one beneficiary
- `SCN-05`: reserved in scenario catalogue for rapid coordinated activity; rapid activity is also present in SCN-03 in this starter version
- `SCN-06`: ambiguous shared business network

Timestamps are ISO-8601 UTC strings. Currency amounts are synthetic USD values for demo consistency only.
