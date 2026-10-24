# Identity Attack Graph — Dataset Starter

This starter generates deterministic synthetic data for the hackathon prototype. It does not yet implement the graph detector or API.

## Requirements

- Python 3.10+
- No third-party packages required for dataset generation or tests

## Windows PowerShell setup

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python scripts\generate_dataset.py
python -m unittest discover -s tests -v
```

If PowerShell blocks activation, run the commands using `py` directly or use Command Prompt activation at `.venv\Scripts\activate.bat`.

## Outputs

Generation writes `data/entities.json`, `data/events.json`, `data/relationships.json`, `data/scenarios.json`, and `data/summary.json`. Use `--seed 7042026` to reproduce the default dataset. A custom output directory is supported with `--out path`.

## Important caveat

The generator and integrity checks are the first workstream only. Next we should inspect the actual counts and scenario composition, then implement graph construction and transparent baseline detection. Do not use `ground_truth_label` as a detector feature.
