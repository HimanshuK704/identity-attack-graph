
"""Build the identity graph and run explainable heuristic detection.

Ground-truth labels are never used as detector inputs.
Shared IP addresses alone do not increase risk scores.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"


def load_dataset(data_dir: Path = DATA_DIR) -> dict:
    """Load the canonical synthetic dataset files."""
    return {
        name: json.loads(
            (data_dir / f"{name}.json").read_text(encoding="utf-8")
        )
        for name in ("entities", "events", "relationships", "scenarios")
    }


def build_graph(data: dict) -> dict:
    """Build nodes and edges in Cytoscape.js-compatible JSON format."""
    nodes = [
        {
            "data": {
                "id": entity["id"],
                "label": entity["label"],
                "type": entity["type"],
                "metadata": entity.get("metadata", {}),
            }
        }
        for entity in data["entities"]
    ]

    edges = [
        {
            "data": {
                "id": relationship["id"],
                "source": relationship["source"],
                "target": relationship["target"],
                "label": relationship["type"],
                "timestamp": relationship["timestamp"],
                "evidence_id": relationship["evidence_id"],
            }
        }
        for relationship in data["relationships"]
    ]

    return {"nodes": nodes, "edges": edges}


def _components(groups: list[set[str]]) -> list[set[str]]:
    """Merge overlapping account groups using union-find."""
    parent: dict[str, str] = {}

    def find(account: str) -> str:
        parent.setdefault(account, account)

        while parent[account] != account:
            parent[account] = parent[parent[account]]
            account = parent[account]

        return account

    def union(first: str, second: str) -> None:
        root_first = find(first)
        root_second = find(second)

        if root_first != root_second:
            parent[max(root_first, root_second)] = min(
                root_first, root_second
            )

    for group in groups:
        ordered = sorted(group)

        for account in ordered:
            find(account)

        for account in ordered[1:]:
            union(ordered[0], account)

    result: dict[str, set[str]] = defaultdict(set)

    for account in parent:
        result[find(account)].add(account)

    return sorted(result.values(), key=lambda group: min(group))


def detect_clusters(data: dict) -> list[dict]:
    """Find suspicious account groups using transparent heuristic rules."""
    entities = {item["id"]: item for item in data["entities"]}
    relationships = data["relationships"]
    events = data["events"]

    accounts = {
        entity_id
        for entity_id, entity in entities.items()
        if entity["type"] == "ACCOUNT"
    }

    device_accounts: dict[str, set[str]] = defaultdict(set)
    ip_accounts: dict[str, set[str]] = defaultdict(set)
    beneficiary_accounts: dict[str, set[str]] = defaultdict(set)

    transaction_owner: dict[str, str] = {}
    transaction_beneficiary: dict[str, str] = {}

    transactions_by_account: dict[
        str, list[tuple[datetime, float, str]]
    ] = defaultdict(list)

    # Extract graph relationships without reading ground-truth labels.
    for relationship in relationships:
        source = relationship["source"]
        target = relationship["target"]
        kind = relationship["type"]

        if (
            kind == "USES_DEVICE"
            and source in accounts
            and entities.get(target, {}).get("type") == "DEVICE"
        ):
            device_accounts[target].add(source)

        elif (
            kind == "LOGGED_IN_FROM"
            and source in accounts
            and entities.get(target, {}).get("type") == "IP_ADDRESS"
        ):
            ip_accounts[target].add(source)

        elif (
            kind == "INITIATED_TRANSACTION"
            and source in accounts
            and entities.get(target, {}).get("type") == "TRANSACTION"
        ):
            transaction_owner[target] = source

        elif (
            kind == "SENT_TO"
            and entities.get(source, {}).get("type") == "TRANSACTION"
            and entities.get(target, {}).get("type") == "BENEFICIARY"
        ):
            transaction_beneficiary[source] = target

    # Build account-to-beneficiary paths from transaction relationships.
    for transaction_id, beneficiary_id in transaction_beneficiary.items():
        account_id = transaction_owner.get(transaction_id)

        if account_id:
            beneficiary_accounts[beneficiary_id].add(account_id)

    # Read amounts and timestamps from events, never scenario labels.
    for event in events:
        if event.get("event_type") != "INITIATED_TRANSACTION":
            continue

        account_id = event["source_id"]
        transaction_id = event["target_id"]

        if (
            account_id not in accounts
            or entities.get(transaction_id, {}).get("type") != "TRANSACTION"
        ):
            continue

        amount = float(event.get("details", {}).get("amount", 0) or 0)
        timestamp = datetime.fromisoformat(
            event["timestamp"].replace("Z", "+00:00")
        )

        transactions_by_account[account_id].append(
            (timestamp, amount, transaction_id)
        )

    # Shared IP addresses are deliberately excluded as cluster triggers.
    candidate_groups = [
        members
        for members in device_accounts.values()
        if len(members) >= 3
    ]

    candidate_groups += [
        members
        for members in beneficiary_accounts.values()
        if len(members) >= 3
    ]

    findings = []

    for index, group in enumerate(_components(candidate_groups), start=1):
        signals = []
        score = 0

        shared_devices = sorted(
            device
            for device, members in device_accounts.items()
            if len(members & group) >= 3
        )

        shared_beneficiaries = sorted(
            beneficiary
            for beneficiary, members in beneficiary_accounts.items()
            if len(members & group) >= 4
        )

        shared_ips = sorted(
            ip
            for ip, members in ip_accounts.items()
            if len(members & group) >= 3
        )

        if shared_devices:
            score += 35
            signals.append({
                "code": "SHARED_DEVICE",
                "description": (
                    "At least three accounts used a common device."
                ),
                "points": 35,
                "entity_ids": shared_devices,
            })

        if shared_beneficiaries:
            score += 35
            signals.append({
                "code": "BENEFICIARY_CONCENTRATION",
                "description": (
                    "At least four accounts sent transactions "
                    "to a common beneficiary."
                ),
                "points": 35,
                "entity_ids": shared_beneficiaries,
            })

        transaction_rows = sorted(
            (
                timestamp,
                account_id,
                amount,
                transaction_id,
            )
            for account_id in group
            for timestamp, amount, transaction_id
            in transactions_by_account.get(account_id, [])
        )

        # Check whether at least four accounts transact in 15 minutes.
        rapid_accounts = set()

        for start_index, (start_time, _, _, _) in enumerate(
            transaction_rows
        ):
            window_accounts = set()

            for timestamp, account_id, _, _ in transaction_rows[start_index:]:
                if (timestamp - start_time).total_seconds() > 15 * 60:
                    break

                window_accounts.add(account_id)

            if len(window_accounts) >= 4:
                rapid_accounts = window_accounts
                break

        if len(rapid_accounts) >= 4:
            score += 30
            signals.append({
                "code": "RAPID_COORDINATED_ACTIVITY",
                "description": (
                    "Transactions from at least four accounts "
                    "occurred within a 15-minute window."
                ),
                "points": 30,
                "account_ids": sorted(rapid_accounts),
            })

        high_value_accounts = {
            account_id
            for _, account_id, amount, _ in transaction_rows
            if amount >= 700
        }

        high_value_members = high_value_accounts & group

        if len(high_value_members) >= 3:
            score += 15
            signals.append({
                "code": "MULTI_ACCOUNT_HIGH_VALUE",
                "description": (
                    "At least three linked accounts made "
                    "synthetic transactions of 700 units or more."
                ),
                "points": 15,
                "account_ids": sorted(high_value_members),
            })

        # Shared IP is contextual evidence only: zero risk points.
        if shared_ips:
            signals.append({
                "code": "SHARED_IP_CONTEXT",
                "description": (
                    "Accounts share an IP address. This is contextual "
                    "and contributes no risk points by itself."
                ),
                "points": 0,
                "entity_ids": shared_ips,
            })

        score = min(score, 100)

        if score < 35:
            continue

        risk_level = (
            "HIGH" if score >= 70
            else "MEDIUM" if score >= 45
            else "LOW"
        )

        linked_entities = set(group)
        linked_entities.update(shared_devices)
        linked_entities.update(shared_beneficiaries)
        linked_entities.update(shared_ips)

        for account_id in group:
            for _, _, transaction_id in transactions_by_account.get(
                account_id, []
            ):
                linked_entities.add(transaction_id)

                beneficiary = transaction_beneficiary.get(transaction_id)
                if beneficiary:
                    linked_entities.add(beneficiary)

        findings.append({
            "cluster_id": f"CL-{index:03d}",
            "risk_score": score,
            "risk_level": risk_level,
            "score_type": "heuristic",
            "account_ids": sorted(group),
            "entity_ids": sorted(linked_entities),
            "signals": signals,
            "summary": (
                f"{len(group)} linked accounts have "
                f"{len(signals)} explainable signal(s); "
                "review the evidence before taking action."
            ),
        })

    return sorted(
        findings,
        key=lambda item: (-item["risk_score"], item["cluster_id"]),
    )



def detect_account_takeovers(data: dict) -> list[dict]:
    """Detect unfamiliar access followed by a transfer to a new beneficiary.

    Uses relationships and timestamps only. Ground-truth labels and scenario
    IDs are deliberately excluded from detection logic.
    """
    from datetime import datetime, timezone

    def parse_time(value):
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except (TypeError, ValueError):
            return None

    relationships = data.get("relationships", [])
    entities = {e["id"]: e for e in data.get("entities", [])}

    def ordered_rels(rel_type, account=None):
        result = [
            r for r in relationships
            if r.get("type") == rel_type
            and (account is None or r.get("source") == account)
        ]
        return sorted(
            result,
            key=lambda r: parse_time(r.get("timestamp"))
            or datetime.min.replace(tzinfo=timezone.utc)
        )

    account_ids = {
        r.get("source")
        for r in relationships
        if r.get("type") in {"USES_DEVICE", "LOGGED_IN_FROM", "INITIATED_TRANSACTION"}
        and entities.get(r.get("source"), {}).get("type") == "ACCOUNT"
    }

    findings = []

    for account_id in sorted(account_ids):
        account_rels = [
            r for r in relationships
            if r.get("source") == account_id
        ]

        access_history = []
        for rel in account_rels:
            if rel.get("type") not in {"USES_DEVICE", "LOGGED_IN_FROM"}:
                continue
            timestamp = parse_time(rel.get("timestamp"))
            if timestamp is None:
                continue
            access_history.append((timestamp, rel))

        access_history.sort(key=lambda item: item[0])
        known_devices = set()
        known_ips = set()
        unfamiliar_accesses = []

        for timestamp, rel in access_history:
            target = rel.get("target")
            kind = rel.get("type")
            known = known_devices if kind == "USES_DEVICE" else known_ips

            if known and target not in known:
                unfamiliar_accesses.append({
                    "timestamp": timestamp,
                    "type": kind,
                    "entity_id": target,
                    "evidence_id": rel.get("evidence_id"),
                })

            known.add(target)

        if not unfamiliar_accesses:
            continue

        # Build each account's beneficiary history from transaction links.
        account_transactions = [
            r for r in account_rels
            if r.get("type") == "INITIATED_TRANSACTION"
            and parse_time(r.get("timestamp")) is not None
        ]
        account_transactions.sort(key=lambda r: parse_time(r["timestamp"]))

        sent_to = {
            r.get("source"): r
            for r in ordered_rels("SENT_TO")
        }

        used_beneficiaries = set()
        matched = []

        for tx_rel in account_transactions:
            tx_time = parse_time(tx_rel["timestamp"])
            tx_id = tx_rel.get("target")
            sent_rel = sent_to.get(tx_id)
            if not sent_rel:
                continue

            beneficiary_id = sent_rel.get("target")
            if not beneficiary_id:
                continue

            matching_access = next(
                (
                    access for access in reversed(unfamiliar_accesses)
                    if access["timestamp"] <= tx_time
                    and (tx_time - access["timestamp"]).total_seconds() <= 3600
                ),
                None,
            )

            is_new_beneficiary = beneficiary_id not in used_beneficiaries

            if matching_access and is_new_beneficiary:
                evidence_ids = [
                    matching_access.get("evidence_id"),
                    tx_rel.get("evidence_id"),
                    sent_rel.get("evidence_id"),
                ]
                matched.append({
                    "timestamp": tx_time,
                    "access": matching_access,
                    "transaction_id": tx_id,
                    "beneficiary_id": beneficiary_id,
                    "evidence_ids": sorted({
                        item for item in evidence_ids if item
                    }),
                })

            # Record beneficiary only after evaluating this transaction,
            # preserving the meaning of "new at the time of transfer".
            used_beneficiaries.add(beneficiary_id)

        if not matched:
            continue

        unique_accesses = {
            item["access"]["entity_id"]: item["access"]
            for item in matched
        }
        evidence_ids = sorted({
            evidence_id
            for item in matched
            for evidence_id in item["evidence_ids"]
        })

        signals = [
            {
                "code": "UNFAMILIAR_ACCESS_CONTEXT",
                "points": 20,
                "description": "A device or IP differs from the account's earlier observed access history.",
            },
            {
                "code": "NEW_BENEFICIARY_AFTER_UNFAMILIAR_ACCESS",
                "points": 20,
                "description": "A transfer to a previously unseen beneficiary followed unfamiliar access within one hour.",
            },
        ]

        findings.append({
            "cluster_id": f"TA-{account_id}",
            "risk_score": 40,
            "risk_level": "LOW",
            "score_type": "heuristic",
            "account_ids": [account_id],
            "entity_ids": sorted({
                account_id,
                *(item["entity_id"] for item in unique_accesses.values()),
                *(item["beneficiary_id"] for item in matched),
                *(item["transaction_id"] for item in matched),
            }),
            "signals": signals,
            "evidence_ids": evidence_ids,
            "summary": (
                "Unfamiliar access was followed by a transfer to a new "
                "beneficiary. This is an investigation lead, not proof "
                "of impersonation or fraud."
            ),
        })

    return sorted(findings, key=lambda item: item["cluster_id"])


def main():
    parser = argparse.ArgumentParser(
        description="Build the identity graph and detect suspicious clusters."
    )
    parser.add_argument("--data-dir", default=str(DATA_DIR))
    parser.add_argument("--out-dir", default=str(DATA_DIR))
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    out_dir = Path(args.out_dir)

    data = load_dataset(data_dir)
    graph = build_graph(data)
    findings = detect_clusters(data)
    findings.extend(detect_account_takeovers(data))

    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "graph.json").write_text(
        json.dumps(graph, indent=2) + "\n",
        encoding="utf-8",
    )

    (out_dir / "clusters.json").write_text(
        json.dumps({
            "score_type": "heuristic",
            "clusters": findings,
        }, indent=2) + "\n",
        encoding="utf-8",
    )

    print(json.dumps({
        "node_count": len(graph["nodes"]),
        "edge_count": len(graph["edges"]),
        "cluster_count": len(findings),
        "clusters": [
            {
                "cluster_id": cluster["cluster_id"],
                "risk_score": cluster["risk_score"],
                "risk_level": cluster["risk_level"],
                "account_count": len(cluster["account_ids"]),
                "signals": [
                    signal["code"] for signal in cluster["signals"]
                ],
            }
            for cluster in findings
        ],
    }, indent=2))


if __name__ == "__main__":
    main()
