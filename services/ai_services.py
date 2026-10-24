
from __future__ import annotations

import json
import os
from collections import deque
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

load_dotenv(BASE_DIR / ".env")


class AIServiceError(Exception):
    """Base exception for AI service failures."""


class AIUnavailableError(AIServiceError):
    """Raised when an API key is not configured."""


def load_data(filename: str) -> Any:
    """Load a project dataset without modifying the source file."""
    path = DATA_DIR / filename
    if not path.is_file():
        raise FileNotFoundError(f"Required data file is missing: {path}")
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def get_cluster(cluster_id: str) -> dict[str, Any]:
    data = load_data("clusters.json")
    for cluster in data.get("clusters", []):
        if str(cluster.get("cluster_id", "")).casefold() == cluster_id.casefold():
            return cluster
    raise KeyError(f"Cluster '{cluster_id}' was not found.")


def _safe_record(record: dict[str, Any]) -> dict[str, Any]:
    """Remove ground-truth labels so they cannot influence AI explanations."""
    blocked = {"ground_truth_label", "label_truth", "is_fraud"}
    return {
        key: value
        for key, value in record.items()
        if key.casefold() not in blocked
    }


def _entity_map() -> dict[str, dict[str, Any]]:
    entities = load_data("entities.json")
    return {
        str(entity.get("id")): _safe_record(entity)
        for entity in entities
        if entity.get("id") is not None
    }


def build_finding_context(cluster_id: str) -> dict[str, Any]:
    """Build a bounded context using observed fields and evidence only."""
    cluster = _safe_record(get_cluster(cluster_id))
    entities = _entity_map()
    events = load_data("events.json")
    relationships = load_data("relationships.json")

    related_ids: set[str] = set()

    for key in ("entity_ids", "related_entity_ids", "account_ids", "related_ids"):
        value = cluster.get(key, [])
        if isinstance(value, list):
            related_ids.update(str(item) for item in value)

    for key, value in cluster.items():
        if key.casefold() in {"entity_id", "account_id"} and isinstance(value, str):
            related_ids.add(value)

    evidence_ids: set[str] = set()
    evidence = cluster.get("evidence", [])

    if isinstance(evidence, list):
        for item in evidence:
            if isinstance(item, str):
                evidence_ids.add(item)
            elif isinstance(item, dict):
                safe_item = _safe_record(item)
                item_id = (
                    safe_item.get("event_id")
                    or safe_item.get("evidence_id")
                    or safe_item.get("id")
                )
                if item_id:
                    evidence_ids.add(str(item_id))

    relevant_events = []

    for raw_event in events:
        event = _safe_record(raw_event)
        event_id = str(event.get("id", ""))
        source = str(event.get("source_id", ""))
        target = str(event.get("target_id", ""))

        if event_id in evidence_ids or source in related_ids or target in related_ids:
            relevant_events.append(event)
            if source:
                related_ids.add(source)
            if target:
                related_ids.add(target)

    relevant_relationships = []

    for raw_relation in relationships:
        relation = _safe_record(raw_relation)
        source = str(relation.get("source", ""))
        target = str(relation.get("target", ""))
        evidence_id = str(relation.get("evidence_id", ""))

        if source in related_ids or target in related_ids or evidence_id in evidence_ids:
            relevant_relationships.append(relation)
            if evidence_id:
                evidence_ids.add(evidence_id)

    safe_entities = [
        entities[entity_id]
        for entity_id in sorted(related_ids)
        if entity_id in entities
    ]

    return {
        "cluster": cluster,
        "entities": safe_entities[:100],
        "events": sorted(
            relevant_events,
            key=lambda item: str(item.get("timestamp", "")),
        )[:200],
        "relationships": relevant_relationships[:250],
        "notice": (
            "Synthetic investigation data. Shared attributes and graph links "
            "are leads for review, not proof of fraud."
        ),
    }


def build_timeline(cluster_id: str) -> dict[str, Any]:
    """Build an event timeline deterministically."""
    context = build_finding_context(cluster_id)

    entities = {
        str(item.get("id")): item
        for item in context["entities"]
    }

    timeline = []

    for event in context["events"]:
        source_id = str(event.get("source_id", ""))
        target_id = str(event.get("target_id", ""))

        timeline.append({
            "timestamp": event.get("timestamp"),
            "event_id": event.get("id"),
            "event_type": event.get("event_type"),
            "source_id": source_id,
            "source_label": entities.get(source_id, {}).get("label", source_id),
            "target_id": target_id,
            "target_label": entities.get(target_id, {}).get("label", target_id),
            "details": event.get("details", {}),
        })

    timeline.sort(key=lambda item: str(item.get("timestamp") or ""))

    return {
        "cluster_id": cluster_id,
        "count": len(timeline),
        "timeline": timeline,
        "generation_status": "deterministic",
        "notice": context["notice"],
    }


def prioritize_findings() -> dict[str, Any]:
    """Sort findings by their existing heuristic risk scores."""
    data = load_data("clusters.json")
    clusters = data.get("clusters", [])

    ordered = sorted(
        clusters,
        key=lambda item: (
            int(item.get("risk_score", 0)),
            len(item.get("signals", []))
            if isinstance(item.get("signals"), list)
            else 0,
        ),
        reverse=True,
    )

    return {
        "count": len(ordered),
        "score_type": data.get("score_type", "heuristic"),
        "findings": ordered,
        "generation_status": "deterministic",
        "notice": (
            "Priority order uses existing heuristic scores. It is not a "
            "probability of fraud or proof of wrongdoing."
        ),
    }


def graph_search(query: str, limit: int = 25) -> dict[str, Any]:
    """Search entities by ID, label, name, or type."""
    term = query.strip().casefold()

    if not term:
        raise ValueError("Search query cannot be empty.")

    graph = load_data("graph.json")
    results = []

    for node in graph.get("nodes", []):
        data = node.get("data", {})

        searchable = " ".join(
            str(data.get(key, ""))
            for key in ("id", "label", "name", "type", "entity_type")
        ).casefold()

        if term in searchable:
            results.append(node)
            if len(results) >= max(1, limit):
                break

    return {
        "query": query,
        "count": len(results),
        "results": results,
        "mode": "deterministic_entity_search",
        "notice": (
            "This endpoint currently supports entity ID, label, name, and type "
            "search. It does not yet translate unrestricted natural language."
        ),
    }


def explain_path(
    source_id: str,
    target_id: str,
    max_depth: int = 4,
) -> dict[str, Any]:
    """Find a shortest path through observed relationships using BFS."""
    if source_id == target_id:
        return {
            "found": True,
            "path": [source_id],
            "hops": 0,
            "relationships": [],
            "generation_status": "deterministic",
            "notice": "Source and target are the same entity.",
        }

    max_depth = max(1, min(int(max_depth), 10))
    relationships = load_data("relationships.json")
    adjacency: dict[str, list[tuple[str, dict[str, Any]]]] = {}

    for raw_relation in relationships:
        relation = _safe_record(raw_relation)
        source = str(relation.get("source", ""))
        target = str(relation.get("target", ""))

        if not source or not target:
            continue

        adjacency.setdefault(source, []).append((target, relation))
        adjacency.setdefault(target, []).append((source, relation))

    queue = deque([(source_id, [source_id], [])])
    visited_depth = {source_id: 0}

    while queue:
        current, path, edges = queue.popleft()
        depth = len(edges)

        if depth >= max_depth:
            continue

        for neighbor, relation in adjacency.get(current, []):
            next_depth = depth + 1

            if next_depth >= visited_depth.get(neighbor, max_depth + 1):
                continue

            next_path = path + [neighbor]
            next_edges = edges + [relation]

            if neighbor == target_id:
                return {
                    "found": True,
                    "path": next_path,
                    "hops": len(next_edges),
                    "relationships": next_edges,
                    "generation_status": "deterministic",
                    "notice": (
                        "A graph path is a connection to investigate, "
                        "not proof of wrongdoing."
                    ),
                }

            visited_depth[neighbor] = next_depth
            queue.append((neighbor, next_path, next_edges))

    return {
        "found": False,
        "path": [],
        "hops": None,
        "relationships": [],
        "generation_status": "deterministic",
        "notice": f"No path found within {max_depth} hops.",
    }


def build_recommendations(cluster_id: str) -> dict[str, Any]:
    """Build deterministic recommendations linked to retrieved evidence."""
    context = build_finding_context(cluster_id)
    cluster = context["cluster"]
    events = context["events"]
    relationships = context["relationships"]

    event_ids = list(dict.fromkeys(
        str(event["id"])
        for event in events
        if event.get("id")
    ))

    relationship_evidence_ids = list(dict.fromkeys(
        str(relation["evidence_id"])
        for relation in relationships
        if relation.get("evidence_id")
    ))

    recommendations = []

    if events:
        recommendations.append({
            "action": "Review the event sequence",
            "reason": f"{len(events)} linked events were retrieved for this finding.",
            "evidence_ids": event_ids[:20],
        })

    if relationships:
        recommendations.append({
            "action": "Verify the relevant entity relationships",
            "reason": (
                f"{len(relationships)} relationships connect the retrieved "
                "entities. Confirm whether the links have a legitimate explanation."
            ),
            "evidence_ids": relationship_evidence_ids[:20],
        })

    recommendations.append({
        "action": "Seek independent corroboration before taking action",
        "reason": (
            "Shared devices, IP addresses, beneficiaries, and graph paths can "
            "have legitimate explanations."
        ),
        "evidence_ids": [],
    })

    return {
        "cluster_id": cluster.get("cluster_id", cluster_id),
        "recommendations": recommendations,
        "generation_status": "deterministic",
        "notice": context["notice"],
    }


def generate_ai_text(task: str, context: dict[str, Any]) -> str:
    """Generate investigation text through OpenRouter."""
    api_key = os.getenv("OPENROUTER_API_KEY")

    if not api_key:
        raise AIUnavailableError(
            "OpenRouter is not configured. Set OPENROUTER_API_KEY in .env."
        )

    model = os.getenv("OPENROUTER_MODEL", "openrouter/free")

    client = OpenAI(
        api_key=api_key,
        base_url="https://openrouter.ai/api/v1",
        timeout=45.0,
        max_retries=1,
    )

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You assist financial investigators using synthetic data. "
                        "Use only supplied context. Never claim a person or account "
                        "committed fraud based on a graph link alone. Clearly separate "
                        "observed facts, inferences, and unknowns. Never invent evidence, "
                        "event IDs, or relationships. Be concise."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        f"Task: {task}\n\nContext JSON:\n"
                        + json.dumps(context, ensure_ascii=False, default=str)
                    ),
                },
            ],
            temperature=0.2,
        )
    except Exception as exc:
        raise AIServiceError(
            f"OpenRouter request failed ({type(exc).__name__}). "
            "Check the API key, model availability, account limits, and connectivity."
        ) from exc

    result = response.choices[0].message.content

    if not result:
        raise AIServiceError("OpenRouter returned an empty response.")

    return result.strip()
