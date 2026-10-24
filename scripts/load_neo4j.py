
"""Load the deterministic JSON dataset into Neo4j.

Default mode is idempotent: it merges existing nodes and relationships.
Use --reset only when you intentionally want to replace this project's
Neo4j data. Other graph data without this project's marker is untouched.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from dotenv import load_dotenv

from neo4j import GraphDatabase

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
PROJECT = "identity-attack-graph"

ENTITY_TYPES = {
    "ACCOUNT", "DEVICE", "IP_ADDRESS", "PHONE",
    "EMAIL", "SESSION", "BENEFICIARY", "TRANSACTION",
}

RELATIONSHIP_TYPES = {
    "USES_DEVICE", "LOGGED_IN_FROM", "OWNS_PHONE",
    "OWNS_EMAIL", "HAS_SESSION", "INITIATED_TRANSACTION",
    "SENT_TO", "RECEIVED_FROM", "SHARES_SIGNAL_WITH",
}

IDENTIFIER_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def load_json_dataset(data_dir: Path = DATA_DIR) -> dict[str, Any]:
    """Read the canonical JSON source files."""
    return {
        name: read_json(data_dir / f"{name}.json")
        for name in ("entities", "events", "relationships", "scenarios")
    }


def validate_dataset(data: dict[str, Any]) -> None:
    """Validate records and endpoints before touching the database."""
    entities = data["entities"]
    events = data["events"]
    relationships = data["relationships"]

    entity_ids = [item["id"] for item in entities]
    event_ids = [item["id"] for item in events]
    relationship_ids = [item["id"] for item in relationships]

    for name, identifiers in (
        ("entity", entity_ids),
        ("event", event_ids),
        ("relationship", relationship_ids),
    ):
        if len(identifiers) != len(set(identifiers)):
            raise ValueError(f"Duplicate {name} IDs detected.")

    known_entity_ids = set(entity_ids)

    for entity in entities:
        if entity.get("type") not in ENTITY_TYPES:
            raise ValueError(
                f"Unsupported entity type on {entity.get('id')}: "
                f"{entity.get('type')}"
            )

    for event in events:
        if event.get("source_id") not in known_entity_ids:
            raise ValueError(
                f"Event {event.get('id')} has an unknown source."
            )
        if event.get("target_id") not in known_entity_ids:
            raise ValueError(
                f"Event {event.get('id')} has an unknown target."
            )
        if not event.get("timestamp"):
            raise ValueError(
                f"Event {event.get('id')} is missing a timestamp."
            )

    for relationship in relationships:
        if relationship.get("source") not in known_entity_ids:
            raise ValueError(
                f"Relationship {relationship.get('id')} "
                "has an unknown source."
            )
        if relationship.get("target") not in known_entity_ids:
            raise ValueError(
                f"Relationship {relationship.get('id')} "
                "has an unknown target."
            )

        rel_type = relationship.get("type")
        if (
            rel_type not in RELATIONSHIP_TYPES
            or not IDENTIFIER_PATTERN.fullmatch(rel_type or "")
        ):
            raise ValueError(
                f"Unsupported relationship type: {rel_type}"
            )

        if not relationship.get("timestamp"):
            raise ValueError(
                f"Relationship {relationship.get('id')} "
                "is missing a timestamp."
            )


def entity_properties(entity: dict[str, Any]) -> dict[str, Any]:
    """Convert nested JSON metadata into Neo4j-compatible properties."""
    metadata = entity.get("metadata") or {}

    return {
        "id": entity["id"],
        "type": entity["type"],
        "label": str(entity.get("label", entity["id"])),
        "scenario_id": entity.get("scenario_id", ""),
        "metadata_json": json.dumps(metadata, sort_keys=True),
        "project": PROJECT,
    }


def event_properties(event: dict[str, Any]) -> dict[str, Any]:
    """Convert an event record into Neo4j-compatible properties."""
    return {
        "id": event["id"],
        "event_type": event["event_type"],
        "timestamp": event["timestamp"],
        "source_id": event["source_id"],
        "target_id": event["target_id"],
        "scenario_id": event.get("scenario_id", ""),
        "details_json": json.dumps(
            event.get("details") or {}, sort_keys=True
        ),
        "project": PROJECT,
    }


def relationship_properties(
    relationship: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": relationship["id"],
        "timestamp": relationship["timestamp"],
        "evidence_id": relationship.get("evidence_id", ""),
        "scenario_id": relationship.get("scenario_id", ""),
        "project": PROJECT,
    }


def create_constraints(tx) -> None:
    """Create stable-ID uniqueness constraints."""
    tx.run("""
        CREATE CONSTRAINT entity_id_unique IF NOT EXISTS
        FOR (n:Entity) REQUIRE n.id IS UNIQUE
    """).consume()

    tx.run("""
        CREATE CONSTRAINT event_id_unique IF NOT EXISTS
        FOR (n:Event) REQUIRE n.id IS UNIQUE
    """).consume()

    tx.run("""
        CREATE CONSTRAINT scenario_id_unique IF NOT EXISTS
        FOR (n:Scenario) REQUIRE n.id IS UNIQUE
    """).consume()


def reset_project_data(tx) -> None:
    """Delete only nodes marked as belonging to this project."""
    tx.run("""
        MATCH (n {project: $project})
        DETACH DELETE n
    """, project=PROJECT).consume()


def upsert_entities(tx, entities: list[dict[str, Any]]) -> None:
    for entity in entities:
        entity_type = entity["type"]
        # The label is interpolated only after strict allowlist validation.
        if entity_type not in ENTITY_TYPES:
            raise ValueError(f"Unsupported entity label: {entity_type}")

        query = f"""
            MERGE (n:Entity:{entity_type} {{id: $id}})
            SET n += $props
        """
        tx.run(
            query,
            id=entity["id"],
            props=entity_properties(entity),
        ).consume()


def upsert_events(tx, events: list[dict[str, Any]]) -> None:
    for event in events:
        tx.run("""
            MERGE (e:Event {id: $id})
            SET e += $props
        """,
            id=event["id"],
            props=event_properties(event),
        ).consume()

        # Event provenance is explicit and independently queryable.
        tx.run("""
            MATCH (source:Entity {id: $source_id})
            MATCH (event:Event {id: $event_id})
            MERGE (source)-[r:RECORDED_EVENT {event_id: $event_id}]->(event)
            SET r.project = $project
        """,
            source_id=event["source_id"],
            event_id=event["id"],
            project=PROJECT,
        ).consume()

        tx.run("""
            MATCH (event:Event {id: $event_id})
            MATCH (target:Entity {id: $target_id})
            MERGE (event)-[r:EVENT_TARGET {event_id: $event_id}]->(target)
            SET r.project = $project
        """,
            event_id=event["id"],
            target_id=event["target_id"],
            project=PROJECT,
        ).consume()


def upsert_relationships(
    tx,
    relationships: list[dict[str, Any]],
) -> None:
    for relationship in relationships:
        rel_type = relationship["type"]

        # Only relationship types declared in RELATIONSHIP_TYPES can
        # enter the Cypher query. Values remain parameterized.
        if (
            rel_type not in RELATIONSHIP_TYPES
            or not IDENTIFIER_PATTERN.fullmatch(rel_type)
        ):
            raise ValueError(f"Unsupported relationship type: {rel_type}")

        query = f"""
            MATCH (source:Entity {{id: $source_id}})
            MATCH (target:Entity {{id: $target_id}})
            MERGE (source)-[r:{rel_type} {{id: $id}}]->(target)
            SET r += $props
        """

        tx.run(
            query,
            source_id=relationship["source"],
            target_id=relationship["target"],
            id=relationship["id"],
            props=relationship_properties(relationship),
        ).consume()


def upsert_scenarios(tx, scenarios: list[dict[str, Any]]) -> None:
    for scenario in scenarios:
        props = {
            "id": scenario["id"],
            "name": scenario.get("name", scenario["id"]),
            "ground_truth_label": scenario.get("ground_truth_label", ""),
            "description": scenario.get("description", ""),
            "synthetic": bool(scenario.get("synthetic", True)),
            "project": PROJECT,
        }

        tx.run("""
            MERGE (s:Scenario {id: $id})
            SET s += $props
        """, id=scenario["id"], props=props).consume()

load_dotenv(ROOT / ".env")

def load_into_neo4j(
    uri: str,
    username: str,
    password: str,
    database: str,
    data: dict[str, Any],
    reset: bool = False,
) -> dict[str, int]:
    """Validate and import all JSON records in one managed transaction."""
    validate_dataset(data)

    driver = GraphDatabase.driver(uri, auth=(username, password))

    try:
        driver.verify_connectivity()

        with driver.session(database=database) as session:
            session.run("""
            CREATE CONSTRAINT entity_id_unique IF NOT EXISTS
            FOR (n:Entity) REQUIRE n.id IS UNIQUE
            """).consume()

            session.run("""
            CREATE CONSTRAINT event_id_unique IF NOT EXISTS
            FOR (n:Event) REQUIRE n.id IS UNIQUE
            """).consume()

            session.run("""
            CREATE CONSTRAINT scenario_id_unique IF NOT EXISTS
            FOR (n:Scenario) REQUIRE n.id IS UNIQUE
            """).consume()

            if reset:
                session.execute_write(reset_project_data)

            session.execute_write(upsert_entities, data["entities"])
            session.execute_write(upsert_events, data["events"])
            session.execute_write(
                upsert_relationships, data["relationships"]
            )
            session.execute_write(upsert_scenarios, data["scenarios"])

            counts = session.run("""
                MATCH (n {project: $project})
                WITH labels(n) AS node_labels, count(n) AS node_count
                RETURN sum(node_count) AS node_count
            """, project=PROJECT).single()

            relationship_count = session.run("""
                MATCH ()-[r]->()
                WHERE r.project = $project
                RETURN count(r) AS relationship_count
            """, project=PROJECT).single()

            return {
                "entity_records": len(data["entities"]),
                "event_records": len(data["events"]),
                "relationship_records": len(data["relationships"]),
                "scenario_records": len(data["scenarios"]),
                "project_nodes_in_neo4j": counts["node_count"],
                "project_relationships_in_neo4j": (
                    relationship_count["relationship_count"]
                ),
            }
    finally:
        driver.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Import the synthetic JSON dataset into Neo4j."
    )
    parser.add_argument("--data-dir", default=str(DATA_DIR))
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Replace existing Neo4j data marked for this project only.",
    )
    args = parser.parse_args()

    uri = os.getenv("NEO4J_URI")
    username = os.getenv("NEO4J_USERNAME")
    password = os.getenv("NEO4J_PASSWORD")
    database = os.getenv("NEO4J_DATABASE", "neo4j")

    missing = [
        key for key, value in (
            ("NEO4J_URI", uri),
            ("NEO4J_USERNAME", username),
            ("NEO4J_PASSWORD", password),
        )
        if not value
    ]

    if missing:
        print(
            "Missing environment variables: " + ", ".join(missing),
            file=sys.stderr,
        )
        print(
            "Configure them in your terminal or local environment.",
            file=sys.stderr,
        )
        return 2

    data = load_json_dataset(Path(args.data_dir))

    try:
        counts = load_into_neo4j(
            uri=uri,
            username=username,
            password=password,
            database=database,
            data=data,
            reset=args.reset,
        )
    except Exception as exc:
        print(f"Neo4j import failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps({
        "status": "success",
        "database": database,
        "reset_used": args.reset,
        "counts": counts,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
