from pathlib import Path
from typing import Any

import json

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

app = FastAPI(
    title="Identity Attack Graph API",
    description=(
        "A synthetic-data investigation API for exploring suspicious "
        "financial-account relationships and explainable risk signals."
    ),
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def load_json(filename: str) -> Any:
    """Load a project JSON file and report useful errors."""
    path = DATA_DIR / filename

    if not path.is_file():
        raise HTTPException(
            status_code=503,
            detail=f"Required data file is missing: data/{filename}",
        )

    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError) as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Could not read data/{filename}: {exc}",
        ) from exc


@app.get("/")
def root():
    return {
        "name": "Identity Attack Graph API",
        "status": "running",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
def health():
    required_files = [
        "summary.json",
        "clusters.json",
        "graph.json",
    ]
    files = {
        filename: (DATA_DIR / filename).is_file()
        for filename in required_files
    }

    return {
        "status": "ok" if all(files.values()) else "degraded",
        "data_directory": str(DATA_DIR),
        "files": files,
    }


@app.get("/api/summary")
def get_summary():
    """Return dataset totals and category breakdowns."""
    return load_json("summary.json")


@app.get("/api/clusters")
def get_clusters(
    risk_level: str | None = Query(default=None),
    min_score: int = Query(default=0, ge=0, le=100),
):
    """List detected clusters, optionally filtered by risk and score."""
    data = load_json("clusters.json")
    clusters = data.get("clusters", [])

    if risk_level:
        requested_level = risk_level.upper()
        clusters = [
            cluster
            for cluster in clusters
            if str(cluster.get("risk_level", "")).upper()
            == requested_level
        ]

    clusters = [
        cluster
        for cluster in clusters
        if cluster.get("risk_score", 0) >= min_score
    ]

    return {
        "score_type": data.get("score_type", "unknown"),
        "count": len(clusters),
        "clusters": clusters,
        "notice": (
            "Scores are heuristic investigation priorities, not "
            "probabilities of fraud or proof of wrongdoing."
        ),
    }


@app.get("/api/clusters/{cluster_id}")
def get_cluster(cluster_id: str):
    """Return one cluster and its explainable signals."""
    data = load_json("clusters.json")

    for cluster in data.get("clusters", []):
        if cluster.get("cluster_id", "").upper() == cluster_id.upper():
            return cluster

    raise HTTPException(
        status_code=404,
        detail=f"Cluster '{cluster_id}' was not found.",
    )


@app.get("/api/graph")
def get_graph(
    node_type: str | None = Query(default=None),
    limit: int = Query(default=500, ge=1, le=5000),
):
    """Return graph nodes and edges for visualization."""
    graph = load_json("graph.json")
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    if node_type:
        wanted = node_type.upper()
        nodes = [
            node for node in nodes
            if str(
                node.get("data", {}).get("type")
                or node.get("data", {}).get("entity_type")
                or ""
            ).upper() == wanted
        ]

        allowed_ids = {
            node.get("data", {}).get("id")
            for node in nodes
        }
        edges = [
            edge for edge in edges
            if (
                edge.get("data", {}).get("source") in allowed_ids
                or edge.get("data", {}).get("target") in allowed_ids
            )
        ]

    return {
        "node_count": len(graph.get("nodes", [])),
        "edge_count": len(graph.get("edges", [])),
        "returned_node_count": min(len(nodes), limit),
        "returned_edge_count": len(edges),
        "nodes": nodes[:limit],
        "edges": edges,
    }


@app.get("/api/search")
def search_entities(
    q: str = Query(min_length=1, max_length=100),
    limit: int = Query(default=25, ge=1, le=100),
):
    """Search graph entities by ID, type, or available label/name."""
    graph = load_json("graph.json")
    term = q.strip().casefold()

    if not term:
        raise HTTPException(status_code=422, detail="Search query is empty.")

    matches = []
    for node in graph.get("nodes", []):
        data = node.get("data", {})
        searchable = " ".join(
            str(data.get(key, ""))
            for key in ("id", "label", "name", "type", "entity_type")
        ).casefold()

        if term in searchable:
            matches.append(node)

        if len(matches) >= limit:
            break

    return {
        "query": q,
        "count": len(matches),
        "results": matches,
    }
from pydantic import BaseModel, Field
from services.ai_services import (
    AIUnavailableError,
    build_finding_context,
    build_recommendations,
    build_timeline,
    explain_path,
    generate_ai_text,
    get_cluster as get_ai_cluster,
    graph_search as run_graph_search,
    prioritize_findings,
)


class ExplainRequest(BaseModel):
    cluster_id: str = Field(min_length=1, max_length=100)
    question: str = Field(
        default="Explain the observed signals, evidence, and uncertainties.",
        min_length=1,
        max_length=2000,
    )


class GraphSearchRequest(BaseModel):
    query: str = Field(min_length=1, max_length=100)
    limit: int = Field(default=25, ge=1, le=100)


class CopilotRequest(BaseModel):
    cluster_id: str = Field(min_length=1, max_length=100)
    question: str = Field(min_length=1, max_length=2000)


class PathExplanationRequest(BaseModel):
    source_id: str = Field(min_length=1, max_length=100)
    target_id: str = Field(min_length=1, max_length=100)
    max_depth: int = Field(default=4, ge=1, le=6)


@app.get("/api/ai/timeline/{cluster_id}")
def ai_timeline(cluster_id: str):
    try:
        return build_timeline(cluster_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (FileNotFoundError, json.JSONDecodeError, OSError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/api/ai/prioritize")
def ai_prioritize():
    try:
        return prioritize_findings()
    except (FileNotFoundError, json.JSONDecodeError, OSError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/api/ai/explain")
def ai_explain(request: ExplainRequest):
    try:
        context = build_finding_context(request.cluster_id)
        explanation = generate_ai_text(
            "Explain this finding for a financial investigator. Answer the user's "
            "question. Separate observed facts from hypotheses and state important "
            "uncertainties. Do not recommend automatic account freezing.\n"
            f"User question: {request.question}",
            context,
        )
        return {
            "cluster_id": request.cluster_id,
            "explanation": explanation,
            "generation_status": "llm_generated",
            "notice": context["notice"],
        }
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except AIUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"AI explanation generation failed: {type(exc).__name__}",
        ) from exc


@app.post("/api/ai/report/{cluster_id}")
def ai_report(cluster_id: str):
    try:
        context = build_finding_context(cluster_id)
        report = generate_ai_text(
            "Create a concise investigation case report with these headings: "
            "Executive Summary, Observed Evidence, Timeline, Potential Explanations, "
            "Evidence Gaps, Recommended Next Steps. Cite only supplied event and "
            "relationship IDs. Explicitly state that links are not proof of fraud.",
            context,
        )
        return {
            "cluster_id": cluster_id,
            "report": report,
            "generation_status": "llm_generated",
            "notice": context["notice"],
        }
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except AIUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Case report generation failed: {type(exc).__name__}",
        ) from exc


@app.post("/api/ai/graph-search")
def ai_graph_search(request: GraphSearchRequest):
    try:
        return run_graph_search(request.query, request.limit)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except (FileNotFoundError, json.JSONDecodeError, OSError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/api/ai/copilot")
def ai_copilot(request: CopilotRequest):
    try:
        context = build_finding_context(request.cluster_id)
        answer = generate_ai_text(
            "Act as an investigation copilot. Answer the investigator's question "
            "using only supplied context. Distinguish evidence from hypotheses. "
            "If the data cannot answer the question, say what is missing. "
            "Never infer guilt from a shared attribute.\n"
            f"Investigator question: {request.question}",
            context,
        )
        return {
            "cluster_id": request.cluster_id,
            "answer": answer,
            "generation_status": "llm_generated",
            "notice": context["notice"],
        }
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except AIUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Copilot response generation failed: {type(exc).__name__}",
        ) from exc


@app.post("/api/ai/path-explanation")
def ai_path_explanation(request: PathExplanationRequest):
    try:
        result = explain_path(
            request.source_id,
            request.target_id,
            request.max_depth,
        )
        if not result.get("found"):
            raise HTTPException(
                status_code=404,
                detail={
                    "message": "No path found within the requested depth.",
                    "result": result,
                },
            )
        graph = load_json("graph.json")
        labels = {
            str(node.get("data", {}).get("id")): node.get("data", {}).get("label")
            for node in graph.get("nodes", [])
        }
        result["path_labels"] = [
            labels.get(node_id, node_id) for node_id in result["path"]
        ]
        return result
    except HTTPException:
        raise
    except (FileNotFoundError, json.JSONDecodeError, OSError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/api/ai/recommendations")
def ai_recommendations(request: ExplainRequest):
    try:
        return build_recommendations(request.cluster_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (FileNotFoundError, json.JSONDecodeError, OSError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
