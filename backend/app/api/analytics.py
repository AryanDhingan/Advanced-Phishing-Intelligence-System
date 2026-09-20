from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.db.database import get_db
from app.db.models import Scan
from app.graph.network import (
    build_user_phishing_graph,
)


router = APIRouter(
    prefix="/api/analytics",
    tags=["Analytics"],
)


@router.get("/summary")
def analytics_summary(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scans = (
        db.query(Scan)
        .filter(
            Scan.user_id == current_user.id
        )
        .order_by(
            Scan.scanned_at.asc()
        )
        .all()
    )

    total_scans = len(scans)

    high_risk = sum(
        1
        for scan in scans
        if scan.risk_level == "HIGH"
    )

    medium_risk = sum(
        1
        for scan in scans
        if scan.risk_level == "MEDIUM"
    )

    low_risk = sum(
        1
        for scan in scans
        if scan.risk_level == "LOW"
    )

    average_risk_score = (
        sum(
            scan.risk_score or 0
            for scan in scans
        )
        / total_scans
        if total_scans
        else 0
    )

    return {
        "total_scans": total_scans,
        "high_risk": high_risk,
        "medium_risk": medium_risk,
        "low_risk": low_risk,
        "average_risk_score": round(
            average_risk_score,
            2,
        ),
        "history": [
            {
                "scan_id": scan.id,
                "risk_score": scan.risk_score,
                "risk_level": scan.risk_level,
                "scanned_at": scan.scanned_at,
            }
            for scan in scans
        ],
    }


@router.get("/network")
def phishing_network(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Return the authenticated user's phishing
    relationship graph.

    Nodes represent scanned URLs.

    Edges represent shared characteristics such as:

    - domain
    - brand
    - phishing indicators
    - suspicious keywords
    """

    graph = build_user_phishing_graph(
        db,
        current_user.id,
    )

    nodes = []

    for node_id, data in graph.nodes(
        data=True
    ):
        nodes.append(
            {
                "id": str(node_id),
                "url": data.get("url"),
                "domain": data.get("domain"),
                "risk_level": data.get(
                    "risk_level"
                ),
                "threat_score": data.get(
                    "threat_score",
                    0,
                ),
                "phishing_probability": data.get(
                    "phishing_probability",
                    0,
                ),
                "indicators": data.get(
                    "indicators",
                    [],
                ),
                "suspicious_keywords": data.get(
                    "suspicious_keywords",
                    [],
                ),
                "brand": data.get(
                    "brand"
                ),
                "title": data.get(
                    "title"
                ),
            }
        )

    edges = []

    for source, target, data in graph.edges(
        data=True
    ):
        edges.append(
            {
                "source": str(source),
                "target": str(target),
                "weight": data.get(
                    "weight",
                    1,
                ),
                "shared_characteristics": data.get(
                    "shared_characteristics",
                    [],
                ),
            }
        )

    connected_components = [
        [
            str(node)
            for node in component
        ]
        for component in (
            __import__(
                "networkx"
            ).connected_components(graph)
        )
    ]

    return {
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "nodes": graph.number_of_nodes(),
            "edges": graph.number_of_edges(),
            "connected_components": len(
                connected_components
            ),
        },
        "connected_components": connected_components,
    }