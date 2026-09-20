import json
from collections import defaultdict

import networkx as nx
from sqlalchemy.orm import Session

from app.db.models import Scan


def _load_json_list(value):
    """
    Safely convert a JSON string stored in SQLite into a list.
    """

    if not value:
        return []

    try:
        parsed = json.loads(value)

        if isinstance(parsed, list):
            return parsed

    except (TypeError, json.JSONDecodeError):
        pass

    return []


def get_user_scan_records(
    db: Session,
    user_id: int,
) -> list[dict]:
    """
    Retrieve graph-relevant scan records for one user.
    """

    scans = (
        db.query(Scan)
        .filter(
            Scan.user_id == user_id,
            Scan.url_id.isnot(None),
        )
        .order_by(
            Scan.scanned_at.asc()
        )
        .all()
    )

    records = []

    for scan in scans:

        url_record = scan.url

        if url_record is None:
            continue

        indicators = _load_json_list(
            scan.indicators
        )

        suspicious_keywords = _load_json_list(
            scan.suspicious_keywords
        )

        records.append(
            {
                "scan_id": scan.id,
                "url": url_record.url,
                "domain": url_record.domain,
                "risk_level": scan.risk_level,
                "threat_score": scan.risk_score or 0,
                "phishing_probability": (
                    (scan.risk_score or 0) / 100
                ),
                "indicators": indicators,
                "suspicious_keywords": suspicious_keywords,
                "brand": scan.brand,
                "title": scan.title,
            }
        )

    return records


def build_phishing_graph(
    scan_records: list[dict],
) -> nx.Graph:
    """
    Build a graph where:

    - URL/domain records are nodes.
    - Edges represent shared phishing characteristics.

    Shared characteristics include:

    - domain
    - brand
    - intelligence indicators
    - suspicious keywords
    """

    graph = nx.Graph()

    # ---------------------------------------------------------
    # Add URL nodes
    # ---------------------------------------------------------

    for index, record in enumerate(
        scan_records
    ):

        node_id = (
            record.get("scan_id")
            or record.get("url")
            or f"url_{index}"
        )

        graph.add_node(
            node_id,
            url=record.get("url"),
            domain=record.get("domain"),
            risk_level=record.get("risk_level"),
            threat_score=record.get(
                "threat_score",
                0,
            ),
            phishing_probability=record.get(
                "phishing_probability",
                0,
            ),
            indicators=record.get(
                "indicators",
                [],
            ),
            suspicious_keywords=record.get(
                "suspicious_keywords",
                [],
            ),
            brand=record.get(
                "brand"
            ),
            title=record.get(
                "title"
            ),
        )

    # ---------------------------------------------------------
    # Group nodes by shared characteristics
    # ---------------------------------------------------------

    characteristic_groups = defaultdict(
        list
    )

    for node_id, data in graph.nodes(
        data=True
    ):

        domain = data.get("domain")

        if domain:
            characteristic_groups[
                f"domain:{domain.lower()}"
            ].append(node_id)

        brand = data.get("brand")

        if brand:
            characteristic_groups[
                f"brand:{brand.lower()}"
            ].append(node_id)

        for indicator in data.get(
            "indicators",
            [],
        ):

            characteristic_groups[
                f"indicator:{indicator.lower()}"
            ].append(node_id)

        for keyword in data.get(
            "suspicious_keywords",
            [],
        ):

            characteristic_groups[
                f"keyword:{keyword.lower()}"
            ].append(node_id)

    # ---------------------------------------------------------
    # Create edges from shared characteristics
    # ---------------------------------------------------------

    for characteristic, nodes in (
        characteristic_groups.items()
    ):

        unique_nodes = list(
            dict.fromkeys(nodes)
        )

        if len(unique_nodes) < 2:
            continue

        for i in range(
            len(unique_nodes)
        ):

            for j in range(
                i + 1,
                len(unique_nodes),
            ):

                node_a = unique_nodes[i]
                node_b = unique_nodes[j]

                if graph.has_edge(
                    node_a,
                    node_b,
                ):

                    graph[node_a][node_b][
                        "weight"
                    ] += 1

                    graph[node_a][node_b][
                        "shared_characteristics"
                    ].append(
                        characteristic
                    )

                else:

                    graph.add_edge(
                        node_a,
                        node_b,
                        weight=1,
                        shared_characteristics=[
                            characteristic
                        ],
                    )

    return graph


def build_user_phishing_graph(
    db: Session,
    user_id: int,
) -> nx.Graph:
    """
    Build a phishing graph directly
    from a user's persisted scans.
    """

    records = get_user_scan_records(
        db,
        user_id,
    )

    return build_phishing_graph(
        records
    )


def get_graph_summary(
    graph: nx.Graph,
) -> dict:
    """
    Return basic graph statistics.
    """

    return {
        "nodes": graph.number_of_nodes(),
        "edges": graph.number_of_edges(),
        "connected_components": nx.number_connected_components(
            graph
        )
        if graph.number_of_nodes()
        else 0,
    }