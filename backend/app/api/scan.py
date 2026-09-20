import json

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.db.database import get_db
from app.db.models import Scan, URL
from app.schemas.scan import ScanRequest, ScanResponse
from app.services.detection_service import detect_url
from app.utils.url_utils import normalize_url, extract_domain


router = APIRouter(
    prefix="/api",
    tags=["Scanning"],
)


@router.post(
    "/scan",
    response_model=ScanResponse,
)
def scan_url(
    request: ScanRequest,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Scan a URL and persist the scan result.

    The scanned URL is linked to an existing URL record when
    possible. Otherwise, a lightweight live-scan URL record
    is created.

    Graph intelligence metadata is also persisted so that
    future graph analysis can identify relationships between
    scanned URLs.
    """

    result = detect_url(request.url)

    if (
        "error" not in result
        or result.get("risk_level")
    ):

        normalized_url = normalize_url(
            request.url
        )

        # -----------------------------------------------------
        # Find existing URL record
        # -----------------------------------------------------

        url_record = (
            db.query(URL)
            .filter(
                URL.normalized_url == normalized_url
            )
            .first()
        )

        # -----------------------------------------------------
        # Create URL record for a new live scan
        # -----------------------------------------------------

        if url_record is None:

            url_record = URL(
                url=request.url,
                normalized_url=normalized_url,
                domain=extract_domain(request.url),
                label=False,
                source="live_scan",
            )

            db.add(url_record)

            db.flush()

        # -----------------------------------------------------
        # Extract graph intelligence metadata
        # -----------------------------------------------------

        indicators = result.get(
            "url_intelligence_indicators",
            [],
        )

        suspicious_keywords = result.get(
            "suspicious_keywords",
            [],
        )

        brand_similarity = result.get(
            "brand_similarity"
        )

        brand = None

        if isinstance(brand_similarity, dict):
            brand = (
                brand_similarity.get("brand")
                or brand_similarity.get("name")
            )

        # -----------------------------------------------------
        # Create scan record
        # -----------------------------------------------------

        scan = Scan(
            user_id=current_user.id,
            url_id=url_record.id,
            risk_score=result.get(
                "threat_score"
            ),
            risk_level=result.get(
                "risk_level"
            ),
            explanation=result.get(
                "intelligence_explanation"
            ),

            indicators=json.dumps(
                indicators
            ),

            suspicious_keywords=json.dumps(
                suspicious_keywords
            ),

            brand=brand,

            title=result.get(
                "title"
            ),
        )

        db.add(scan)

        db.commit()

    return result