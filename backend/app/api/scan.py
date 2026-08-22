from fastapi import APIRouter

from app.schemas.scan import (
    ScanRequest,
    ScanResponse,
)

from app.services.detection_service import (
    detect_url,
)


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
):

    result = detect_url(
        request.url
    )

    return result