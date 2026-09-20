from fastapi import APIRouter, Depends

from app.core.auth import get_current_user

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
    current_user=Depends(get_current_user),
):

    result = detect_url(
        request.url
    )

    return result