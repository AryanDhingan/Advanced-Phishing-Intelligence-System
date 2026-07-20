from sqlalchemy.orm import Session

from app.db.models import URL
from app.db.models import Feature


def save_batch(
    session: Session,
    url_objects: list[URL],
    feature_objects: list[Feature]
) -> None:
    """
    Save a batch of URL and Feature objects.
    """

    try:

        session.add_all(url_objects)

        session.flush()

        for feature, url in zip(feature_objects, url_objects):
            feature.url_id = url.id

        session.add_all(feature_objects)

        session.commit()

    except Exception:

        session.rollback()

        raise