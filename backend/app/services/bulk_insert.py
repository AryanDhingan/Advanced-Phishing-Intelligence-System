from sqlalchemy.orm import Session

from app.db.models import URL


def save_batch(
    session: Session,
    url_objects: list[URL]
) -> None:
    """
    Save a batch of URL objects.
    Their Feature objects are automatically
    persisted because of the ORM relationship.
    """

    try:

        session.add_all(url_objects)

        session.commit()

    except Exception:

        session.rollback()

        raise