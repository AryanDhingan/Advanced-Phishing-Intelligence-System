from app.db.database import SessionLocal
from app.services.bulk_insert import save_batch
from app.db.models import URL
from app.db.models import Feature

session = SessionLocal()

url = URL(
    url="https://example.com",
    normalized_url="https://example.com",
    domain="example.com",
    label=False,
    source="test"
)

feature = Feature(
    url_length=19,
    domain_length=11,
)

save_batch(
    session=session,
    url_objects=[url],
    feature_objects=[feature]
)

print("Batch insert successful.")

session.close()