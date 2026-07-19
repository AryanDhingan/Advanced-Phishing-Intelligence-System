from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Float
from sqlalchemy import Boolean
from sqlalchemy import DateTime
from sqlalchemy import ForeignKey

from sqlalchemy.orm import relationship

from datetime import datetime

from app.db.database import Base


class User(Base):

    __tablename__ = "users"

    id = Column(Integer, primary_key=True)

    username = Column(String, unique=True)

    password_hash = Column(String)

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )

    scans = relationship(
        "Scan",
        back_populates="user"
    )


class URL(Base):

    __tablename__ = "urls"

    id = Column(Integer, primary_key=True)

    url = Column(String, unique=True)

    domain = Column(String)

    label = Column(Integer)

    source = Column(String)

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )

    features = relationship(
        "Feature",
        back_populates="url"
    )

    scans = relationship(
        "Scan",
        back_populates="url"
    )


class Feature(Base):

    __tablename__ = "features"

    id = Column(Integer, primary_key=True)

    url_id = Column(
        Integer,
        ForeignKey("urls.id")
    )

    url_length = Column(Integer)

    dot_count = Column(Integer)

    hyphen_count = Column(Integer)

    at_count = Column(Integer)

    entropy = Column(Float)

    subdomain_count = Column(Integer)

    ip_as_domain = Column(Boolean)

    suspicious_keyword_count = Column(Integer)

    url = relationship(
        "URL",
        back_populates="features"
    )


class Scan(Base):

    __tablename__ = "scans"

    id = Column(Integer, primary_key=True)

    user_id = Column(
        Integer,
        ForeignKey("users.id")
    )

    url_id = Column(
        Integer,
        ForeignKey("urls.id")
    )

    risk_score = Column(Float)

    risk_level = Column(String)

    explanation = Column(String)

    scanned_at = Column(
        DateTime,
        default=datetime.utcnow
    )

    user = relationship(
        "User",
        back_populates="scans"
    )

    url = relationship(
        "URL",
        back_populates="scans"
    )