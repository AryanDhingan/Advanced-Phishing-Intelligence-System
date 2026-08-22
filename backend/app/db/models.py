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

    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("Scan", back_populates="user")


class URL(Base):

    __tablename__ = "urls"

    id = Column(Integer, primary_key=True)

    url = Column(String, unique=True)

    # NEW
    normalized_url = Column(String, unique=True)

    domain = Column(String)

    label = Column(Boolean)

    source = Column(String)

    created_at = Column(DateTime, default=datetime.utcnow)

    # NEW
    ingested_at = Column(DateTime, default=datetime.utcnow)

    features = relationship(
        "Feature", back_populates="url", uselist=False, cascade="all, delete-orphan"
    )

    scans = relationship("Scan", back_populates="url")


class Feature(Base):

    __tablename__ = "features"

    id = Column(Integer, primary_key=True)

    url_id = Column(Integer, ForeignKey("urls.id"), unique=True)

    # -------------------------
    # URL Based Features
    # -------------------------

    url_length = Column(Integer)
    domain_length = Column(Integer)
    is_domain_ip = Column(Boolean)

    tld = Column(String)
    tld_length = Column(Integer)
    tld_legitimate_prob = Column(Float)

    url_similarity_index = Column(Float)
    char_continuation_rate = Column(Float)

    no_of_subdomain = Column(Integer)

    has_obfuscation = Column(Boolean)
    no_of_obfuscated_char = Column(Integer)
    obfuscation_ratio = Column(Float)

    no_of_letters_in_url = Column(Integer)
    letter_ratio_in_url = Column(Float)

    no_of_digits_in_url = Column(Integer)
    digit_ratio_in_url = Column(Float)

    no_of_equals_in_url = Column(Integer)
    no_of_qmark_in_url = Column(Integer)
    no_of_ampersand_in_url = Column(Integer)

    no_of_other_special_chars = Column(Integer)
    special_char_ratio = Column(Float)

    is_https = Column(Boolean)

    # -------------------------
    # Webpage Features
    # -------------------------

    line_of_code = Column(Integer)
    largest_line_length = Column(Integer)

    has_title = Column(Boolean)
    title = Column(String)

    domain_title_match_score = Column(Float)
    url_title_match_score = Column(Float)

    has_favicon = Column(Boolean)
    robots = Column(Boolean)
    is_responsive = Column(Boolean)

    no_of_url_redirect = Column(Integer)
    no_of_self_redirect = Column(Integer)

    has_description = Column(Boolean)

    no_of_popup = Column(Integer)
    no_of_iframe = Column(Integer)

    has_external_form_submit = Column(Boolean)

    has_social_net = Column(Boolean)

    has_submit_button = Column(Boolean)
    has_hidden_fields = Column(Boolean)
    has_password_field = Column(Boolean)

    bank = Column(Boolean)
    pay = Column(Boolean)
    crypto = Column(Boolean)

    has_copyright_info = Column(Boolean)

    no_of_image = Column(Integer)
    no_of_css = Column(Integer)
    no_of_js = Column(Integer)

    no_of_self_ref = Column(Integer)
    no_of_empty_ref = Column(Integer)
    no_of_external_ref = Column(Integer)

    url = relationship("URL", back_populates="features")


class Scan(Base):

    __tablename__ = "scans"

    id = Column(Integer, primary_key=True)

    user_id = Column(Integer, ForeignKey("users.id"))

    url_id = Column(Integer, ForeignKey("urls.id"))

    risk_score = Column(Float)

    risk_level = Column(String)

    explanation = Column(String)

    scanned_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="scans")

    url = relationship("URL", back_populates="scans")