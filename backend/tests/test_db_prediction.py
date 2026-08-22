from app.db.database import SessionLocal
from app.db.models import URL, Feature

from app.ml.predictor import predict


MODEL_FEATURES = [
    "url_length",
    "domain_length",
    "is_domain_ip",
    "tld_length",
    "tld_legitimate_prob",
    "url_similarity_index",
    "char_continuation_rate",
    "no_of_subdomain",
    "has_obfuscation",
    "no_of_obfuscated_char",
    "obfuscation_ratio",
    "no_of_letters_in_url",
    "letter_ratio_in_url",
    "no_of_digits_in_url",
    "digit_ratio_in_url",
    "no_of_equals_in_url",
    "no_of_qmark_in_url",
    "no_of_ampersand_in_url",
    "no_of_other_special_chars",
    "special_char_ratio",
    "is_https",
    "line_of_code",
    "largest_line_length",
    "has_title",
    "domain_title_match_score",
    "url_title_match_score",
    "has_favicon",
    "robots",
    "is_responsive",
    "no_of_url_redirect",
    "no_of_self_redirect",
    "has_description",
    "no_of_popup",
    "no_of_iframe",
    "has_external_form_submit",
    "has_social_net",
    "has_submit_button",
    "has_hidden_fields",
    "has_password_field",
    "bank",
    "pay",
    "crypto",
    "has_copyright_info",
    "no_of_image",
    "no_of_css",
    "no_of_js",
    "no_of_self_ref",
    "no_of_empty_ref",
    "no_of_external_ref",
]


print("========================================")
print("DATABASE → ML PREDICTION TEST")
print("========================================")

session = SessionLocal()

try:

    record = (
        session.query(URL, Feature)
        .join(
            Feature,
            URL.id == Feature.url_id
        )
        .filter(URL.label == True)
        .first()
    )

    if record is None:
        raise RuntimeError(
            "No phishing record found."
        )

    url = record[0]
    feature = record[1]

    print("URL:", url.url)
    print("Actual label:", url.label)
    print("Feature ID:", feature.id)

    # Convert SQLAlchemy Feature object
    # into application feature dictionary.
    merged_features = {
        name: getattr(feature, name)
        for name in MODEL_FEATURES
    }

    print(
        "Features loaded:",
        len(merged_features)
    )

    result = predict(
        merged_features
    )

    print("----------------------------------------")

    print(
        "Prediction:",
        result["prediction"]
    )

    print(
        "Phishing probability:",
        result["phishing_probability"]
    )

    print(
        "Risk level:",
        result["risk_level"]
    )

    print("========================================")

    if result["prediction"] != 1:
        print(
            "WARNING: Model classified the known "
            "phishing record as legitimate."
        )
    else:
        print(
            "Known phishing record correctly "
            "classified as phishing."
        )

    print(
        "DATABASE → ML TEST COMPLETED."
    )

finally:

    session.close()