from sqlalchemy import select

from app.db.database import SessionLocal
from app.db.models import URL, Feature

from app.dl.predictor import predict


def main():

    print("=" * 70)
    print("DEEP LEARNING DATABASE PREDICTION TEST")
    print("=" * 70)

    session = SessionLocal()

    try:

        # --------------------------------------------------
        # Load a small sample directly from the database
        # --------------------------------------------------

        phishing_statement = (
            select(URL, Feature)
            .join(
                Feature,
                URL.id == Feature.url_id,
            )
            .where(URL.label == True)
            .limit(5)
        )

        legitimate_statement = (
            select(URL, Feature)
            .join(
                Feature,
                URL.id == Feature.url_id,
            )
            .where(URL.label == False)
            .limit(5)
        )

        phishing_rows = session.execute(
            phishing_statement
        ).all()

        legitimate_rows = session.execute(
            legitimate_statement
        ).all()

        rows = phishing_rows + legitimate_rows

        print()
        print(f"Database records loaded: {len(rows)}")

        print()
        print("=" * 70)
        print("PREDICTIONS")
        print("=" * 70)

        correct = 0

        for index, (url_record, feature_record) in enumerate(rows, start=1):

            # Build feature dictionary from the same 49
            # attributes used by the DL training pipeline.
            feature_columns = [
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

            features = {
                column: getattr(
                    feature_record,
                    column,
                    0,
                )
                for column in feature_columns
            }

            result = predict(features)

            actual = int(bool(url_record.label))
            predicted = result["prediction"]

            if actual == predicted:
                correct += 1

            actual_label = (
                "Phishing"
                if actual == 1
                else "Legitimate"
            )

            predicted_label = (
                "Phishing"
                if predicted == 1
                else "Legitimate"
            )

            print()
            print(f"Record {index}")
            print(f"URL       : {url_record.normalized_url}")
            print(f"Actual    : {actual_label}")
            print(f"Predicted : {predicted_label}")
            print(
                f"Probability: "
                f"{result['phishing_probability']:.6f}"
            )
            print(
                f"Risk      : "
                f"{result['risk_level']}"
            )

        accuracy = (
            correct / len(rows)
            if rows
            else 0
        )

        print()
        print("=" * 70)
        print("DATABASE TEST SUMMARY")
        print("=" * 70)
        print(f"Correct predictions: {correct}/{len(rows)}")
        print(f"Accuracy           : {accuracy:.4f}")
        print("=" * 70)

    finally:

        session.close()


if __name__ == "__main__":
    main()