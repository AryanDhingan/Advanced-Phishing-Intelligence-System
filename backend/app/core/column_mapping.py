"""
Maps PhiUSIIL dataset column names
to SQLAlchemy Feature model attributes.
"""

COLUMN_MAPPING = {

    # -------------------------
    # URL Features
    # -------------------------

    "URLLength": "url_length",
    "DomainLength": "domain_length",
    "IsDomainIP": "is_domain_ip",

    "TLD": "tld",
    "TLDLength": "tld_length",
    "TLDLegitimateProb": "tld_legitimate_prob",

    "URLSimilarityIndex": "url_similarity_index",
    "CharContinuationRate": "char_continuation_rate",

    "NoOfSubDomain": "no_of_subdomain",

    "HasObfuscation": "has_obfuscation",
    "NoOfObfuscatedChar": "no_of_obfuscated_char",
    "ObfuscationRatio": "obfuscation_ratio",

    "NoOfLettersInURL": "no_of_letters_in_url",
    "LetterRatioInURL": "letter_ratio_in_url",

    "NoOfDegitsInURL": "no_of_digits_in_url",
    "DegitRatioInURL": "digit_ratio_in_url",

    "NoOfEqualsInURL": "no_of_equals_in_url",
    "NoOfQMarkInURL": "no_of_qmark_in_url",
    "NoOfAmpersandInURL": "no_of_ampersand_in_url",

    "NoOfOtherSpecialCharsInURL": "no_of_other_special_chars",
    "SpacialCharRatioInURL": "special_char_ratio",

    "IsHTTPS": "is_https",

    # -------------------------
    # Webpage Features
    # -------------------------

    "LineOfCode": "line_of_code",
    "LargestLineLength": "largest_line_length",

    "HasTitle": "has_title",
    "Title": "title",

    "DomainTitleMatchScore": "domain_title_match_score",
    "URLTitleMatchScore": "url_title_match_score",

    "HasFavicon": "has_favicon",
    "Robots": "robots",
    "IsResponsive": "is_responsive",

    "NoOfURLRedirect": "no_of_url_redirect",
    "NoOfSelfRedirect": "no_of_self_redirect",

    "HasDescription": "has_description",

    "NoOfPopup": "no_of_popup",
    "NoOfiFrame": "no_of_iframe",

    "HasExternalFormSubmit": "has_external_form_submit",

    "HasSocialNet": "has_social_net",

    "HasSubmitButton": "has_submit_button",
    "HasHiddenFields": "has_hidden_fields",
    "HasPasswordField": "has_password_field",

    "Bank": "bank",
    "Pay": "pay",
    "Crypto": "crypto",

    "HasCopyrightInfo": "has_copyright_info",

    "NoOfImage": "no_of_image",
    "NoOfCSS": "no_of_css",
    "NoOfJS": "no_of_js",

    "NoOfSelfRef": "no_of_self_ref",
    "NoOfEmptyRef": "no_of_empty_ref",
    "NoOfExternalRef": "no_of_external_ref",
}