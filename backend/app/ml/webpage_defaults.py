"""
Default webpage features used when a target webpage
cannot be fetched.

These defaults allow URL-based analysis to continue
without pretending that webpage information was observed.
"""


def get_default_webpage_features() -> dict:
    """
    Return safe default values for all 29 webpage features.
    """

    return {
        "line_of_code": 0,
        "largest_line_length": 0,

        "has_title": False,
        "title": "",

        "domain_title_match_score": 0.0,
        "url_title_match_score": 0.0,

        "has_favicon": False,
        "robots": False,
        "is_responsive": False,

        "no_of_url_redirect": 0,
        "no_of_self_redirect": 0,

        "has_description": False,

        "no_of_popup": 0,
        "no_of_iframe": 0,

        "has_external_form_submit": False,

        "has_social_net": False,

        "has_submit_button": False,
        "has_hidden_fields": False,
        "has_password_field": False,

        "bank": False,
        "pay": False,
        "crypto": False,

        "has_copyright_info": False,

        "no_of_image": 0,
        "no_of_css": 0,
        "no_of_js": 0,

        "no_of_self_ref": 0,
        "no_of_empty_ref": 0,
        "no_of_external_ref": 0,
    }