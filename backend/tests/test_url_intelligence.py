from app.intelligence.url_intelligence import (
    analyze_url_intelligence,
)


TEST_URLS = [
    "https://www.google.com",
    "https://paypa1.com/login",
    "http://paypal-login-security.com/verify",
    "https://secure-paypal-verification.com/account/login",
    "https://192.168.1.100/login",
    "https://example.com",
]


print("========================================")
print("URL INTELLIGENCE TEST")
print("========================================")


for url in TEST_URLS:

    result = analyze_url_intelligence(
        url
    )

    print()
    print("URL:", url)
    print(
        "Intelligence score:",
        result["intelligence_score"],
    )
    print(
        "Indicators:",
        result["indicators"],
    )
    print(
        "Suspicious keywords:",
        result["suspicious_keywords"],
    )
    print(
        "Brand similarity:",
        result["brand_similarity"],
    )
    print(
        "Explanation:",
        result["explanation"],
    )

    print("----------------------------------------")


print()
print("URL INTELLIGENCE TEST COMPLETED.")