from app.nlp.analyzer import analyze_url


url = "https://www.google.com"

result = analyze_url(url)

print("========================================")
print("NLP ANALYZER TEST")
print("========================================")

print("URL:", result["url"])
print("Title:", result["title"])
print("Password field:", result["has_password_field"])
print("Flags:", result["flags"])
print("Urgency terms:", result["urgency_terms"])
print("Brand similarity:", result["brand_similarity"])
print("Error:", result["error"])

print("========================================")

if result["error"] is None:
    print("Analyzer test PASSED.")
else:
    print("Analyzer test FAILED.")