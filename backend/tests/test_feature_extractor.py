from app.ml.feature_extractor import extract_url_features


url = " HTTPS://WWW.Google.com/login?id=123&user=test "

features = extract_url_features(url)

print("========================================")
print("FEATURE EXTRACTION TEST")
print("========================================")

print("URL length:", features["url_length"])
print("Domain length:", features["domain_length"])
print("Domain IP:", features["is_domain_ip"])
print("TLD:", features["tld"])
print("Subdomains:", features["no_of_subdomain"])
print("Letters:", features["no_of_letters_in_url"])
print("Digits:", features["no_of_digits_in_url"])
print("Equals:", features["no_of_equals_in_url"])
print("Question marks:", features["no_of_qmark_in_url"])
print("Ampersands:", features["no_of_ampersand_in_url"])
print("HTTPS:", features["is_https"])
print("Obfuscation:", features["has_obfuscation"])

print("========================================")

print("Total extracted features:", len(features))

print("Feature extraction test completed.")