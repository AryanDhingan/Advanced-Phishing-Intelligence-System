from app.nlp.scraper import scrape_url


url = "https://www.google.com"

result = scrape_url(url)

print("========================================")
print("NLP SCRAPER TEST")
print("========================================")

print("URL:", result["url"])
print("Status:", result["status_code"])
print("Title:", result["title"])
print("Forms:", result["forms"])
print("Password field:", result["has_password_field"])
print("Text length:", len(result["text"]))
print("Error:", result["error"])

print("========================================")

if result["error"] is None:
    print("Scraper test PASSED.")
else:
    print("Scraper test FAILED.")