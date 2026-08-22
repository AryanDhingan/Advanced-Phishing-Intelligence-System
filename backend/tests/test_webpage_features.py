from app.nlp.scraper import scrape_url
from app.ml.webpage_features import extract_webpage_features


url = "https://www.google.com"

scraped = scrape_url(url)

if scraped["error"]:
    print("Scraping failed:")
    print(scraped["error"])
    raise SystemExit(1)

features = extract_webpage_features(
    scraped["url"],
    scraped["html"],
)

print("========================================")
print("WEBPAGE FEATURE TEST")
print("========================================")

for key, value in features.items():
    print(f"{key}: {value}")

print("========================================")
print("Total webpage features:", len(features))
print("Webpage feature extraction PASSED.")