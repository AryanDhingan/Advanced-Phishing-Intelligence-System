from app.services.detection_service import detect_url


print("========================================")
print("FULL DETECTION SERVICE TEST")
print("========================================")


url = "https://www.google.com"


result = detect_url(url)


print("URL:", url)

print("----------------------------------------")

for key, value in result.items():
    print(f"{key}: {value}")

print("========================================")
print("DETECTION SERVICE TEST COMPLETED.")