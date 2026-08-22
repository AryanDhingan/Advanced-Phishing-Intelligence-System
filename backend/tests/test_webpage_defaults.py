from app.ml.webpage_defaults import (
    get_default_webpage_features,
)


features = get_default_webpage_features()


print("========================================")
print("WEBPAGE DEFAULT FEATURES TEST")
print("========================================")

print("Total features:", len(features))

print("----------------------------------------")

for key, value in features.items():
    print(f"{key}: {value}")

print("========================================")

if len(features) != 29:
    raise RuntimeError(
        f"Expected 29 webpage features, got {len(features)}"
    )

print("WEBPAGE DEFAULT FEATURES TEST PASSED.")