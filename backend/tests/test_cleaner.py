from app.services.validator import validate_dataset
from app.services.cleaner import clean_dataset

df = validate_dataset()

clean_df = clean_dataset(df)

print(clean_df.head())

print(clean_df.columns.tolist())