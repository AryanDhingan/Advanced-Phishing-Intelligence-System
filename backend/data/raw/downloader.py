import pandas as pd

# Use the full path so Python knows exactly where to look
df = pd.read_csv(r'C:\advanced-phishing-intelligence-system\backend\data\raw\PhiUSIIL_Phishing_URL_Dataset.csv', nrows=1)

print(list(df.columns))