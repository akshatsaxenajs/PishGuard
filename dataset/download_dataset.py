
import pandas as pd
from pathlib import Path
from ucimlrepo import fetch_ucirepo

print("Downloading PhiUSIIL dataset...")

# Fetch dataset from UCI
dataset = fetch_ucirepo(id=967)

# Extract URL and target labels
features = dataset.data.features
targets = dataset.data.targets

print("\nAvailable feature columns:")
print(features.columns.tolist())

print("\nAvailable target columns:")
print(targets.columns.tolist())

# Keep only URL and its label
data = pd.DataFrame({
    "URL": features["URL"],
    "Label": targets.iloc[:, 0]
})

# Save dataset
output_path = Path(__file__).parent / "phishing_urls.csv"
data.to_csv(output_path, index=False)

print("\nDataset downloaded successfully!")
print("Total records:", len(data))

print("\nLabel distribution:")
print(data["Label"].value_counts())

print("\nSaved at:", output_path)
