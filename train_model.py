
import pandas as pd
import joblib
import json

from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)

# Project paths
BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "dataset" / "phishing_urls.csv"
MODEL_PATH = BASE_DIR / "models" / "phishing_model.joblib"
REPORT_PATH = BASE_DIR / "reports" / "model_metrics.json"

print("Loading dataset...")

data = pd.read_csv(DATA_PATH)

# Remove missing and duplicate URLs
data = data.dropna(subset=["URL", "Label"])
data = data.drop_duplicates(subset=["URL"])

X = data["URL"].astype(str)

# UCI: 0 = phishing, 1 = legitimate
# Our model: 1 = phishing, 0 = legitimate
y = (data["Label"].astype(int) == 0).astype(int)

print("Total usable URLs:", len(data))
print("Phishing URLs:", int(y.sum()))
print("Legitimate URLs:", int((y == 0).sum()))

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nBuilding Machine Learning pipeline...")

model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            analyzer="char",
            ngram_range=(3, 5),
            min_df=2,
            max_features=100000,
            sublinear_tf=True
        )
    ),
    (
        "classifier",
        SGDClassifier(
            loss="log_loss",
            max_iter=15,
            tol=0.001,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1
        )
    )
])

print("\nTraining model. Please wait...")

model.fit(X_train, y_train)

print("\nTesting model...")

predictions = model.predict(X_test)

# Calculate evaluation metrics
metrics = {
    "accuracy": float(accuracy_score(y_test, predictions)),
    "precision": float(precision_score(y_test, predictions)),
    "recall": float(recall_score(y_test, predictions)),
    "f1_score": float(f1_score(y_test, predictions))
}

print("\n===== MODEL PERFORMANCE =====")

for name, value in metrics.items():
    print(f"{name}: {value:.4f}")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions,
        target_names=["Legitimate", "Phishing"]
    )
)

print("Confusion Matrix:")
print(confusion_matrix(y_test, predictions))

# Save trained model
joblib.dump(model, MODEL_PATH)

# Save evaluation metrics
with open(REPORT_PATH, "w") as file:
    json.dump(metrics, file, indent=4)

print("\nModel saved at:", MODEL_PATH)
print("Metrics saved at:", REPORT_PATH)
print("\nTraining completed successfully!")
