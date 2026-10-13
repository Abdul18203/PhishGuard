
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd
from ucimlrepo import fetch_ucirepo
from sklearn.base import clone
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "phishing_model.joblib"

print("Downloading dataset...")
dataset = fetch_ucirepo(id=967)

urls = dataset.data.features["URL"].astype(str).str.strip()
labels = dataset.data.targets["label"].astype(int)

hostnames = urls.map(
    lambda url: (
        urlparse(url).hostname or ""
    ).lower().removeprefix("www.")
)

valid = urls.ne("") & hostnames.ne("") & labels.isin([0, 1])
urls = urls[valid].reset_index(drop=True)
labels = labels[valid].reset_index(drop=True)
hostnames = hostnames[valid].reset_index(drop=True)

print(f"Usable URLs: {len(urls)}")
print(f"Unique hostnames: {hostnames.nunique()}")

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.2,
    random_state=42,
)

train_idx, test_idx = next(
    splitter.split(urls, labels, groups=hostnames)
)

X_train = urls.iloc[train_idx]
X_test = urls.iloc[test_idx]
y_train = labels.iloc[train_idx]
y_test = labels.iloc[test_idx]

overlap = set(hostnames.iloc[train_idx]) & set(hostnames.iloc[test_idx])
assert not overlap, "Hostname leakage detected!"

print(f"Training URLs: {len(X_train)}")
print(f"Testing URLs: {len(X_test)}")
print(f"Shared hostnames: {len(overlap)}")

model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            analyzer="char",
            ngram_range=(3, 5),
            min_df=2,
            max_features=200000,
            sublinear_tf=True,
        ),
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42,
        ),
    ),
])

print("\nTraining a fresh model for domain-separated evaluation...")
model.fit(X_train, y_train)

predictions = model.predict(X_test)

print("\n--- Domain-separated evaluation ---")
print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")
print("\nClassification report:")
print(
    classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Phishing", "Legitimate"],
        zero_division=0,
    )
)
print("Confusion matrix (rows=true, columns=predicted):")
print(confusion_matrix(y_test, predictions, labels=[0, 1]))

print("\n--- Known legitimate URL sanity checks ---")
for url in [
    "https://example.com",
    "https://github.com",
    "https://google.com",
    "https://www.google.com",
    "https://www.wikipedia.org",
]:
    prediction = int(model.predict([url])[0])
    phishing_probability = model.predict_proba([url])[0][
        list(model.classes_).index(0)
    ]
    verdict = "PHISHING" if prediction == 0 else "LEGITIMATE"
    print(f"{url} -> {verdict} ({phishing_probability:.2%} phishing score)")

print("\nThe existing phishing_model.joblib was not changed.")
print("Evaluation completed.")
